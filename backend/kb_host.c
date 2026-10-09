/*
 * Linux host implementation of the TweakWin kernel backend.
 *
 * TweakOS 0.3 runs on Linux, so this is the backend `tweakwin run` uses
 * today. It re-implements the TweakKernel M4 object model in userspace
 * rather than mapping Windows semantics onto Linux ones: the layers above
 * see M4 handles, M4 rights, M4 wait rules, M4 VM states and M4 exception
 * records, and nothing more. Limits default to generous host values;
 * TWEAKWIN_KB_LIMITS=m4 applies TweakKernel M4's (16 handles, 16 threads,
 * 64 VM regions, 4 MiB sections) so exhaustion paths can be tested here.
 *
 * Kernel objects live in one table guarded by g_mu. Waiters queue on each
 * object in FIFO order and are satisfied at signal time, exactly once.
 */
#define _GNU_SOURCE
#include "kb.h"

#include <asm/prctl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
#define KB_ASAN 1
void __sanitizer_start_switch_fiber(void **fake_stack_save, const void *bottom, size_t size);
void __sanitizer_finish_switch_fiber(void *fake_stack_save, const void **bottom_old, size_t *size_old);
#else
#define KB_ASAN 0
#endif

#define PAGE 4096ull
#define VM_MIN 0x10000ull
#define VM_LIMIT 0x00007FFFFFFF0000ull

/* ------------------------------------------------------------------ */
/* state                                                               */

struct kobj;
struct waiter;

struct waitblock {
    struct waiter *w;
    struct kobj *obj;
    uint32_t index;
    int linked;
    struct waitblock *next, *prev;
};

struct waiter {
    pthread_cond_t cv;
    int64_t result; /* -1 pending, else satisfied index */
    uint32_t n;
    struct waitblock wb[64];
};

struct kobj {
    int type;
    int refs;
    struct waitblock *head, *tail;
    union {
        struct { int signaled, manual; } ev;
        struct { uint32_t count, max; } sem;
        struct {
            int done;
            uint32_t reason;
            int64_t status;
            uint64_t detail, id;
            pid_t pid;              /* process only */
            struct child_slot *slot;/* process only */
        } task;
        struct { int memfd; uint64_t size; uint32_t wviews, xviews; } sec;
    } u;
};

struct hslot {
    uint32_t gen;
    uint32_t rights;
    struct kobj *obj;
};

struct region {
    uint64_t base, size;
    uint32_t type;      /* TW_KB_VMT_PRIVATE / SECTION */
    uint8_t *pg;        /* per page: bit 7 committed, bits 0-2 prot */
    struct kobj *sec;   /* section view */
    uint32_t view_prot;
};

struct hthread {
    struct kobj *obj;       /* thread object (NULL for unregistered host threads) */
    uint64_t tid;
    int initial;            /* thread running tw_kb_run_on_stack */
    uint64_t exit_ctx[8];
    int32_t exit_status;
    int exit_how;
    int in_exc;
    void *altstack;
    size_t altstack_len;
    uint64_t entry, stack, arg, gs;
    void *asan_fake;
    const void *host_bottom;
    size_t host_size;
};

/* Shared page between a spawned child and its parent. */
struct child_slot {
    uint32_t magic;
    uint32_t reason;
    int64_t status;
    uint64_t blob_len;
    /* blob follows */
};
#define CHILD_MAGIC 0x54574B42u /* "TWKB" */

/*
 * Foreign fault regions. The legacy loader maps the PE image and its stack
 * outside the backend VM; this table lets on_fault recognise a fault in
 * that code and accept the guest stack for the exception record. On
 * TweakKernel M4 the image is already in the kernel's own VM, so the
 * registration is a no-op there.
 */
#define FAULT_REGIONS 16
struct fault_region {
    int live;
    uint64_t base, end;
    int writable;
};
static struct fault_region g_fault_regions[FAULT_REGIONS];

/*
 * Minimal context save/jump. glibc's fortified longjmp refuses to move
 * between the guest stack and a host stack at a lower address, which is
 * exactly what leaving a guest thread does.
 * ctx: rbx rbp r12 r13 r14 r15 rsp rip
 */
__attribute__((returns_twice)) int kb_ctx_save(uint64_t *ctx);
__attribute__((noreturn)) void kb_ctx_jump(uint64_t *ctx);
__asm__(".text\n"
        ".globl kb_ctx_save\n"
        ".type kb_ctx_save,@function\n"
        "kb_ctx_save:\n"
        "  movq %rbx, 0(%rdi)\n"
        "  movq %rbp, 8(%rdi)\n"
        "  movq %r12, 16(%rdi)\n"
        "  movq %r13, 24(%rdi)\n"
        "  movq %r14, 32(%rdi)\n"
        "  movq %r15, 40(%rdi)\n"
        "  leaq 8(%rsp), %rdx\n"
        "  movq %rdx, 48(%rdi)\n"
        "  movq (%rsp), %rdx\n"
        "  movq %rdx, 56(%rdi)\n"
        "  xorl %eax, %eax\n"
        "  ret\n"
        ".size kb_ctx_save, .-kb_ctx_save\n"
        ".globl kb_ctx_jump\n"
        ".type kb_ctx_jump,@function\n"
        "kb_ctx_jump:\n"
        "  movq 0(%rdi), %rbx\n"
        "  movq 8(%rdi), %rbp\n"
        "  movq 16(%rdi), %r12\n"
        "  movq 24(%rdi), %r13\n"
        "  movq 32(%rdi), %r14\n"
        "  movq 40(%rdi), %r15\n"
        "  movq 48(%rdi), %rsp\n"
        "  movl $1, %eax\n"
        "  jmpq *56(%rdi)\n"
        ".size kb_ctx_jump, .-kb_ctx_jump\n");

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static __thread int t_holds;
static __thread struct hthread *t_self;
static __thread int t_in_exc_fallback; /* recursion guard for the legacy main thread (no hthread) */

static tw_kb_info_t g_info;
static int g_inited;
static struct hslot *g_slots;       /* index 1..max_handles */
static struct region *g_regions;
static uint32_t g_nregions;
static atomic_uint_fast64_t g_next_tid = 1;
static int g_live_threads;          /* guest threads (initial + created) */
static int g_process_started;       /* tw_kb_run_on_stack has run */
static struct hthread *g_initial;
static pthread_cond_t g_last_cv;
static int g_last_done;
static int32_t g_last_status;
static uint64_t g_exc_handler;
static struct child_slot *g_child_slot; /* when this process was spawned */
static size_t g_child_slot_len;
static struct sigaction g_old_act[32];

static void lock(void)
{
    pthread_mutex_lock(&g_mu);
    t_holds = 1;
}

static void unlock(void)
{
    t_holds = 0;
    pthread_mutex_unlock(&g_mu);
}

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int prot_ok(uint32_t prot)
{
    return (prot & ~7u) == 0 && !((prot & 2u) && (prot & 4u));
}

static uint32_t prot_norm(uint32_t prot)
{
    if (prot == 0) return TW_KB_PROT_NONE;
    if (prot & 2u) return TW_KB_PROT_RW;
    if (prot & 4u) return TW_KB_PROT_RX;
    return TW_KB_PROT_R;
}

static int host_prot(uint32_t p)
{
    switch (prot_norm(p)) {
    case TW_KB_PROT_R:  return PROT_READ;
    case TW_KB_PROT_RW: return PROT_READ | PROT_WRITE;
    case TW_KB_PROT_RX: return PROT_READ | PROT_EXEC;
    default:            return PROT_NONE;
    }
}

/* ------------------------------------------------------------------ */
/* init                                                                */

static void read_limits(void)
{
    const char *l = getenv("TWEAKWIN_KB_LIMITS");
    int m4 = l && strcmp(l, "m4") == 0;
    g_info.name = "host-linux";
    g_info.abi_version = 2;
    g_info.syscall_count = 48;
    g_info.kernel_features = 0;
    g_info.caps = TW_KB_CAPS_M4 | TW_KB_CAP_HOST_FILES | TW_KB_CAP_HOST_CONSOLE | TW_KB_CAP_HOST_SPAWN;
    g_info.max_handles = m4 ? 16 : 4096;
    g_info.max_threads = m4 ? 16 : 512;
    g_info.max_vm_regions = m4 ? 64 : 8192;
    g_info.max_wait = m4 ? 8 : 64;
    g_info.max_commit = 16ull << 20;
    g_info.max_reserve = 64ull << 30;
    g_info.max_section = m4 ? (4ull << 20) : (256ull << 20);
    g_info.vm_min = VM_MIN;
    g_info.vm_limit = VM_LIMIT;
    g_info.timer_ns = 1000000ull;
}

static void install_signals(void);

int tw_kb_init(void)
{
    lock();
    if (g_inited) {
        unlock();
        return TW_KB_OK;
    }
    read_limits();
    g_slots = calloc((size_t)g_info.max_handles + 1, sizeof *g_slots);
    g_regions = calloc(g_info.max_vm_regions, sizeof *g_regions);
    if (!g_slots || !g_regions) {
        free(g_slots);
        free(g_regions);
        g_slots = NULL;
        g_regions = NULL;
        unlock();
        return TW_KB_ENOMEM;
    }
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&g_last_cv, &ca);
    pthread_condattr_destroy(&ca);
    g_inited = 1;
    unlock();
    install_signals();
    return TW_KB_OK;
}

const tw_kb_info_t *tw_kb_info(void)
{
    if (!g_inited) tw_kb_init();
    return &g_info;
}

/* ------------------------------------------------------------------ */
/* objects and handles                                                 */

static struct kobj *obj_new(int type)
{
    struct kobj *o = calloc(1, sizeof *o);
    if (!o) return NULL;
    o->type = type;
    o->refs = 1;
    return o;
}

static void obj_put(struct kobj *o)
{
    if (!o || --o->refs > 0) return;
    if (o->type == TW_KB_TYPE_SECTION && o->u.sec.memfd >= 0) close(o->u.sec.memfd);
    free(o);
}

static tw_kh slot_install(struct kobj *o, uint32_t rights)
{
    for (uint32_t i = 1; i <= g_info.max_handles; i++) {
        if (g_slots[i].obj) continue;
        if (g_slots[i].gen == 0) g_slots[i].gen = 1;
        g_slots[i].obj = o;
        g_slots[i].rights = rights;
        o->refs++;
        return (tw_kh)(((uint64_t)g_slots[i].gen << 16) | i);
    }
    return TW_KB_ENOMEM;
}

static int slot_lookup(tw_kh h, int type, uint32_t need, struct hslot **out)
{
    if (h <= 0) return TW_KB_EBADH;
    uint64_t v = (uint64_t)h;
    uint32_t i = (uint32_t)(v & 0xffff);
    uint64_t gen = v >> 16;
    if (i == 0 || i > g_info.max_handles || gen == 0 || gen > 0xffffffffull) return TW_KB_EBADH;
    struct hslot *s = &g_slots[i];
    if (!s->obj || s->gen != (uint32_t)gen) return TW_KB_EBADH;
    if (type && s->obj->type != type) return TW_KB_EBADH;
    if ((s->rights & need) != need) return TW_KB_EPERM;
    *out = s;
    return 0;
}

/* ---- waits ---- */

static int obj_signaled(const struct kobj *o)
{
    switch (o->type) {
    case TW_KB_TYPE_EVENT:     return o->u.ev.signaled;
    case TW_KB_TYPE_SEMAPHORE: return o->u.sem.count > 0;
    case TW_KB_TYPE_THREAD:
    case TW_KB_TYPE_PROCESS:   return o->u.task.done;
    default:                   return 0;
    }
}

static void obj_consume(struct kobj *o)
{
    if (o->type == TW_KB_TYPE_EVENT && !o->u.ev.manual) o->u.ev.signaled = 0;
    else if (o->type == TW_KB_TYPE_SEMAPHORE && o->u.sem.count) o->u.sem.count--;
}

static void wb_unlink(struct waitblock *b)
{
    struct kobj *o = b->obj;
    if (!b->linked) return;
    if (b->prev) b->prev->next = b->next;
    else o->head = b->next;
    if (b->next) b->next->prev = b->prev;
    else o->tail = b->prev;
    b->next = b->prev = NULL;
    b->linked = 0;
}

/* Satisfy queued waiters, oldest first, while the object stays signaled.
 * A satisfied waiter is unlinked from every object it waits on, so the
 * scan restarts from the (new) head each time. */
static void obj_wake(struct kobj *o)
{
    while (o->head && obj_signaled(o)) {
        struct waitblock *b = o->head;
        struct waiter *w = b->w;
        w->result = b->index;
        obj_consume(o);
        for (uint32_t i = 0; i < w->n; i++) wb_unlink(&w->wb[i]);
        pthread_cond_signal(&w->cv);
    }
}

static int64_t do_wait(const tw_kh *hs, uint32_t count, uint64_t timeout_ns)
{
    if (count == 0 || count > g_info.max_wait) return TW_KB_EINVAL;
    struct waiter *w = calloc(1, sizeof *w);
    if (!w) return TW_KB_ENOMEM;
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&w->cv, &ca);
    pthread_condattr_destroy(&ca);
    w->result = -1;

    lock();
    struct kobj *objs[64];
    for (uint32_t i = 0; i < count; i++) {
        struct hslot *s;
        int rc = slot_lookup(hs[i], 0, 0, &s);
        int t = rc ? 0 : s->obj->type;
        if (!rc && t != TW_KB_TYPE_EVENT && t != TW_KB_TYPE_SEMAPHORE && t != TW_KB_TYPE_THREAD &&
            t != TW_KB_TYPE_PROCESS)
            rc = TW_KB_EBADH;
        if (!rc && !(s->rights & TW_KB_RIGHT_WAIT)) rc = TW_KB_EPERM;
        if (rc) {
            unlock();
            pthread_cond_destroy(&w->cv);
            free(w);
            return rc;
        }
        objs[i] = s->obj;
    }
    /* Already signaled? First in argument order wins. */
    for (uint32_t i = 0; i < count; i++) {
        if (obj_signaled(objs[i])) {
            obj_consume(objs[i]);
            unlock();
            pthread_cond_destroy(&w->cv);
            free(w);
            return i;
        }
    }
    if (timeout_ns == 0) {
        unlock();
        pthread_cond_destroy(&w->cv);
        free(w);
        return TW_KB_WAIT_TIMEOUT;
    }
    w->n = count;
    for (uint32_t i = 0; i < count; i++) {
        struct waitblock *b = &w->wb[i];
        b->w = w;
        b->obj = objs[i];
        b->index = i;
        b->linked = 1;
        objs[i]->refs++; /* the waiter keeps the object alive */
        b->prev = objs[i]->tail;
        b->next = NULL;
        if (objs[i]->tail) objs[i]->tail->next = b;
        else objs[i]->head = b;
        objs[i]->tail = b;
    }
    struct timespec dl;
    int timed = timeout_ns != TW_KB_INFINITE;
    if (timed) {
        uint64_t at = mono_ns();
        at = (timeout_ns > UINT64_MAX - at) ? UINT64_MAX : at + timeout_ns;
        dl.tv_sec = (time_t)(at / 1000000000ull);
        dl.tv_nsec = (long)(at % 1000000000ull);
    }
    while (w->result < 0) {
        t_holds = 0;
        int rc = timed ? pthread_cond_timedwait(&w->cv, &g_mu, &dl) : pthread_cond_wait(&w->cv, &g_mu);
        t_holds = 1;
        if (rc == ETIMEDOUT && w->result < 0) break;
    }
    int64_t res = w->result >= 0 ? w->result : TW_KB_WAIT_TIMEOUT;
    /* Unlink anything still queued, then drop the waiter's references. */
    for (uint32_t i = 0; i < w->n; i++) {
        struct waitblock *b = &w->wb[i];
        if (!b->obj) continue;
        wb_unlink(b);
        obj_put(b->obj);
        b->obj = NULL;
    }
    unlock();
    pthread_cond_destroy(&w->cv);
    free(w);
    return res;
}

int64_t tw_kb_wait_one(tw_kh h, uint64_t timeout_ns)
{
    return do_wait(&h, 1, timeout_ns);
}

int64_t tw_kb_wait_any(const tw_kh *hs, uint32_t count, uint64_t timeout_ns)
{
    if (!hs) return TW_KB_EFAULT;
    return do_wait(hs, count, timeout_ns);
}

/* ---- events / semaphores ---- */

tw_kh tw_kb_event_create(uint32_t flags)
{
    if (flags & ~(TW_KB_EVENT_MANUAL | TW_KB_EVENT_SIGNALED)) return TW_KB_EINVAL;
    lock();
    struct kobj *o = obj_new(TW_KB_TYPE_EVENT);
    if (!o) {
        unlock();
        return TW_KB_ENOMEM;
    }
    o->u.ev.manual = (flags & TW_KB_EVENT_MANUAL) != 0;
    o->u.ev.signaled = (flags & TW_KB_EVENT_SIGNALED) != 0;
    tw_kh h = slot_install(o, TW_KB_RIGHT_WAIT | TW_KB_RIGHT_SIGNAL | TW_KB_RIGHT_QUERY);
    obj_put(o);
    unlock();
    return h;
}

static int64_t event_op(tw_kh h, int set)
{
    lock();
    struct hslot *s;
    int rc = slot_lookup(h, TW_KB_TYPE_EVENT, TW_KB_RIGHT_SIGNAL, &s);
    if (rc) {
        unlock();
        return rc;
    }
    struct kobj *o = s->obj;
    int64_t prev = o->u.ev.signaled;
    o->u.ev.signaled = set;
    if (set) obj_wake(o);
    unlock();
    return prev;
}

int64_t tw_kb_event_set(tw_kh h) { return event_op(h, 1); }
int64_t tw_kb_event_reset(tw_kh h) { return event_op(h, 0); }

tw_kh tw_kb_sem_create(uint32_t initial, uint32_t max)
{
    if (max == 0 || max > 0x7FFFFFFFu || initial > max) return TW_KB_EINVAL;
    lock();
    struct kobj *o = obj_new(TW_KB_TYPE_SEMAPHORE);
    if (!o) {
        unlock();
        return TW_KB_ENOMEM;
    }
    o->u.sem.count = initial;
    o->u.sem.max = max;
    tw_kh h = slot_install(o, TW_KB_RIGHT_WAIT | TW_KB_RIGHT_SIGNAL | TW_KB_RIGHT_QUERY);
    obj_put(o);
    unlock();
    return h;
}

int64_t tw_kb_sem_release(tw_kh h, uint32_t count)
{
    if (count == 0 || count > 0x7FFFFFFFu) return TW_KB_EINVAL;
    lock();
    struct hslot *s;
    int rc = slot_lookup(h, TW_KB_TYPE_SEMAPHORE, TW_KB_RIGHT_SIGNAL, &s);
    if (rc) {
        unlock();
        return rc;
    }
    struct kobj *o = s->obj;
    if ((uint64_t)o->u.sem.count + count > o->u.sem.max) {
        unlock();
        return TW_KB_ESTATE;
    }
    int64_t prev = o->u.sem.count;
    o->u.sem.count += count;
    obj_wake(o);
    unlock();
    return prev;
}

/* ---- handles ---- */

tw_kh tw_kb_dup(tw_kh h, uint32_t rights, tw_kh target)
{
    lock();
    struct hslot *s;
    int rc = slot_lookup(h, 0, 0, &s);
    if (rc) {
        unlock();
        return rc;
    }
    if (rights == 0 || (rights & ~s->rights)) {
        unlock();
        return TW_KB_EPERM;
    }
    if (target != 0) {
        struct hslot *t;
        rc = slot_lookup(target, TW_KB_TYPE_PROCESS, TW_KB_RIGHT_MANAGE, &t);
        unlock();
        if (rc) return rc;
        /* A child is another Linux process: there is no shared handle
         * table to install into. TweakKernel M4 supports this; the host
         * backend does not. */
        return TW_KB_ENOSYS;
    }
    tw_kh n = slot_install(s->obj, rights);
    unlock();
    return n;
}

int64_t tw_kb_handle_info(tw_kh h)
{
    lock();
    struct hslot *s;
    int rc = slot_lookup(h, 0, 0, &s);
    int64_t r = rc ? rc : (int64_t)(((uint64_t)s->obj->type << 32) | s->rights);
    unlock();
    return r;
}

int tw_kb_close(tw_kh h)
{
    lock();
    struct hslot *s;
    int rc = slot_lookup(h, 0, 0, &s);
    if (rc) {
        unlock();
        return rc;
    }
    struct kobj *o = s->obj;
    s->obj = NULL;
    s->rights = 0;
    s->gen++;
    if (s->gen == 0 || s->gen > 0xffff) s->gen = 1;
    obj_put(o);
    unlock();
    return 0;
}

int tw_kb_exit_info(tw_kh h, tw_kb_exitinfo *out)
{
    if (!out) return TW_KB_EFAULT;
    lock();
    struct hslot *s;
    int rc = slot_lookup(h, 0, TW_KB_RIGHT_QUERY, &s);
    if (rc) {
        unlock();
        return rc;
    }
    struct kobj *o = s->obj;
    if (o->type != TW_KB_TYPE_THREAD && o->type != TW_KB_TYPE_PROCESS) {
        unlock();
        return TW_KB_EBADH;
    }
    if (!o->u.task.done) {
        unlock();
        return TW_KB_ESTATE;
    }
    out->size = sizeof *out;
    out->reason = o->u.task.reason;
    out->status = o->u.task.status;
    out->detail = o->u.task.detail;
    out->id = o->u.task.id;
    unlock();
    return 0;
}

/* ------------------------------------------------------------------ */
/* misc                                                                */

int64_t tw_kb_debug_write(const void *buf, size_t len)
{
    if (!buf || len == 0 || len > 256) return TW_KB_EINVAL;
    ssize_t n = write(STDERR_FILENO, buf, len);
    return n < 0 ? TW_KB_EIO : n;
}

uint64_t tw_kb_time_ns(void) { return mono_ns(); }

int tw_kb_sleep_ns(uint64_t ns)
{
    if (ns == 0) {
        sched_yield();
        return 0;
    }
    struct timespec ts;
    ts.tv_sec = (time_t)(ns / 1000000000ull);
    ts.tv_nsec = (long)(ns % 1000000000ull);
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
    return 0;
}

uint64_t tw_kb_process_id(void) { return (uint64_t)getpid(); }

uint64_t tw_kb_thread_id(void)
{
    if (t_self) return t_self->tid;
    return (uint64_t)syscall(SYS_gettid);
}

int tw_kb_tls_set(int which, uint64_t base)
{
    if (which == TW_KB_TLS_FS) return TW_KB_ENOSYS; /* FS belongs to the host C library */
    if (which != TW_KB_TLS_GS) return TW_KB_EINVAL;
    if (base >= VM_LIMIT) return TW_KB_EINVAL;
    return syscall(SYS_arch_prctl, ARCH_SET_GS, (unsigned long)base) == 0 ? 0 : TW_KB_EINVAL;
}

uint64_t tw_kb_tls_get(int which)
{
    unsigned long v = 0;
    if (which != TW_KB_TLS_GS) return 0;
    syscall(SYS_arch_prctl, ARCH_GET_GS, &v);
    return v;
}

/* ------------------------------------------------------------------ */
/* virtual memory                                                      */

static int range_ok(uint64_t addr, uint64_t *size, uint64_t max)
{
    if ((addr & (PAGE - 1)) || *size == 0 || *size > max) return -1;
    uint64_t sz = (*size + PAGE - 1) & ~(PAGE - 1);
    if (addr < VM_MIN || addr >= VM_LIMIT || sz > VM_LIMIT - addr) return -1;
    *size = sz;
    return 0;
}

static int rfind(uint64_t addr)
{
    for (uint32_t i = 0; i < g_nregions; i++)
        if (addr >= g_regions[i].base && addr - g_regions[i].base < g_regions[i].size) return (int)i;
    return -1;
}

static int rcontaining(uint64_t addr, uint64_t size)
{
    int i = rfind(addr);
    if (i < 0) return -1;
    const struct region *r = &g_regions[i];
    return size <= r->size - (addr - r->base) ? i : -1;
}

static int roverlaps(uint64_t base, uint64_t size)
{
    for (uint32_t i = 0; i < g_nregions; i++) {
        const struct region *r = &g_regions[i];
        if (base < r->base + r->size && r->base < base + size) return 1;
    }
    return 0;
}

static struct region *rinsert(uint64_t base, uint64_t size, uint32_t type)
{
    if (g_nregions >= g_info.max_vm_regions) return NULL;
    uint8_t *pg = calloc(size / PAGE, 1);
    if (!pg) return NULL;
    uint32_t at = 0;
    while (at < g_nregions && g_regions[at].base < base) at++;
    memmove(&g_regions[at + 1], &g_regions[at], (g_nregions - at) * sizeof *g_regions);
    g_nregions++;
    struct region *r = &g_regions[at];
    memset(r, 0, sizeof *r);
    r->base = base;
    r->size = size;
    r->type = type;
    r->pg = pg;
    return r;
}

static void rremove(int i)
{
    free(g_regions[i].pg);
    memmove(&g_regions[i], &g_regions[i + 1], (g_nregions - (uint32_t)i - 1) * sizeof *g_regions);
    g_nregions--;
}

static int commit_locked(uint64_t addr, uint64_t size, uint32_t prot)
{
    if (!prot_ok(prot) || range_ok(addr, &size, g_info.max_commit)) return TW_KB_EINVAL;
    int i = rcontaining(addr, size);
    if (i < 0) return TW_KB_EFAULT;
    struct region *r = &g_regions[i];
    if (r->type != TW_KB_VMT_PRIVATE) return TW_KB_EINVAL;
    uint32_t np = prot_norm(prot);
    uint64_t first = (addr - r->base) / PAGE, n = size / PAGE;
    for (uint64_t k = 0; k < n;) {
        uint8_t *st = &r->pg[first + k];
        if (*st & 0x80) {
            k++;
            continue; /* already committed: contents and protection kept */
        }
        uint64_t run = 1;
        while (k + run < n && !(r->pg[first + k + run] & 0x80)) run++;
        void *va = (void *)(uintptr_t)(addr + k * PAGE);
        if (mprotect(va, run * PAGE, host_prot(np)) != 0) return TW_KB_ENOMEM;
        for (uint64_t j = 0; j < run; j++) r->pg[first + k + j] = (uint8_t)(0x80 | np);
        k += run;
    }
    return 0;
}

int64_t tw_kb_vm_reserve(uint64_t base, uint64_t size, uint32_t prot, uint32_t flags)
{
    if ((flags & ~TW_KB_VM_COMMIT) || !prot_ok(prot)) return TW_KB_EINVAL;
    if (base == 0) {
        if (size == 0 || size > g_info.max_reserve) return TW_KB_EINVAL;
        size = (size + PAGE - 1) & ~(PAGE - 1);
    } else if (range_ok(base, &size, g_info.max_reserve)) {
        return TW_KB_EINVAL;
    }
    if ((flags & TW_KB_VM_COMMIT) && size > g_info.max_commit) return TW_KB_EINVAL;
    lock();
    if (g_nregions >= g_info.max_vm_regions) {
        unlock();
        return TW_KB_ENOMEM;
    }
    if (base && roverlaps(base, size)) {
        unlock();
        return TW_KB_ESTATE;
    }
    void *p = mmap(base ? (void *)(uintptr_t)base : NULL, size, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | (base ? MAP_FIXED_NOREPLACE : 0), -1, 0);
    if (p == MAP_FAILED) {
        unlock();
        return base ? TW_KB_ESTATE : TW_KB_ENOMEM;
    }
    uint64_t at = (uint64_t)(uintptr_t)p;
    if ((base && at != base) || at < VM_MIN || at + size > VM_LIMIT) {
        munmap(p, size);
        unlock();
        return base ? TW_KB_ESTATE : TW_KB_ENOMEM;
    }
    struct region *r = rinsert(at, size, TW_KB_VMT_PRIVATE);
    if (!r) {
        munmap(p, size);
        unlock();
        return TW_KB_ENOMEM;
    }
    if (flags & TW_KB_VM_COMMIT) {
        int rc = commit_locked(at, size, prot);
        if (rc) {
            munmap(p, size);
            rremove(rfind(at));
            unlock();
            return rc;
        }
    }
    unlock();
    return (int64_t)at;
}

int tw_kb_vm_commit(uint64_t addr, uint64_t size, uint32_t prot)
{
    lock();
    int rc = commit_locked(addr, size, prot);
    unlock();
    return rc;
}

static void decommit_range(struct region *r, uint64_t addr, uint64_t size)
{
    uint64_t first = (addr - r->base) / PAGE, n = size / PAGE;
    madvise((void *)(uintptr_t)addr, size, MADV_DONTNEED);
    mprotect((void *)(uintptr_t)addr, size, PROT_NONE);
    for (uint64_t k = 0; k < n; k++) r->pg[first + k] = 0;
}

int tw_kb_vm_decommit(uint64_t addr, uint64_t size)
{
    if (range_ok(addr, &size, g_info.max_reserve)) return TW_KB_EINVAL;
    lock();
    int i = rcontaining(addr, size);
    if (i < 0) {
        unlock();
        return TW_KB_EFAULT;
    }
    if (g_regions[i].type != TW_KB_VMT_PRIVATE) {
        unlock();
        return TW_KB_EINVAL;
    }
    decommit_range(&g_regions[i], addr, size);
    unlock();
    return 0;
}

int tw_kb_vm_release(uint64_t base)
{
    lock();
    int i = rfind(base);
    if (i < 0 || g_regions[i].base != base) {
        unlock();
        return TW_KB_EFAULT;
    }
    if (g_regions[i].type != TW_KB_VMT_PRIVATE) {
        unlock();
        return TW_KB_EINVAL;
    }
    munmap((void *)(uintptr_t)base, g_regions[i].size);
    rremove(i);
    unlock();
    return 0;
}

int64_t tw_kb_vm_protect(uint64_t addr, uint64_t size, uint32_t prot)
{
    if (!prot_ok(prot) || range_ok(addr, &size, g_info.max_reserve)) return TW_KB_EINVAL;
    lock();
    int i = rcontaining(addr, size);
    if (i < 0) {
        unlock();
        return TW_KB_EFAULT;
    }
    struct region *r = &g_regions[i];
    if (r->type != TW_KB_VMT_PRIVATE) {
        unlock();
        return TW_KB_EINVAL;
    }
    uint64_t first = (addr - r->base) / PAGE, n = size / PAGE;
    for (uint64_t k = 0; k < n; k++) {
        if (!(r->pg[first + k] & 0x80)) {
            unlock();
            return TW_KB_EFAULT;
        }
    }
    int64_t old = r->pg[first] & 7;
    uint32_t np = prot_norm(prot);
    if (mprotect((void *)(uintptr_t)addr, size, host_prot(np)) != 0) {
        unlock();
        return TW_KB_ENOMEM;
    }
    for (uint64_t k = 0; k < n; k++) r->pg[first + k] = (uint8_t)(0x80 | np);
    unlock();
    return old;
}

static void query_locked(uint64_t addr, tw_kb_vminfo *info)
{
    memset(info, 0, sizeof *info);
    uint64_t page = addr & ~(PAGE - 1);
    info->base = page;
    int i = rfind(page);
    if (i < 0) {
        uint64_t lo = 0, hi = VM_LIMIT;
        for (uint32_t k = 0; k < g_nregions; k++) {
            const struct region *r = &g_regions[k];
            if (r->base + r->size <= page && r->base + r->size > lo) lo = r->base + r->size;
            if (r->base > page && r->base < hi) hi = r->base;
        }
        info->size = hi - page;
        info->region_base = lo;
        info->region_size = hi - lo;
        info->state = TW_KB_VM_FREE;
        info->type = TW_KB_VMT_NONE;
        return;
    }
    const struct region *r = &g_regions[i];
    info->region_base = r->base;
    info->region_size = r->size;
    info->type = r->type;
    uint64_t idx = (page - r->base) / PAGE;
    uint8_t st = r->pg[idx];
    info->state = (st & 0x80) ? TW_KB_VM_COMMITTED : TW_KB_VM_RESERVED;
    info->prot = (st & 0x80) ? (st & 7u) : 0;
    uint64_t n = r->size / PAGE, k = idx;
    while (k < n && r->pg[k] == st) k++;
    info->size = (k - idx) * PAGE;
}

int tw_kb_vm_query(uint64_t addr, tw_kb_vminfo *out)
{
    if (!out) return TW_KB_EFAULT;
    if (addr >= VM_LIMIT) return TW_KB_EINVAL;
    lock();
    query_locked(addr, out);
    unlock();
    return 0;
}

/* ------------------------------------------------------------------ */
/* sections                                                            */

tw_kh tw_kb_section_create(uint64_t size)
{
    if (size == 0 || size > g_info.max_section) return TW_KB_EINVAL;
    size = (size + PAGE - 1) & ~(PAGE - 1);
    int fd = (int)syscall(SYS_memfd_create, "tweakwin-section", MFD_CLOEXEC);
    if (fd < 0) return TW_KB_ENOMEM;
    if (ftruncate(fd, (off_t)size) != 0) {
        close(fd);
        return TW_KB_ENOMEM;
    }
    lock();
    struct kobj *o = obj_new(TW_KB_TYPE_SECTION);
    if (!o) {
        unlock();
        close(fd);
        return TW_KB_ENOMEM;
    }
    o->u.sec.memfd = fd;
    o->u.sec.size = size;
    tw_kh h = slot_install(o, TW_KB_RIGHT_READ | TW_KB_RIGHT_WRITE | TW_KB_RIGHT_EXEC | TW_KB_RIGHT_QUERY);
    obj_put(o);
    unlock();
    return h;
}

int64_t tw_kb_section_map(tw_kh h, uint64_t base, uint32_t prot, uint64_t offset, uint64_t size)
{
    if (prot == 0 || !prot_ok(prot)) return TW_KB_EINVAL;
    uint32_t need = TW_KB_RIGHT_READ;
    if (prot & 2u) need |= TW_KB_RIGHT_WRITE;
    if (prot & 4u) need |= TW_KB_RIGHT_EXEC;
    lock();
    struct hslot *s;
    int rc = slot_lookup(h, TW_KB_TYPE_SECTION, need, &s);
    if (rc) {
        unlock();
        return rc;
    }
    struct kobj *o = s->obj;
    uint64_t bytes = o->u.sec.size;
    if ((offset & (PAGE - 1)) || offset >= bytes) {
        unlock();
        return TW_KB_EINVAL;
    }
    if (size == 0) size = bytes - offset;
    size = (size + PAGE - 1) & ~(PAGE - 1);
    if (size == 0 || size > bytes - offset || (base && range_ok(base, &size, g_info.max_section))) {
        unlock();
        return TW_KB_EINVAL;
    }
    uint32_t np = prot_norm(prot);
    if ((np == TW_KB_PROT_RW && o->u.sec.xviews) || (np == TW_KB_PROT_RX && o->u.sec.wviews)) {
        unlock();
        return TW_KB_ESTATE;
    }
    if (g_nregions >= g_info.max_vm_regions) {
        unlock();
        return TW_KB_ENOMEM;
    }
    if (base && roverlaps(base, size)) {
        unlock();
        return TW_KB_ESTATE;
    }
    void *p = mmap(base ? (void *)(uintptr_t)base : NULL, size, host_prot(np),
                   MAP_SHARED | (base ? MAP_FIXED_NOREPLACE : 0), o->u.sec.memfd, (off_t)offset);
    if (p == MAP_FAILED || (base && (uint64_t)(uintptr_t)p != base)) {
        if (p != MAP_FAILED) munmap(p, size);
        unlock();
        return base ? TW_KB_ESTATE : TW_KB_ENOMEM;
    }
    struct region *r = rinsert((uint64_t)(uintptr_t)p, size, TW_KB_VMT_SECTION);
    if (!r) {
        munmap(p, size);
        unlock();
        return TW_KB_ENOMEM;
    }
    memset(r->pg, 0x80 | np, size / PAGE);
    r->sec = o;
    r->view_prot = np;
    o->refs++;
    if (np == TW_KB_PROT_RW) o->u.sec.wviews++;
    if (np == TW_KB_PROT_RX) o->u.sec.xviews++;
    unlock();
    return (int64_t)(uintptr_t)p;
}

int tw_kb_section_unmap(uint64_t view_base)
{
    lock();
    int i = rfind(view_base);
    if (i < 0 || g_regions[i].base != view_base) {
        unlock();
        return TW_KB_EFAULT;
    }
    struct region *r = &g_regions[i];
    if (r->type != TW_KB_VMT_SECTION) {
        unlock();
        return TW_KB_EINVAL;
    }
    struct kobj *o = r->sec;
    if (r->view_prot == TW_KB_PROT_RW && o->u.sec.wviews) o->u.sec.wviews--;
    if (r->view_prot == TW_KB_PROT_RX && o->u.sec.xviews) o->u.sec.xviews--;
    munmap((void *)(uintptr_t)r->base, r->size);
    rremove(i);
    obj_put(o);
    unlock();
    return 0;
}

/* ------------------------------------------------------------------ */
/* threads                                                             */

__attribute__((noinline, used, no_sanitize("address")))
static void kb_asan_arrived(struct hthread *t)
{
#if KB_ASAN
    __sanitizer_finish_switch_fiber(t->asan_fake, &t->host_bottom, &t->host_size);
#else
    (void)t;
#endif
}

/* SysV: rdi entry, rsi exact guest RSP, rdx arg, rcx thread record.
 * Calls kb_asan_arrived below the guest RSP (that memory is free stack),
 * then enters the guest with every GPR but RSP/RDI zero. Never returns:
 * the thread leaves through tw_kb_thread_exit / tw_kb_process_exit. */
__attribute__((naked, noinline, noreturn))
static void kb_enter_guest(uint64_t entry __attribute__((unused)), uint64_t stack __attribute__((unused)),
                           uint64_t arg __attribute__((unused)), struct hthread *t __attribute__((unused)))
{
    __asm__ volatile(
        "movq %rdi, %r12\n\t"
        "movq %rdx, %r13\n\t"
        "movq %rsi, %r14\n\t"
        "movq %rsi, %rsp\n\t"
        "subq $8, %rsp\n\t"
        "andq $-16, %rsp\n\t"
        "movq %rcx, %rdi\n\t"
        "call kb_asan_arrived\n\t"
        "movq %r14, %rsp\n\t"
        "movq %r13, %rdi\n\t"
        "movq %r12, %rax\n\t"
        "cld\n\t"
        "xorl %ecx, %ecx\n\t"
        "xorl %edx, %edx\n\t"
        "xorl %esi, %esi\n\t"
        "xorl %ebp, %ebp\n\t"
        "xorl %ebx, %ebx\n\t"
        "xorl %r8d, %r8d\n\t"
        "xorl %r9d, %r9d\n\t"
        "xorl %r10d, %r10d\n\t"
        "xorl %r11d, %r11d\n\t"
        "xorl %r12d, %r12d\n\t"
        "xorl %r13d, %r13d\n\t"
        "xorl %r14d, %r14d\n\t"
        "xorl %r15d, %r15d\n\t"
        "jmpq *%rax\n\t");
}

__attribute__((no_sanitize("address"), noreturn))
static void kb_enter(struct hthread *t)
{
#if KB_ASAN
    tw_kb_vminfo vi;
    const void *bottom = (const void *)(uintptr_t)(t->stack - PAGE);
    size_t sz = PAGE;
    if (tw_kb_vm_query(t->stack - 1, &vi) == 0 && vi.state == TW_KB_VM_COMMITTED) {
        bottom = (const void *)(uintptr_t)vi.region_base;
        sz = (size_t)(t->stack - vi.region_base);
    }
    __sanitizer_start_switch_fiber(&t->asan_fake, bottom, sz);
#endif
    kb_enter_guest(t->entry, t->stack, t->arg, t);
}

static void setup_altstack(struct hthread *t)
{
    size_t len = 256 * 1024;
    void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return;
    stack_t ss;
    ss.ss_sp = p;
    ss.ss_size = len;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != 0) {
        munmap(p, len);
        return;
    }
    t->altstack = p;
    t->altstack_len = len;
}

static void drop_altstack(struct hthread *t)
{
    if (!t->altstack) return;
    stack_t ss;
    memset(&ss, 0, sizeof ss);
    ss.ss_flags = SS_DISABLE;
    sigaltstack(&ss, NULL);
    munmap(t->altstack, t->altstack_len);
    t->altstack = NULL;
}

/* Called with g_mu held. Marks the thread object dead and wakes waiters. */
static void thread_finish_locked(struct hthread *t, int32_t status, uint32_t reason, uint64_t detail)
{
    if (t->obj) {
        t->obj->u.task.done = 1;
        t->obj->u.task.status = status;
        t->obj->u.task.reason = reason;
        t->obj->u.task.detail = detail;
        obj_wake(t->obj);
        obj_put(t->obj);
        t->obj = NULL;
    }
}

static void child_report(uint32_t reason, int32_t status)
{
    if (g_child_slot) {
        g_child_slot->reason = reason;
        g_child_slot->status = status;
    }
}

static void *thread_main(void *p)
{
    struct hthread *t = p;
    t_self = t;
    tw_kb_tls_set(TW_KB_TLS_GS, t->gs);
    setup_altstack(t);
    if (kb_ctx_save(t->exit_ctx) == 0) kb_enter(t);
#if KB_ASAN
    __sanitizer_finish_switch_fiber(t->asan_fake, NULL, NULL);
#endif
    syscall(SYS_arch_prctl, ARCH_SET_GS, 0ul);
    drop_altstack(t);
    lock();
    int32_t st = t->exit_status;
    thread_finish_locked(t, st, TW_KB_EXIT_NORMAL, 0);
    g_live_threads--;
    int last = g_live_threads == 0 && g_process_started;
    if (last && g_initial) {
        g_last_done = 1;
        g_last_status = st;
        pthread_cond_broadcast(&g_last_cv);
        last = 0;
    }
    unlock();
    free(t);
    t_self = NULL;
    if (last) {
        child_report(TW_KB_EXIT_NORMAL, st);
        _exit(st & 0xff);
    }
    return NULL;
}

tw_kh tw_kb_thread_create(uint64_t entry, uint64_t stack, uint64_t arg, uint64_t gs_base)
{
    if (entry == 0 || entry >= VM_LIMIT || stack == 0 || stack >= VM_LIMIT || (stack & 7) ||
        gs_base >= VM_LIMIT)
        return TW_KB_EINVAL;
    struct hthread *t = calloc(1, sizeof *t);
    if (!t) return TW_KB_ENOMEM;
    lock();
    if ((uint32_t)g_live_threads >= g_info.max_threads) {
        unlock();
        free(t);
        return TW_KB_ENOMEM;
    }
    struct kobj *o = obj_new(TW_KB_TYPE_THREAD);
    if (!o) {
        unlock();
        free(t);
        return TW_KB_ENOMEM;
    }
    t->tid = atomic_fetch_add(&g_next_tid, 1) + 0x1000;
    o->u.task.id = t->tid;
    tw_kh h = slot_install(o, TW_KB_RIGHT_WAIT | TW_KB_RIGHT_QUERY | TW_KB_RIGHT_MANAGE);
    if (h < 0) {
        obj_put(o);
        unlock();
        free(t);
        return h;
    }
    t->obj = o; /* the running thread keeps its creation reference */
    t->entry = entry;
    t->stack = stack;
    t->arg = arg;
    t->gs = gs_base;
    g_live_threads++;
    unlock();

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 1u << 20);
    pthread_t pt;
    int rc = pthread_create(&pt, &attr, thread_main, t);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        lock();
        g_live_threads--;
        struct hslot *s;
        if (slot_lookup(h, 0, 0, &s) == 0) {
            s->obj = NULL;
            s->gen++;
            obj_put(o);
        }
        obj_put(o);
        unlock();
        free(t);
        return TW_KB_ENOMEM;
    }
    return h;
}

__attribute__((no_sanitize("address"), noreturn))
static void leave_guest(struct hthread *t)
{
#if KB_ASAN
    __sanitizer_start_switch_fiber(&t->asan_fake, t->host_bottom, t->host_size);
#endif
    kb_ctx_jump(t->exit_ctx);
}

void tw_kb_thread_exit(int32_t status)
{
    struct hthread *t = t_self;
    if (!t) {
        /* Not a backend thread (e.g. a host test harness). */
        pthread_exit(NULL);
    }
    t->exit_status = status;
    t->exit_how = 1;
    leave_guest(t);
}

int32_t tw_kb_run_on_stack(uint64_t entry, uint64_t stack, uint64_t arg, uint64_t gs_base, int *how)
{
    struct hthread *t = calloc(1, sizeof *t);
    if (!t) {
        if (how) *how = 0;
        return TW_KB_ENOMEM;
    }
    lock();
    struct kobj *o = obj_new(TW_KB_TYPE_THREAD);
    t->tid = atomic_fetch_add(&g_next_tid, 1) + 0x1000;
    if (o) o->u.task.id = t->tid;
    t->obj = o;
    t->initial = 1;
    t->entry = entry;
    t->stack = stack;
    t->arg = arg;
    t->gs = gs_base;
    g_live_threads++;
    g_process_started = 1;
    g_initial = t;
    g_last_done = 0;
    unlock();

    struct hthread *saved = t_self;
    t_self = t;
    tw_kb_tls_set(TW_KB_TLS_GS, gs_base);
    setup_altstack(t);
    if (kb_ctx_save(t->exit_ctx) == 0) kb_enter(t);
#if KB_ASAN
    __sanitizer_finish_switch_fiber(t->asan_fake, NULL, NULL);
#endif
    syscall(SYS_arch_prctl, ARCH_SET_GS, 0ul);
    drop_altstack(t);
    int32_t st = t->exit_status;
    int h = t->exit_how;
    lock();
    thread_finish_locked(t, st, TW_KB_EXIT_NORMAL, 0);
    g_live_threads--;
    if (h == 1 && g_live_threads > 0) {
        /* ExitThread on the initial thread: the process lives until the
         * last thread exits, whose status becomes the process status. */
        while (!g_last_done) {
            t_holds = 0;
            pthread_cond_wait(&g_last_cv, &g_mu);
            t_holds = 1;
        }
        st = g_last_status;
    }
    g_initial = NULL;
    g_process_started = 0;
    g_exc_handler = 0;
    unlock();
    t_self = saved;
    free(t);
    if (how) *how = h;
    return st;
}

void tw_kb_process_exit(int32_t status)
{
    struct hthread *t = t_self;
    lock();
    int only = t && t->initial && g_live_threads == 1;
    unlock();
    if (only) {
        t->exit_status = status;
        t->exit_how = 2;
        leave_guest(t);
    }
    child_report(TW_KB_EXIT_NORMAL, status);
    _exit(status & 0xff);
}

int tw_kb_process_terminate(tw_kh h, int32_t status)
{
    lock();
    struct hslot *s;
    int rc = slot_lookup(h, TW_KB_TYPE_PROCESS, TW_KB_RIGHT_MANAGE, &s);
    if (rc) {
        unlock();
        return rc;
    }
    struct kobj *o = s->obj;
    if (o->u.task.done) {
        unlock();
        return TW_KB_ESTATE;
    }
    if (o->u.task.slot) {
        o->u.task.slot->reason = TW_KB_EXIT_KILLED;
        o->u.task.slot->status = status;
    }
    pid_t pid = o->u.task.pid;
    unlock();
    kill(pid, SIGKILL);
    return 0;
}

/* ------------------------------------------------------------------ */
/* exceptions                                                          */

static const int g_fault_sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP };

uint64_t tw_kb_exc_handler(uint64_t entry)
{
    if (entry >= VM_LIMIT) return (uint64_t)(int64_t)TW_KB_EINVAL;
    lock();
    uint64_t prev = g_exc_handler;
    g_exc_handler = entry;
    unlock();
    return prev;
}

/* Is [a, a+len) committed and writable guest memory? Caller holds g_mu. */
static int writable_locked(uint64_t a, uint64_t len)
{
    uint64_t end = a + len;
    if (end < a) return 0;
    for (uint64_t p = a & ~(PAGE - 1); p < end; p += PAGE) {
        int i = rfind(p);
        if (i >= 0) {
            uint8_t st = g_regions[i].pg[(p - g_regions[i].base) / PAGE];
            if (!(st & 0x80) || (st & 7u) != TW_KB_PROT_RW) return 0;
            continue;
        }
        int fr = 0;
        for (int k = 0; k < FAULT_REGIONS; k++)
            if (g_fault_regions[k].live && g_fault_regions[k].writable && p >= g_fault_regions[k].base &&
                p < g_fault_regions[k].end) {
                fr = 1;
                break;
            }
        if (!fr) return 0;
    }
    return 1;
}

static void die_fault(uint64_t vector, uint64_t rip, const char *why)
{
    char buf[160];
    int n = snprintf(buf, sizeof buf, "tweakwin: guest fault vector %llu at 0x%llx: %s; process terminated\n",
                     (unsigned long long)vector, (unsigned long long)rip, why);
    if (n > 0) {
        ssize_t w = write(STDERR_FILENO, buf, (size_t)n);
        (void)w;
    }
    child_report(TW_KB_EXIT_FAULT, -1);
    _exit(255);
}

static void chain_old(int sig, siginfo_t *si, void *uc)
{
    struct sigaction *old = &g_old_act[sig];
    if ((old->sa_flags & SA_SIGINFO) && old->sa_sigaction) {
        old->sa_sigaction(sig, si, uc);
        return;
    }
    if (old->sa_handler != SIG_DFL && old->sa_handler != SIG_IGN && old->sa_handler) {
        old->sa_handler(sig);
        return;
    }
    signal(sig, SIG_DFL);
}

__attribute__((no_sanitize("address", "undefined")))
static void on_fault(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = ucv;
    greg_t *g = uc->uc_mcontext.gregs;
    struct hthread *t = t_self;
    int *in_exc = t ? &t->in_exc : &t_in_exc_fallback;
    uint64_t rip = (uint64_t)g[REG_RIP];
    uint64_t vector = (uint64_t)g[REG_TRAPNO];
    if (sig == SIGTRAP && vector != TW_KB_VEC_BP && vector != TW_KB_VEC_DB) vector = TW_KB_VEC_BP;

    /* A fault while TweakWin holds its own lock is a host bug, not a guest
     * exception. (t_self may be NULL: the legacy main thread is not a
     * backend thread, but it still runs guest code.) */
    if (t_holds) {
        chain_old(sig, si, ucv);
        return;
    }
    lock();
    int in_guest = rfind(rip) >= 0;
    if (!in_guest) {
        for (int i = 0; i < FAULT_REGIONS; i++)
            if (g_fault_regions[i].live && rip >= g_fault_regions[i].base &&
                rip < g_fault_regions[i].end) {
                in_guest = 1;
                break;
            }
    }
    uint64_t handler = g_exc_handler;
    unlock();
    if (!in_guest) {
        chain_old(sig, si, ucv);
        return;
    }
    if (!handler) die_fault(vector, rip, "no exception handler");
    if (*in_exc) die_fault(vector, rip, "fault inside the exception handler");

    uint64_t rsp = (uint64_t)g[REG_RSP];
    uint64_t rec_at = (rsp - 128 - TW_KB_EXC_RECORD_SIZE) & ~15ull;
    lock();
    int ok = rsp > 128 + TW_KB_EXC_RECORD_SIZE + 8 && writable_locked(rec_at - 8, TW_KB_EXC_RECORD_SIZE + 8);
    unlock();
    if (!ok) die_fault(vector, rip, "exception record does not fit on the stack");

    tw_kb_excrec *r = (tw_kb_excrec *)(uintptr_t)rec_at;
    memset(r, 0, sizeof *r);
    r->size = TW_KB_EXC_RECORD_SIZE;
    r->version = TW_KB_EXC_VERSION;
    r->vector = vector;
    r->error_code = (uint64_t)g[REG_ERR];
    r->fault_address = vector == TW_KB_VEC_PF ? (uint64_t)(uintptr_t)si->si_addr : (uint64_t)g[REG_CR2];
    if (vector != TW_KB_VEC_PF) r->fault_address = 0;
    r->rip = rip;
    r->rsp = rsp;
    r->rflags = (uint64_t)g[REG_EFL];
    r->rax = (uint64_t)g[REG_RAX];
    r->rbx = (uint64_t)g[REG_RBX];
    r->rcx = (uint64_t)g[REG_RCX];
    r->rdx = (uint64_t)g[REG_RDX];
    r->rsi = (uint64_t)g[REG_RSI];
    r->rdi = (uint64_t)g[REG_RDI];
    r->rbp = (uint64_t)g[REG_RBP];
    r->r8 = (uint64_t)g[REG_R8];
    r->r9 = (uint64_t)g[REG_R9];
    r->r10 = (uint64_t)g[REG_R10];
    r->r11 = (uint64_t)g[REG_R11];
    r->r12 = (uint64_t)g[REG_R12];
    r->r13 = (uint64_t)g[REG_R13];
    r->r14 = (uint64_t)g[REG_R14];
    r->r15 = (uint64_t)g[REG_R15];
    *(uint64_t *)(uintptr_t)(rec_at - 8) = 0;

    *in_exc = 1;
    g[REG_RIP] = (greg_t)handler;
    g[REG_RSP] = (greg_t)(rec_at - 8);
    g[REG_RDI] = (greg_t)rec_at;
    g[REG_EFL] = 0x202;
}

static void install_signals(void)
{
    for (size_t i = 0; i < sizeof g_fault_sigs / sizeof g_fault_sigs[0]; i++) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = on_fault;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
        sigemptyset(&sa.sa_mask);
        sigaction(g_fault_sigs[i], &sa, &g_old_act[g_fault_sigs[i]]);
    }
}

/* rdi = private record copy whose reserved[0] holds the target RSP - 24.
 * The C side left [rsp-24] = rdi, [rsp-16] = rflags, [rsp-8] = rip on the
 * target stack. Every register is loaded before RSP moves, so nothing is
 * read from below the new RSP. */
__attribute__((naked, noreturn))
static void kb_exc_resume(const tw_kb_excrec *r __attribute__((unused)))
{
    __asm__ volatile(
        "movq 56(%rdi), %rax\n\t"
        "movq 64(%rdi), %rbx\n\t"
        "movq 72(%rdi), %rcx\n\t"
        "movq 80(%rdi), %rdx\n\t"
        "movq 88(%rdi), %rsi\n\t"
        "movq 104(%rdi), %rbp\n\t"
        "movq 112(%rdi), %r8\n\t"
        "movq 120(%rdi), %r9\n\t"
        "movq 128(%rdi), %r10\n\t"
        "movq 136(%rdi), %r11\n\t"
        "movq 144(%rdi), %r12\n\t"
        "movq 152(%rdi), %r13\n\t"
        "movq 160(%rdi), %r14\n\t"
        "movq 168(%rdi), %r15\n\t"
        "movq 176(%rdi), %rsp\n\t"
        "popq %rdi\n\t"
        "popfq\n\t"
        "ret\n\t");
}

int tw_kb_exc_return(tw_kb_excrec *rec, uint32_t action)
{
    struct hthread *t = t_self;
    int *in_exc = t ? &t->in_exc : &t_in_exc_fallback;
    if (!*in_exc) return TW_KB_ESTATE;
    if (action == TW_KB_EXC_TERMINATE) {
        child_report(TW_KB_EXIT_FAULT, -1);
        _exit(255);
    }
    if (action != TW_KB_EXC_CONTINUE) return TW_KB_EINVAL;
    if (!rec) return TW_KB_EFAULT;
    tw_kb_excrec r;
    memcpy(&r, rec, sizeof r);
    if (r.size != TW_KB_EXC_RECORD_SIZE || r.version != TW_KB_EXC_VERSION) return TW_KB_EINVAL;
    if (r.rip == 0 || r.rip >= VM_LIMIT || r.rsp >= VM_LIMIT || r.rsp < 24) return TW_KB_EINVAL;
    lock();
    int ok = writable_locked(r.rsp - 24, 24);
    unlock();
    if (!ok) return TW_KB_EFAULT;
    uint64_t *slot = (uint64_t *)(uintptr_t)(r.rsp - 24);
    slot[0] = r.rdi;
    slot[1] = (r.rflags & 0x240DD5ull) | 0x202ull;
    slot[2] = r.rip;
    r.reserved[0] = r.rsp - 24;
    *in_exc = 0;
    kb_exc_resume(&r);
}

/* ------------------------------------------------------------------ */
/* host services                                                       */

static int map_errno(int e)
{
    switch (e) {
    case ENOENT:  return TW_KB_ENOENT;
    case EEXIST:  return TW_KB_EEXIST;
    case EACCES:
    case EPERM:
    case EROFS:   return TW_KB_EACCES;
    case EISDIR:  return TW_KB_EISDIR;
    case ENOTDIR: return TW_KB_ENOTDIR;
    case ELOOP:   return TW_KB_ELOOP;
    case ENOTEMPTY: return TW_KB_ENOTEMPTY;
    case ENOMEM:
    case EMFILE:
    case ENFILE:  return TW_KB_ENOMEM;
    case EBADF:   return TW_KB_EBADH;
    case EINVAL:
    case ENAMETOOLONG: return TW_KB_EINVAL;
    default:      return TW_KB_EIO;
    }
}

int64_t tw_kb_file_open(const char *path, uint32_t flags)
{
    if (!path || !path[0]) return TW_KB_EINVAL;
    int of = O_CLOEXEC;
    int rd = (flags & TW_KB_O_READ) != 0, wr = (flags & TW_KB_O_WRITE) != 0;
    if (flags & TW_KB_O_DIRECTORY) of |= O_RDONLY | O_DIRECTORY;
    else if (rd && wr) of |= O_RDWR;
    else if (wr) of |= O_WRONLY;
    else of |= O_RDONLY;
    if (flags & TW_KB_O_CREATE) of |= O_CREAT;
    if (flags & TW_KB_O_EXCL) of |= O_EXCL;
    if (flags & TW_KB_O_TRUNC) of |= O_TRUNC;
    if (flags & TW_KB_O_APPEND) of |= O_APPEND;
    if (flags & TW_KB_O_NOFOLLOW) of |= O_NOFOLLOW;
    int fd = open(path, of, 0666);
    if (fd < 0) return map_errno(errno);
    return fd;
}

int64_t tw_kb_file_read(int64_t fid, void *buf, uint64_t len)
{
    for (;;) {
        ssize_t n = read((int)fid, buf, len > 0x7ffff000u ? 0x7ffff000u : (size_t)len);
        if (n >= 0) return n;
        if (errno != EINTR) return map_errno(errno);
    }
}

int64_t tw_kb_file_write(int64_t fid, const void *buf, uint64_t len)
{
    uint64_t done = 0;
    const uint8_t *p = buf;
    while (done < len) {
        uint64_t chunk = len - done;
        if (chunk > 0x7ffff000u) chunk = 0x7ffff000u;
        ssize_t n = write((int)fid, p + done, (size_t)chunk);
        if (n < 0) {
            if (errno == EINTR) continue;
            return done ? (int64_t)done : map_errno(errno);
        }
        if (n == 0) break;
        done += (uint64_t)n;
    }
    return (int64_t)done;
}

int64_t tw_kb_file_seek(int64_t fid, int64_t off, int whence)
{
    int w = whence == 0 ? SEEK_SET : whence == 1 ? SEEK_CUR : whence == 2 ? SEEK_END : -1;
    if (w < 0) return TW_KB_EINVAL;
    off_t r = lseek((int)fid, (off_t)off, w);
    return r < 0 ? map_errno(errno) : (int64_t)r;
}

static void fill_stat(const struct stat *s, tw_kb_fstat *st)
{
    memset(st, 0, sizeof *st);
    if (S_ISREG(s->st_mode)) st->type = TW_KB_FT_FILE;
    else if (S_ISDIR(s->st_mode)) st->type = TW_KB_FT_DIR;
    else if (S_ISCHR(s->st_mode)) st->type = TW_KB_FT_CHAR;
    else if (S_ISFIFO(s->st_mode) || S_ISSOCK(s->st_mode)) st->type = TW_KB_FT_PIPE;
    st->readonly = (s->st_mode & S_IWUSR) == 0;
    st->size = (uint64_t)s->st_size;
    st->mtime_ns = (int64_t)s->st_mtim.tv_sec * 1000000000ll + s->st_mtim.tv_nsec;
    st->atime_ns = (int64_t)s->st_atim.tv_sec * 1000000000ll + s->st_atim.tv_nsec;
    st->ctime_ns = (int64_t)s->st_ctim.tv_sec * 1000000000ll + s->st_ctim.tv_nsec;
}

int tw_kb_file_stat(int64_t fid, tw_kb_fstat *st)
{
    struct stat s;
    if (fstat((int)fid, &s) != 0) return map_errno(errno);
    fill_stat(&s, st);
    return 0;
}

int tw_kb_file_truncate(int64_t fid, uint64_t size)
{
    return ftruncate((int)fid, (off_t)size) == 0 ? 0 : map_errno(errno);
}

#define MAX_DIRS 1024
static DIR *g_dirs[MAX_DIRS];

int tw_kb_file_close(int64_t fid)
{
    if (fid >= 0 && fid < MAX_DIRS && g_dirs[fid]) {
        closedir(g_dirs[fid]); /* closes fid */
        g_dirs[fid] = NULL;
        return 0;
    }
    return close((int)fid) == 0 ? 0 : map_errno(errno);
}

int64_t tw_kb_file_dup(int64_t fid)
{
    int fd = fcntl((int)fid, F_DUPFD_CLOEXEC, 3);
    return fd < 0 ? map_errno(errno) : fd;
}

int tw_kb_path_stat(const char *path, tw_kb_fstat *st, int follow)
{
    struct stat s;
    int rc = follow ? stat(path, &s) : lstat(path, &s);
    if (rc != 0) return map_errno(errno);
    fill_stat(&s, st);
    return 0;
}

int tw_kb_path_unlink(const char *path) { return unlink(path) == 0 ? 0 : map_errno(errno); }
int tw_kb_path_mkdir(const char *path) { return mkdir(path, 0777) == 0 ? 0 : map_errno(errno); }
int tw_kb_path_rmdir(const char *path) { return rmdir(path) == 0 ? 0 : map_errno(errno); }

int tw_kb_dir_next(int64_t fid, char *name, size_t cap, uint32_t *type)
{
    if (fid < 0 || fid >= MAX_DIRS) return TW_KB_EBADH;
    if (!g_dirs[fid]) {
        g_dirs[fid] = fdopendir((int)fid);
        if (!g_dirs[fid]) return map_errno(errno);
    }
    for (;;) {
        errno = 0;
        struct dirent *d = readdir(g_dirs[fid]);
        if (!d) return errno ? map_errno(errno) : 0;
        if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, "..")) continue;
        size_t n = strlen(d->d_name);
        if (n + 1 > cap) continue;
        memcpy(name, d->d_name, n + 1);
        if (type) {
            *type = d->d_type == DT_DIR ? TW_KB_FT_DIR : d->d_type == DT_REG ? TW_KB_FT_FILE : TW_KB_FT_UNKNOWN;
        }
        return 1;
    }
}

static int ascii_ieq(const char *a, const char *b)
{
    for (;; a++, b++) {
        unsigned char x = (unsigned char)*a, y = (unsigned char)*b;
        if (x >= 'A' && x <= 'Z') x = (unsigned char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (unsigned char)(y + 32);
        if (x != y) return 0;
        if (!x) return 1;
    }
}

int tw_kb_dir_lookup_ci(const char *dir, const char *leaf, char *out, size_t cap)
{
    DIR *d = opendir(dir);
    if (!d) return map_errno(errno);
    int found = TW_KB_ENOENT;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (ascii_ieq(e->d_name, leaf)) {
            size_t n = strlen(e->d_name);
            if (n + 1 <= cap) {
                memcpy(out, e->d_name, n + 1);
                found = 0;
            } else {
                found = TW_KB_EINVAL;
            }
            break;
        }
    }
    closedir(d);
    return found;
}

int64_t tw_kb_console_stream(int which)
{
    if (which < 0 || which > 2) return TW_KB_EINVAL;
    int fd = fcntl(which, F_DUPFD_CLOEXEC, 3);
    return fd < 0 ? map_errno(errno) : fd;
}

int tw_kb_file_is_terminal(int64_t fid) { return isatty((int)fid); }

/* ---- spawn ---- */

static void *reaper(void *p)
{
    struct kobj *o = p;
    int status = 0;
    pid_t pid = o->u.task.pid;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    lock();
    struct child_slot *s = o->u.task.slot;
    if (WIFEXITED(status)) {
        if (s && s->reason) {
            o->u.task.reason = s->reason;
            o->u.task.status = (int32_t)s->status;
        } else {
            o->u.task.reason = TW_KB_EXIT_NORMAL;
            o->u.task.status = WEXITSTATUS(status);
        }
    } else {
        o->u.task.reason = (s && s->reason == TW_KB_EXIT_KILLED) ? TW_KB_EXIT_KILLED : TW_KB_EXIT_FAULT;
        o->u.task.status = (s && s->reason == TW_KB_EXIT_KILLED) ? (int32_t)s->status : -1;
        o->u.task.detail = WIFSIGNALED(status) ? (uint64_t)WTERMSIG(status) : 0;
    }
    o->u.task.done = 1;
    obj_wake(o);
    obj_put(o);
    unlock();
    return NULL;
}

tw_kh tw_kb_process_spawn(const void *blob, size_t len, const int64_t std_fids[3])
{
    if (!blob && len) return TW_KB_EFAULT;
    if (len > (64u << 20)) return TW_KB_EINVAL;
    size_t total = (sizeof(struct child_slot) + len + PAGE - 1) & ~(PAGE - 1);
    int fd = (int)syscall(SYS_memfd_create, "tweakwin-startup", 0);
    if (fd < 0) return TW_KB_ENOMEM;
    if (ftruncate(fd, (off_t)total) != 0) {
        close(fd);
        return TW_KB_ENOMEM;
    }
    struct child_slot *slot = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (slot == MAP_FAILED) {
        close(fd);
        return TW_KB_ENOMEM;
    }
    slot->magic = CHILD_MAGIC;
    slot->blob_len = len;
    if (len) memcpy(slot + 1, blob, len);

    lock();
    struct kobj *o = obj_new(TW_KB_TYPE_PROCESS);
    if (!o) {
        unlock();
        munmap(slot, total);
        close(fd);
        return TW_KB_ENOMEM;
    }
    tw_kh h = slot_install(o, TW_KB_RIGHT_WAIT | TW_KB_RIGHT_QUERY | TW_KB_RIGHT_MANAGE);
    if (h < 0) {
        obj_put(o);
        unlock();
        munmap(slot, total);
        close(fd);
        return h;
    }
    unlock();

    char fdarg[32];
    snprintf(fdarg, sizeof fdarg, "%d", fd);
    pid_t pid = fork();
    if (pid == 0) {
        for (int i = 0; i < 3; i++) {
            if (std_fids && std_fids[i] >= 0 && std_fids[i] != i) {
                if (dup2((int)std_fids[i], i) < 0) _exit(127);
            }
        }
        char *argv[] = { (char *)"tweakwin", (char *)"__child", fdarg, NULL };
        execv("/proc/self/exe", argv);
        _exit(127);
    }
    close(fd);
    lock();
    if (pid < 0) {
        struct hslot *s;
        if (slot_lookup(h, 0, 0, &s) == 0) {
            s->obj = NULL;
            s->gen++;
            obj_put(o);
        }
        obj_put(o);
        unlock();
        munmap(slot, total);
        return TW_KB_ENOMEM;
    }
    o->u.task.pid = pid;
    o->u.task.id = (uint64_t)pid;
    o->u.task.slot = slot; /* never unmapped: tiny, lives as long as the parent */
    o->refs++;             /* reaper reference */
    unlock();
    pthread_t pt;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&pt, &attr, reaper, o) != 0) {
        /* Cannot observe the child; still return the handle. */
        lock();
        obj_put(o);
        unlock();
    }
    pthread_attr_destroy(&attr);
    return h;
}

static void *g_child_blob;
static size_t g_child_blob_len;

int tw_kb_process_startup_blob(void **blob, size_t *len)
{
    if (!g_child_slot) return 0;
    *blob = g_child_blob;
    *len = g_child_blob_len;
    return 1;
}

int tw_kb_fault_region_add(uint64_t base, uint64_t size, int writable);
int tw_kb_fault_region_add(uint64_t base, uint64_t size, int writable)
{
    if (size == 0) return TW_KB_EINVAL;
    lock();
    for (int i = 0; i < FAULT_REGIONS; i++) {
        if (!g_fault_regions[i].live) {
            g_fault_regions[i].live = 1;
            g_fault_regions[i].base = base;
            g_fault_regions[i].end = base + size;
            g_fault_regions[i].writable = writable != 0;
            unlock();
            return 0;
        }
    }
    unlock();
    return TW_KB_ENOMEM;
}

void tw_kb_fault_region_clear(void);
void tw_kb_fault_region_clear(void)
{
    lock();
    for (int i = 0; i < FAULT_REGIONS; i++) g_fault_regions[i].live = 0;
    unlock();
}

int tw_kb_host_adopt_child(int fd)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || (size_t)st.st_size < sizeof(struct child_slot)) return TW_KB_EINVAL;
    size_t total = (size_t)st.st_size;
    struct child_slot *s = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (s == MAP_FAILED) return TW_KB_ENOMEM;
    if (s->magic != CHILD_MAGIC || s->blob_len > total - sizeof *s) {
        munmap(s, total);
        return TW_KB_EINVAL;
    }
    void *copy = malloc(s->blob_len ? s->blob_len : 1);
    if (!copy) {
        munmap(s, total);
        return TW_KB_ENOMEM;
    }
    memcpy(copy, s + 1, s->blob_len);
    g_child_slot = s;
    g_child_slot_len = total;
    g_child_blob = copy;
    g_child_blob_len = s->blob_len;
    return 0;
}
