/*
 * TweakKernel M4 implementation of the TweakWin kernel backend.
 *
 * Freestanding: no C library, no host headers beyond <stdint.h>/<stddef.h>.
 * Every call is one SYSCALL with the documented M4 numbers and argument
 * registers (kb_m4_abi.h); kernel error values pass through unchanged
 * because TW_KB_E* == -TWEAK_ERR_*.
 *
 * Built into the M4 test image (tests/m4/) and compiled on every host
 * build so it cannot rot. It must never be *called* on Linux: the numbers
 * would mean unrelated Linux syscalls.
 */
#include "kb.h"
#include "kb_m4_abi.h"

static inline int64_t m4_call(uint64_t n, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                              uint64_t a5)
{
    register uint64_t r10 __asm__("r10") = a3;
    register uint64_t r8 __asm__("r8") = a4;
    register uint64_t r9 __asm__("r9") = a5;
    int64_t ret;
    __asm__ volatile("syscall"
                     : "=a"(ret), "+r"(r10), "+r"(r8), "+r"(r9)
                     : "a"(n), "D"(a0), "S"(a1), "d"(a2)
                     : "rcx", "r11", "memory");
    return ret;
}

#define C0(n) m4_call((n), 0, 0, 0, 0, 0, 0)
#define C1(n, a) m4_call((n), (uint64_t)(a), 0, 0, 0, 0, 0)
#define C2(n, a, b) m4_call((n), (uint64_t)(a), (uint64_t)(b), 0, 0, 0, 0)
#define C3(n, a, b, c) m4_call((n), (uint64_t)(a), (uint64_t)(b), (uint64_t)(c), 0, 0, 0)
#define C4(n, a, b, c, d) m4_call((n), (uint64_t)(a), (uint64_t)(b), (uint64_t)(c), (uint64_t)(d), 0, 0)
#define C5(n, a, b, c, d, e) \
    m4_call((n), (uint64_t)(a), (uint64_t)(b), (uint64_t)(c), (uint64_t)(d), (uint64_t)(e), 0)
#define C6(n, a, b, c, d, e, f) \
    m4_call((n), (uint64_t)(a), (uint64_t)(b), (uint64_t)(c), (uint64_t)(d), (uint64_t)(e), (uint64_t)(f))

static tw_kb_info_t g_info;
static int g_inited;

int tw_kb_init(void)
{
    if (g_inited) return TW_KB_OK;
    int64_t ver = C1(M4_SYS_ABI_INFO, M4_ABI_INFO_VERSION);
    if (ver < 0) ver = C0(M4_SYS_ABI); /* pre-M4 kernels only have ABI */
    if (ver != M4_ABI_VERSION) return TW_KB_ENOSYS;
    int64_t count = C1(M4_SYS_ABI_INFO, M4_ABI_INFO_SYSCALLS);
    int64_t feat = C1(M4_SYS_ABI_INFO, M4_ABI_INFO_FEATURES);
    if (count < M4_SYS_COUNT || feat < 0) return TW_KB_ENOSYS;

    uint64_t caps = 0;
    if (feat & M4_FEATURE_THREADS) caps |= TW_KB_CAP_THREADS;
    if (feat & M4_FEATURE_TLS) caps |= TW_KB_CAP_TLS_GS;
    if (feat & M4_FEATURE_WAIT) caps |= TW_KB_CAP_WAIT_ANY;
    if (feat & M4_FEATURE_EVENT) caps |= TW_KB_CAP_EVENTS;
    if (feat & M4_FEATURE_SEMAPHORE) caps |= TW_KB_CAP_SEMAPHORES;
    if (feat & M4_FEATURE_DUP) caps |= TW_KB_CAP_DUP;
    if (feat & M4_FEATURE_VM) caps |= TW_KB_CAP_VM;
    if (feat & M4_FEATURE_SECTION) caps |= TW_KB_CAP_SECTIONS;
    if (feat & M4_FEATURE_EXCEPTION) caps |= TW_KB_CAP_EXCEPTIONS;
    if (feat & M4_FEATURE_FPU) caps |= TW_KB_CAP_FPU_SSE;
    /*
     * M5 capabilities stay off. A kernel that reports more calls or more
     * feature bits is not trusted to have any particular M5 semantics until
     * this backend is taught that ABI (docs/KERNEL-REQUIREMENTS.md); the NT
     * layer keeps using the M4 paths meanwhile.
     */
    g_info.name = "tweakkernel-m4";
    g_info.abi_version = (uint32_t)ver;
    g_info.syscall_count = (uint32_t)count;
    g_info.kernel_features = (uint64_t)feat;
    g_info.caps = caps;
    g_info.max_handles = M4_HANDLES;
    g_info.max_threads = M4_THREADS;
    g_info.max_vm_regions = M4_VM_REGIONS;
    g_info.max_wait = M4_WAIT_MAX;
    g_info.max_commit = M4_COMMIT_MAX;
    g_info.max_reserve = M4_RESERVE_MAX;
    g_info.max_section = M4_SECTION_MAX;
    g_info.vm_min = M4_VM_MIN;
    g_info.vm_limit = M4_VM_LIMIT;
    g_info.timer_ns = M4_TICK_NS;
    g_inited = 1;
    return TW_KB_OK;
}

const tw_kb_info_t *tw_kb_info(void)
{
    if (!g_inited && tw_kb_init() != TW_KB_OK) return 0;
    return &g_info;
}

/* ns -> PIT ticks, rounded up so a wait is never shorter than asked. */
static uint64_t ticks_for(uint64_t ns)
{
    if (ns == TW_KB_INFINITE) return M4_WAIT_INFINITE;
    if (ns == 0) return 0;
    uint64_t t = ns / M4_TICK_NS + (ns % M4_TICK_NS ? 1 : 0);
    return t >= M4_WAIT_INFINITE ? M4_WAIT_INFINITE - 1 : t;
}

int64_t tw_kb_debug_write(const void *buf, size_t len)
{
    const char *p = buf;
    size_t done = 0;
    while (done < len) {
        size_t n = len - done > M4_DEBUG_MAX ? M4_DEBUG_MAX : len - done;
        int64_t r = C2(M4_SYS_DEBUG, p + done, n);
        if (r < 0) return done ? (int64_t)done : r;
        done += (size_t)r;
    }
    return (int64_t)done;
}

uint64_t tw_kb_time_ns(void)
{
    return (uint64_t)C0(M4_SYS_TICKS) * M4_TICK_NS;
}

int tw_kb_sleep_ns(uint64_t ns)
{
    if (ns == 0) {
        C0(M4_SYS_YIELD);
        return 0;
    }
    uint64_t t = ticks_for(ns);
    while (t) {
        uint64_t n = t > M4_SLEEP_MAX ? M4_SLEEP_MAX : t;
        int64_t r = C1(M4_SYS_SLEEP, n);
        if (r < 0) return (int)r;
        t -= n;
    }
    return 0;
}

uint64_t tw_kb_process_id(void) { return (uint64_t)C0(M4_SYS_PROCESS_SELF); }
uint64_t tw_kb_thread_id(void) { return (uint64_t)C0(M4_SYS_THREAD_SELF); }

tw_kh tw_kb_thread_create(uint64_t entry, uint64_t stack, uint64_t arg, uint64_t gs_base)
{
    return C6(M4_SYS_THREAD_CREATE, entry, stack, arg, 0, 0, gs_base);
}

void tw_kb_thread_exit(int32_t status)
{
    for (;;) C1(M4_SYS_THREAD_EXIT, (int64_t)status);
}

int32_t tw_kb_run_on_stack(uint64_t entry, uint64_t stack, uint64_t arg, uint64_t gs_base, int *how)
{
    (void)how;
    if (C2(M4_SYS_TLS_SET, TW_KB_TLS_GS, gs_base) < 0) return TW_KB_EINVAL;
    /* The calling thread becomes the guest thread; it leaves through
     * THREAD_EXIT / EXIT, so nothing comes back here. */
    __asm__ volatile(
        "movq %0, %%rsp\n\t"
        "movq %1, %%rdi\n\t"
        "cld\n\t"
        "xorl %%ecx, %%ecx\n\t"
        "xorl %%edx, %%edx\n\t"
        "xorl %%esi, %%esi\n\t"
        "xorl %%ebp, %%ebp\n\t"
        "xorl %%ebx, %%ebx\n\t"
        "xorl %%r8d, %%r8d\n\t"
        "xorl %%r9d, %%r9d\n\t"
        "xorl %%r10d, %%r10d\n\t"
        "xorl %%r11d, %%r11d\n\t"
        "xorl %%r12d, %%r12d\n\t"
        "xorl %%r13d, %%r13d\n\t"
        "xorl %%r14d, %%r14d\n\t"
        "xorl %%r15d, %%r15d\n\t"
        "jmpq *%%rax\n\t"
        :
        : "r"(stack), "r"(arg), "a"(entry)
        : "memory");
    __builtin_unreachable();
}

void tw_kb_process_exit(int32_t status)
{
    for (;;) C1(M4_SYS_EXIT, (int64_t)status);
}

int tw_kb_tls_set(int which, uint64_t base) { return (int)C2(M4_SYS_TLS_SET, which, base); }
uint64_t tw_kb_tls_get(int which) { return (uint64_t)C1(M4_SYS_TLS_GET, which); }

int64_t tw_kb_wait_one(tw_kh h, uint64_t timeout_ns)
{
    return C2(M4_SYS_WAIT_ONE, h, ticks_for(timeout_ns));
}

int64_t tw_kb_wait_any(const tw_kh *hs, uint32_t count, uint64_t timeout_ns)
{
    return C3(M4_SYS_WAIT_ANY, hs, count, ticks_for(timeout_ns));
}

tw_kh tw_kb_event_create(uint32_t flags) { return C1(M4_SYS_EVENT_CREATE, flags); }
int64_t tw_kb_event_set(tw_kh h) { return C1(M4_SYS_EVENT_SET, h); }
int64_t tw_kb_event_reset(tw_kh h) { return C1(M4_SYS_EVENT_RESET, h); }
tw_kh tw_kb_sem_create(uint32_t initial, uint32_t max) { return C2(M4_SYS_SEM_CREATE, initial, max); }
int64_t tw_kb_sem_release(tw_kh h, uint32_t count) { return C2(M4_SYS_SEM_RELEASE, h, count); }

tw_kh tw_kb_dup(tw_kh h, uint32_t rights, tw_kh target) { return C3(M4_SYS_HANDLE_DUP, h, rights, target); }
int64_t tw_kb_handle_info(tw_kh h) { return C1(M4_SYS_HANDLE_INFO, h); }
int tw_kb_close(tw_kh h) { return (int)C1(M4_SYS_CLOSE, h); }

int tw_kb_exit_info(tw_kh h, tw_kb_exitinfo *out)
{
    return (int)C3(M4_SYS_EXIT_INFO, h, out, sizeof *out);
}

int tw_kb_process_terminate(tw_kh h, int32_t status)
{
    return (int)C2(M4_SYS_PROCESS_TERMINATE, h, (int64_t)status);
}

int64_t tw_kb_vm_reserve(uint64_t base, uint64_t size, uint32_t prot, uint32_t flags)
{
    return C4(M4_SYS_VM_RESERVE, base, size, prot, flags);
}

int tw_kb_vm_commit(uint64_t addr, uint64_t size, uint32_t prot) { return (int)C3(M4_SYS_VM_COMMIT, addr, size, prot); }
int tw_kb_vm_decommit(uint64_t addr, uint64_t size) { return (int)C2(M4_SYS_VM_DECOMMIT, addr, size); }
int tw_kb_vm_release(uint64_t base) { return (int)C1(M4_SYS_VM_RELEASE, base); }
int64_t tw_kb_vm_protect(uint64_t addr, uint64_t size, uint32_t prot) { return C3(M4_SYS_VM_PROTECT, addr, size, prot); }

int tw_kb_vm_query(uint64_t addr, tw_kb_vminfo *out)
{
    return (int)C3(M4_SYS_VM_QUERY, addr, out, sizeof *out);
}

tw_kh tw_kb_section_create(uint64_t size) { return C2(M4_SYS_SECTION_CREATE, size, 0); }

int64_t tw_kb_section_map(tw_kh s, uint64_t base, uint32_t prot, uint64_t offset, uint64_t size)
{
    return C5(M4_SYS_SECTION_MAP, s, base, prot, offset, size);
}

int tw_kb_section_unmap(uint64_t view_base) { return (int)C1(M4_SYS_SECTION_UNMAP, view_base); }

uint64_t tw_kb_exc_handler(uint64_t entry) { return (uint64_t)C1(M4_SYS_EXC_HANDLER, entry); }

int tw_kb_exc_return(tw_kb_excrec *rec, uint32_t action)
{
    return (int)C2(M4_SYS_EXC_RETURN, rec, action);
}

/* ---- host services: not part of TweakKernel M4 ---- */

int64_t tw_kb_file_open(const char *path, uint32_t flags) { (void)path; (void)flags; return TW_KB_ENOSYS; }
int64_t tw_kb_file_read(int64_t f, void *b, uint64_t l) { (void)f; (void)b; (void)l; return TW_KB_ENOSYS; }
int64_t tw_kb_file_write(int64_t f, const void *b, uint64_t l)
{
    /* Console streams 1/2 map to the kernel debug channel. */
    if (f == 1 || f == 2) return tw_kb_debug_write(b, (size_t)l);
    return TW_KB_ENOSYS;
}
int64_t tw_kb_file_seek(int64_t f, int64_t o, int w) { (void)f; (void)o; (void)w; return TW_KB_ENOSYS; }
int tw_kb_file_stat(int64_t f, tw_kb_fstat *st)
{
    if (f == 1 || f == 2) {
        st->type = TW_KB_FT_CHAR;
        st->readonly = 0;
        st->size = 0;
        st->mtime_ns = st->atime_ns = st->ctime_ns = 0;
        return 0;
    }
    return TW_KB_ENOSYS;
}
int tw_kb_file_truncate(int64_t f, uint64_t s) { (void)f; (void)s; return TW_KB_ENOSYS; }
int tw_kb_file_close(int64_t f) { return (f == 1 || f == 2) ? 0 : TW_KB_ENOSYS; }
int64_t tw_kb_file_dup(int64_t f) { return (f == 1 || f == 2) ? f : TW_KB_ENOSYS; }
int tw_kb_path_stat(const char *p, tw_kb_fstat *st, int fo) { (void)p; (void)st; (void)fo; return TW_KB_ENOSYS; }
int tw_kb_path_unlink(const char *p) { (void)p; return TW_KB_ENOSYS; }
int tw_kb_path_mkdir(const char *p) { (void)p; return TW_KB_ENOSYS; }
int tw_kb_path_rmdir(const char *p) { (void)p; return TW_KB_ENOSYS; }
int tw_kb_dir_next(int64_t f, char *n, size_t c, uint32_t *t) { (void)f; (void)n; (void)c; (void)t; return TW_KB_ENOSYS; }
int tw_kb_dir_lookup_ci(const char *d, const char *l, char *o, size_t c) { (void)d; (void)l; (void)o; (void)c; return TW_KB_ENOSYS; }
int64_t tw_kb_console_stream(int which) { return (which == 1 || which == 2) ? which : TW_KB_ENOSYS; }
int tw_kb_file_is_terminal(int64_t f) { return f == 1 || f == 2; }
tw_kh tw_kb_process_spawn(const void *b, size_t l, const int64_t s[3]) { (void)b; (void)l; (void)s; return TW_KB_ENOSYS; }
int tw_kb_process_startup_blob(void **b, size_t *l) { (void)b; (void)l; return 0; }
int tw_kb_host_adopt_child(int fd) { (void)fd; return TW_KB_ENOSYS; }

int tw_kb_fault_region_add(uint64_t base, uint64_t size, int writable)
{
    (void)base; (void)size; (void)writable;
    return TW_KB_OK; /* the kernel already tracks the image's VM */
}
void tw_kb_fault_region_clear(void) {}
