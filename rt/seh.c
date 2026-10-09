/*
 * SEH foundation. The backend delivers a fault on the faulting thread with
 * a TweakExceptionRecord; this translates it into a Windows EXCEPTION_RECORD
 * + CONTEXT, presents EXCEPTION_POINTERS to the guest's vectored exception
 * handlers (AddVectoredExceptionHandler) and then the unhandled-exception
 * filter, and either resumes (EXCEPTION_CONTINUE_EXECUTION) or terminates.
 *
 * SCOPE: this is vectored dispatch plus a translated top-level filter. It is
 * NOT frame-based __try/__except/__finally: TweakWin does not yet parse
 * .pdata/.xdata or run language-specific handlers with RtlUnwind, so a guest
 * that relies on table-based unwinding is not supported. That is called out
 * in docs/EXCEPTIONS.md rather than faked. A fault inside a handler, or an
 * unhandled exception, terminates the process cleanly (the backend already
 * terminates on a recursive fault during dispatch).
 *
 * The dispatcher is TweakWin code entered by the backend as the process
 * exception handler. It runs on the faulting thread with GS = that thread's
 * TEB, so guest handlers it calls see correct thread-local state.
 */
#include "excformat.h"
#include "rt.h"

#include "../backend/kb.h"

#include <pthread.h>
#include <stdint.h>
#include <string.h>

uint64_t tw_rt_current_teb(void);

#define MAX_VEH 32

struct veh {
    int live;
    uint32_t id;
    uint64_t handler; /* guest LONG(*)(EXCEPTION_POINTERS*) */
    int first;        /* added with FirstHandler != 0 */
};

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static struct veh g_veh[MAX_VEH];
static uint32_t g_veh_next = 1;
static uint64_t g_unhandled_filter; /* guest LONG(*)(EXCEPTION_POINTERS*) */
static int g_installed;

/* Map a backend fault vector to a Windows exception code. */
static uint32_t code_for(const tw_kb_excrec *r)
{
    switch (r->vector) {
    case TW_KB_VEC_PF: return EXC_ACCESS_VIOLATION;
    case TW_KB_VEC_UD: return EXC_ILLEGAL_INSTRUCTION;
    case TW_KB_VEC_GP:
        /* On TweakKernel M4 a ring-3 int3 surfaces as #GP(0x1A); treat that
         * exact case as a breakpoint, otherwise a privileged-instruction
         * fault. */
        if (r->error_code == 0x1A) return EXC_BREAKPOINT;
        return EXC_PRIV_INSTRUCTION;
    case TW_KB_VEC_BP: return EXC_BREAKPOINT;
    case TW_KB_VEC_DB: return EXC_SINGLE_STEP;
    case TW_KB_VEC_DE: return EXC_INT_DIVIDE_BY_ZERO;
    case TW_KB_VEC_OF: return EXC_INT_OVERFLOW;
    case TW_KB_VEC_BR: return EXC_ARRAY_BOUNDS;
    case TW_KB_VEC_MF: return EXC_FLT_INVALID_OP;
    case TW_KB_VEC_XM: return EXC_FLT_INVALID_OP;
    case TW_KB_VEC_AC: return EXC_ACCESS_VIOLATION;
    default:           return EXC_ILLEGAL_INSTRUCTION;
    }
}

static void wr32(uint64_t a, uint32_t v) { memcpy((void *)(uintptr_t)a, &v, 4); }
static void wr64(uint64_t a, uint64_t v) { memcpy((void *)(uintptr_t)a, &v, 8); }
static uint64_t rd64(uint64_t a) { uint64_t v; memcpy(&v, (void *)(uintptr_t)a, 8); return v; }

/* Fill a Windows CONTEXT from the backend record. */
static void fill_context(uint64_t ctx, const tw_kb_excrec *r)
{
    memset((void *)(uintptr_t)ctx, 0, CTX_SIZE);
    wr32(ctx + CTX_ContextFlags, CONTEXT_CONTROL | CONTEXT_INTEGER);
    wr32(ctx + CTX_EFlags, (uint32_t)r->rflags);
    wr64(ctx + CTX_Rax, r->rax);
    wr64(ctx + CTX_Rcx, r->rcx);
    wr64(ctx + CTX_Rdx, r->rdx);
    wr64(ctx + CTX_Rbx, r->rbx);
    wr64(ctx + CTX_Rsp, r->rsp);
    wr64(ctx + CTX_Rbp, r->rbp);
    wr64(ctx + CTX_Rsi, r->rsi);
    wr64(ctx + CTX_Rdi, r->rdi);
    wr64(ctx + CTX_R8, r->r8);
    wr64(ctx + CTX_R9, r->r9);
    wr64(ctx + CTX_R10, r->r10);
    wr64(ctx + CTX_R11, r->r11);
    wr64(ctx + CTX_R12, r->r12);
    wr64(ctx + CTX_R13, r->r13);
    wr64(ctx + CTX_R14, r->r14);
    wr64(ctx + CTX_R15, r->r15);
    wr64(ctx + CTX_Rip, r->rip);
}

/* Copy back the integer+control registers a handler may have edited. */
static void apply_context(tw_kb_excrec *r, uint64_t ctx)
{
    r->rax = rd64(ctx + CTX_Rax);
    r->rcx = rd64(ctx + CTX_Rcx);
    r->rdx = rd64(ctx + CTX_Rdx);
    r->rbx = rd64(ctx + CTX_Rbx);
    r->rsp = rd64(ctx + CTX_Rsp);
    r->rbp = rd64(ctx + CTX_Rbp);
    r->rsi = rd64(ctx + CTX_Rsi);
    r->rdi = rd64(ctx + CTX_Rdi);
    r->r8 = rd64(ctx + CTX_R8);
    r->r9 = rd64(ctx + CTX_R9);
    r->r10 = rd64(ctx + CTX_R10);
    r->r11 = rd64(ctx + CTX_R11);
    r->r12 = rd64(ctx + CTX_R12);
    r->r13 = rd64(ctx + CTX_R13);
    r->r14 = rd64(ctx + CTX_R14);
    r->r15 = rd64(ctx + CTX_R15);
    r->rip = rd64(ctx + CTX_Rip);
}

typedef int32_t(__attribute__((ms_abi)) * veh_fn)(void *);

/* Snapshot the VEH list so a handler can add/remove without racing us. */
static int snapshot(uint64_t *out, int cap)
{
    pthread_mutex_lock(&g_mu);
    int n = 0;
    for (int i = 0; i < MAX_VEH && n < cap; i++)
        if (g_veh[i].live && g_veh[i].first) out[n++] = g_veh[i].handler;
    for (int i = 0; i < MAX_VEH && n < cap; i++)
        if (g_veh[i].live && !g_veh[i].first) out[n++] = g_veh[i].handler;
    pthread_mutex_unlock(&g_mu);
    return n;
}

/* The process exception handler the backend enters. Runs on the faulting
 * thread's stack with GS = TEB, rdi = record. */
__attribute__((used)) static void tw_seh_dispatch(tw_kb_excrec *r)
{
    /* Carve EXCEPTION_RECORD, CONTEXT, EXCEPTION_POINTERS out of the space
     * below the record (the backend left a 128-byte red zone gap and the
     * record itself is above rsp). We allocate from the current stack via a
     * local array so it is guest-mapped memory with the right lifetime. */
    uint8_t scratch[ER_SIZE + CTX_SIZE + EP_SIZE + 64];
    uint64_t er = ((uint64_t)(uintptr_t)scratch + 15) & ~15ull;
    uint64_t ctx = (er + ER_SIZE + 15) & ~15ull;
    uint64_t ep = (ctx + CTX_SIZE + 15) & ~15ull;

    uint32_t code = code_for(r);
    memset((void *)(uintptr_t)er, 0, ER_SIZE);
    wr32(er + ER_ExceptionCode, code);
    wr32(er + ER_ExceptionFlags, 0); /* continuable */
    wr64(er + ER_ExceptionAddress, r->rip);
    if (code == EXC_ACCESS_VIOLATION) {
        wr32(er + ER_NumberParameters, 2);
        /* [0]: 0 read, 1 write, 8 execute. page-fault error code bit1=write,
         * bit4=instruction fetch. */
        uint64_t acc = (r->error_code & 0x10) ? 8 : (r->error_code & 0x2) ? 1 : 0;
        wr64(er + ER_ExceptionInformation + 0, acc);
        wr64(er + ER_ExceptionInformation + 8, r->fault_address);
    }
    fill_context(ctx, r);
    wr64(ep + EP_ExceptionRecord, er);
    wr64(ep + EP_ContextRecord, ctx);

    uint64_t list[MAX_VEH];
    int n = snapshot(list, MAX_VEH);
    int disposition = EXCEPTION_CONTINUE_SEARCH;
    for (int i = 0; i < n; i++) {
        veh_fn fn;
        memcpy(&fn, &list[i], sizeof fn);
        int32_t d = fn((void *)(uintptr_t)ep);
        if (d == EXCEPTION_CONTINUE_EXECUTION) {
            disposition = d;
            break;
        }
        /* EXCEPTION_CONTINUE_SEARCH: try the next handler. */
    }

    if (disposition != EXCEPTION_CONTINUE_EXECUTION && g_unhandled_filter) {
        veh_fn fn;
        memcpy(&fn, &g_unhandled_filter, sizeof fn);
        int32_t d = fn((void *)(uintptr_t)ep);
        if (d == EXCEPTION_CONTINUE_EXECUTION) disposition = d;
    }

    if (disposition == EXCEPTION_CONTINUE_EXECUTION) {
        apply_context(r, ctx);
        tw_kb_exc_return(r, TW_KB_EXC_CONTINUE); /* does not return on success */
    }
    /* Unhandled: end the process with a fault status. */
    tw_kb_exc_return(r, TW_KB_EXC_TERMINATE);
}

int tw_rt_seh_install(void);
int tw_rt_seh_install(void)
{
    if (g_installed) return 0;
    uint64_t entry;
    void (*fn)(tw_kb_excrec *) = tw_seh_dispatch;
    memcpy(&entry, &fn, sizeof entry);
    int64_t prev = (int64_t)tw_kb_exc_handler(entry);
    if (prev < 0) return -1;
    g_installed = 1;
    return 0;
}

void tw_rt_seh_reset(void);
void tw_rt_seh_reset(void)
{
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < MAX_VEH; i++) g_veh[i].live = 0;
    g_unhandled_filter = 0;
    pthread_mutex_unlock(&g_mu);
    if (g_installed) {
        tw_kb_exc_handler(0);
        g_installed = 0;
    }
}

/* Returns an opaque non-zero cookie, or 0 on failure. */
uint64_t tw_rt_veh_add(int first, uint64_t handler);
uint64_t tw_rt_veh_add(int first, uint64_t handler)
{
    if (!handler) return 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < MAX_VEH; i++) {
        if (!g_veh[i].live) {
            g_veh[i].live = 1;
            g_veh[i].first = first != 0;
            g_veh[i].handler = handler;
            g_veh[i].id = g_veh_next++;
            uint32_t id = g_veh[i].id;
            pthread_mutex_unlock(&g_mu);
            return ((uint64_t)id << 8) | (uint32_t)(i + 1);
        }
    }
    pthread_mutex_unlock(&g_mu);
    return 0;
}

int tw_rt_veh_remove(uint64_t cookie);
int tw_rt_veh_remove(uint64_t cookie)
{
    int idx = (int)((cookie & 0xff)) - 1;
    uint32_t id = (uint32_t)(cookie >> 8);
    if (idx < 0 || idx >= MAX_VEH) return -1;
    pthread_mutex_lock(&g_mu);
    int rc = -1;
    if (g_veh[idx].live && g_veh[idx].id == id) {
        g_veh[idx].live = 0;
        rc = 0;
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

/* Returns the previous filter (guest pointer). */
uint64_t tw_rt_set_unhandled_filter(uint64_t filter);
uint64_t tw_rt_set_unhandled_filter(uint64_t filter)
{
    pthread_mutex_lock(&g_mu);
    uint64_t prev = g_unhandled_filter;
    g_unhandled_filter = filter;
    pthread_mutex_unlock(&g_mu);
    return prev;
}
