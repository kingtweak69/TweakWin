#include "thread.h"
#include "rt.h"
#include "winnt.h"

#include <pthread.h>
#include <stdint.h>
#include <string.h>

uint64_t tw_rt_current_teb(void);
void tw_rt_set_current_teb(uint64_t);
uint64_t tw_rt_build_teb(uint64_t stack_base, uint64_t stack_limit, uint64_t tid);
void tw_modules_thread_notify(uint32_t reason);

#define DLL_THREAD_ATTACH 2
#define DLL_THREAD_DETACH 3

/* Per-thread startup descriptor (guest memory so it works on both backends). */
struct thread_desc {
    uint64_t start;
    uint64_t param;
    uint64_t teb;
    uint64_t stack_base; /* rt_galloc base, freed on exit */
    uint64_t desc_base;  /* this descriptor's rt_galloc base */
};

/* The guest thread entry. Arrives with GS = our TEB (set by the backend),
 * rdi = descriptor pointer, on its own stack. */
__attribute__((noreturn)) static void thread_tramp(uint64_t descr)
{
    struct thread_desc d;
    memcpy(&d, (const void *)(uintptr_t)descr, sizeof d);
    tw_rt_set_current_teb(d.teb);
    tw_rt_tls_thread_attach(d.teb);
    tw_rt_tls_run_callbacks(DLL_THREAD_ATTACH);
    tw_modules_thread_notify(DLL_THREAD_ATTACH);

    uint32_t(__attribute__((ms_abi)) * start)(void *);
    memcpy(&start, &d.start, sizeof start);
    uint32_t ret = start((void *)(uintptr_t)d.param);

    tw_modules_thread_notify(DLL_THREAD_DETACH);
    tw_rt_tls_run_callbacks(DLL_THREAD_DETACH);
    tw_rt_tls_thread_detach(d.teb);
    /* The stack we are running on (d.stack_base) and the TEB are freed at
     * process teardown, not here: a thread cannot unmap its own stack. */
    tw_rt_thread_exit(ret);
}

tw_kh tw_rt_thread_create(uint64_t start, uint64_t param, uint64_t stack_size, uint32_t flags,
                          uint64_t *tid)
{
    if (flags != 0) return TW_KB_ENOSYS; /* CREATE_SUSPENDED etc. need M5 */
    if (start == 0) return TW_KB_EINVAL;
    uint64_t ssz = stack_size ? stack_size : (1u << 20);
    if (ssz < (64u << 10)) ssz = 64u << 10;
    if (ssz > (8u << 20)) ssz = 8u << 20;

    uint64_t stk = rt_galloc((size_t)ssz);
    if (!stk) return TW_KB_ENOMEM;
    uint64_t teb = tw_rt_build_teb(stk + ssz, stk, 0);
    if (!teb) {
        rt_gfree(stk);
        return TW_KB_ENOMEM;
    }
    uint64_t dp = rt_galloc(sizeof(struct thread_desc));
    if (!dp) {
        rt_gfree(teb);
        rt_gfree(stk);
        return TW_KB_ENOMEM;
    }
    struct thread_desc d = { start, param, teb, stk, dp };
    memcpy((void *)(uintptr_t)dp, &d, sizeof d);

    /* Entry stack top: 16-aligned minus 8, as after a CALL. */
    uint64_t top = (stk + ssz - 16) & ~15ull;
    top -= 8;
    uint64_t entry;
    void (*fn)(uint64_t) = thread_tramp;
    memcpy(&entry, &fn, sizeof entry);

    tw_kh h = tw_kb_thread_create(entry, top, dp, teb);
    if (h < 0) {
        rt_gfree(dp);
        rt_gfree(teb);
        rt_gfree(stk);
        return h;
    }
    if (tid) *tid = 0; /* filled by the caller via HANDLE_INFO if needed */
    return h;
}

__attribute__((noreturn)) void tw_rt_thread_exit(uint32_t code)
{
    tw_rt_set_current_teb(0);
    tw_kb_thread_exit((int32_t)code);
}
