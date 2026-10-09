#ifndef TWEAKWIN_K32PRIV_H
#define TWEAKWIN_K32PRIV_H

#include "kernel32.h"

#include "../common/debug.h"
#include "../loader/load.h"
#include "../runtime/gueststr.h"
#include "../runtime/handle.h"
#include "../runtime/process.h"
#include "../runtime/utf.h"
#include "../runtime/vmem.h"

#define TW_GUEST_CSTR_MAX 32768u

static inline struct tw_loaded *tw_k32_guest(void)
{
    struct tw_loaded *p = tw_current_process();
    return p ? p : tw_runtime_image();
}

static inline int tw_k32_ok_r(const void *p, uint64_t n)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!im || !p || n == 0) return 0;
    return tw_guest_readable(im, (uint64_t)(uintptr_t)p, n);
}

static inline int tw_k32_ok_w(void *p, uint64_t n)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!im || !p || n == 0) return 0;
    return tw_guest_writable(im, (uint64_t)(uintptr_t)p, n);
}

#endif
