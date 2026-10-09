#ifndef TWEAKWIN_RT_THREAD_H
#define TWEAKWIN_RT_THREAD_H

/*
 * Windows threads over the backend. Each thread gets its own TEB (GS base),
 * its own implicit-TLS block, and runs the guest start routine with the
 * Microsoft x64 ABI; its return value becomes the thread exit code.
 */

#include "../backend/kb.h"

#include <stdint.h>

#define TW_CREATE_SUSPENDED 0x00000004u

/* Create a thread that calls start(param) (ms_abi). Returns the backend
 * thread handle (install it in the Win32 object table), or a TW_KB_E* on
 * failure. *tid gets the thread id. flags other than 0 are rejected
 * (CREATE_SUSPENDED needs M5 suspend/resume). */
tw_kh tw_rt_thread_create(uint64_t start, uint64_t param, uint64_t stack_size, uint32_t flags,
                          uint64_t *tid);

/* Exit the calling guest thread with `code`. Does not return. */
__attribute__((noreturn)) void tw_rt_thread_exit(uint32_t code);

#endif
