#ifndef TWEAKWIN_NT_SYNC_H
#define TWEAKWIN_NT_SYNC_H

/*
 * NT synchronization layer. Returns NTSTATUS and operates on backend
 * handles (tw_kh). The Win32 wrappers build HANDLEs over these and
 * translate NTSTATUS to LastError. Waits take a 100-ns relative timeout
 * like the native NtWaitForSingleObject (negative = relative); callers at
 * the kernel32 level pass milliseconds and convert.
 */

#include "ntstatus.h"
#include "../backend/kb.h"

#include <stdint.h>

#define TW_WAIT_OBJECT_0  0x00000000u
#define TW_WAIT_TIMEOUT   0x00000102u
#define TW_WAIT_FAILED    0xFFFFFFFFu
#define TW_INFINITE_MS    0xFFFFFFFFu

NTSTATUS tw_nt_create_event(tw_kh *out, int manual_reset, int initial_state);
NTSTATUS tw_nt_set_event(tw_kh h, int32_t *prev_state);
NTSTATUS tw_nt_reset_event(tw_kh h, int32_t *prev_state);
NTSTATUS tw_nt_create_semaphore(tw_kh *out, int32_t initial, int32_t maximum);
NTSTATUS tw_nt_release_semaphore(tw_kh h, int32_t count, int32_t *prev_count);

/* `ms` is a Win32 millisecond timeout (TW_INFINITE_MS for no timeout).
 * *result is TW_WAIT_OBJECT_0(+index) or TW_WAIT_TIMEOUT. */
NTSTATUS tw_nt_wait_single(tw_kh h, uint32_t ms, uint32_t *result);
NTSTATUS tw_nt_wait_multiple(const tw_kh *hs, uint32_t count, int wait_all, uint32_t ms,
                             uint32_t *result);

uint64_t tw_nt_ms_to_ns(uint32_t ms);

#endif
