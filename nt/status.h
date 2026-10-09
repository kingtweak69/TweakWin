#ifndef TWEAKWIN_NT_STATUS_H
#define TWEAKWIN_NT_STATUS_H

/*
 * The three error domains and the only conversions between them:
 *
 *   backend  TW_KB_E*      (backend/kb.h)      -> NTSTATUS   tw_nt_from_kb
 *   NTSTATUS               (nt/ntstatus.h)     -> Win32      tw_nt_to_win32
 *
 * NT-layer functions return NTSTATUS. Win32 wrappers call tw_nt_to_win32
 * and store the result in the thread's LastErrorValue. Nothing converts a
 * Win32 code back into an NTSTATUS.
 */

#include "ntstatus.h"

#include <stdint.h>

/* `ctx` picks the NTSTATUS a generic backend error means for the caller. */
enum tw_kb_ctx {
    TW_KBC_GENERIC = 0,
    TW_KBC_HANDLE,   /* operation on an existing handle */
    TW_KBC_VM,       /* address-space operation */
    TW_KBC_CREATE,   /* object creation */
    TW_KBC_FILE      /* host file service */
};

NTSTATUS tw_nt_from_kb(int64_t kb_err, int ctx);

/* RtlNtStatusToDosError. Unknown NTSTATUS -> ERROR_MR_MID_NOT_FOUND (317). */
uint32_t tw_nt_to_win32(NTSTATUS st);

/* Short symbolic name for diagnostics ("STATUS_ACCESS_VIOLATION"), or NULL. */
const char *tw_nt_status_name(NTSTATUS st);

#endif
