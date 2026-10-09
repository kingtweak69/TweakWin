/* kernel32 synchronization: events, semaphores, waits. Built on the NT
 * sync layer (nt/sync.c) and the Win32 object table (rt/object.c); NTSTATUS
 * is translated to LastError here, never mixed with it above. */
#include "k32priv.h"

#include "../nt/status.h"
#include "../nt/sync.h"
#include "../rt/object.h"
#include "../rt/rt.h"

#include <string.h>

static void set_err_from_status(NTSTATUS st)
{
    tw_set_last_error(tw_nt_to_win32(st));
}

static TW_HANDLE make_event(int manual, int initial)
{
    if (!tw_rt_active()) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    tw_kh kh = 0;
    NTSTATUS st = tw_nt_create_event(&kh, manual, initial);
    if (!NT_SUCCESS(st)) {
        set_err_from_status(st);
        return NULL;
    }
    TW_HANDLE h = tw_obj_install(kh, TW_KB_TYPE_EVENT);
    if (!h) {
        tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    tw_set_last_error(TW_ERROR_SUCCESS);
    return h;
}

TW_HANDLE TW_MS_ABI tw_k32_CreateEventA(void *sa, TW_BOOL manual, TW_BOOL initial, const char *name)
{
    (void)sa;
    if (name) { /* named objects need M5 */
        tw_set_last_error(TW_ERROR_NOT_SUPPORTED);
        return NULL;
    }
    return make_event(manual != 0, initial != 0);
}

TW_HANDLE TW_MS_ABI tw_k32_CreateEventW(void *sa, TW_BOOL manual, TW_BOOL initial, const uint16_t *name)
{
    (void)sa;
    if (name) {
        tw_set_last_error(TW_ERROR_NOT_SUPPORTED);
        return NULL;
    }
    return make_event(manual != 0, initial != 0);
}

TW_BOOL TW_MS_ABI tw_k32_SetEvent(TW_HANDLE h)
{
    tw_kh kh = 0;
    int type = 0;
    if (tw_obj_lookup(h, &kh, &type) != 0 || type != TW_KB_TYPE_EVENT) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FALSE;
    }
    NTSTATUS st = tw_nt_set_event(kh, NULL);
    if (!NT_SUCCESS(st)) {
        set_err_from_status(st);
        return TW_FALSE;
    }
    return TW_TRUE;
}

TW_BOOL TW_MS_ABI tw_k32_ResetEvent(TW_HANDLE h)
{
    tw_kh kh = 0;
    int type = 0;
    if (tw_obj_lookup(h, &kh, &type) != 0 || type != TW_KB_TYPE_EVENT) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FALSE;
    }
    NTSTATUS st = tw_nt_reset_event(kh, NULL);
    if (!NT_SUCCESS(st)) {
        set_err_from_status(st);
        return TW_FALSE;
    }
    return TW_TRUE;
}

static TW_HANDLE make_sem(int32_t initial, int32_t maximum)
{
    if (!tw_rt_active()) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    tw_kh kh = 0;
    NTSTATUS st = tw_nt_create_semaphore(&kh, initial, maximum);
    if (!NT_SUCCESS(st)) {
        set_err_from_status(st);
        return NULL;
    }
    TW_HANDLE h = tw_obj_install(kh, TW_KB_TYPE_SEMAPHORE);
    if (!h) {
        tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    tw_set_last_error(TW_ERROR_SUCCESS);
    return h;
}

TW_HANDLE TW_MS_ABI tw_k32_CreateSemaphoreA(void *sa, int32_t initial, int32_t maximum, const char *name)
{
    (void)sa;
    if (name) {
        tw_set_last_error(TW_ERROR_NOT_SUPPORTED);
        return NULL;
    }
    return make_sem(initial, maximum);
}

TW_HANDLE TW_MS_ABI tw_k32_CreateSemaphoreW(void *sa, int32_t initial, int32_t maximum,
                                            const uint16_t *name)
{
    (void)sa;
    if (name) {
        tw_set_last_error(TW_ERROR_NOT_SUPPORTED);
        return NULL;
    }
    return make_sem(initial, maximum);
}

TW_BOOL TW_MS_ABI tw_k32_ReleaseSemaphore(TW_HANDLE h, int32_t count, int32_t *prev)
{
    tw_kh kh = 0;
    int type = 0;
    if (tw_obj_lookup(h, &kh, &type) != 0 || type != TW_KB_TYPE_SEMAPHORE) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FALSE;
    }
    if (prev && !tw_k32_ok_w(prev, sizeof(int32_t))) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return TW_FALSE;
    }
    int32_t p = 0;
    NTSTATUS st = tw_nt_release_semaphore(kh, count, &p);
    if (!NT_SUCCESS(st)) {
        set_err_from_status(st);
        return TW_FALSE;
    }
    if (prev) memcpy(prev, &p, sizeof p);
    return TW_TRUE;
}

/* Resolve a waitable Win32 HANDLE to a backend handle. */
static int wait_handle(TW_HANDLE h, tw_kh *kh)
{
    int type = 0;
    if (tw_obj_lookup(h, kh, &type) != 0) return -1;
    if (type != TW_KB_TYPE_EVENT && type != TW_KB_TYPE_SEMAPHORE && type != TW_KB_TYPE_THREAD &&
        type != TW_KB_TYPE_PROCESS)
        return -1;
    return 0;
}

TW_DWORD TW_MS_ABI tw_k32_WaitForSingleObject(TW_HANDLE h, TW_DWORD ms)
{
    tw_kh kh = 0;
    if (wait_handle(h, &kh) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_WAIT_FAILED;
    }
    uint32_t result = 0;
    NTSTATUS st = tw_nt_wait_single(kh, ms, &result);
    if (st == STATUS_SUCCESS || st == STATUS_TIMEOUT) return result;
    set_err_from_status(st);
    return TW_WAIT_FAILED;
}

TW_DWORD TW_MS_ABI tw_k32_WaitForMultipleObjects(TW_DWORD count, const TW_HANDLE *handles,
                                                 TW_BOOL waitAll, TW_DWORD ms)
{
    if (count == 0 || count > TW_MAXIMUM_WAIT_OBJECTS || !handles) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_WAIT_FAILED;
    }
    if (!tw_k32_ok_r(handles, (uint64_t)count * sizeof(TW_HANDLE))) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return TW_WAIT_FAILED;
    }
    tw_kh khs[TW_MAXIMUM_WAIT_OBJECTS];
    for (TW_DWORD i = 0; i < count; i++) {
        if (wait_handle(handles[i], &khs[i]) != 0) {
            tw_set_last_error(TW_ERROR_INVALID_HANDLE);
            return TW_WAIT_FAILED;
        }
    }
    uint32_t result = 0;
    NTSTATUS st = tw_nt_wait_multiple(khs, count, waitAll != 0, ms, &result);
    if (st == STATUS_SUCCESS || st == STATUS_TIMEOUT) return result;
    if (st == STATUS_NOT_IMPLEMENTED) {
        /* WaitForMultipleObjects(bWaitAll=TRUE) needs TweakKernel M5 WAIT_ALL. */
        tw_set_last_error(TW_ERROR_CALL_NOT_IMPLEMENTED);
        return TW_WAIT_FAILED;
    }
    set_err_from_status(st);
    return TW_WAIT_FAILED;
}
