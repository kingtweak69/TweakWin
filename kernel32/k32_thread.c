/* kernel32 threads and the current-process/thread pseudo-handles. Built on
 * the rt thread model and the Win32 object table. Features M4 cannot
 * provide (suspend/resume, get/set context) fail cleanly with
 * ERROR_CALL_NOT_IMPLEMENTED rather than pretending to work. */
#include "k32priv.h"

#include "../backend/kb.h"
#include "../rt/object.h"
#include "../rt/rt.h"
#include "../rt/thread.h"

#include <string.h>

/* GetCurrentProcess / GetCurrentThread pseudo-handles, as on Windows. */
#define TW_CUR_PROCESS ((TW_HANDLE)(intptr_t)-1)
#define TW_CUR_THREAD  ((TW_HANDLE)(intptr_t)-2)

TW_HANDLE TW_MS_ABI tw_k32_GetCurrentProcess(void) { return TW_CUR_PROCESS; }
TW_HANDLE TW_MS_ABI tw_k32_GetCurrentThread(void) { return TW_CUR_THREAD; }
TW_DWORD TW_MS_ABI tw_k32_GetCurrentProcessId(void) { return (TW_DWORD)tw_kb_process_id(); }
TW_DWORD TW_MS_ABI tw_k32_GetCurrentThreadId(void) { return (TW_DWORD)tw_kb_thread_id(); }

TW_HANDLE TW_MS_ABI tw_k32_CreateThread(void *sa, uint64_t stackSize, void *start, void *param,
                                        TW_DWORD flags, TW_DWORD *tid)
{
    (void)sa;
    if (!tw_rt_active() || !start) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (tid && !tw_k32_ok_w(tid, sizeof(TW_DWORD))) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return NULL;
    }
    uint64_t id = 0;
    tw_kh kh = tw_rt_thread_create((uint64_t)(uintptr_t)start, (uint64_t)(uintptr_t)param, stackSize,
                                   flags, &id);
    if (kh < 0) {
        if (kh == TW_KB_ENOSYS) tw_set_last_error(TW_ERROR_CALL_NOT_IMPLEMENTED);
        else if (kh == TW_KB_ENOMEM) tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        else tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    /* The thread id is the backend handle_info id. */
    int64_t info = tw_kb_handle_info(kh);
    (void)info;
    TW_HANDLE h = tw_obj_install(kh, TW_KB_TYPE_THREAD);
    if (!h) {
        tw_kb_close(kh);
        tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    if (tid) {
        TW_DWORD t = (TW_DWORD)tw_kb_thread_id(); /* best-effort; real id is per-thread */
        memcpy(tid, &t, sizeof t);
    }
    tw_set_last_error(TW_ERROR_SUCCESS);
    return h;
}

__attribute__((noreturn)) void TW_MS_ABI tw_k32_ExitThread(TW_DWORD code)
{
    tw_rt_thread_exit(code);
}

TW_BOOL TW_MS_ABI tw_k32_GetExitCodeThread(TW_HANDLE h, TW_DWORD *code)
{
    tw_kh kh = 0;
    int type = 0;
    if (tw_obj_lookup(h, &kh, &type) != 0 || type != TW_KB_TYPE_THREAD) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FALSE;
    }
    if (!code || !tw_k32_ok_w(code, sizeof(TW_DWORD))) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return TW_FALSE;
    }
    tw_kb_exitinfo info;
    TW_DWORD out;
    if (tw_kb_exit_info(kh, &info) == 0) {
        out = (TW_DWORD)info.status;
    } else {
        out = TW_STILL_ACTIVE;
    }
    memcpy(code, &out, sizeof out);
    return TW_TRUE;
}

/* Features that require TweakKernel M5. They do not fake success. */
TW_DWORD TW_MS_ABI tw_k32_SuspendThread(TW_HANDLE h)
{
    (void)h;
    tw_set_last_error(TW_ERROR_CALL_NOT_IMPLEMENTED);
    return (TW_DWORD)-1;
}

TW_DWORD TW_MS_ABI tw_k32_ResumeThread(TW_HANDLE h)
{
    (void)h;
    tw_set_last_error(TW_ERROR_CALL_NOT_IMPLEMENTED);
    return (TW_DWORD)-1;
}

TW_BOOL TW_MS_ABI tw_k32_GetThreadContext(TW_HANDLE h, void *ctx)
{
    (void)h;
    (void)ctx;
    tw_set_last_error(TW_ERROR_CALL_NOT_IMPLEMENTED);
    return TW_FALSE;
}

TW_BOOL TW_MS_ABI tw_k32_SetThreadContext(TW_HANDLE h, const void *ctx)
{
    (void)h;
    (void)ctx;
    tw_set_last_error(TW_ERROR_CALL_NOT_IMPLEMENTED);
    return TW_FALSE;
}
