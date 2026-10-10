#include "k32priv.h"

#include "../rt/object.h"
#include "../runtime/modules.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif

static int legacy_fd(TW_HANDLE h)
{
    if (h == TW_HANDLE_STDOUT) return STDOUT_FILENO;
    if (h == TW_HANDLE_STDERR) return STDERR_FILENO;
    return -1;
}

TW_HANDLE TW_MS_ABI tw_k32_GetStdHandle(TW_DWORD nStdHandle)
{
    if (tw_runtime_bound()) {
        TW_HANDLE h = tw_std_get(nStdHandle);
        if (h == TW_INVALID_HANDLE_VALUE || !h)
            tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return h;
    }
    switch (nStdHandle) {
    case TW_STD_INPUT_HANDLE:  return TW_HANDLE_STDIN;
    case TW_STD_OUTPUT_HANDLE: return TW_HANDLE_STDOUT;
    case TW_STD_ERROR_HANDLE:  return TW_HANDLE_STDERR;
    default:
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_INVALID_HANDLE_VALUE;
    }
}

TW_BOOL TW_MS_ABI tw_k32_SetStdHandle(TW_DWORD nStdHandle, TW_HANDLE hHandle)
{
    if (!tw_runtime_bound()) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    if (tw_std_set(nStdHandle, hHandle) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FALSE;
    }
    return TW_TRUE;
}

static TW_BOOL xfer(TW_HANDLE hFile, void *buf, TW_DWORD n, TW_DWORD *got_out, int writing)
{
    struct tw_loaded *proc = tw_k32_guest();
    if (!proc) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    if (got_out) {
        if (!tw_k32_ok_w(got_out, sizeof(TW_DWORD))) {
            tw_set_last_error(TW_ERROR_NOACCESS);
            return TW_FALSE;
        }
        *got_out = 0;
    }
    if (n == 0) return TW_TRUE;
    if (!buf) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    if (writing) {
        if (!tw_k32_ok_r(buf, n)) {
            tw_set_last_error(TW_ERROR_NOACCESS);
            return TW_FALSE;
        }
    } else if (!tw_k32_ok_w(buf, n)) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return TW_FALSE;
    }

    int fd = -1;
    int rd = 0, wr = 0;
    if (tw_runtime_bound()) {
        if (tw_handle_fd(hFile, &fd, &rd, &wr) != 0) {
            tw_set_last_error(TW_ERROR_INVALID_HANDLE);
            return TW_FALSE;
        }
        if (writing && !wr) {
            tw_set_last_error(TW_ERROR_ACCESS_DENIED);
            return TW_FALSE;
        }
        if (!writing && !rd) {
            tw_set_last_error(TW_ERROR_ACCESS_DENIED);
            return TW_FALSE;
        }
    } else if (writing) {
        fd = legacy_fd(hFile);
        if (fd < 0) {
            tw_set_last_error(TW_ERROR_INVALID_HANDLE);
            return TW_FALSE;
        }
    } else {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FALSE;
    }

    uint8_t *p = buf;
    TW_DWORD left = n;
    TW_DWORD got = 0;
    while (left) {
        ssize_t k = writing ? write(fd, p, left) : read(fd, p, left);
        if (k < 0) {
            if (errno == EINTR) continue;
            tw_set_last_error(writing ? TW_ERROR_WRITE_FAULT : TW_ERROR_READ_FAULT);
            if (got_out) *got_out = got;
            return TW_FALSE;
        }
        if (k == 0) break;
        p += (size_t)k;
        left -= (TW_DWORD)k;
        got += (TW_DWORD)k;
        if (!writing) break; /* short reads are success */
    }
    if (got_out) *got_out = got;
    if (writing && got != n) {
        tw_set_last_error(TW_ERROR_WRITE_FAULT);
        return TW_FALSE;
    }
    return TW_TRUE;
}

TW_BOOL TW_MS_ABI tw_k32_WriteFile(TW_HANDLE hFile, const void *lpBuffer,
                                   TW_DWORD nNumberOfBytesToWrite,
                                   TW_DWORD *lpNumberOfBytesWritten,
                                   void *lpOverlapped)
{
    if (lpOverlapped != NULL) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        TW_DEBUG(TW_DBG_HANDLES, "WriteFile: overlapped I/O is not implemented");
        return TW_FALSE;
    }
    return xfer(hFile, (void *)lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, 1);
}

TW_BOOL TW_MS_ABI tw_k32_ReadFile(TW_HANDLE hFile, void *lpBuffer,
                                  TW_DWORD nNumberOfBytesToRead,
                                  TW_DWORD *lpNumberOfBytesRead,
                                  void *lpOverlapped)
{
    if (lpOverlapped != NULL) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    return xfer(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, 0);
}

void TW_MS_ABI tw_k32_ExitProcess(TW_UINT uExitCode)
{
    struct tw_loaded *proc = tw_current_process();
    TW_DEBUG(TW_DBG_LOADER, "ExitProcess(%u)", uExitCode);
    if (!proc) _exit((int)(uExitCode & 0xff));
    tw_modules_process_detach();
    proc->guest_exit = uExitCode;
    proc->did_exit = 1;
    proc->status = TW_LOAD_OK;
    tw_guest_exit_longjmp(proc);
}

TW_BOOL TW_MS_ABI tw_k32_CloseHandle(TW_HANDLE hObject)
{
    if (!tw_runtime_bound()) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FALSE;
    }
    /* Kernel objects (events, semaphores, threads, ...) live in the rt
     * object table; files and the heap live in runtime/handle.c. */
    if (tw_obj_is(hObject)) {
        if (tw_obj_close(hObject) != 0) {
            tw_set_last_error(TW_ERROR_INVALID_HANDLE);
            return TW_FALSE;
        }
        return TW_TRUE;
    }
    if (tw_handle_close(hObject) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FALSE;
    }
    return TW_TRUE;
}

TW_DWORD TW_MS_ABI tw_k32_GetFileType(TW_HANDLE hFile)
{
    int fd = -1;
    if (!tw_runtime_bound() || tw_handle_fd(hFile, &fd, NULL, NULL) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FILE_TYPE_UNKNOWN;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FILE_TYPE_UNKNOWN;
    }
    if (S_ISFIFO(st.st_mode)) return TW_FILE_TYPE_PIPE;
    if (S_ISCHR(st.st_mode) || isatty(fd)) return TW_FILE_TYPE_CHAR;
    if (S_ISREG(st.st_mode)) return TW_FILE_TYPE_DISK;
    return TW_FILE_TYPE_UNKNOWN;
}

static const tw_k32_desc k_exports[] = {
    { "GetStdHandle", 1, (tw_k32_fn)tw_k32_GetStdHandle },
    { "WriteFile", 2, (tw_k32_fn)tw_k32_WriteFile },
    { "ExitProcess", 3, (tw_k32_fn)tw_k32_ExitProcess },
    { "GetCommandLineA", 4, (tw_k32_fn)tw_k32_GetCommandLineA },
    { "GetCommandLineW", 5, (tw_k32_fn)tw_k32_GetCommandLineW },
    { "GetModuleHandleA", 6, (tw_k32_fn)tw_k32_GetModuleHandleA },
    { "GetModuleHandleW", 7, (tw_k32_fn)tw_k32_GetModuleHandleW },
    { "GetModuleFileNameA", 8, (tw_k32_fn)tw_k32_GetModuleFileNameA },
    { "GetModuleFileNameW", 9, (tw_k32_fn)tw_k32_GetModuleFileNameW },
    { "GetLastError", 10, (tw_k32_fn)tw_k32_GetLastError },
    { "SetLastError", 11, (tw_k32_fn)tw_k32_SetLastError },
    { "VirtualAlloc", 12, (tw_k32_fn)tw_k32_VirtualAlloc },
    { "VirtualFree", 13, (tw_k32_fn)tw_k32_VirtualFree },
    { "VirtualProtect", 14, (tw_k32_fn)tw_k32_VirtualProtect },
    { "VirtualQuery", 15, (tw_k32_fn)tw_k32_VirtualQuery },
    { "GetProcessHeap", 16, (tw_k32_fn)tw_k32_GetProcessHeap },
    { "HeapAlloc", 17, (tw_k32_fn)tw_k32_HeapAlloc },
    { "HeapFree", 18, (tw_k32_fn)tw_k32_HeapFree },
    { "HeapReAlloc", 19, (tw_k32_fn)tw_k32_HeapReAlloc },
    { "HeapSize", 20, (tw_k32_fn)tw_k32_HeapSize },
    { "ReadFile", 21, (tw_k32_fn)tw_k32_ReadFile },
    { "SetStdHandle", 22, (tw_k32_fn)tw_k32_SetStdHandle },
    { "CreateFileA", 23, (tw_k32_fn)tw_k32_CreateFileA },
    { "CreateFileW", 24, (tw_k32_fn)tw_k32_CreateFileW },
    { "CloseHandle", 25, (tw_k32_fn)tw_k32_CloseHandle },
    { "GetFileType", 26, (tw_k32_fn)tw_k32_GetFileType },
    { "GetEnvironmentVariableA", 27, (tw_k32_fn)tw_k32_GetEnvironmentVariableA },
    { "GetEnvironmentVariableW", 28, (tw_k32_fn)tw_k32_GetEnvironmentVariableW },
    { "SetEnvironmentVariableA", 29, (tw_k32_fn)tw_k32_SetEnvironmentVariableA },
    { "SetEnvironmentVariableW", 30, (tw_k32_fn)tw_k32_SetEnvironmentVariableW },
    { "GetEnvironmentStringsA", 31, (tw_k32_fn)tw_k32_GetEnvironmentStringsA },
    { "GetEnvironmentStringsW", 32, (tw_k32_fn)tw_k32_GetEnvironmentStringsW },
    { "FreeEnvironmentStringsA", 33, (tw_k32_fn)tw_k32_FreeEnvironmentStringsA },
    { "FreeEnvironmentStringsW", 34, (tw_k32_fn)tw_k32_FreeEnvironmentStringsW },
    { "Sleep", 35, (tw_k32_fn)tw_k32_Sleep },
    { "GetTickCount", 36, (tw_k32_fn)tw_k32_GetTickCount },
    { "GetTickCount64", 37, (tw_k32_fn)tw_k32_GetTickCount64 },
    { "QueryPerformanceCounter", 38, (tw_k32_fn)tw_k32_QueryPerformanceCounter },
    { "QueryPerformanceFrequency", 39, (tw_k32_fn)tw_k32_QueryPerformanceFrequency },
    { "MultiByteToWideChar", 40, (tw_k32_fn)tw_k32_MultiByteToWideChar },
    { "WideCharToMultiByte", 41, (tw_k32_fn)tw_k32_WideCharToMultiByte },
    { "CreateEventA", 42, (tw_k32_fn)tw_k32_CreateEventA },
    { "CreateEventW", 43, (tw_k32_fn)tw_k32_CreateEventW },
    { "SetEvent", 44, (tw_k32_fn)tw_k32_SetEvent },
    { "ResetEvent", 45, (tw_k32_fn)tw_k32_ResetEvent },
    { "CreateSemaphoreA", 46, (tw_k32_fn)tw_k32_CreateSemaphoreA },
    { "CreateSemaphoreW", 47, (tw_k32_fn)tw_k32_CreateSemaphoreW },
    { "ReleaseSemaphore", 48, (tw_k32_fn)tw_k32_ReleaseSemaphore },
    { "WaitForSingleObject", 49, (tw_k32_fn)tw_k32_WaitForSingleObject },
    { "WaitForMultipleObjects", 50, (tw_k32_fn)tw_k32_WaitForMultipleObjects },
    { "GetCurrentProcess", 51, (tw_k32_fn)tw_k32_GetCurrentProcess },
    { "GetCurrentThread", 52, (tw_k32_fn)tw_k32_GetCurrentThread },
    { "GetCurrentProcessId", 53, (tw_k32_fn)tw_k32_GetCurrentProcessId },
    { "GetCurrentThreadId", 54, (tw_k32_fn)tw_k32_GetCurrentThreadId },
    { "CreateThread", 55, (tw_k32_fn)tw_k32_CreateThread },
    { "ExitThread", 56, (tw_k32_fn)tw_k32_ExitThread },
    { "GetExitCodeThread", 57, (tw_k32_fn)tw_k32_GetExitCodeThread },
    { "SuspendThread", 58, (tw_k32_fn)tw_k32_SuspendThread },
    { "ResumeThread", 59, (tw_k32_fn)tw_k32_ResumeThread },
    { "GetThreadContext", 60, (tw_k32_fn)tw_k32_GetThreadContext },
    { "SetThreadContext", 61, (tw_k32_fn)tw_k32_SetThreadContext },
    { "TlsAlloc", 62, (tw_k32_fn)tw_k32_TlsAlloc },
    { "TlsFree", 63, (tw_k32_fn)tw_k32_TlsFree },
    { "TlsGetValue", 64, (tw_k32_fn)tw_k32_TlsGetValue },
    { "TlsSetValue", 65, (tw_k32_fn)tw_k32_TlsSetValue },
    { "AddVectoredExceptionHandler", 66, (tw_k32_fn)tw_k32_AddVectoredExceptionHandler },
    { "RemoveVectoredExceptionHandler", 67, (tw_k32_fn)tw_k32_RemoveVectoredExceptionHandler },
    { "SetUnhandledExceptionFilter", 68, (tw_k32_fn)tw_k32_SetUnhandledExceptionFilter },
    { "LoadLibraryA", 69, (tw_k32_fn)tw_k32_LoadLibraryA },
    { "LoadLibraryW", 70, (tw_k32_fn)tw_k32_LoadLibraryW },
    { "LoadLibraryExA", 71, (tw_k32_fn)tw_k32_LoadLibraryExA },
    { "LoadLibraryExW", 72, (tw_k32_fn)tw_k32_LoadLibraryExW },
    { "GetProcAddress", 73, (tw_k32_fn)tw_k32_GetProcAddress },
    { "FreeLibrary", 74, (tw_k32_fn)tw_k32_FreeLibrary },
    { "GetFileAttributesA", 75, (tw_k32_fn)tw_k32_GetFileAttributesA },
    { "GetFileAttributesW", 76, (tw_k32_fn)tw_k32_GetFileAttributesW },
    { "FindFirstFileA", 77, (tw_k32_fn)tw_k32_FindFirstFileA },
    { "FindFirstFileW", 78, (tw_k32_fn)tw_k32_FindFirstFileW },
    { "FindNextFileA", 79, (tw_k32_fn)tw_k32_FindNextFileA },
    { "FindNextFileW", 80, (tw_k32_fn)tw_k32_FindNextFileW },
    { "FindClose", 81, (tw_k32_fn)tw_k32_FindClose },
    { "GetCurrentDirectoryA", 82, (tw_k32_fn)tw_k32_GetCurrentDirectoryA },
    { "SetCurrentDirectoryA", 83, (tw_k32_fn)tw_k32_SetCurrentDirectoryA },
};

const tw_k32_desc *tw_k32_exports(size_t *n)
{
    if (n) *n = sizeof k_exports / sizeof k_exports[0];
    return k_exports;
}
