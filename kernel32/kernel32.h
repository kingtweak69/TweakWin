#ifndef TWEAKWIN_KERNEL32_H
#define TWEAKWIN_KERNEL32_H

#include "../runtime/winapi.h"

#include <stddef.h>
#include <stdint.h>

typedef void (*tw_k32_fn)(void);

typedef struct {
    const char *name;
    uint16_t ordinal;
    tw_k32_fn fn;
} tw_k32_desc;

const tw_k32_desc *tw_k32_exports(size_t *n);

TW_HANDLE TW_MS_ABI tw_k32_GetStdHandle(TW_DWORD nStdHandle);
TW_BOOL TW_MS_ABI tw_k32_SetStdHandle(TW_DWORD nStdHandle, TW_HANDLE hHandle);
TW_BOOL TW_MS_ABI tw_k32_WriteFile(TW_HANDLE hFile, const void *lpBuffer,
                                   TW_DWORD nNumberOfBytesToWrite,
                                   TW_DWORD *lpNumberOfBytesWritten,
                                   void *lpOverlapped);
TW_BOOL TW_MS_ABI tw_k32_ReadFile(TW_HANDLE hFile, void *lpBuffer,
                                  TW_DWORD nNumberOfBytesToRead,
                                  TW_DWORD *lpNumberOfBytesRead,
                                  void *lpOverlapped);
void TW_MS_ABI tw_k32_ExitProcess(TW_UINT uExitCode);
TW_BOOL TW_MS_ABI tw_k32_CloseHandle(TW_HANDLE hObject);
TW_DWORD TW_MS_ABI tw_k32_GetFileType(TW_HANDLE hFile);

TW_HANDLE TW_MS_ABI tw_k32_CreateFileA(const char *lpFileName, TW_DWORD dwDesiredAccess,
                                       TW_DWORD dwShareMode, void *lpSecurityAttributes,
                                       TW_DWORD dwCreationDisposition,
                                       TW_DWORD dwFlagsAndAttributes, TW_HANDLE hTemplateFile);
TW_HANDLE TW_MS_ABI tw_k32_CreateFileW(const uint16_t *lpFileName, TW_DWORD dwDesiredAccess,
                                       TW_DWORD dwShareMode, void *lpSecurityAttributes,
                                       TW_DWORD dwCreationDisposition,
                                       TW_DWORD dwFlagsAndAttributes, TW_HANDLE hTemplateFile);

void *TW_MS_ABI tw_k32_VirtualAlloc(void *lpAddress, uint64_t dwSize, TW_DWORD flAllocationType,
                                    TW_DWORD flProtect);
TW_BOOL TW_MS_ABI tw_k32_VirtualFree(void *lpAddress, uint64_t dwSize, TW_DWORD dwFreeType);
TW_BOOL TW_MS_ABI tw_k32_VirtualProtect(void *lpAddress, uint64_t dwSize, TW_DWORD flNewProtect,
                                        TW_DWORD *lpflOldProtect);
TW_SIZE_T TW_MS_ABI tw_k32_VirtualQuery(const void *lpAddress, void *lpBuffer, TW_SIZE_T dwLength);

TW_HANDLE TW_MS_ABI tw_k32_GetProcessHeap(void);
void *TW_MS_ABI tw_k32_HeapAlloc(TW_HANDLE hHeap, TW_DWORD dwFlags, uint64_t dwBytes);
TW_BOOL TW_MS_ABI tw_k32_HeapFree(TW_HANDLE hHeap, TW_DWORD dwFlags, void *lpMem);
void *TW_MS_ABI tw_k32_HeapReAlloc(TW_HANDLE hHeap, TW_DWORD dwFlags, void *lpMem, uint64_t dwBytes);
uint64_t TW_MS_ABI tw_k32_HeapSize(TW_HANDLE hHeap, TW_DWORD dwFlags, const void *lpMem);

char *TW_MS_ABI tw_k32_GetCommandLineA(void);
uint16_t *TW_MS_ABI tw_k32_GetCommandLineW(void);
void *TW_MS_ABI tw_k32_GetModuleHandleA(const char *lpModuleName);
void *TW_MS_ABI tw_k32_GetModuleHandleW(const uint16_t *lpModuleName);
TW_DWORD TW_MS_ABI tw_k32_GetModuleFileNameA(void *hModule, char *lpFilename, TW_DWORD nSize);
TW_DWORD TW_MS_ABI tw_k32_GetModuleFileNameW(void *hModule, uint16_t *lpFilename, TW_DWORD nSize);
TW_DWORD TW_MS_ABI tw_k32_GetLastError(void);
void TW_MS_ABI tw_k32_SetLastError(TW_DWORD dwErrCode);

TW_DWORD TW_MS_ABI tw_k32_GetEnvironmentVariableA(const char *lpName, char *lpBuffer, TW_DWORD nSize);
TW_DWORD TW_MS_ABI tw_k32_GetEnvironmentVariableW(const uint16_t *lpName, uint16_t *lpBuffer, TW_DWORD nSize);
TW_BOOL TW_MS_ABI tw_k32_SetEnvironmentVariableA(const char *lpName, const char *lpValue);
TW_BOOL TW_MS_ABI tw_k32_SetEnvironmentVariableW(const uint16_t *lpName, const uint16_t *lpValue);
char *TW_MS_ABI tw_k32_GetEnvironmentStringsA(void);
uint16_t *TW_MS_ABI tw_k32_GetEnvironmentStringsW(void);
TW_BOOL TW_MS_ABI tw_k32_FreeEnvironmentStringsA(char *penv);
TW_BOOL TW_MS_ABI tw_k32_FreeEnvironmentStringsW(uint16_t *penv);

void TW_MS_ABI tw_k32_Sleep(TW_DWORD dwMilliseconds);
TW_DWORD TW_MS_ABI tw_k32_GetTickCount(void);
uint64_t TW_MS_ABI tw_k32_GetTickCount64(void);
TW_BOOL TW_MS_ABI tw_k32_QueryPerformanceCounter(void *lpPerformanceCount);
TW_BOOL TW_MS_ABI tw_k32_QueryPerformanceFrequency(void *lpFrequency);

int32_t TW_MS_ABI tw_k32_MultiByteToWideChar(TW_DWORD CodePage, TW_DWORD dwFlags,
                                             const char *lpMultiByteStr, int32_t cbMultiByte,
                                             uint16_t *lpWideCharStr, int32_t cchWideChar);
int32_t TW_MS_ABI tw_k32_WideCharToMultiByte(TW_DWORD CodePage, TW_DWORD dwFlags,
                                             const uint16_t *lpWideCharStr, int32_t cchWideChar,
                                             char *lpMultiByteStr, int32_t cbMultiByte,
                                             const char *lpDefaultChar, int32_t *lpUsedDefaultChar);


/* ---- M3 runtime: synchronization, threads, TLS ---- */
TW_HANDLE TW_MS_ABI tw_k32_CreateEventA(void *sa, TW_BOOL manual, TW_BOOL initial, const char *name);
TW_HANDLE TW_MS_ABI tw_k32_CreateEventW(void *sa, TW_BOOL manual, TW_BOOL initial, const uint16_t *name);
TW_BOOL TW_MS_ABI tw_k32_SetEvent(TW_HANDLE h);
TW_BOOL TW_MS_ABI tw_k32_ResetEvent(TW_HANDLE h);
TW_HANDLE TW_MS_ABI tw_k32_CreateSemaphoreA(void *sa, int32_t initial, int32_t maximum, const char *name);
TW_HANDLE TW_MS_ABI tw_k32_CreateSemaphoreW(void *sa, int32_t initial, int32_t maximum, const uint16_t *name);
TW_BOOL TW_MS_ABI tw_k32_ReleaseSemaphore(TW_HANDLE h, int32_t count, int32_t *prev);
TW_DWORD TW_MS_ABI tw_k32_WaitForSingleObject(TW_HANDLE h, TW_DWORD ms);
TW_DWORD TW_MS_ABI tw_k32_WaitForMultipleObjects(TW_DWORD count, const TW_HANDLE *handles, TW_BOOL waitAll, TW_DWORD ms);
TW_HANDLE TW_MS_ABI tw_k32_GetCurrentProcess(void);
TW_HANDLE TW_MS_ABI tw_k32_GetCurrentThread(void);
TW_DWORD TW_MS_ABI tw_k32_GetCurrentProcessId(void);
TW_DWORD TW_MS_ABI tw_k32_GetCurrentThreadId(void);
TW_HANDLE TW_MS_ABI tw_k32_CreateThread(void *sa, uint64_t stackSize, void *start, void *param, TW_DWORD flags, TW_DWORD *tid);
__attribute__((noreturn)) void TW_MS_ABI tw_k32_ExitThread(TW_DWORD code);
TW_BOOL TW_MS_ABI tw_k32_GetExitCodeThread(TW_HANDLE h, TW_DWORD *code);
TW_DWORD TW_MS_ABI tw_k32_SuspendThread(TW_HANDLE h);
TW_DWORD TW_MS_ABI tw_k32_ResumeThread(TW_HANDLE h);
TW_BOOL TW_MS_ABI tw_k32_GetThreadContext(TW_HANDLE h, void *ctx);
TW_BOOL TW_MS_ABI tw_k32_SetThreadContext(TW_HANDLE h, const void *ctx);
TW_DWORD TW_MS_ABI tw_k32_TlsAlloc(void);
TW_BOOL TW_MS_ABI tw_k32_TlsFree(TW_DWORD index);
void *TW_MS_ABI tw_k32_TlsGetValue(TW_DWORD index);
TW_BOOL TW_MS_ABI tw_k32_TlsSetValue(TW_DWORD index, void *value);


/* ---- exception handling ---- */
void *TW_MS_ABI tw_k32_AddVectoredExceptionHandler(TW_DWORD first, void *handler);
TW_DWORD TW_MS_ABI tw_k32_RemoveVectoredExceptionHandler(void *handle);
void *TW_MS_ABI tw_k32_SetUnhandledExceptionFilter(void *filter);

#endif
