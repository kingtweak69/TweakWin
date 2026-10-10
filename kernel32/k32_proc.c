#include "k32priv.h"

#include "../runtime/modules.h"

#include <errno.h>
#include <sched.h>
#include <string.h>
#include <time.h>

static int copy_module_name_a(const char *src, char *dst, TW_DWORD cap, TW_DWORD *out)
{
    size_t n = strlen(src);
    if (cap == 0) {
        tw_set_last_error(TW_ERROR_INSUFFICIENT_BUFFER);
        return -1;
    }
    size_t put = n;
    int trunc = 0;
    if (put >= cap) {
        put = cap - 1;
        trunc = 1;
    }
    if (!tw_k32_ok_w(dst, put + 1)) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return -1;
    }
    memcpy(dst, src, put);
    dst[put] = '\0';
    if (trunc) {
        tw_set_last_error(TW_ERROR_INSUFFICIENT_BUFFER);
        *out = cap;
        return 0;
    }
    *out = (TW_DWORD)put;
    return 0;
}

static const char *module_path(void *h)
{
    struct tw_loaded *im = tw_k32_guest();
    uint64_t hv = (uint64_t)(uintptr_t)h;
    if (!h || (im && hv == im->base)) return tw_runtime_exe();
    if (hv == tw_runtime_k32_base()) return "C:\\TweakWin\\kernel32.dll";
    if (hv == tw_runtime_ntdll_base()) return "C:\\TweakWin\\ntdll.dll";
    static _Thread_local char dllpath[4096];
    if (tw_dll_path(hv, dllpath, sizeof dllpath) == 0) return dllpath;
    return NULL;
}

static int ieq_ascii(const char *a, const char *b)
{
    for (;;) {
        unsigned char ca = (unsigned char)*a++;
        unsigned char cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        if (ca == 0) return 1;
    }
}

static const char *basename_of(const char *p)
{
    const char *s = p;
    for (const char *q = p; *q; q++)
        if (*q == '\\' || *q == '/') s = q + 1;
    return s;
}

static void *module_lookup(const char *name)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!name || !name[0]) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (ieq_ascii(name, "kernel32.dll") || ieq_ascii(name, "kernel32"))
        return (void *)(uintptr_t)tw_runtime_k32_base();
    if (ieq_ascii(name, "ntdll.dll") || ieq_ascii(name, "ntdll"))
        return (void *)(uintptr_t)tw_runtime_ntdll_base();
    const char *exe = tw_runtime_exe();
    if (exe && (ieq_ascii(name, exe) || ieq_ascii(name, basename_of(exe))))
        return im ? (void *)(uintptr_t)im->base : NULL;
    uint64_t dh = tw_dll_module_handle(name);
    if (dh) return (void *)(uintptr_t)dh;
    tw_set_last_error(TW_ERROR_MOD_NOT_FOUND);
    return NULL;
}

char *TW_MS_ABI tw_k32_GetCommandLineA(void)
{
    uint64_t a = tw_runtime_cmdline_a();
    if (!tw_runtime_bound() || !a) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    return (char *)(uintptr_t)a;
}

uint16_t *TW_MS_ABI tw_k32_GetCommandLineW(void)
{
    uint64_t a = tw_runtime_cmdline_w();
    if (!tw_runtime_bound() || !a) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    return (uint16_t *)(uintptr_t)a;
}

void *TW_MS_ABI tw_k32_GetModuleHandleA(const char *lpModuleName)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!tw_runtime_bound() || !im) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!lpModuleName) return (void *)(uintptr_t)im->base;
    const char *gs = NULL;
    size_t n = 0;
    if (tw_guest_cstr(im, (uint64_t)(uintptr_t)lpModuleName, TW_GUEST_CSTR_MAX, &gs, &n) != 0) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return NULL;
    }
    return module_lookup(gs);
}

void *TW_MS_ABI tw_k32_GetModuleHandleW(const uint16_t *lpModuleName)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!tw_runtime_bound() || !im) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!lpModuleName) return (void *)(uintptr_t)im->base;
    const uint16_t *gs = NULL;
    size_t n = 0;
    if (tw_guest_wstr(im, (uint64_t)(uintptr_t)lpModuleName, TW_GUEST_CSTR_MAX, &gs, &n) != 0) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return NULL;
    }
    uint8_t utf[1024];
    size_t need = 0;
    if (tw_utf16_to_utf8(gs, (int)n, utf, sizeof utf, &need, 1) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    return module_lookup((const char *)utf);
}

TW_DWORD TW_MS_ABI tw_k32_GetModuleFileNameA(void *hModule, char *lpFilename, TW_DWORD nSize)
{
    if (!tw_runtime_bound()) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    const char *src = module_path(hModule);
    if (!src) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return 0;
    }
    TW_DWORD out = 0;
    if (copy_module_name_a(src, lpFilename, nSize, &out) != 0) return 0;
    return out;
}

TW_DWORD TW_MS_ABI tw_k32_GetModuleFileNameW(void *hModule, uint16_t *lpFilename, TW_DWORD nSize)
{
    if (!tw_runtime_bound()) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    const char *src = module_path(hModule);
    if (!src) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return 0;
    }
    if (nSize == 0) {
        tw_set_last_error(TW_ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    size_t need = 0;
    if (tw_utf8_to_utf16((const uint8_t *)src, -1, NULL, 0, &need, 1) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    size_t put = need;
    int trunc = 0;
    if (put > nSize) {
        put = nSize;
        trunc = 1;
    }
    if (((uintptr_t)lpFilename & 1u) || !tw_k32_ok_w(lpFilename, put * 2)) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return 0;
    }
    if (trunc) {
        /* Convert into a host buffer, then copy the prefix and force a NUL. */
        uint16_t tmp[4096];
        if (need > 4096) {
            tw_set_last_error(TW_ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        tw_utf8_to_utf16((const uint8_t *)src, -1, tmp, need, &need, 1);
        if (put == 0) {
            tw_set_last_error(TW_ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        memcpy(lpFilename, tmp, (put - 1) * 2);
        lpFilename[put - 1] = 0;
        tw_set_last_error(TW_ERROR_INSUFFICIENT_BUFFER);
        return nSize;
    }
    tw_utf8_to_utf16((const uint8_t *)src, -1, lpFilename, nSize, &need, 1);
    return (TW_DWORD)(need - 1);
}

TW_DWORD TW_MS_ABI tw_k32_GetLastError(void)
{
    return tw_get_last_error();
}

void TW_MS_ABI tw_k32_SetLastError(TW_DWORD dwErrCode)
{
    tw_set_last_error(dwErrCode);
}

static TW_DWORD env_get_result(const char *name, char *buf, TW_DWORD cap)
{
    uint32_t needed = 0;
    int rc = tw_env_get_a(name, NULL, 0, &needed);
    if (rc == 1) {
        tw_set_last_error(TW_ERROR_ENVVAR_NOT_FOUND);
        return 0;
    }
    if (rc != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (cap == 0 || !buf || cap < needed) {
        if (cap != 0 && buf) tw_set_last_error(TW_ERROR_INSUFFICIENT_BUFFER);
        return needed;
    }
    if (!tw_k32_ok_w(buf, needed)) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return 0;
    }
    tw_env_get_a(name, buf, cap, &needed);
    tw_set_last_error(TW_ERROR_SUCCESS);
    return needed - 1;
}

TW_DWORD TW_MS_ABI tw_k32_GetEnvironmentVariableA(const char *lpName, char *lpBuffer, TW_DWORD nSize)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!tw_runtime_bound() || !im || !lpName) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    const char *gs = NULL;
    size_t n = 0;
    if (tw_guest_cstr(im, (uint64_t)(uintptr_t)lpName, TW_GUEST_CSTR_MAX, &gs, &n) != 0) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return 0;
    }
    return env_get_result(gs, lpBuffer, nSize);
}

TW_DWORD TW_MS_ABI tw_k32_GetEnvironmentVariableW(const uint16_t *lpName, uint16_t *lpBuffer, TW_DWORD nSize)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!tw_runtime_bound() || !im || !lpName) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    const uint16_t *gs = NULL;
    size_t n = 0;
    if (tw_guest_wstr(im, (uint64_t)(uintptr_t)lpName, TW_GUEST_CSTR_MAX, &gs, &n) != 0) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return 0;
    }
    uint8_t name[512];
    size_t need = 0;
    if (tw_utf16_to_utf8(gs, (int)n, name, sizeof name, &need, 1) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    uint32_t needed = 0;
    int rc = tw_env_get_a((const char *)name, NULL, 0, &needed);
    if (rc == 1) {
        tw_set_last_error(TW_ERROR_ENVVAR_NOT_FOUND);
        return 0;
    }
    if (rc != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    char val[4097];
    if (needed > sizeof val) {
        tw_set_last_error(TW_ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    tw_env_get_a((const char *)name, val, (uint32_t)sizeof val, &needed);
    size_t units = 0;
    if (tw_utf8_to_utf16((const uint8_t *)val, -1, NULL, 0, &units, 1) != 0) {
        tw_set_last_error(TW_ERROR_NO_UNICODE_TRANSLATION);
        return 0;
    }
    if (nSize == 0 || !lpBuffer || nSize < units) {
        if (nSize != 0 && lpBuffer) tw_set_last_error(TW_ERROR_INSUFFICIENT_BUFFER);
        return (TW_DWORD)units;
    }
    if (((uintptr_t)lpBuffer & 1u) || !tw_k32_ok_w(lpBuffer, units * 2)) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return 0;
    }
    tw_utf8_to_utf16((const uint8_t *)val, -1, lpBuffer, nSize, &units, 1);
    tw_set_last_error(TW_ERROR_SUCCESS);
    return (TW_DWORD)(units - 1);
}

static TW_BOOL env_set_result(const char *name, const char *value)
{
    if (tw_env_set_a(name, value) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    return TW_TRUE;
}

TW_BOOL TW_MS_ABI tw_k32_SetEnvironmentVariableA(const char *lpName, const char *lpValue)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!tw_runtime_bound() || !im || !lpName) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    const char *ns = NULL;
    size_t nn = 0;
    if (tw_guest_cstr(im, (uint64_t)(uintptr_t)lpName, TW_GUEST_CSTR_MAX, &ns, &nn) != 0) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return TW_FALSE;
    }
    const char *vs = NULL;
    if (lpValue) {
        size_t vn = 0;
        if (tw_guest_cstr(im, (uint64_t)(uintptr_t)lpValue, TW_GUEST_CSTR_MAX, &vs, &vn) != 0) {
            tw_set_last_error(TW_ERROR_NOACCESS);
            return TW_FALSE;
        }
    }
    return env_set_result(ns, vs);
}

TW_BOOL TW_MS_ABI tw_k32_SetEnvironmentVariableW(const uint16_t *lpName, const uint16_t *lpValue)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!tw_runtime_bound() || !im || !lpName) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    const uint16_t *ns = NULL;
    size_t nn = 0;
    if (tw_guest_wstr(im, (uint64_t)(uintptr_t)lpName, TW_GUEST_CSTR_MAX, &ns, &nn) != 0) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return TW_FALSE;
    }
    uint8_t name[512];
    size_t need = 0;
    if (tw_utf16_to_utf8(ns, (int)nn, name, sizeof name, &need, 1) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    uint8_t val[4097];
    const char *vptr = NULL;
    if (lpValue) {
        const uint16_t *vs = NULL;
        size_t vn = 0;
        if (tw_guest_wstr(im, (uint64_t)(uintptr_t)lpValue, TW_GUEST_CSTR_MAX, &vs, &vn) != 0) {
            tw_set_last_error(TW_ERROR_NOACCESS);
            return TW_FALSE;
        }
        if (tw_utf16_to_utf8(vs, (int)vn, val, sizeof val, &need, 1) != 0) {
            tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
            return TW_FALSE;
        }
        vptr = (const char *)val;
    }
    return env_set_result((const char *)name, vptr);
}

char *TW_MS_ABI tw_k32_GetEnvironmentStringsA(void)
{
    if (!tw_runtime_bound()) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    uint64_t a = tw_env_block_a();
    if (!a) {
        tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    return (char *)(uintptr_t)a;
}

uint16_t *TW_MS_ABI tw_k32_GetEnvironmentStringsW(void)
{
    if (!tw_runtime_bound()) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    uint64_t a = tw_env_block_w();
    if (!a) {
        tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    return (uint16_t *)(uintptr_t)a;
}

TW_BOOL TW_MS_ABI tw_k32_FreeEnvironmentStringsA(char *penv)
{
    if (!penv || tw_env_block_free((uint64_t)(uintptr_t)penv) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    return TW_TRUE;
}

TW_BOOL TW_MS_ABI tw_k32_FreeEnvironmentStringsW(uint16_t *penv)
{
    return tw_k32_FreeEnvironmentStringsA((char *)penv);
}

void TW_MS_ABI tw_k32_Sleep(TW_DWORD dwMilliseconds)
{
    if (dwMilliseconds == 0) {
        sched_yield();
        return;
    }
    struct timespec ts;
    ts.tv_sec = (time_t)(dwMilliseconds / 1000u);
    ts.tv_nsec = (long)(dwMilliseconds % 1000u) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

TW_DWORD TW_MS_ABI tw_k32_GetTickCount(void)
{
    return (TW_DWORD)(tw_runtime_mono_ns() / 1000000ull);
}

uint64_t TW_MS_ABI tw_k32_GetTickCount64(void)
{
    return tw_runtime_mono_ns() / 1000000ull;
}

static TW_BOOL write_i64(void *dst, int64_t v)
{
    if (!tw_k32_ok_w(dst, 8)) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return TW_FALSE;
    }
    memcpy(dst, &v, 8);
    return TW_TRUE;
}

TW_BOOL TW_MS_ABI tw_k32_QueryPerformanceCounter(void *lpPerformanceCount)
{
    if (!lpPerformanceCount) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    return write_i64(lpPerformanceCount, (int64_t)tw_runtime_mono_ns());
}

TW_BOOL TW_MS_ABI tw_k32_QueryPerformanceFrequency(void *lpFrequency)
{
    if (!lpFrequency) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    /* Counter units are nanoseconds of CLOCK_MONOTONIC. */
    return write_i64(lpFrequency, 1000000000LL);
}

static int32_t mb2wc(TW_DWORD cp, TW_DWORD flags, const uint8_t *src, int src_len,
                     uint16_t *dst, int32_t cch)
{
    if (!tw_cp_ok(cp) || (flags & ~TW_MB_ERR_INVALID_CHARS) != 0) {
        tw_set_last_error(flags ? TW_ERROR_INVALID_FLAGS : TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (!tw_cp_ok(cp)) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    size_t need = 0;
    int rc = tw_utf8_to_utf16(src, src_len, NULL, 0, &need, 1);
    if (rc == -1) {
        tw_set_last_error(TW_ERROR_NO_UNICODE_TRANSLATION);
        return 0;
    }
    if (cch == 0) return (int32_t)need;
    if (cch < 0 || (size_t)cch < need || !dst) {
        tw_set_last_error(TW_ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    if (((uintptr_t)dst & 1u) || !tw_k32_ok_w(dst, need * 2)) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return 0;
    }
    tw_utf8_to_utf16(src, src_len, dst, (size_t)cch, &need, 1);
    return (int32_t)need;
}

int32_t TW_MS_ABI tw_k32_MultiByteToWideChar(TW_DWORD CodePage, TW_DWORD dwFlags,
                                             const char *lpMultiByteStr, int32_t cbMultiByte,
                                             uint16_t *lpWideCharStr, int32_t cchWideChar)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!im || !lpMultiByteStr) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (!tw_cp_ok(CodePage)) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    if ((dwFlags & ~TW_MB_ERR_INVALID_CHARS) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_FLAGS);
        return 0;
    }
    const uint8_t *src;
    int slen;
    if (cbMultiByte < 0) {
        const char *gs = NULL;
        size_t n = 0;
        if (tw_guest_cstr(im, (uint64_t)(uintptr_t)lpMultiByteStr, TW_GUEST_CSTR_MAX, &gs, &n) != 0) {
            tw_set_last_error(TW_ERROR_NOACCESS);
            return 0;
        }
        src = (const uint8_t *)gs;
        slen = -1;
    } else {
        if ((uint32_t)cbMultiByte > TW_GUEST_CSTR_MAX ||
            !tw_k32_ok_r(lpMultiByteStr, (uint64_t)cbMultiByte)) {
            tw_set_last_error(TW_ERROR_NOACCESS);
            return 0;
        }
        src = (const uint8_t *)lpMultiByteStr;
        slen = cbMultiByte;
    }
    return mb2wc(CodePage, dwFlags, src, slen, lpWideCharStr, cchWideChar);
}

int32_t TW_MS_ABI tw_k32_WideCharToMultiByte(TW_DWORD CodePage, TW_DWORD dwFlags,
                                             const uint16_t *lpWideCharStr, int32_t cchWideChar,
                                             char *lpMultiByteStr, int32_t cbMultiByte,
                                             const char *lpDefaultChar, int32_t *lpUsedDefaultChar)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!im || !lpWideCharStr || lpDefaultChar || lpUsedDefaultChar) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (!tw_cp_ok(CodePage)) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    if ((dwFlags & ~TW_WC_ERR_INVALID_CHARS) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_FLAGS);
        return 0;
    }
    const uint16_t *src;
    int slen;
    if (cchWideChar < 0) {
        const uint16_t *gs = NULL;
        size_t n = 0;
        if (tw_guest_wstr(im, (uint64_t)(uintptr_t)lpWideCharStr, TW_GUEST_CSTR_MAX, &gs, &n) != 0) {
            tw_set_last_error(TW_ERROR_NOACCESS);
            return 0;
        }
        src = gs;
        slen = -1;
    } else {
        if ((uint32_t)cchWideChar > TW_GUEST_CSTR_MAX || ((uintptr_t)lpWideCharStr & 1u) ||
            !tw_k32_ok_r(lpWideCharStr, (uint64_t)cchWideChar * 2)) {
            tw_set_last_error(TW_ERROR_NOACCESS);
            return 0;
        }
        src = lpWideCharStr;
        slen = cchWideChar;
    }
    size_t need = 0;
    if (tw_utf16_to_utf8(src, slen, NULL, 0, &need, 1) != 0) {
        tw_set_last_error(TW_ERROR_NO_UNICODE_TRANSLATION);
        return 0;
    }
    if (cbMultiByte == 0) return (int32_t)need;
    if (cbMultiByte < 0 || (size_t)cbMultiByte < need || !lpMultiByteStr) {
        tw_set_last_error(TW_ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    if (!tw_k32_ok_w(lpMultiByteStr, need)) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return 0;
    }
    tw_utf16_to_utf8(src, slen, (uint8_t *)lpMultiByteStr, (size_t)cbMultiByte, &need, 1);
    return (int32_t)need;
}
