#include "k32priv.h"

#include "../runtime/modules.h"

#include <string.h>

/* LoadLibraryEx flags (Microsoft documentation). Only 0 and
 * LOAD_WITH_ALTERED_SEARCH_PATH are implemented. */
#define K_LOAD_WITH_ALTERED_SEARCH_PATH 0x00000008u
#define K_KNOWN_UNSUPPORTED 0x0000FFF7u /* DONT_RESOLVE_DLL_REFERENCES, AS_DATAFILE, LOAD_LIBRARY_* ... */

static void *load_utf8(const char *name, TW_DWORD flags)
{
    if (!tw_runtime_bound()) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (flags & ~(K_KNOWN_UNSUPPORTED | K_LOAD_WITH_ALTERED_SEARCH_PATH)) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (flags & K_KNOWN_UNSUPPORTED) {
        tw_set_last_error(TW_ERROR_NOT_SUPPORTED);
        return NULL;
    }
    uint64_t h = 0;
    uint32_t e = tw_dll_load(name, flags, &h);
    if (e) {
        tw_set_last_error(e);
        return NULL;
    }
    tw_set_last_error(TW_ERROR_SUCCESS);
    return (void *)(uintptr_t)h;
}

static void *load_a(const char *p, TW_DWORD flags)
{
    struct tw_loaded *im = tw_k32_guest();
    const char *gs = NULL;
    size_t n = 0;
    if (!im || !p || tw_guest_cstr(im, (uint64_t)(uintptr_t)p, TW_GUEST_CSTR_MAX, &gs, &n) != 0) {
        tw_set_last_error(p ? TW_ERROR_NOACCESS : TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (n == 0 || n >= 4000) {
        tw_set_last_error(n ? TW_ERROR_INVALID_NAME : TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    return load_utf8(gs, flags);
}

static void *load_w(const uint16_t *p, TW_DWORD flags)
{
    struct tw_loaded *im = tw_k32_guest();
    const uint16_t *gs = NULL;
    size_t n = 0;
    if (!im || !p || tw_guest_wstr(im, (uint64_t)(uintptr_t)p, TW_GUEST_CSTR_MAX, &gs, &n) != 0) {
        tw_set_last_error(p ? TW_ERROR_NOACCESS : TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (n == 0 || n >= 1000) {
        tw_set_last_error(n ? TW_ERROR_INVALID_NAME : TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    uint8_t utf[4096];
    size_t need = 0;
    if (tw_utf16_to_utf8(gs, (int)n, utf, sizeof utf - 1, &need, 1) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_NAME);
        return NULL;
    }
    utf[need] = '\0';
    return load_utf8((const char *)utf, flags);
}

void *TW_MS_ABI tw_k32_LoadLibraryA(const char *lpLibFileName)
{
    return load_a(lpLibFileName, 0);
}

void *TW_MS_ABI tw_k32_LoadLibraryW(const uint16_t *lpLibFileName)
{
    return load_w(lpLibFileName, 0);
}

void *TW_MS_ABI tw_k32_LoadLibraryExA(const char *lpLibFileName, TW_HANDLE hFile, TW_DWORD dwFlags)
{
    if (hFile) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    return load_a(lpLibFileName, dwFlags);
}

void *TW_MS_ABI tw_k32_LoadLibraryExW(const uint16_t *lpLibFileName, TW_HANDLE hFile, TW_DWORD dwFlags)
{
    if (hFile) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    return load_w(lpLibFileName, dwFlags);
}

void *TW_MS_ABI tw_k32_GetProcAddress(void *hModule, const char *lpProcName)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!tw_runtime_bound() || !im || !hModule) {
        tw_set_last_error(!hModule ? TW_ERROR_INVALID_HANDLE : TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    uint32_t err = 0;
    uint64_t r;
    if ((uint64_t)(uintptr_t)lpProcName < 0x10000u) {
        uint32_t ord = (uint32_t)(uintptr_t)lpProcName;
        if (ord == 0) {
            tw_set_last_error(TW_ERROR_PROC_NOT_FOUND);
            return NULL;
        }
        r = tw_dll_proc((uint64_t)(uintptr_t)hModule, NULL, ord, 1, &err);
    } else {
        const char *gs = NULL;
        size_t n = 0;
        if (tw_guest_cstr(im, (uint64_t)(uintptr_t)lpProcName, 4096, &gs, &n) != 0) {
            tw_set_last_error(TW_ERROR_NOACCESS);
            return NULL;
        }
        r = tw_dll_proc((uint64_t)(uintptr_t)hModule, gs, 0, 0, &err);
    }
    if (!r) {
        tw_set_last_error(err ? err : TW_ERROR_PROC_NOT_FOUND);
        return NULL;
    }
    tw_set_last_error(TW_ERROR_SUCCESS);
    return (void *)(uintptr_t)r;
}

TW_BOOL TW_MS_ABI tw_k32_FreeLibrary(void *hModule)
{
    if (!tw_runtime_bound() || !hModule) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FALSE;
    }
    uint32_t e = tw_dll_free((uint64_t)(uintptr_t)hModule);
    if (e) {
        tw_set_last_error(e);
        return TW_FALSE;
    }
    tw_set_last_error(TW_ERROR_SUCCESS);
    return TW_TRUE;
}
