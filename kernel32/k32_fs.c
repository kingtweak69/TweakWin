#include "k32priv.h"

#include "../runtime/winfs.h"

#include <pthread.h>
#include <string.h>

/*
 * Windows-namespace file queries (M4): attributes, directory enumeration,
 * current directory. CreateFile keeps its M2 relative-path behaviour and
 * does not go through this namespace.
 */

#define MAX_FIND 32
#define FIND_BASE 0x7000u
#define FILETIME_EPOCH 116444736000000000ull

static pthread_mutex_t g_find_mu = PTHREAD_MUTEX_INITIALIZER;
static tw_winfs_find *g_find[MAX_FIND];

static uint32_t path_a(const char *p, char *tmp, size_t cap)
{
    struct tw_loaded *im = tw_k32_guest();
    const char *gs = NULL;
    size_t n = 0;
    if (!im || !p) return TW_ERROR_INVALID_PARAMETER;
    if (tw_guest_cstr(im, (uint64_t)(uintptr_t)p, TW_GUEST_CSTR_MAX, &gs, &n) != 0) return TW_ERROR_NOACCESS;
    if (n == 0 || n >= cap) return TW_ERROR_INVALID_NAME;
    memcpy(tmp, gs, n + 1);
    return 0;
}

static uint32_t path_w(const uint16_t *p, char *tmp, size_t cap)
{
    struct tw_loaded *im = tw_k32_guest();
    const uint16_t *gs = NULL;
    size_t n = 0;
    if (!im || !p) return TW_ERROR_INVALID_PARAMETER;
    if (tw_guest_wstr(im, (uint64_t)(uintptr_t)p, TW_GUEST_CSTR_MAX, &gs, &n) != 0) return TW_ERROR_NOACCESS;
    if (n == 0 || n * 3 >= cap) return TW_ERROR_INVALID_NAME;
    size_t need = 0;
    if (tw_utf16_to_utf8(gs, (int)n, (uint8_t *)tmp, cap - 1, &need, 1) != 0) return TW_ERROR_INVALID_NAME;
    tmp[need] = '\0';
    return 0;
}

static TW_DWORD attrs_common(const char *path)
{
    uint32_t err = 0;
    TW_DWORD a = tw_winfs_attributes(path, &err);
    if (a == TW_WINFS_INVALID_ATTRS) {
        tw_set_last_error(err);
        return 0xFFFFFFFFu;
    }
    tw_set_last_error(TW_ERROR_SUCCESS);
    return a;
}

TW_DWORD TW_MS_ABI tw_k32_GetFileAttributesA(const char *lpFileName)
{
    char buf[TW_WINFS_PATH_MAX];
    uint32_t e = tw_runtime_bound() ? path_a(lpFileName, buf, sizeof buf) : TW_ERROR_INVALID_PARAMETER;
    if (e) {
        tw_set_last_error(e);
        return 0xFFFFFFFFu;
    }
    return attrs_common(buf);
}

TW_DWORD TW_MS_ABI tw_k32_GetFileAttributesW(const uint16_t *lpFileName)
{
    char buf[TW_WINFS_PATH_MAX];
    uint32_t e = tw_runtime_bound() ? path_w(lpFileName, buf, sizeof buf) : TW_ERROR_INVALID_PARAMETER;
    if (e) {
        tw_set_last_error(e);
        return 0xFFFFFFFFu;
    }
    return attrs_common(buf);
}

/* WIN32_FIND_DATAA / W layout, Microsoft documentation. */
static void fill_find(uint8_t *out, const tw_winfs_entry *e, int wide)
{
    uint64_t ft = (e->mtime_unix * 10000000ull) + FILETIME_EPOCH;
    uint32_t zero = 0;
    memset(out, 0, wide ? 592 : 320);
    memcpy(out, &e->attrs, 4);
    memcpy(out + 4, &ft, 8);  /* creation (not tracked: use mtime) */
    memcpy(out + 12, &ft, 8); /* last access */
    memcpy(out + 20, &ft, 8); /* last write */
    uint32_t hi = (uint32_t)(e->size >> 32), lo = (uint32_t)e->size;
    memcpy(out + 28, &hi, 4);
    memcpy(out + 32, &lo, 4);
    memcpy(out + 36, &zero, 4);
    memcpy(out + 40, &zero, 4);
    if (wide) {
        size_t need = 0;
        uint16_t tmp[260];
        if (tw_utf8_to_utf16((const uint8_t *)e->name, -1, tmp, 260, &need, 0) == 0 && need > 0 && need <= 260)
            memcpy(out + 44, tmp, need * 2);
    } else {
        size_t n = strlen(e->name);
        if (n > 259) n = 259;
        memcpy(out + 44, e->name, n);
    }
}

static TW_HANDLE find_first(const char *pattern, void *data, int wide)
{
    if (!tw_k32_ok_w(data, wide ? 592 : 320)) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return TW_INVALID_HANDLE_VALUE;
    }
    tw_winfs_find *f = NULL;
    tw_winfs_entry first;
    uint32_t e = tw_winfs_find_open(pattern, &f, &first);
    if (e) {
        tw_set_last_error(e);
        return TW_INVALID_HANDLE_VALUE;
    }
    pthread_mutex_lock(&g_find_mu);
    for (size_t i = 0; i < MAX_FIND; i++) {
        if (!g_find[i]) {
            g_find[i] = f;
            pthread_mutex_unlock(&g_find_mu);
            fill_find(data, &first, wide);
            tw_set_last_error(TW_ERROR_SUCCESS);
            return (TW_HANDLE)(uintptr_t)(FIND_BASE + i * 8);
        }
    }
    pthread_mutex_unlock(&g_find_mu);
    tw_winfs_find_close(f);
    tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
    return TW_INVALID_HANDLE_VALUE;
}

TW_HANDLE TW_MS_ABI tw_k32_FindFirstFileA(const char *lpFileName, void *lpFindFileData)
{
    char buf[TW_WINFS_PATH_MAX];
    uint32_t e = tw_runtime_bound() ? path_a(lpFileName, buf, sizeof buf) : TW_ERROR_INVALID_PARAMETER;
    if (e) {
        tw_set_last_error(e);
        return TW_INVALID_HANDLE_VALUE;
    }
    return find_first(buf, lpFindFileData, 0);
}

TW_HANDLE TW_MS_ABI tw_k32_FindFirstFileW(const uint16_t *lpFileName, void *lpFindFileData)
{
    char buf[TW_WINFS_PATH_MAX];
    uint32_t e = tw_runtime_bound() ? path_w(lpFileName, buf, sizeof buf) : TW_ERROR_INVALID_PARAMETER;
    if (e) {
        tw_set_last_error(e);
        return TW_INVALID_HANDLE_VALUE;
    }
    return find_first(buf, lpFindFileData, 1);
}

static tw_winfs_find **slot_of(TW_HANDLE h)
{
    uint64_t v = (uint64_t)(uintptr_t)h;
    if (v < FIND_BASE || (v - FIND_BASE) % 8 || (v - FIND_BASE) / 8 >= MAX_FIND) return NULL;
    return &g_find[(v - FIND_BASE) / 8];
}

static TW_BOOL find_next(TW_HANDLE h, void *data, int wide)
{
    if (!tw_k32_ok_w(data, wide ? 592 : 320)) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return TW_FALSE;
    }
    pthread_mutex_lock(&g_find_mu);
    tw_winfs_find **s = slot_of(h);
    tw_winfs_entry e;
    int got = 0;
    int valid = s && *s;
    if (valid) got = tw_winfs_find_next(*s, &e);
    pthread_mutex_unlock(&g_find_mu);
    if (!valid) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FALSE;
    }
    if (!got) {
        tw_set_last_error(TW_ERROR_NO_MORE_FILES);
        return TW_FALSE;
    }
    fill_find(data, &e, wide);
    tw_set_last_error(TW_ERROR_SUCCESS);
    return TW_TRUE;
}

TW_BOOL TW_MS_ABI tw_k32_FindNextFileA(TW_HANDLE h, void *d)
{
    return find_next(h, d, 0);
}

TW_BOOL TW_MS_ABI tw_k32_FindNextFileW(TW_HANDLE h, void *d)
{
    return find_next(h, d, 1);
}

TW_BOOL TW_MS_ABI tw_k32_FindClose(TW_HANDLE h)
{
    pthread_mutex_lock(&g_find_mu);
    tw_winfs_find **s = slot_of(h);
    tw_winfs_find *f = s ? *s : NULL;
    if (f) *s = NULL;
    pthread_mutex_unlock(&g_find_mu);
    if (!f) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FALSE;
    }
    tw_winfs_find_close(f);
    tw_set_last_error(TW_ERROR_SUCCESS);
    return TW_TRUE;
}

TW_DWORD TW_MS_ABI tw_k32_GetCurrentDirectoryA(TW_DWORD nBufferLength, char *lpBuffer)
{
    char cwd[TW_WINFS_PATH_MAX];
    if (!tw_runtime_bound() || tw_winfs_getcwd(cwd, sizeof cwd) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    size_t n = strlen(cwd);
    if (nBufferLength < n + 1) return (TW_DWORD)(n + 1);
    if (!tw_k32_ok_w(lpBuffer, n + 1)) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return 0;
    }
    memcpy(lpBuffer, cwd, n + 1);
    tw_set_last_error(TW_ERROR_SUCCESS);
    return (TW_DWORD)n;
}

TW_BOOL TW_MS_ABI tw_k32_SetCurrentDirectoryA(const char *lpPathName)
{
    char buf[TW_WINFS_PATH_MAX];
    uint32_t e = tw_runtime_bound() ? path_a(lpPathName, buf, sizeof buf) : TW_ERROR_INVALID_PARAMETER;
    if (!e) e = tw_winfs_setcwd(buf);
    if (e) {
        tw_set_last_error(e);
        return TW_FALSE;
    }
    tw_set_last_error(TW_ERROR_SUCCESS);
    return TW_TRUE;
}
