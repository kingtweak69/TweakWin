#include "advapi32.h"

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif

#include "../kernel32/k32priv.h"
#include "../runtime/registry.h"

#include <stdlib.h>
#include <string.h>

#define NAME_UNITS_MAX 16383u
#define KEY_UNITS_MAX  4096u

typedef int32_t TW_LONG;

/* Read a guest ANSI (UTF-8) / UTF-16 string as a malloc'd UTF-8 string. */
static uint32_t rd_str(const void *p, int wide, size_t max_units, char **out)
{
    *out = NULL;
    struct tw_loaded *im = tw_k32_guest();
    if (!im) return TW_ERROR_INVALID_HANDLE;
    if (!wide) {
        const char *gs = NULL;
        size_t n = 0;
        if (tw_guest_cstr(im, (uint64_t)(uintptr_t)p, max_units + 1, &gs, &n) != 0)
            return n == 0 && tw_k32_ok_r(p, 1) ? TW_ERROR_INVALID_PARAMETER : TW_ERROR_NOACCESS;
        char *c = malloc(n + 1);
        if (!c) return TW_ERROR_NOT_ENOUGH_MEMORY;
        memcpy(c, gs, n);
        c[n] = '\0';
        *out = c;
        return 0;
    }
    const uint16_t *gs = NULL;
    size_t n = 0;
    if (tw_guest_wstr(im, (uint64_t)(uintptr_t)p, max_units + 1, &gs, &n) != 0) return TW_ERROR_NOACCESS;
    char *c = malloc(n * 4 + 1);
    if (!c) return TW_ERROR_NOT_ENOUGH_MEMORY;
    size_t need = 0;
    if (tw_utf16_to_utf8(gs, (int)n, (uint8_t *)c, n * 4 + 1, &need, 1) != 0 || need > n * 4) {
        free(c);
        return TW_ERROR_INVALID_PARAMETER;
    }
    c[need] = '\0';
    *out = c;
    return 0;
}

static int is_text(uint32_t type)
{
    return type == TW_REG_SZ || type == TW_REG_EXPAND_SZ || type == TW_REG_MULTI_SZ;
}

static TW_LONG open_common(void *hkey, const void *sub, int wide, uint32_t opts, void *res, int create,
                           uint32_t *disp_out)
{
    if (!tw_runtime_bound() || !tw_k32_ok_w(res, 8)) return TW_ERROR_NOACCESS;
    char *name = NULL;
    uint32_t e = 0;
    if (sub) e = rd_str(sub, wide, KEY_UNITS_MAX, &name);
    else if (create) e = TW_ERROR_INVALID_PARAMETER;
    if (e) return (TW_LONG)e;
    (void)opts;
    uint64_t out = 0;
    e = tw_reg_open((uint64_t)(uintptr_t)hkey, name, create, &out, disp_out);
    free(name);
    if (e) return (TW_LONG)e;
    memcpy(res, &out, 8);
    return 0;
}

static TW_LONG RegOpenKeyEx(void *hkey, const void *sub, TW_DWORD opts, TW_DWORD sam, void *res, int wide)
{
    (void)sam;
    if (opts & ~8u) return TW_ERROR_INVALID_PARAMETER;
    return open_common(hkey, sub, wide, opts, res, 0, NULL);
}

static TW_LONG create_ex(void *hkey, const void *sub, TW_DWORD reserved, void *cls, TW_DWORD opts,
                         TW_DWORD sam, void *sa, void *res, TW_DWORD *disp, int wide)
{
    (void)cls;
    (void)sam;
    if (reserved != 0 || sa != NULL || (opts & ~1u)) return TW_ERROR_INVALID_PARAMETER;
    if (disp && !tw_k32_ok_w(disp, 4)) return TW_ERROR_NOACCESS;
    uint32_t d = 0;
    TW_LONG r = open_common(hkey, sub, wide, opts, res, 1, &d);
    if (r == 0 && disp) *disp = d;
    return r;
}

static TW_LONG TW_MS_ABI adv_RegOpenKeyExA(void *h, const char *s, TW_DWORD o, TW_DWORD m, void *r)
{
    return RegOpenKeyEx(h, s, o, m, r, 0);
}
static TW_LONG TW_MS_ABI adv_RegOpenKeyExW(void *h, const uint16_t *s, TW_DWORD o, TW_DWORD m, void *r)
{
    return RegOpenKeyEx(h, s, o, m, r, 1);
}
static TW_LONG TW_MS_ABI adv_RegCreateKeyExA(void *h, const char *s, TW_DWORD rs, char *c, TW_DWORD o,
                                             TW_DWORD m, void *sa, void *r, TW_DWORD *d)
{
    return create_ex(h, s, rs, c, o, m, sa, r, d, 0);
}
static TW_LONG TW_MS_ABI adv_RegCreateKeyExW(void *h, const uint16_t *s, TW_DWORD rs, uint16_t *c, TW_DWORD o,
                                             TW_DWORD m, void *sa, void *r, TW_DWORD *d)
{
    return create_ex(h, s, rs, c, o, m, sa, r, d, 1);
}

static TW_LONG TW_MS_ABI adv_RegCloseKey(void *h)
{
    if (!tw_runtime_bound()) return TW_ERROR_INVALID_HANDLE;
    return (TW_LONG)tw_reg_close((uint64_t)(uintptr_t)h);
}

static TW_LONG delete_value(void *h, const void *name, int wide)
{
    if (!tw_runtime_bound()) return TW_ERROR_INVALID_HANDLE;
    char *n = NULL;
    uint32_t e = 0;
    if (name) e = rd_str(name, wide, NAME_UNITS_MAX, &n);
    if (e) return (TW_LONG)e;
    e = tw_reg_delete_value((uint64_t)(uintptr_t)h, n);
    free(n);
    return (TW_LONG)e;
}
static TW_LONG TW_MS_ABI adv_RegDeleteValueA(void *h, const char *n) { return delete_value(h, n, 0); }
static TW_LONG TW_MS_ABI adv_RegDeleteValueW(void *h, const uint16_t *n) { return delete_value(h, n, 1); }

static TW_LONG set_value(void *h, const void *name, TW_DWORD reserved, TW_DWORD type, const uint8_t *data,
                         TW_DWORD cb, int wide)
{
    if (!tw_runtime_bound()) return TW_ERROR_INVALID_HANDLE;
    if (reserved != 0) return TW_ERROR_INVALID_PARAMETER;
    if (cb > TW_REG_MAX_DATA) return TW_ERROR_NOT_ENOUGH_MEMORY;
    if (cb && !tw_k32_ok_r(data, cb)) return TW_ERROR_NOACCESS;
    if (!cb && data == NULL && type != TW_REG_NONE && type != TW_REG_BINARY && !is_text(type))
        return TW_ERROR_INVALID_PARAMETER;
    char *n = NULL;
    uint32_t e = 0;
    if (name) e = rd_str(name, wide, NAME_UNITS_MAX, &n);
    if (e) return (TW_LONG)e;
    uint8_t *conv = NULL;
    const uint8_t *src = data;
    uint32_t len = cb;
    if (!wide && is_text(type) && cb) {
        conv = malloc((size_t)cb * 2 + 2);
        size_t need = 0;
        if (!conv) {
            free(n);
            return TW_ERROR_NOT_ENOUGH_MEMORY;
        }
        if (tw_utf8_to_utf16(data, (int)cb, (uint16_t *)conv, (size_t)cb + 1, &need, 0) != 0) {
            free(conv);
            free(n);
            return TW_ERROR_NO_UNICODE_TRANSLATION;
        }
        src = conv;
        len = (uint32_t)(need * 2);
    }
    e = tw_reg_set((uint64_t)(uintptr_t)h, n, type, src, len);
    free(conv);
    free(n);
    return (TW_LONG)e;
}
static TW_LONG TW_MS_ABI adv_RegSetValueExA(void *h, const char *n, TW_DWORD r, TW_DWORD t, const uint8_t *d, TW_DWORD cb)
{
    return set_value(h, n, r, t, d, cb, 0);
}
static TW_LONG TW_MS_ABI adv_RegSetValueExW(void *h, const uint16_t *n, TW_DWORD r, TW_DWORD t, const uint8_t *d, TW_DWORD cb)
{
    return set_value(h, n, r, t, d, cb, 1);
}

static TW_LONG query_value(void *h, const void *name, void *reserved, TW_DWORD *ptype, uint8_t *data,
                           TW_DWORD *pcb, int wide)
{
    if (!tw_runtime_bound()) return TW_ERROR_INVALID_HANDLE;
    if (reserved != NULL) return TW_ERROR_INVALID_PARAMETER;
    if (data && !pcb) return TW_ERROR_INVALID_PARAMETER;
    if (pcb && !tw_k32_ok_w(pcb, 4)) return TW_ERROR_NOACCESS;
    if (ptype && !tw_k32_ok_w(ptype, 4)) return TW_ERROR_NOACCESS;
    TW_DWORD cap = pcb ? *pcb : 0;
    if (data && cap && !tw_k32_ok_w(data, cap)) return TW_ERROR_NOACCESS;
    char *n = NULL;
    uint32_t e = 0;
    if (name) e = rd_str(name, wide, NAME_UNITS_MAX, &n);
    if (e) return (TW_LONG)e;
    uint32_t type = 0, len = 0;
    uint8_t *raw = NULL;
    e = tw_reg_get((uint64_t)(uintptr_t)h, n, &type, &raw, &len);
    free(n);
    if (e) return (TW_LONG)e;
    uint8_t *out = raw;
    uint32_t outlen = len;
    uint8_t *conv = NULL;
    if (!wide && is_text(type) && len >= 2) {
        size_t units = len / 2, need = 0;
        conv = malloc(units * 3 + 1);
        if (!conv) {
            free(raw);
            return TW_ERROR_NOT_ENOUGH_MEMORY;
        }
        if (tw_utf16_to_utf8((const uint16_t *)(const void *)raw, (int)units, conv, units * 3 + 1, &need, 0) != 0) {
            free(raw);
            free(conv);
            return TW_ERROR_NO_UNICODE_TRANSLATION;
        }
        out = conv;
        outlen = (uint32_t)need;
    } else if (!wide && is_text(type)) {
        outlen = len; /* empty or a lone byte: nothing to convert */
    }
    TW_LONG rc = 0;
    if (ptype) *ptype = type;
    if (data) {
        if (cap < outlen) {
            rc = TW_ERROR_MORE_DATA;
        } else if (outlen) {
            memcpy(data, out, outlen);
        }
    }
    if (pcb) *pcb = outlen;
    free(raw);
    free(conv);
    return rc;
}
static TW_LONG TW_MS_ABI adv_RegQueryValueExA(void *h, const char *n, void *r, TW_DWORD *t, uint8_t *d, TW_DWORD *cb)
{
    return query_value(h, n, r, t, d, cb, 0);
}
static TW_LONG TW_MS_ABI adv_RegQueryValueExW(void *h, const uint16_t *n, void *r, TW_DWORD *t, uint8_t *d, TW_DWORD *cb)
{
    return query_value(h, n, r, t, d, cb, 1);
}

static const tw_k32_desc k_adv[] = {
    { "RegCloseKey", 1, (tw_k32_fn)adv_RegCloseKey },
    { "RegCreateKeyExA", 2, (tw_k32_fn)adv_RegCreateKeyExA },
    { "RegCreateKeyExW", 3, (tw_k32_fn)adv_RegCreateKeyExW },
    { "RegDeleteValueA", 4, (tw_k32_fn)adv_RegDeleteValueA },
    { "RegDeleteValueW", 5, (tw_k32_fn)adv_RegDeleteValueW },
    { "RegOpenKeyExA", 6, (tw_k32_fn)adv_RegOpenKeyExA },
    { "RegOpenKeyExW", 7, (tw_k32_fn)adv_RegOpenKeyExW },
    { "RegQueryValueExA", 8, (tw_k32_fn)adv_RegQueryValueExA },
    { "RegQueryValueExW", 9, (tw_k32_fn)adv_RegQueryValueExW },
    { "RegSetValueExA", 10, (tw_k32_fn)adv_RegSetValueExA },
    { "RegSetValueExW", 11, (tw_k32_fn)adv_RegSetValueExW },
};

const tw_k32_desc *tw_advapi32_exports(size_t *n)
{
    if (n) *n = sizeof k_adv / sizeof k_adv[0];
    return k_adv;
}
