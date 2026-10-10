#include "registry.h"

#include "winapi.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define MAX_HANDLES 256
#define MAX_CHILDREN 1024
#define MAX_VALUES 1024
#define MAX_DEPTH 64
#define HANDLE_BASE 0x5000u

typedef struct {
    char *name;
    uint32_t type;
    uint8_t *data;
    uint32_t len;
} reg_value;

typedef struct reg_key {
    char *name;
    struct reg_key **kids;
    size_t nkids;
    reg_value *vals;
    size_t nvals;
    int depth;
} reg_key;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static reg_key g_hkcu = { "HKEY_CURRENT_USER", NULL, 0, NULL, 0, 0 };
static reg_key g_hklm = { "HKEY_LOCAL_MACHINE", NULL, 0, NULL, 0, 0 };
static reg_key *g_handles[MAX_HANDLES];

static int lc(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static int ieq(const char *a, const char *b)
{
    while (*a && lc((unsigned char)*a) == lc((unsigned char)*b)) a++, b++;
    return *a == *b;
}

/* Returns the key for a predefined or opened handle, or NULL. */
static reg_key *lookup(uint64_t h)
{
    uint64_t hi = h >> 32;
    uint32_t lo = (uint32_t)h;
    if ((hi == 0 || hi == 0xFFFFFFFFu) && lo >= 0x80000000u) {
        if (lo == TW_HKEY_CURRENT_USER) return &g_hkcu;
        if (lo == TW_HKEY_LOCAL_MACHINE) return &g_hklm;
        return NULL;
    }
    if (h >= HANDLE_BASE && (h - HANDLE_BASE) % 8 == 0 && (h - HANDLE_BASE) / 8 < MAX_HANDLES)
        return g_handles[(h - HANDLE_BASE) / 8];
    return NULL;
}

static int ieq_n(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (lc((unsigned char)a[i]) != lc((unsigned char)b[i])) return 0;
    return 1;
}

static reg_key *find_kid(reg_key *k, const char *name, size_t n)
{
    for (size_t i = 0; i < k->nkids; i++)
        if (strlen(k->kids[i]->name) == n && ieq_n(k->kids[i]->name, name, n)) return k->kids[i];
    return NULL;
}

static reg_key *add_kid(reg_key *k, const char *name, size_t n)
{
    if (k->nkids >= MAX_CHILDREN || k->depth + 1 > MAX_DEPTH) return NULL;
    reg_key *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->name = malloc(n + 1);
    reg_key **nk = realloc(k->kids, (k->nkids + 1) * sizeof *nk);
    if (!c->name || !nk) {
        free(c->name);
        free(c);
        if (nk) k->kids = nk;
        return NULL;
    }
    memcpy(c->name, name, n);
    c->name[n] = '\0';
    c->depth = k->depth + 1;
    k->kids = nk;
    k->kids[k->nkids++] = c;
    return c;
}

static void free_tree(reg_key *k, int is_root)
{
    for (size_t i = 0; i < k->nkids; i++) free_tree(k->kids[i], 0);
    free(k->kids);
    for (size_t i = 0; i < k->nvals; i++) {
        free(k->vals[i].name);
        free(k->vals[i].data);
    }
    free(k->vals);
    k->kids = NULL;
    k->vals = NULL;
    k->nkids = k->nvals = 0;
    if (!is_root) {
        free(k->name);
        free(k);
    }
}

uint32_t tw_reg_open(uint64_t parent, const char *subkey, int create, uint64_t *out, uint32_t *disposition)
{
    if (out) *out = 0;
    if (!out) return TW_ERROR_INVALID_PARAMETER;
    pthread_mutex_lock(&g_mu);
    uint32_t rc = 0;
    reg_key *k = lookup(parent);
    uint32_t disp = TW_REG_OPENED_EXISTING_KEY;
    if (!k) {
        rc = TW_ERROR_INVALID_HANDLE;
    } else if (subkey && subkey[0] == '\\') {
        rc = TW_ERROR_BAD_PATHNAME;
    } else {
        const char *s = subkey ? subkey : "";
        while (*s && rc == 0) {
            const char *e = strchr(s, '\\');
            size_t n = e ? (size_t)(e - s) : strlen(s);
            if (n == 0) { /* "a\\b" or trailing '\\': skip empty components */
                s = e ? e + 1 : s + n;
                continue;
            }
            if (n > TW_REG_MAX_NAME) {
                rc = create ? TW_ERROR_INVALID_PARAMETER : TW_ERROR_FILE_NOT_FOUND;
                break;
            }
            reg_key *c = find_kid(k, s, n);
            if (!c) {
                if (!create) {
                    rc = TW_ERROR_FILE_NOT_FOUND;
                    break;
                }
                c = add_kid(k, s, n);
                if (!c) {
                    rc = TW_ERROR_NOT_ENOUGH_MEMORY;
                    break;
                }
                disp = TW_REG_CREATED_NEW_KEY;
            }
            k = c;
            s = e ? e + 1 : s + n;
        }
        if (rc == 0) {
            size_t slot = MAX_HANDLES;
            for (size_t i = 0; i < MAX_HANDLES; i++)
                if (!g_handles[i]) {
                    slot = i;
                    break;
                }
            if (slot == MAX_HANDLES) {
                rc = TW_ERROR_NOT_ENOUGH_MEMORY;
            } else {
                g_handles[slot] = k;
                *out = HANDLE_BASE + slot * 8;
                if (disposition) *disposition = disp;
            }
        }
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

uint32_t tw_reg_close(uint64_t key)
{
    pthread_mutex_lock(&g_mu);
    uint32_t rc = 0;
    uint64_t hi = key >> 32;
    if ((hi == 0 || hi == 0xFFFFFFFFu) && (uint32_t)key >= 0x80000000u) {
        if (!lookup(key)) rc = TW_ERROR_INVALID_HANDLE;
    } else if (!lookup(key)) {
        rc = TW_ERROR_INVALID_HANDLE;
    } else {
        g_handles[(key - HANDLE_BASE) / 8] = NULL;
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

static reg_value *find_val(reg_key *k, const char *name)
{
    for (size_t i = 0; i < k->nvals; i++)
        if (ieq(k->vals[i].name, name)) return &k->vals[i];
    return NULL;
}

static int type_ok(uint32_t type, uint32_t len)
{
    switch (type) {
    case TW_REG_NONE:
    case TW_REG_BINARY:
    case TW_REG_SZ:
    case TW_REG_EXPAND_SZ:
    case TW_REG_MULTI_SZ:
        return 1;
    case TW_REG_DWORD:
    case TW_REG_DWORD_BE:
        return len == 4;
    case TW_REG_QWORD:
        return len == 8;
    default:
        return 0;
    }
}

uint32_t tw_reg_set(uint64_t key, const char *name, uint32_t type, const void *data, uint32_t len)
{
    if (!name) name = "";
    if (strlen(name) > 16383) return TW_ERROR_INVALID_PARAMETER;
    if (len > TW_REG_MAX_DATA) return TW_ERROR_NOT_ENOUGH_MEMORY;
    if (len && !data) return TW_ERROR_NOACCESS;
    if (!type_ok(type, len)) return TW_ERROR_INVALID_PARAMETER;
    pthread_mutex_lock(&g_mu);
    uint32_t rc = 0;
    reg_key *k = lookup(key);
    if (!k) {
        rc = TW_ERROR_INVALID_HANDLE;
    } else {
        uint8_t *copy = malloc(len ? len : 1);
        if (!copy) {
            rc = TW_ERROR_NOT_ENOUGH_MEMORY;
        } else {
            if (len) memcpy(copy, data, len);
            reg_value *v = find_val(k, name);
            if (v) {
                free(v->data);
            } else if (k->nvals >= MAX_VALUES) {
                free(copy);
                rc = TW_ERROR_NOT_ENOUGH_MEMORY;
            } else {
                reg_value *nv = realloc(k->vals, (k->nvals + 1) * sizeof *nv);
                char *nm = nv ? strdup(name) : NULL;
                if (!nv || !nm) {
                    if (nv) k->vals = nv;
                    free(nm);
                    free(copy);
                    rc = TW_ERROR_NOT_ENOUGH_MEMORY;
                } else {
                    k->vals = nv;
                    v = &k->vals[k->nvals++];
                    v->name = nm;
                }
            }
            if (rc == 0) {
                v->type = type;
                v->data = copy;
                v->len = len;
            }
        }
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

uint32_t tw_reg_get(uint64_t key, const char *name, uint32_t *type, uint8_t **data, uint32_t *len)
{
    if (!name) name = "";
    pthread_mutex_lock(&g_mu);
    uint32_t rc = 0;
    reg_key *k = lookup(key);
    reg_value *v = k ? find_val(k, name) : NULL;
    if (!k) {
        rc = TW_ERROR_INVALID_HANDLE;
    } else if (!v) {
        rc = TW_ERROR_FILE_NOT_FOUND;
    } else {
        uint8_t *copy = malloc(v->len ? v->len : 1);
        if (!copy) {
            rc = TW_ERROR_NOT_ENOUGH_MEMORY;
        } else {
            if (v->len) memcpy(copy, v->data, v->len);
            *type = v->type;
            *data = copy;
            *len = v->len;
        }
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

uint32_t tw_reg_delete_value(uint64_t key, const char *name)
{
    if (!name) name = "";
    pthread_mutex_lock(&g_mu);
    uint32_t rc = 0;
    reg_key *k = lookup(key);
    reg_value *v = k ? find_val(k, name) : NULL;
    if (!k) {
        rc = TW_ERROR_INVALID_HANDLE;
    } else if (!v) {
        rc = TW_ERROR_FILE_NOT_FOUND;
    } else {
        free(v->name);
        free(v->data);
        *v = k->vals[--k->nvals];
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

size_t tw_reg_open_handles(void)
{
    size_t n = 0;
    pthread_mutex_lock(&g_mu);
    for (size_t i = 0; i < MAX_HANDLES; i++)
        if (g_handles[i]) n++;
    pthread_mutex_unlock(&g_mu);
    return n;
}

void tw_reg_reset(void)
{
    pthread_mutex_lock(&g_mu);
    free_tree(&g_hkcu, 1);
    free_tree(&g_hklm, 1);
    memset(g_handles, 0, sizeof g_handles);
    pthread_mutex_unlock(&g_mu);
}
