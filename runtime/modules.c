#include "modules.h"

#include "process.h"
#include "winfs.h"
#include "../advapi32/advapi32.h"
#include "../backend/kb.h"
#include "../kernel32/kernel32.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif

#define TW_MAX_MODULES 8
#define TW_MAX_DLLS 64
#define TW_MAX_FWD_DEPTH 16

static const tw_module *g_mods[TW_MAX_MODULES];
static size_t g_nmods;
static int g_init;

typedef void (*tw_anyfn)(void);

static uint64_t fptr64(tw_anyfn f)
{
    uint64_t u = 0;
    memcpy(&u, &f, sizeof f);
    return u;
}

static int ascii_ieq(const char *a, const char *b)
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

static void add_mod(const tw_module *m)
{
    if (g_nmods >= TW_MAX_MODULES) return;
    g_mods[g_nmods++] = m;
}

static tw_export k32_exports_live[128];
static tw_module k32_mod_live;
static size_t k32_nexports;

static const tw_module ntdll_mod = {
    "ntdll.dll",
    NULL,
    0,
};

void tw_modules_register_kernel32(void)
{
    size_t n = 0;
    const tw_k32_desc *d = tw_k32_exports(&n);
    if (n > 128) n = 128;
    for (size_t i = 0; i < n; i++) {
        k32_exports_live[i].name = d[i].name;
        k32_exports_live[i].ordinal = d[i].ordinal;
        k32_exports_live[i].addr = fptr64((tw_anyfn)d[i].fn);
    }
    k32_nexports = n;
    k32_mod_live.name = "kernel32.dll";
    k32_mod_live.exports = k32_exports_live;
    k32_mod_live.nexports = k32_nexports;
    add_mod(&k32_mod_live);
}

static tw_export adv_exports_live[64];
static tw_module adv_mod_live;

void tw_modules_register_advapi32(void)
{
    size_t n = 0;
    const tw_k32_desc *d = tw_advapi32_exports(&n);
    if (n > 64) n = 64;
    for (size_t i = 0; i < n; i++) {
        adv_exports_live[i].name = d[i].name;
        adv_exports_live[i].ordinal = d[i].ordinal;
        adv_exports_live[i].addr = fptr64((tw_anyfn)d[i].fn);
    }
    adv_mod_live.name = "advapi32.dll";
    adv_mod_live.exports = adv_exports_live;
    adv_mod_live.nexports = n;
    add_mod(&adv_mod_live);
}

void tw_modules_register_ntdll(void)
{
    add_mod(&ntdll_mod);
}

void tw_modules_init(void)
{
    if (g_init) return;
    g_nmods = 0;
    tw_modules_register_kernel32();
    tw_modules_register_ntdll();
    tw_modules_register_advapi32();
    g_init = 1;
}

/* ------------------------------------------------------------------ */
/* Dynamic modules                                                     */

enum dll_state {
    DS_LOADING = 1,
    DS_MAPPED,
    DS_ATTACHING,
    DS_ATTACHED,
    DS_DETACHING,
    DS_DETACHED,
    DS_FAILED
};

typedef struct tw_dll {
    tw_loaded im;
    char *virt;              /* C:\... path it was loaded from */
    char key[64];            /* lower-case file name, always with an extension */
    int refcnt;
    int state;
    int busy;                /* DllMain currently running */
    int dying;               /* being rolled back */
    uint64_t attach_seq;
    struct tw_dll **deps;    /* one reference held on each */
    size_t ndeps, capdeps;
} tw_dll;

static pthread_mutex_t g_lock;
static pthread_once_t g_lock_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_reg = PTHREAD_MUTEX_INITIALIZER;
static tw_dll *g_dlls[TW_MAX_DLLS];
static tw_dll *g_batch[TW_MAX_DLLS];
static size_t g_nbatch;
static int g_depth;
static uint64_t g_seq;
static tw_dll g_exe_owner;
static char g_builtin_tag[8];

static void lock_init(void)
{
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_lock, &a);
    pthread_mutexattr_destroy(&a);
}

static void loader_lock(void)
{
    pthread_once(&g_lock_once, lock_init);
    pthread_mutex_lock(&g_lock);
}

static void loader_unlock(void)
{
    pthread_mutex_unlock(&g_lock);
}

/* Lower-case file name with ".dll" appended when it has no extension. */
static int name_key(const char *in, char *out, size_t cap)
{
    const char *b = in;
    for (const char *q = in; *q; q++)
        if (*q == '\\' || *q == '/' || *q == ':') b = q + 1;
    size_t n = strlen(b);
    int dot = strchr(b, '.') != NULL;
    if (n == 0 || n + (dot ? 0 : 4) >= cap) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = b[i];
        out[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
    out[n] = '\0';
    if (!dot) strcat(out, ".dll");
    else if (out[n - 1] == '.') out[n - 1] = '\0';
    return 0;
}

static int has_sep(const char *s)
{
    return strpbrk(s, "\\/:") != NULL;
}

static tw_dll *dll_by_handle(uint64_t h)
{
    for (size_t i = 0; i < TW_MAX_DLLS; i++)
        if (g_dlls[i] && !g_dlls[i]->dying && g_dlls[i]->state != DS_LOADING && g_dlls[i]->im.base == h)
            return g_dlls[i];
    return NULL;
}

static tw_dll *dll_by_key(const char *key)
{
    for (size_t i = 0; i < TW_MAX_DLLS; i++)
        if (g_dlls[i] && !g_dlls[i]->dying && strcmp(g_dlls[i]->key, key) == 0) return g_dlls[i];
    return NULL;
}

static tw_dll *dll_by_virt(const char *virt)
{
    for (size_t i = 0; i < TW_MAX_DLLS; i++)
        if (g_dlls[i] && !g_dlls[i]->dying && g_dlls[i]->virt && ascii_ieq(g_dlls[i]->virt, virt))
            return g_dlls[i];
    return NULL;
}

static int add_dep(tw_dll *owner, tw_dll *dep)
{
    if (owner->ndeps == owner->capdeps) {
        size_t nc = owner->capdeps ? owner->capdeps * 2 : 4;
        tw_dll **nd = realloc(owner->deps, nc * sizeof *nd);
        if (!nd) return -1;
        owner->deps = nd;
        owner->capdeps = nc;
    }
    owner->deps[owner->ndeps++] = dep;
    return 0;
}

static void refresh_fault_regions(void)
{
    struct tw_loaded *exe = tw_runtime_image();
    if (!exe) return;
    tw_kb_fault_region_clear();
    tw_kb_fault_region_add(exe->base, exe->image_size, 0);
    tw_kb_fault_region_add((uint64_t)(uintptr_t)exe->stack, exe->stack_len, 1);
    for (size_t i = 0; i < TW_MAX_DLLS; i++)
        if (g_dlls[i] && g_dlls[i]->im.image) tw_kb_fault_region_add(g_dlls[i]->im.base, g_dlls[i]->im.image_size, 0);
}

/* Free the record and its mapping. Reference bookkeeping is the caller's. */
static void dll_free_record(tw_dll *d)
{
    pthread_mutex_lock(&g_reg);
    for (size_t i = 0; i < TW_MAX_DLLS; i++)
        if (g_dlls[i] == d) g_dlls[i] = NULL;
    pthread_mutex_unlock(&g_reg);
    if (d->im.map_ptr || d->im.image) tw_unload_dll(&d->im);
    else tw_pe_free(&d->im.pe);
    free(d->deps);
    free(d->virt);
    free(d);
}

typedef int(TW_MS_ABI *dllmain_fn)(void *, uint32_t, void *);

static int call_main(tw_dll *d, uint32_t reason, void *reserved)
{
    if (!d->im.pe.entry_rva) return 1;
    uint64_t a = d->im.base + d->im.pe.entry_rva;
    dllmain_fn fn;
    memcpy(&fn, &a, sizeof fn);
    d->busy++;
    int r = fn((void *)(uintptr_t)d->im.base, reason, reserved);
    d->busy--;
    return r != 0;
}

static void release(tw_dll *d);

static void destroy(tw_dll *d)
{
    if (d->state == DS_ATTACHED) {
        d->state = DS_DETACHING;
        call_main(d, 0 /* DLL_PROCESS_DETACH */, NULL);
    }
    d->state = DS_DETACHED;
    tw_dll **deps = d->deps;
    size_t n = d->ndeps;
    d->deps = NULL;
    d->ndeps = d->capdeps = 0;
    for (size_t i = n; i-- > 0;) release(deps[i]);
    free(deps);
    dll_free_record(d);
    refresh_fault_regions();
}

static void release(tw_dll *d)
{
    if (d->refcnt > 0) d->refcnt--;
    if (d->refcnt > 0) return;
    if (d->busy || d->state == DS_DETACHING || d->state == DS_ATTACHING || d->state == DS_LOADING)
        return; /* reaped by tw_modules_unload_all */
    destroy(d);
}

/* ---- export resolution ---- */

static const tw_pe_export *find_export(const tw_pe_image *pe, const char *name, uint32_t ord, int by_ord)
{
    if (!pe->exports.present) return NULL;
    for (size_t i = 0; i < pe->exports.nentries; i++) {
        const tw_pe_export *e = &pe->exports.entries[i];
        if (by_ord) {
            if (e->ordinal == ord) return e;
        } else if (name && e->name && strcmp(e->name, name) == 0) {
            return e;
        }
    }
    return NULL;
}

static uint64_t resolve_any(const char *dll, const char *name, uint32_t ord, int by_ord, int depth,
                            char *err, size_t errlen);

static uint64_t builtin_resolve(const tw_module *m, const char *name, uint32_t ord, int by_ord)
{
    for (size_t i = 0; i < m->nexports; i++) {
        const tw_export *e = &m->exports[i];
        if (by_ord) {
            if (e->ordinal && e->ordinal == ord) return e->addr;
        } else if (name && e->name && strcmp(e->name, name) == 0) {
            return e->addr;
        }
    }
    return 0;
}

static uint64_t dll_resolve(tw_dll *d, const char *name, uint32_t ord, int by_ord, int depth,
                            char *err, size_t errlen)
{
    if (depth > TW_MAX_FWD_DEPTH) {
        snprintf(err, errlen, "export forwarder chain too deep or cyclic at %s", d->key);
        return 0;
    }
    if (!d->im.image) {
        snprintf(err, errlen, "module %s is not mapped", d->key);
        return 0;
    }
    const tw_pe_export *e = find_export(&d->im.pe, name, ord, by_ord);
    if (!e) {
        if (by_ord) snprintf(err, errlen, "unknown symbol %s!#%u", d->key, ord);
        else snprintf(err, errlen, "unknown symbol %s!%s", d->key, name ? name : "(null)");
        return 0;
    }
    if (e->forwarder) {
        const char *f = e->forwarder;
        const char *dot = strchr(f, '.');
        if (!dot || dot == f || !dot[1] || (size_t)(dot - f) > 200) {
            snprintf(err, errlen, "malformed export forwarder '%.100s' in %s", f, d->key);
            return 0;
        }
        char mod[208];
        memcpy(mod, f, (size_t)(dot - f));
        mod[dot - f] = '\0';
        const char *fn = dot + 1;
        uint32_t fo = 0;
        int fby = 0;
        if (fn[0] == '#') {
            uint32_t v = 0;
            const char *q = fn + 1;
            if (!*q) goto bad;
            for (; *q; q++) {
                if (*q < '0' || *q > '9') goto bad;
                v = v * 10 + (uint32_t)(*q - '0');
                if (v > 0xffff) goto bad;
            }
            if (v == 0) goto bad;
            fo = v;
            fby = 1;
            fn = NULL;
        }
        char dllname[256];
        snprintf(dllname, sizeof dllname, "%s.dll", mod);
        return resolve_any(dllname, fn, fo, fby, depth + 1, err, errlen);
    bad:
        snprintf(err, errlen, "malformed export forwarder '%.100s' in %s", f, d->key);
        return 0;
    }
    if (e->rva == 0 || e->rva >= d->im.pe.size_of_image) {
        snprintf(err, errlen, "export %s!%s points outside the image", d->key, e->name ? e->name : "#");
        return 0;
    }
    return d->im.base + e->rva;
}

static uint64_t resolve_any(const char *dll, const char *name, uint32_t ord, int by_ord, int depth,
                            char *err, size_t errlen)
{
    if (err && errlen) err[0] = '\0';
    tw_modules_init();
    for (size_t i = 0; i < g_nmods; i++) {
        if (ascii_ieq(g_mods[i]->name, dll)) {
            uint64_t a = builtin_resolve(g_mods[i], name, ord, by_ord);
            if (!a && err && errlen) {
                if (by_ord) snprintf(err, errlen, "unknown symbol %s!#%u", g_mods[i]->name, ord);
                else snprintf(err, errlen, "unknown symbol %s!%s", g_mods[i]->name, name ? name : "(null)");
            }
            return a;
        }
    }
    char key[64];
    tw_dll *d = NULL;
    loader_lock();
    if (dll && name_key(dll, key, sizeof key) == 0) d = dll_by_key(key);
    uint64_t r = 0;
    if (d) {
        char tmp[256];
        r = dll_resolve(d, name, ord, by_ord, depth, tmp, sizeof tmp);
        if (!r && err && errlen) snprintf(err, errlen, "%s", tmp);
    } else if (err && errlen) {
        snprintf(err, errlen, "unknown DLL '%s'", dll ? dll : "(null)");
    }
    loader_unlock();
    return r;
}

const tw_module *tw_modules_find(const char *dll)
{
    if (!dll) return NULL;
    tw_modules_init();
    for (size_t i = 0; i < g_nmods; i++) {
        if (ascii_ieq(g_mods[i]->name, dll)) return g_mods[i];
    }
    return NULL;
}

uint64_t tw_modules_resolve(const char *dll, const char *name, uint16_t ordinal,
                            int by_ordinal, char *err, size_t errlen)
{
    return resolve_any(dll, name, ordinal, by_ordinal, 0, err, errlen);
}

/* ---- acquisition (find or map) ---- */

static uint32_t status_to_werr(tw_load_status st)
{
    switch (st) {
    case TW_LOAD_ERR_UNRESOLVED_DLL: return TW_ERROR_MOD_NOT_FOUND;
    case TW_LOAD_ERR_UNRESOLVED_SYMBOL: return TW_ERROR_PROC_NOT_FOUND;
    case TW_LOAD_ERR_NOMEM:
    case TW_LOAD_ERR_MAP: return TW_ERROR_NOT_ENOUGH_MEMORY;
    case TW_LOAD_ERR_RUNTIME: return TW_ERROR_DLL_INIT_FAILED;
    default: return TW_ERROR_BAD_EXE_FORMAT;
    }
}

#define note(err, n, fmt, a, b) \
    do { \
        if ((err) && (n)) snprintf((err), (n), fmt, (a) ? (a) : "", (b) ? (b) : ""); \
    } while (0)

static uint32_t acquire(const char *name, uint32_t flags, tw_dll **out, char *err, size_t errlen);

/* Load (non-fatally) the modules named by this DLL's export forwarders. */
static void load_forwarder_deps(tw_dll *d)
{
    const tw_pe_exports *ex = &d->im.pe.exports;
    if (!ex->present) return;
    for (size_t i = 0; i < ex->nentries; i++) {
        const char *f = ex->entries[i].forwarder;
        if (!f) continue;
        const char *dot = strchr(f, '.');
        if (!dot || dot == f || (size_t)(dot - f) > 200) continue;
        char mod[256];
        snprintf(mod, sizeof mod, "%.*s.dll", (int)(dot - f), f);
        if (tw_modules_find(mod)) continue;
        int have = 0;
        for (size_t k = 0; k < d->ndeps; k++)
            if (ascii_ieq(d->deps[k]->key, mod)) have = 1;
        if (have) continue;
        tw_dll *dep = NULL;
        char tmp[128];
        if (acquire(mod, 0, &dep, tmp, sizeof tmp) == 0 && dep && add_dep(d, dep) != 0) release(dep);
    }
}

static uint32_t acquire(const char *name, uint32_t flags, tw_dll **out, char *err, size_t errlen)
{
    (void)flags;
    *out = NULL;
    char key[64];
    if (name_key(name, key, sizeof key) != 0) {
        note(err, errlen, "invalid module name '%s'%s", name, "");
        return TW_ERROR_INVALID_NAME;
    }
    tw_dll *d;
    if (!has_sep(name) && (d = dll_by_key(key)) != NULL) {
        d->refcnt++;
        *out = d;
        return 0;
    }
    char host[TW_WINFS_PATH_MAX], virt[TW_WINFS_PATH_MAX];
    uint32_t e = tw_winfs_search_dll(name, host, sizeof host, virt, sizeof virt);
    if (e) {
        note(err, errlen, "cannot find DLL '%s'%s", name, "");
        return e == TW_ERROR_INVALID_NAME ? e : TW_ERROR_MOD_NOT_FOUND;
    }
    if ((d = dll_by_virt(virt)) != NULL) {
        d->refcnt++;
        *out = d;
        return 0;
    }
    size_t slot = TW_MAX_DLLS;
    for (size_t i = 0; i < TW_MAX_DLLS; i++)
        if (!g_dlls[i]) {
            slot = i;
            break;
        }
    if (slot == TW_MAX_DLLS || g_nbatch >= TW_MAX_DLLS) {
        note(err, errlen, "too many loaded modules (%s)%s", name, "");
        return TW_ERROR_NOT_ENOUGH_MEMORY;
    }
    d = calloc(1, sizeof *d);
    if (!d) return TW_ERROR_NOT_ENOUGH_MEMORY;
    d->virt = strdup(virt);
    if (!d->virt) {
        free(d);
        return TW_ERROR_NOT_ENOUGH_MEMORY;
    }
    snprintf(d->key, sizeof d->key, "%s", key);
    d->refcnt = 1;
    d->state = DS_LOADING;
    d->im.mod_owner = d;
    pthread_mutex_lock(&g_reg);
    g_dlls[slot] = d;
    pthread_mutex_unlock(&g_reg);
    g_batch[g_nbatch++] = d;

    tw_pe_error perr;
    tw_load_status st = tw_load_dll(host, TW_BASE_PREFER, &d->im, &perr);
    if (st != TW_LOAD_OK) {
        if (err && errlen) snprintf(err, errlen, "%s: %s", key, d->im.err);
        return status_to_werr(st);
    }
    load_forwarder_deps(d);
    d->state = DS_MAPPED;
    *out = d;
    return 0;
}

/* Undo every module created since `start`: detach what attached, drop the
 * references they held, unmap. Nothing created before `start` is touched
 * except for the reference counts the batch members held on it. */
static void rollback(size_t start)
{
    for (size_t i = start; i < g_nbatch; i++) g_batch[i]->dying = 1;
    for (size_t i = g_nbatch; i-- > start;) {
        tw_dll *d = g_batch[i];
        if (d->state == DS_ATTACHED) {
            d->state = DS_DETACHING;
            call_main(d, 0, NULL);
        }
        d->state = DS_DETACHED;
    }
    for (size_t i = g_nbatch; i-- > start;) {
        tw_dll *d = g_batch[i];
        for (size_t k = d->ndeps; k-- > 0;)
            if (!d->deps[k]->dying && d->deps[k]->refcnt > 0) d->deps[k]->refcnt--;
    }
    for (size_t i = g_nbatch; i-- > start;) dll_free_record(g_batch[i]);
    g_nbatch = start;
    refresh_fault_regions();
}

static int attach_module(tw_dll *d, void *reserved, char *err, size_t errlen)
{
    if (d->state != DS_MAPPED) return 0;
    d->state = DS_ATTACHING;
    for (size_t i = 0; i < d->ndeps; i++)
        if (attach_module(d->deps[i], reserved, err, errlen) != 0) {
            d->state = DS_FAILED;
            return -1;
        }
    if (!call_main(d, 1 /* DLL_PROCESS_ATTACH */, reserved)) {
        note(err, errlen, "DllMain(DLL_PROCESS_ATTACH) of %s returned FALSE%s", d->key, "");
        d->state = DS_FAILED;
        return -1;
    }
    d->state = DS_ATTACHED;
    d->attach_seq = ++g_seq;
    return 0;
}

tw_load_status tw_modules_require(struct tw_loaded *importer, const char *dll, char *err, size_t errlen)
{
    if (err && errlen) err[0] = '\0';
    tw_modules_init();
    if (!dll) {
        note(err, errlen, "import from a NULL DLL name%s%s", "", "");
        return TW_LOAD_ERR_UNRESOLVED_DLL;
    }
    if (tw_modules_find(dll)) return TW_LOAD_OK;
    loader_lock();
    tw_dll *owner = importer && importer->mod_owner ? importer->mod_owner : &g_exe_owner;
    size_t start = g_nbatch;
    int top = g_depth == 0;
    g_depth++;
    tw_dll *dep = NULL;
    uint32_t e = acquire(dll, 0, &dep, err, errlen);
    g_depth--;
    tw_load_status st = TW_LOAD_OK;
    if (e == 0 && add_dep(owner, dep) != 0) {
        release(dep);
        e = TW_ERROR_NOT_ENOUGH_MEMORY;
    }
    if (e) {
        if (err && errlen && !err[0]) snprintf(err, errlen, "unknown DLL '%s'", dll);
        st = e == TW_ERROR_MOD_NOT_FOUND ? TW_LOAD_ERR_UNRESOLVED_DLL
             : e == TW_ERROR_PROC_NOT_FOUND ? TW_LOAD_ERR_UNRESOLVED_SYMBOL
             : e == TW_ERROR_NOT_ENOUGH_MEMORY ? TW_LOAD_ERR_NOMEM
             : TW_LOAD_ERR_MALFORMED;
        if (top) rollback(start);
    } else if (top) {
        g_nbatch = start;
    }
    loader_unlock();
    return st;
}

/* ---- public LoadLibrary-level API ---- */

static const char *builtin_name_for(const char *name)
{
    char key[64];
    if (name_key(name, key, sizeof key) != 0) return NULL;
    tw_modules_init();
    for (size_t i = 0; i < g_nmods; i++)
        if (ascii_ieq(g_mods[i]->name, key)) return g_mods[i]->name;
    return NULL;
}

static uint64_t builtin_handle(const char *bname)
{
    if (ascii_ieq(bname, "kernel32.dll")) return tw_runtime_k32_base();
    if (ascii_ieq(bname, "ntdll.dll")) return tw_runtime_ntdll_base();
    return (uint64_t)(uintptr_t)&g_builtin_tag[ascii_ieq(bname, "advapi32.dll") ? 1 : 2];
}

uint32_t tw_dll_load(const char *name, uint32_t flags, uint64_t *handle)
{
    if (handle) *handle = 0;
    if (!name || !name[0]) return TW_ERROR_INVALID_PARAMETER;
    if (flags & ~TW_LOAD_WITH_ALTERED_SEARCH_PATH) return TW_ERROR_INVALID_PARAMETER;
    const char *bn = builtin_name_for(name);
    if (bn && !has_sep(name)) {
        if (handle) *handle = builtin_handle(bn);
        return 0;
    }
    loader_lock();
    size_t start = g_nbatch;
    g_depth++;
    tw_dll *d = NULL;
    char err[256];
    uint32_t e = acquire(name, flags, &d, err, sizeof err);
    int was_attached = d && d->state == DS_ATTACHED;
    if (!e && !was_attached && attach_module(d, NULL, err, sizeof err) != 0) e = TW_ERROR_DLL_INIT_FAILED;
    g_depth--;
    if (e) {
        int in_batch = 0;
        for (size_t i = start; i < g_nbatch; i++)
            if (g_batch[i] == d) in_batch = 1;
        rollback(start);
        if (d && !in_batch) release(d); /* drop the caller's reference */
    } else {
        g_nbatch = start;
        refresh_fault_regions();
        if (handle) *handle = d->im.base;
    }
    loader_unlock();
    return e;
}

uint32_t tw_dll_free(uint64_t handle)
{
    tw_modules_init();
    for (size_t i = 0; i < g_nmods; i++)
        if (builtin_handle(g_mods[i]->name) == handle) return 0; /* built-ins are never unloaded */
    loader_lock();
    tw_dll *d = dll_by_handle(handle);
    uint32_t e = 0;
    if (!d || d->refcnt <= 0) e = TW_ERROR_INVALID_HANDLE;
    else release(d);
    loader_unlock();
    return e;
}

uint64_t tw_dll_proc(uint64_t handle, const char *name, uint32_t ordinal, int by_ordinal, uint32_t *err)
{
    char why[256];
    uint64_t r = 0;
    uint32_t e = 0;
    loader_lock();
    tw_dll *d = dll_by_handle(handle);
    if (d) {
        r = dll_resolve(d, name, ordinal, by_ordinal, 0, why, sizeof why);
        if (!r) e = TW_ERROR_PROC_NOT_FOUND;
    } else {
        tw_modules_init();
        for (size_t i = 0; i < g_nmods && !r; i++) {
            if (builtin_handle(g_mods[i]->name) == handle) {
                r = builtin_resolve(g_mods[i], name, ordinal, by_ordinal);
                if (!r) e = TW_ERROR_PROC_NOT_FOUND;
                break;
            }
            if (i + 1 == g_nmods) e = TW_ERROR_MOD_NOT_FOUND;
        }
    }
    loader_unlock();
    if (err) *err = e;
    return r;
}

uint64_t tw_dll_module_handle(const char *name)
{
    if (!name) return 0;
    const char *bn = builtin_name_for(name);
    if (bn) return builtin_handle(bn);
    uint64_t h = 0;
    loader_lock();
    tw_dll *d = NULL;
    if (has_sep(name)) {
        char norm[TW_WINFS_PATH_MAX];
        if (tw_winfs_normalize(name, 0, norm, sizeof norm) == 0) d = dll_by_virt(norm);
    } else {
        char key[64];
        if (name_key(name, key, sizeof key) == 0) d = dll_by_key(key);
    }
    if (d && d->state != DS_LOADING) h = d->im.base;
    loader_unlock();
    return h;
}

int tw_dll_path(uint64_t handle, char *out, size_t cap)
{
    int rc = -1;
    loader_lock();
    tw_dll *d = dll_by_handle(handle);
    if (d && d->virt && strlen(d->virt) < cap) {
        strcpy(out, d->virt);
        rc = 0;
    }
    loader_unlock();
    return rc;
}

int tw_dll_refcount(uint64_t handle)
{
    int r = -1;
    loader_lock();
    tw_dll *d = dll_by_handle(handle);
    if (d) r = d->refcnt;
    loader_unlock();
    return r;
}

size_t tw_dll_count(void)
{
    size_t n = 0;
    loader_lock();
    for (size_t i = 0; i < TW_MAX_DLLS; i++)
        if (g_dlls[i]) n++;
    loader_unlock();
    return n;
}

int tw_modules_attach_pending(char *err, size_t errlen)
{
    loader_lock();
    int rc = 0;
    for (size_t i = 0; i < TW_MAX_DLLS && rc == 0; i++)
        if (g_dlls[i] && g_dlls[i]->state == DS_MAPPED)
            rc = attach_module(g_dlls[i], (void *)(uintptr_t)1, err, errlen);
    loader_unlock();
    return rc;
}

void tw_modules_process_detach(void)
{
    loader_lock();
    for (;;) {
        tw_dll *best = NULL;
        for (size_t i = 0; i < TW_MAX_DLLS; i++)
            if (g_dlls[i] && g_dlls[i]->state == DS_ATTACHED &&
                (!best || g_dlls[i]->attach_seq > best->attach_seq))
                best = g_dlls[i];
        if (!best) break;
        best->state = DS_DETACHING;
        call_main(best, 0, (void *)(uintptr_t)1);
        best->state = DS_DETACHED;
    }
    loader_unlock();
}

void tw_modules_thread_notify(uint32_t reason)
{
    if (!g_seq) return;
    loader_lock();
    uint64_t last = 0;
    for (;;) {
        tw_dll *pick = NULL;
        for (size_t i = 0; i < TW_MAX_DLLS; i++) {
            tw_dll *d = g_dlls[i];
            if (!d || d->state != DS_ATTACHED || d->attach_seq <= last) continue;
            if (!pick || d->attach_seq < pick->attach_seq) pick = d;
        }
        if (!pick) break;
        last = pick->attach_seq;
        call_main(pick, reason, NULL);
    }
    loader_unlock();
}

void tw_modules_unload_all(void)
{
    loader_lock();
    for (size_t i = 0; i < TW_MAX_DLLS; i++) {
        tw_dll *d = g_dlls[i];
        if (!d) continue;
        d->dying = 1;
        d->state = DS_DETACHED;
    }
    for (size_t i = TW_MAX_DLLS; i-- > 0;)
        if (g_dlls[i]) dll_free_record(g_dlls[i]);
    free(g_exe_owner.deps);
    memset(&g_exe_owner, 0, sizeof g_exe_owner);
    g_nbatch = 0;
    g_depth = 0;
    g_seq = 0;
    loader_unlock();
}

int tw_modules_guest_check(uint64_t addr, uint64_t len, int need)
{
    int ok = 0;
    uint64_t end = addr + len;
    if (end < addr) return 0;
    pthread_mutex_lock(&g_reg);
    for (size_t i = 0; i < TW_MAX_DLLS && !ok; i++) {
        const tw_dll *d = g_dlls[i];
        if (!d || d->dying || d->state < DS_MAPPED) continue;
        for (size_t k = 0; k < d->im.nregions; k++) {
            const tw_region *r = &d->im.regions[k];
            if (addr >= r->start && end <= r->end && (r->prot & need) == need) {
                ok = 1;
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_reg);
    return ok;
}

