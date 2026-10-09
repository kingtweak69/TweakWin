#include "modules.h"

#include "../kernel32/kernel32.h"

#include <stdio.h>
#include <string.h>

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif

#define TW_MAX_MODULES 8

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
    g_init = 1;
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
    if (err && errlen) err[0] = '\0';
    const tw_module *m = tw_modules_find(dll);
    if (!m) {
        if (err && errlen)
            snprintf(err, errlen, "unknown DLL '%s'", dll ? dll : "(null)");
        return 0;
    }
    for (size_t i = 0; i < m->nexports; i++) {
        const tw_export *e = &m->exports[i];
        if (by_ordinal) {
            if (e->ordinal && e->ordinal == ordinal) return e->addr;
        } else if (name && e->name && strcmp(e->name, name) == 0) {
            return e->addr;
        }
    }
    if (err && errlen) {
        if (by_ordinal)
            snprintf(err, errlen, "unknown symbol %s!#%u", m->name, ordinal);
        else
            snprintf(err, errlen, "unknown symbol %s!%s", m->name, name ? name : "(null)");
    }
    return 0;
}
