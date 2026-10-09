#include "debug.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned g_mask;
static int g_init;

static const struct { const char *name; unsigned bit; } k_cats[] = {
    { "loader",     TW_DBG_LOADER },
    { "imports",    TW_DBG_IMPORTS },
    { "memory",     TW_DBG_MEMORY },
    { "handles",    TW_DBG_HANDLES },
    { "filesystem", TW_DBG_FILESYSTEM },
    { "registry",   TW_DBG_REGISTRY },
    { "thread",     TW_DBG_THREAD },
    { "user32",     TW_DBG_USER32 },
    { "gdi",        TW_DBG_GDI },
    { "network",    TW_DBG_NETWORK },
};

#define NCATS (sizeof(k_cats) / sizeof(k_cats[0]))

void tw_debug_init(void)
{
    const char *env = getenv("TWEAKWIN_DEBUG");
    g_mask = 0;
    g_init = 1;
    if (!env || !*env) return;

    const char *p = env;
    while (*p) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == 3 && strncmp(p, "all", 3) == 0) {
            g_mask = ~0u;
        } else {
            int found = 0;
            for (size_t i = 0; i < NCATS; i++) {
                if (strlen(k_cats[i].name) == len && strncmp(p, k_cats[i].name, len) == 0) {
                    g_mask |= k_cats[i].bit;
                    found = 1;
                    break;
                }
            }
            if (!found && len > 0)
                fprintf(stderr, "tweakwin: warning: unknown debug category '%.*s'\n", (int)len, p);
        }
        if (!end) break;
        p = end + 1;
    }
}

unsigned tw_debug_mask(void)
{
    if (!g_init) tw_debug_init();
    return g_mask;
}

const char *tw_debug_name(unsigned cat)
{
    for (size_t i = 0; i < NCATS; i++)
        if (k_cats[i].bit == cat) return k_cats[i].name;
    return "?";
}

void tw_debug_log(unsigned cat, const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "[tweakwin:%s] ", tw_debug_name(cat));
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
