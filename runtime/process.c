#include "process.h"

#include "../loader/load.h"
#include "utf.h"
#include "vmem.h"
#include "../rt/rt.h"
#include "handle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#define TW_ENV_MAX        64
#define TW_ENV_NAME_MAX   256
#define TW_ENV_VALUE_MAX  4096
#define TW_CMDLINE_MAX    32767
#define TW_ENV_BLOCKS     8

extern char **environ;

struct tw_env_ent {
    int live;
    char *name;
    char *value;
};

static struct tw_loaded *g_im;
static int g_bound;
static uint32_t g_last;
static char g_exe[4096];
static uint64_t g_cmd_a;
static uint64_t g_cmd_w;
static struct tw_env_ent g_env[TW_ENV_MAX];
static uint64_t g_blocks[TW_ENV_BLOCKS];
static TW_HANDLE g_heap;
static uint64_t g_k32_base;
static uint64_t g_nt_base;

int tw_runtime_bound(void)
{
    return g_bound;
}

struct tw_loaded *tw_runtime_image(void)
{
    return g_bound ? g_im : NULL;
}

void tw_set_last_error(uint32_t err)
{
    g_last = err;
    /* When the rt process environment is active, LastError is per-thread
     * storage in TEB.LastErrorValue. Keep the legacy global in sync for
     * host unit tests that run without a TEB. */
    if (tw_rt_active()) tw_rt_set_last_error(err);
}

uint32_t tw_get_last_error(void)
{
    if (tw_rt_active()) return tw_rt_get_last_error();
    return g_last;
}

const char *tw_runtime_exe(void)
{
    return g_exe;
}

uint64_t tw_runtime_cmdline_a(void)
{
    return g_cmd_a;
}

uint64_t tw_runtime_cmdline_w(void)
{
    return g_cmd_w;
}

uint64_t tw_runtime_k32_base(void)
{
    return g_k32_base;
}

uint64_t tw_runtime_ntdll_base(void)
{
    return g_nt_base;
}

TW_HANDLE tw_runtime_heap(void)
{
    return g_heap;
}

uint64_t tw_runtime_mono_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int ascii_name_ok(const char *name)
{
    if (!name || !name[0]) return 0;
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        if (*p < 0x20 || *p > 0x7e) return 0;
        if (*p == '=') return 0;
        if (++n >= TW_ENV_NAME_MAX) return 0;
    }
    return 1;
}

static unsigned char fold(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return (unsigned char)(c - 'A' + 'a');
    return c;
}

static int name_ieq(const char *a, const char *b)
{
    for (;;) {
        unsigned char ca = fold((unsigned char)*a++);
        unsigned char cb = fold((unsigned char)*b++);
        if (ca != cb) return 0;
        if (ca == 0) return 1;
    }
}

static void env_clear(void)
{
    for (int i = 0; i < TW_ENV_MAX; i++) {
        free(g_env[i].name);
        free(g_env[i].value);
        g_env[i].name = NULL;
        g_env[i].value = NULL;
        g_env[i].live = 0;
    }
    for (int i = 0; i < TW_ENV_BLOCKS; i++) g_blocks[i] = 0;
}

static struct tw_env_ent *env_find(const char *name)
{
    for (int i = 0; i < TW_ENV_MAX; i++) {
        if (g_env[i].live && name_ieq(g_env[i].name, name)) return &g_env[i];
    }
    return NULL;
}

int tw_env_get_a(const char *name, char *buf, uint32_t cap, uint32_t *needed)
{
    if (!ascii_name_ok(name)) return -1;
    struct tw_env_ent *e = env_find(name);
    if (!e) return 1;
    size_t n = strlen(e->value);
    if (n >= UINT32_MAX) return -1;
    if (needed) *needed = (uint32_t)n + 1;
    if (!buf || cap < n + 1) return 0;
    memcpy(buf, e->value, n + 1);
    return 0;
}

int tw_env_set_a(const char *name, const char *value)
{
    if (!ascii_name_ok(name)) return -1;
    if (value && strlen(value) > TW_ENV_VALUE_MAX) return -1;
    struct tw_env_ent *e = env_find(name);
    if (!value) {
        if (!e) return 0;
        free(e->name);
        free(e->value);
        e->name = NULL;
        e->value = NULL;
        e->live = 0;
        return 0;
    }
    if (!e) {
        for (int i = 0; i < TW_ENV_MAX; i++) {
            if (!g_env[i].live) { e = &g_env[i]; break; }
        }
        if (!e) return -1;
        e->name = strdup(name);
        if (!e->name) return -1;
        e->live = 1;
    }
    char *copy = strdup(value);
    if (!copy) return -1;
    free(e->value);
    e->value = copy;
    return 0;
}

static int remember_block(uint64_t addr)
{
    for (int i = 0; i < TW_ENV_BLOCKS; i++) {
        if (g_blocks[i] == 0) { g_blocks[i] = addr; return 0; }
    }
    return -1;
}

int tw_env_block_free(uint64_t addr)
{
    if (!addr) return -1;
    for (int i = 0; i < TW_ENV_BLOCKS; i++) {
        if (g_blocks[i] == addr) {
            g_blocks[i] = 0;
            if (tw_vmem_unmap(addr, TW_VM_BLOB) != 0) return -1;
            return 0;
        }
    }
    return -1;
}

uint64_t tw_env_block_a(void)
{
    size_t bytes = 2; /* block terminator, plus a second NUL when there are no entries */
    for (int i = 0; i < TW_ENV_MAX; i++) {
        if (!g_env[i].live) continue;
        bytes += strlen(g_env[i].name) + 1 + strlen(g_env[i].value) + 1;
    }
    char *tmp = malloc(bytes);
    if (!tmp) return 0;
    size_t n = 0;
    for (int i = 0; i < TW_ENV_MAX; i++) {
        if (!g_env[i].live) continue;
        size_t ln = strlen(g_env[i].name);
        size_t lv = strlen(g_env[i].value);
        memcpy(tmp + n, g_env[i].name, ln);
        n += ln;
        tmp[n++] = '=';
        memcpy(tmp + n, g_env[i].value, lv);
        n += lv;
        tmp[n++] = '\0';
    }
    tmp[n++] = '\0';
    if (n == 1) tmp[n++] = '\0';
    void *blob = tw_vmem_blob(n);
    if (!blob) { free(tmp); return 0; }
    memcpy(blob, tmp, n);
    free(tmp);
    uint64_t addr = (uint64_t)(uintptr_t)blob;
    if (remember_block(addr) != 0) {
        tw_vmem_unmap(addr, TW_VM_BLOB);
        return 0;
    }
    return addr;
}

uint64_t tw_env_block_w(void)
{
    size_t units = 2;
    int any = 0;
    for (int i = 0; i < TW_ENV_MAX; i++) {
        if (!g_env[i].live) continue;
        any = 1;
        size_t need = 0;
        char pair[TW_ENV_NAME_MAX + 1 + TW_ENV_VALUE_MAX + 1];
        int nw = snprintf(pair, sizeof pair, "%s=%s", g_env[i].name, g_env[i].value);
        if (nw < 0 || (size_t)nw >= sizeof pair) return 0;
        if (tw_utf8_to_utf16((const uint8_t *)pair, -1, NULL, 0, &need, 1) != 0) return 0;
        if (need == 0) return 0;
        units += need; /* includes that entry's NUL */
    }
    if (!any) units = 2;
    /* The loop added a NUL per entry. One extra NUL terminates the block.
     * tw_utf8_to_utf16(..., -1) already includes one NUL, so units is
     * (sum of entry widths including NULs) + 1. */
    uint16_t *tmp = calloc(units, sizeof(uint16_t));
    if (!tmp) return 0;
    size_t n = 0;
    for (int i = 0; i < TW_ENV_MAX; i++) {
        if (!g_env[i].live) continue;
        char pair[TW_ENV_NAME_MAX + 1 + TW_ENV_VALUE_MAX + 1];
        snprintf(pair, sizeof pair, "%s=%s", g_env[i].name, g_env[i].value);
        size_t need = 0;
        if (tw_utf8_to_utf16((const uint8_t *)pair, -1, tmp + n, units - n, &need, 1) != 0) {
            free(tmp);
            return 0;
        }
        n += need;
    }
    if (n == 0) {
        tmp[0] = 0;
        tmp[1] = 0;
        n = 2;
    } else {
        tmp[n++] = 0;
    }
    size_t bytes = n * sizeof(uint16_t);
    void *blob = tw_vmem_blob(bytes);
    if (!blob) { free(tmp); return 0; }
    memcpy(blob, tmp, bytes);
    free(tmp);
    uint64_t addr = (uint64_t)(uintptr_t)blob;
    if (remember_block(addr) != 0) {
        tw_vmem_unmap(addr, TW_VM_BLOB);
        return 0;
    }
    return addr;
}

static int append_bytes(char *dst, size_t cap, size_t *n, const void *s, size_t len)
{
    if (len > cap - *n) return -1;
    if (len) memcpy(dst + *n, s, len);
    *n += len;
    return 0;
}

static int needs_quotes(const char *s)
{
    if (!s[0]) return 1;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '"') return 1;
    }
    return 0;
}

/* Inverse of the CommandLineToArgvW rules in the Win32 documentation. */
static int append_arg(char *dst, size_t cap, size_t *n, const char *arg)
{
    if (*n && append_bytes(dst, cap, n, " ", 1)) return -1;
    if (!needs_quotes(arg))
        return append_bytes(dst, cap, n, arg, strlen(arg));
    if (append_bytes(dst, cap, n, "\"", 1)) return -1;
    size_t bs = 0;
    for (const char *p = arg;; p++) {
        if (*p == '\\') { bs++; continue; }
        size_t out = (*p == '\0' || *p == '"') ? bs * 2 : bs;
        if (*p == '"') out += 1;
        for (size_t i = 0; i < out; i++)
            if (append_bytes(dst, cap, n, "\\", 1)) return -1;
        bs = 0;
        if (*p == '\0') break;
        if (append_bytes(dst, cap, n, p, 1)) return -1;
    }
    return append_bytes(dst, cap, n, "\"", 1);
}

static void slashes(char *s)
{
    for (; *s; s++)
        if (*s == '/') *s = '\\';
}

static int build_cmdline(int argc, char **argv)
{
    char host[TW_CMDLINE_MAX + 1];
    size_t n = 0;
    if (argc < 1 || !argv || !argv[0]) return -1;
    char prog[4096];
    if (strlen(argv[0]) >= sizeof prog) return -1;
    memcpy(prog, argv[0], strlen(argv[0]) + 1);
    slashes(prog);
    if (strlen(prog) >= sizeof g_exe) return -1;
    memcpy(g_exe, prog, strlen(prog) + 1);
    if (append_arg(host, sizeof host - 1, &n, prog)) return -1;
    for (int i = 1; i < argc; i++) {
        if (!argv[i]) return -1;
        if (append_arg(host, sizeof host - 1, &n, argv[i])) return -1;
    }
    host[n] = '\0';

    void *a = tw_vmem_blob(n + 1);
    if (!a) return -1;
    memcpy(a, host, n + 1);
    g_cmd_a = (uint64_t)(uintptr_t)a;

    size_t units = 0;
    if (tw_utf8_to_utf16((const uint8_t *)host, -1, NULL, 0, &units, 1) != 0) return -1;
    void *w = tw_vmem_blob(units * sizeof(uint16_t));
    if (!w) return -1;
    if (tw_utf8_to_utf16((const uint8_t *)host, -1, w, units, &units, 1) != 0) return -1;
    g_cmd_w = (uint64_t)(uintptr_t)w;
    return 0;
}

static void seed_env(void)
{
    if (!environ) return;
    for (char **e = environ; *e; e++) {
        const char *s = *e;
        const char pfx[] = "TWEAKWIN_GUEST_";
        if (strncmp(s, pfx, sizeof pfx - 1) != 0) continue;
        const char *body = s + (sizeof pfx - 1);
        const char *eq = strchr(body, '=');
        if (!eq || eq == body) continue;
        size_t nlen = (size_t)(eq - body);
        if (nlen == 0 || nlen >= TW_ENV_NAME_MAX) continue;
        char name[TW_ENV_NAME_MAX];
        memcpy(name, body, nlen);
        name[nlen] = '\0';
        if (!ascii_name_ok(name)) continue;
        const char *val = eq + 1;
        if (strlen(val) > TW_ENV_VALUE_MAX) continue;
        /* Host bytes that are not UTF-8 are not imported. */
        size_t dummy = 0;
        if (tw_utf8_to_utf16((const uint8_t *)val, -1, NULL, 0, &dummy, 1) != 0) continue;
        tw_env_set_a(name, val);
    }
}

void tw_runtime_unbind(void)
{
    tw_handle_shutdown();
    tw_vmem_reset();
    env_clear();
    g_im = NULL;
    g_bound = 0;
    g_cmd_a = 0;
    g_cmd_w = 0;
    g_heap = NULL;
    g_k32_base = 0;
    g_nt_base = 0;
    g_exe[0] = '\0';
    g_last = 0;
}

int tw_runtime_bind(struct tw_loaded *im, const char *exe, int argc, char **argv)
{
    (void)exe;
    tw_runtime_unbind();
    if (!im) return -1;
    g_im = im;
    if (tw_handle_open_stdio() != 0) {
        tw_runtime_unbind();
        return -1;
    }
    if (build_cmdline(argc, argv) != 0) {
        tw_runtime_unbind();
        return -1;
    }
    seed_env();
    g_heap = tw_handle_alloc_heap();
    if (!g_heap) {
        tw_runtime_unbind();
        return -1;
    }
    void *k = tw_vmem_map(4096, 0, PROT_READ, 0x02u, TW_VM_BLOB);
    void *n = tw_vmem_map(4096, 0, PROT_READ, 0x02u, TW_VM_BLOB);
    if (!k || !n) {
        tw_runtime_unbind();
        return -1;
    }
    g_k32_base = (uint64_t)(uintptr_t)k;
    g_nt_base = (uint64_t)(uintptr_t)n;
    g_last = 0;
    g_bound = 1;
    return 0;
}
