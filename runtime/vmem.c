#include "vmem.h"

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#else
#define MAP_ANONYMOUS 0x20
#endif
#endif

#define TW_VMEM_MAX 256
#define TW_VMEM_MAX_ONE   (64u * 1024u * 1024u)
#define TW_VMEM_MAX_TOTAL (256u * 1024u * 1024u)

struct span {
    int live;
    int kind;
    uint64_t map_base;
    size_t map_len;
    uint64_t user_base;
    uint64_t user_end;
    size_t user_size;
    uint64_t alloc_base;
    int prot;
    uint32_t win_protect;
    uint32_t alloc_protect;
};

static struct span g_sp[TW_VMEM_MAX];
static size_t g_total;

static size_t host_page(void)
{
    long n = sysconf(_SC_PAGESIZE);
    return n > 0 ? (size_t)n : 4096u;
}

static size_t round_up(size_t v, size_t a)
{
    if (a <= 1) return v;
    size_t r = v % a;
    if (r == 0) return v;
    if (v > SIZE_MAX - (a - r)) return 0;
    return v + (a - r);
}

static int add_ovf(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a > UINT64_MAX - b) return 1;
    *out = a + b;
    return 0;
}

static void drop_map(uint64_t map_base, size_t map_len)
{
    int seen = 0;
    for (size_t i = 0; i < TW_VMEM_MAX; i++) {
        if (!g_sp[i].live || g_sp[i].map_base != map_base) continue;
        if (!seen) {
            munmap((void *)(uintptr_t)map_base, map_len);
            if (g_total >= map_len) g_total -= map_len;
            else g_total = 0;
            seen = 1;
        }
        g_sp[i].live = 0;
    }
}

void tw_vmem_reset(void)
{
    for (size_t i = 0; i < TW_VMEM_MAX; i++) {
        if (!g_sp[i].live) continue;
        uint64_t b = g_sp[i].map_base;
        size_t n = g_sp[i].map_len;
        drop_map(b, n);
    }
    g_total = 0;
}

static struct span *slot_new(void)
{
    for (size_t i = 0; i < TW_VMEM_MAX; i++)
        if (!g_sp[i].live) return &g_sp[i];
    return NULL;
}

static int free_slots(void)
{
    int n = 0;
    for (size_t i = 0; i < TW_VMEM_MAX; i++)
        if (!g_sp[i].live) n++;
    return n;
}

int tw_vmem_check(uint64_t addr, uint64_t len, int prot)
{
    if (len == 0) return 1;
    uint64_t end;
    if (add_ovf(addr, len, &end)) return 0;
    for (size_t i = 0; i < TW_VMEM_MAX; i++) {
        const struct span *s = &g_sp[i];
        if (!s->live) continue;
        if (addr >= s->user_base && end <= s->user_end && (s->prot & prot) == prot)
            return 1;
    }
    return 0;
}

int tw_vmem_query(uint64_t addr, struct tw_vmem_info *out)
{
    if (!out) return 0;
    for (size_t i = 0; i < TW_VMEM_MAX; i++) {
        const struct span *s = &g_sp[i];
        if (!s->live) continue;
        if (addr >= s->user_base && addr < s->user_end) {
            out->base = s->user_base;
            out->end = s->user_end;
            out->alloc_base = s->alloc_base;
            out->user_size = s->user_size;
            out->prot = s->prot;
            out->win_protect = s->win_protect;
            out->alloc_protect = s->alloc_protect;
            out->kind = s->kind;
            return 1;
        }
    }
    return 0;
}

int tw_vmem_find_base(uint64_t addr, int kind, struct tw_vmem_info *out)
{
    if (!out) return 0;
    for (size_t i = 0; i < TW_VMEM_MAX; i++) {
        const struct span *s = &g_sp[i];
        if (!s->live || s->kind != kind || s->alloc_base != addr) continue;
        out->base = s->user_base;
        out->end = s->user_end;
        out->alloc_base = s->alloc_base;
        out->user_size = s->user_size;
        out->prot = s->prot;
        out->win_protect = s->win_protect;
        out->alloc_protect = s->alloc_protect;
        out->kind = s->kind;
        return 1;
    }
    return 0;
}

void *tw_vmem_map(size_t user_size, size_t user_off, int prot, uint32_t win_protect, int kind)
{
    if (user_size > TW_VMEM_MAX_ONE) return NULL;
    size_t pg = host_page();
    if (user_off % pg) return NULL;
    size_t commit = round_up(user_size ? user_size : 1, pg);
    if (!commit || user_off > SIZE_MAX - commit) return NULL;
    size_t total = user_off + commit;
    if (total > TW_VMEM_MAX_TOTAL || g_total > TW_VMEM_MAX_TOTAL - total) return NULL;
    struct span *s = slot_new();
    if (!s) return NULL;

    void *p = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if (user_off && mprotect(p, user_off, PROT_NONE) != 0) {
        munmap(p, total);
        return NULL;
    }
    uint8_t *user = (uint8_t *)p + user_off;
    if (prot != (PROT_READ | PROT_WRITE)) {
        if (mprotect(user, commit, prot) != 0) {
            munmap(p, total);
            return NULL;
        }
    }

    uint64_t ub = (uint64_t)(uintptr_t)user;
    s->live = 1;
    s->kind = kind;
    s->map_base = (uint64_t)(uintptr_t)p;
    s->map_len = total;
    s->user_base = ub;
    s->alloc_base = ub;
    s->user_size = user_size;
    /* VirtualAlloc exposes the committed pages. Heap and blobs expose the
     * requested size so an API cannot be talked into reading past the object
     * into the rest of the page. */
    s->user_end = ub + (kind == TW_VM_ALLOC ? (uint64_t)commit : (uint64_t)user_size);
    s->prot = prot;
    s->win_protect = win_protect;
    s->alloc_protect = win_protect;
    g_total += total;
    return user;
}

void *tw_vmem_blob(size_t bytes)
{
    if (bytes == 0) bytes = 1;
    return tw_vmem_map(bytes, 0, PROT_READ | PROT_WRITE, 0x04u, TW_VM_BLOB);
}

int tw_vmem_protect(uint64_t addr, uint64_t len, int prot, uint32_t win_protect)
{
    size_t pg = host_page();
    if (len == 0 || (addr % pg) != 0) return -1;
    size_t rounded = round_up((size_t)len, pg);
    if (!rounded || (uint64_t)rounded != rounded) return -1;
    if ((uint64_t)rounded < len) return -1;
    uint64_t end;
    if (add_ovf(addr, (uint64_t)rounded, &end)) return -1;

    struct span *s = NULL;
    for (size_t i = 0; i < TW_VMEM_MAX; i++) {
        if (!g_sp[i].live || g_sp[i].kind != TW_VM_ALLOC) continue;
        if (addr >= g_sp[i].user_base && end <= g_sp[i].user_end) {
            s = &g_sp[i];
            break;
        }
    }
    if (!s) return -1;

    int extra = 0;
    if (addr > s->user_base) extra++;
    if (end < s->user_end) extra++;
    if (free_slots() < extra) return -1;

    if (mprotect((void *)(uintptr_t)addr, rounded, prot) != 0) return -1;

    uint64_t old_base = s->user_base;
    uint64_t old_end = s->user_end;
    int old_prot = s->prot;
    uint32_t old_win = s->win_protect;
    size_t old_usize = s->user_size;

    s->user_base = addr;
    s->user_end = end;
    s->user_size = (size_t)(end - addr);
    s->prot = prot;
    s->win_protect = win_protect;

    if (old_base < addr) {
        struct span *l = slot_new();
        *l = *s;
        l->user_base = old_base;
        l->user_end = addr;
        l->user_size = (size_t)(addr - old_base);
        l->prot = old_prot;
        l->win_protect = old_win;
        l->live = 1;
    }
    if (end < old_end) {
        struct span *r = slot_new();
        *r = *s;
        r->user_base = end;
        r->user_end = old_end;
        r->user_size = (size_t)(old_end - end);
        r->prot = old_prot;
        r->win_protect = old_win;
        r->live = 1;
    }
    (void)old_usize;
    return 0;
}

int tw_vmem_unmap(uint64_t addr, int kind)
{
    for (size_t i = 0; i < TW_VMEM_MAX; i++) {
        if (!g_sp[i].live || g_sp[i].kind != kind) continue;
        if (g_sp[i].alloc_base != addr) continue;
        drop_map(g_sp[i].map_base, g_sp[i].map_len);
        return 0;
    }
    return -1;
}

int tw_vmem_heap_resize(uint64_t addr, size_t new_size)
{
    for (size_t i = 0; i < TW_VMEM_MAX; i++) {
        struct span *s = &g_sp[i];
        if (!s->live || s->kind != TW_VM_HEAP || s->alloc_base != addr) continue;
        if (s->user_base < s->map_base) return -1;
        size_t off = (size_t)(s->user_base - s->map_base);
        if (off > s->map_len) return -1;
        size_t cap = s->map_len - off;
        if (new_size > cap) return -1;
        s->user_size = new_size;
        s->user_end = s->user_base + new_size;
        return 0;
    }
    return -1;
}
