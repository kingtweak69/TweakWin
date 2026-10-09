/*
 * Thread-safe guest-memory allocator over the backend VM. Every rt/
 * structure (TEB, PEB, process parameters, TLS blocks, thread stacks) and
 * the guest-pointer validator for them live here. Because it is all one
 * backend VM, the same allocations work on the host and on TweakKernel M4,
 * are page-protected, and are seen by tw_rt_guest_check.
 */
#include "rt.h"

#include "../backend/kb.h"

#include <pthread.h>
#include <string.h>
#include <sys/mman.h>

#define RT_MEM_MAX 512

struct rt_span {
    int live;
    uint64_t base;
    uint64_t size; /* reserved/committed bytes (page-rounded) */
};

static struct rt_span g_spans[RT_MEM_MAX];
static pthread_mutex_t g_mem_mu = PTHREAD_MUTEX_INITIALIZER;

static uint64_t page_round(uint64_t v)
{
    return (v + 4095ull) & ~4095ull;
}

uint64_t rt_galloc_prot(size_t size, uint32_t kb_prot)
{
    if (size == 0) size = 1;
    uint64_t want = page_round(size);
    pthread_mutex_lock(&g_mem_mu);
    int slot = -1;
    for (int i = 0; i < RT_MEM_MAX; i++) {
        if (!g_spans[i].live) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&g_mem_mu);
        return 0;
    }
    int64_t base = tw_kb_vm_reserve(0, want, kb_prot, TW_KB_VM_COMMIT);
    if (base <= 0) {
        pthread_mutex_unlock(&g_mem_mu);
        return 0;
    }
    g_spans[slot].live = 1;
    g_spans[slot].base = (uint64_t)base;
    g_spans[slot].size = want;
    pthread_mutex_unlock(&g_mem_mu);
    return (uint64_t)base;
}

uint64_t rt_galloc(size_t size)
{
    uint64_t b = rt_galloc_prot(size, TW_KB_PROT_RW);
    if (b) memset((void *)(uintptr_t)b, 0, page_round(size ? size : 1));
    return b;
}

int rt_gprotect(uint64_t base, size_t size, uint32_t kb_prot)
{
    return tw_kb_vm_protect(base, page_round(size), kb_prot) < 0 ? -1 : 0;
}

void rt_gfree(uint64_t base)
{
    pthread_mutex_lock(&g_mem_mu);
    for (int i = 0; i < RT_MEM_MAX; i++) {
        if (g_spans[i].live && g_spans[i].base == base) {
            g_spans[i].live = 0;
            tw_kb_vm_release(base);
            break;
        }
    }
    pthread_mutex_unlock(&g_mem_mu);
}

void tw_rt_mem_reset(void);
void tw_rt_mem_reset(void)
{
    pthread_mutex_lock(&g_mem_mu);
    for (int i = 0; i < RT_MEM_MAX; i++) {
        if (g_spans[i].live) {
            tw_kb_vm_release(g_spans[i].base);
            g_spans[i].live = 0;
        }
    }
    pthread_mutex_unlock(&g_mem_mu);
}

int tw_rt_guest_check(uint64_t addr, uint64_t len, int need)
{
    if (len == 0) return 1;
    uint64_t end;
    if (__builtin_add_overflow(addr, len, &end)) return 0;

    /* Fast path: is it inside a known rt span? (All rt spans are RW.) */
    pthread_mutex_lock(&g_mem_mu);
    int inside = 0;
    for (int i = 0; i < RT_MEM_MAX; i++) {
        if (g_spans[i].live && addr >= g_spans[i].base && end <= g_spans[i].base + g_spans[i].size) {
            inside = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_mem_mu);
    if (!inside) return 0;

    /* Confirm the whole span is committed with the required protection by
     * walking the backend VM (handles later VirtualProtect splits). */
    uint32_t want = TW_KB_PROT_R;
    if (need & PROT_WRITE) want = TW_KB_PROT_RW;
    uint64_t p = addr;
    while (p < end) {
        tw_kb_vminfo vi;
        if (tw_kb_vm_query(p, &vi) != 0) return 0;
        if (vi.state != TW_KB_VM_COMMITTED) return 0;
        if ((want & TW_KB_PROT_R) && !(vi.prot & TW_KB_PROT_R)) return 0;
        if ((want & 0x2u) && !(vi.prot & 0x2u)) return 0;
        uint64_t next = vi.base + vi.size;
        if (next <= p) return 0;
        p = next;
    }
    return 1;
}
