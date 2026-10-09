#include "k32priv.h"

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int page_prot(TW_DWORD fl, int *prot)
{
    switch (fl) {
    case TW_PAGE_NOACCESS:     *prot = PROT_NONE; return 0;
    case TW_PAGE_READONLY:     *prot = PROT_READ; return 0;
    case TW_PAGE_READWRITE:    *prot = PROT_READ | PROT_WRITE; return 0;
    case TW_PAGE_EXECUTE:      *prot = PROT_EXEC; return 0;
    case TW_PAGE_EXECUTE_READ: *prot = PROT_READ | PROT_EXEC; return 0;
    default:
        /* PAGE_EXECUTE_READWRITE and anything else: refused, including W+X. */
        return -1;
    }
}

static TW_DWORD prot_page(int prot)
{
    int x = (prot & PROT_EXEC) != 0;
    int w = (prot & PROT_WRITE) != 0;
    int r = (prot & PROT_READ) != 0;
    if (x && r) return TW_PAGE_EXECUTE_READ;
    if (x) return TW_PAGE_EXECUTE;
    if (w) return TW_PAGE_READWRITE;
    if (r) return TW_PAGE_READONLY;
    return TW_PAGE_NOACCESS;
}

static size_t host_page(void)
{
    long n = sysconf(_SC_PAGESIZE);
    return n > 0 ? (size_t)n : 4096u;
}

void *TW_MS_ABI tw_k32_VirtualAlloc(void *lpAddress, uint64_t dwSize, TW_DWORD flAllocationType,
                                    TW_DWORD flProtect)
{
    if (!tw_runtime_bound()) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (lpAddress) {
        tw_set_last_error(TW_ERROR_INVALID_ADDRESS);
        return NULL;
    }
    if (dwSize == 0 || dwSize > 64ull * 1024ull * 1024ull) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (flAllocationType != (TW_MEM_COMMIT | TW_MEM_RESERVE)) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    int prot = 0;
    if (page_prot(flProtect, &prot) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    void *p = tw_vmem_map((size_t)dwSize, 0, prot, flProtect, TW_VM_ALLOC);
    if (!p) {
        tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    TW_DEBUG(TW_DBG_MEMORY, "VirtualAlloc %p size 0x%llx prot 0x%x", p,
             (unsigned long long)dwSize, flProtect);
    return p;
}

TW_BOOL TW_MS_ABI tw_k32_VirtualFree(void *lpAddress, uint64_t dwSize, TW_DWORD dwFreeType)
{
    if (!tw_runtime_bound() || !lpAddress) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    if (dwFreeType != TW_MEM_RELEASE || dwSize != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    if (tw_vmem_unmap((uint64_t)(uintptr_t)lpAddress, TW_VM_ALLOC) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    return TW_TRUE;
}

TW_BOOL TW_MS_ABI tw_k32_VirtualProtect(void *lpAddress, uint64_t dwSize, TW_DWORD flNewProtect,
                                        TW_DWORD *lpflOldProtect)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!tw_runtime_bound() || !im || !lpAddress || dwSize == 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    if (!lpflOldProtect || !tw_k32_ok_w(lpflOldProtect, sizeof(TW_DWORD))) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return TW_FALSE;
    }
    struct tw_vmem_info info;
    if (!tw_vmem_query((uint64_t)(uintptr_t)lpAddress, &info) || info.kind != TW_VM_ALLOC) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    int prot = 0;
    if (page_prot(flNewProtect, &prot) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    TW_DWORD old = info.win_protect;
    if (tw_vmem_protect((uint64_t)(uintptr_t)lpAddress, dwSize, prot, flNewProtect) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    *lpflOldProtect = old;
    return TW_TRUE;
}

static void put64(uint8_t *b, int off, uint64_t v) { memcpy(b + off, &v, 8); }
static void put32(uint8_t *b, int off, uint32_t v) { memcpy(b + off, &v, 4); }

TW_SIZE_T TW_MS_ABI tw_k32_VirtualQuery(const void *lpAddress, void *lpBuffer, TW_SIZE_T dwLength)
{
    struct tw_loaded *im = tw_k32_guest();
    if (!im || !lpBuffer || dwLength < TW_MBI_SIZE) {
        tw_set_last_error(TW_ERROR_BAD_LENGTH);
        return 0;
    }
    if (!tw_k32_ok_w(lpBuffer, TW_MBI_SIZE)) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return 0;
    }
    uint8_t mbi[TW_MBI_SIZE];
    memset(mbi, 0, sizeof mbi);
    uint64_t addr = (uint64_t)(uintptr_t)lpAddress;
    struct tw_vmem_info info;
    if (tw_vmem_query(addr, &info)) {
        put64(mbi, 0, info.base);
        put64(mbi, 8, info.alloc_base);
        put32(mbi, 16, info.alloc_protect);
        put64(mbi, 24, info.end - info.base);
        put32(mbi, 32, TW_MEM_COMMIT);
        put32(mbi, 36, info.win_protect);
        put32(mbi, 40, TW_MEM_PRIVATE);
    } else {
        int hit = 0;
        if (im) {
            for (size_t i = 0; i < im->nregions; i++) {
                const tw_region *r = &im->regions[i];
                if (addr >= r->start && addr < r->end) {
                    put64(mbi, 0, r->start);
                    put64(mbi, 8, im->base);
                    put32(mbi, 16, prot_page(r->prot));
                    put64(mbi, 24, r->end - r->start);
                    put32(mbi, 32, TW_MEM_COMMIT);
                    put32(mbi, 36, prot_page(r->prot));
                    put32(mbi, 40, addr >= im->base && addr < im->base + im->image_size
                                       ? TW_MEM_IMAGE : TW_MEM_PRIVATE);
                    hit = 1;
                    break;
                }
            }
        }
        if (!hit) {
            size_t pg = host_page();
            uint64_t base = addr & ~((uint64_t)pg - 1);
            put64(mbi, 0, base);
            put64(mbi, 24, pg);
            put32(mbi, 32, TW_MEM_FREE);
            put32(mbi, 36, TW_PAGE_NOACCESS);
        }
    }
    memcpy(lpBuffer, mbi, TW_MBI_SIZE);
    return TW_MBI_SIZE;
}

static int heap_flags_ok(TW_DWORD flags, TW_DWORD allow)
{
    return (flags & ~allow) == 0;
}

TW_HANDLE TW_MS_ABI tw_k32_GetProcessHeap(void)
{
    TW_HANDLE h = tw_runtime_heap();
    if (!tw_runtime_bound() || !h) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return NULL;
    }
    return h;
}

void *TW_MS_ABI tw_k32_HeapAlloc(TW_HANDLE hHeap, TW_DWORD dwFlags, uint64_t dwBytes)
{
    if (!tw_runtime_bound() || !tw_handle_is_heap(hHeap) || hHeap != tw_runtime_heap()) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return NULL;
    }
    if (!heap_flags_ok(dwFlags, TW_HEAP_NO_SERIALIZE | TW_HEAP_ZERO_MEMORY)) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (dwBytes > 64ull * 1024ull * 1024ull) {
        tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    size_t pg = host_page();
    size_t req = (size_t)dwBytes;
    void *p = tw_vmem_map(req ? req : 1, pg, PROT_READ | PROT_WRITE, TW_PAGE_READWRITE, TW_VM_HEAP);
    if (!p) {
        tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    if (req == 0) {
        /* Visible size stays 0; the mapping exists so HeapFree has an address. */
        if (tw_vmem_heap_resize((uint64_t)(uintptr_t)p, 0) != 0) {
            tw_vmem_unmap((uint64_t)(uintptr_t)p, TW_VM_HEAP);
            tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
    } else if (dwFlags & TW_HEAP_ZERO_MEMORY) {
        memset(p, 0, req);
    }
    return p;
}

TW_BOOL TW_MS_ABI tw_k32_HeapFree(TW_HANDLE hHeap, TW_DWORD dwFlags, void *lpMem)
{
    if (!heap_flags_ok(dwFlags, TW_HEAP_NO_SERIALIZE)) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    if (!lpMem) return TW_TRUE;
    if (!tw_runtime_bound() || !tw_handle_is_heap(hHeap) || hHeap != tw_runtime_heap()) {
        tw_set_last_error(TW_ERROR_INVALID_HANDLE);
        return TW_FALSE;
    }
    if (tw_vmem_unmap((uint64_t)(uintptr_t)lpMem, TW_VM_HEAP) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    return TW_TRUE;
}

void *TW_MS_ABI tw_k32_HeapReAlloc(TW_HANDLE hHeap, TW_DWORD dwFlags, void *lpMem, uint64_t dwBytes)
{
    if (!lpMem || !tw_runtime_bound() || !tw_handle_is_heap(hHeap) || hHeap != tw_runtime_heap()) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!heap_flags_ok(dwFlags, TW_HEAP_NO_SERIALIZE | TW_HEAP_ZERO_MEMORY | TW_HEAP_REALLOC_IN_PLACE_ONLY)) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (dwBytes > 64ull * 1024ull * 1024ull) {
        tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    struct tw_vmem_info info;
    if (!tw_vmem_find_base((uint64_t)(uintptr_t)lpMem, TW_VM_HEAP, &info)) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    size_t old = info.user_size;
    size_t want = (size_t)dwBytes;
    if (tw_vmem_heap_resize((uint64_t)(uintptr_t)lpMem, want) == 0) {
        if (want > old && (dwFlags & TW_HEAP_ZERO_MEMORY))
            memset((uint8_t *)lpMem + old, 0, want - old);
        return lpMem;
    }
    if (dwFlags & TW_HEAP_REALLOC_IN_PLACE_ONLY) {
        tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    void *n = tw_k32_HeapAlloc(hHeap, dwFlags & ~TW_HEAP_REALLOC_IN_PLACE_ONLY, dwBytes);
    if (!n) return NULL;
    size_t copy = old < want ? old : want;
    if (copy) memcpy(n, lpMem, copy);
    tw_vmem_unmap((uint64_t)(uintptr_t)lpMem, TW_VM_HEAP);
    return n;
}

uint64_t TW_MS_ABI tw_k32_HeapSize(TW_HANDLE hHeap, TW_DWORD dwFlags, const void *lpMem)
{
    if (!heap_flags_ok(dwFlags, TW_HEAP_NO_SERIALIZE) || !lpMem ||
        !tw_runtime_bound() || !tw_handle_is_heap(hHeap)) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return ~(uint64_t)0;
    }
    struct tw_vmem_info info;
    if (!tw_vmem_find_base((uint64_t)(uintptr_t)lpMem, TW_VM_HEAP, &info)) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return ~(uint64_t)0;
    }
    return info.user_size;
}
