#ifndef TWEAKWIN_VMEM_H
#define TWEAKWIN_VMEM_H

/*
 * Guest-visible allocations that are not part of the PE image: VirtualAlloc
 * regions, heap blocks, and dedicated pages that hold the command line or
 * an environment-block copy. Host malloc memory is never registered here.
 */

#include <stddef.h>
#include <stdint.h>

enum tw_vmem_kind {
    TW_VM_ALLOC = 1,
    TW_VM_HEAP = 2,
    TW_VM_BLOB = 3
};

void tw_vmem_reset(void);

/* True if [addr, addr+len) sits in one span with every bit in `prot`. */
int tw_vmem_check(uint64_t addr, uint64_t len, int prot);

struct tw_vmem_info {
    uint64_t base;
    uint64_t end;
    uint64_t alloc_base;
    size_t user_size;
    int prot;
    uint32_t win_protect;
    uint32_t alloc_protect;
    int kind;
};

int tw_vmem_query(uint64_t addr, struct tw_vmem_info *out);

/* Like query, but matches the allocation base even when the visible size is 0. */
int tw_vmem_find_base(uint64_t addr, int kind, struct tw_vmem_info *out);

/*
 * Page-rounded anonymous mapping. `user_off` is the guest-visible start
 * within the mapping (heap header lives before it). Returns the user
 * pointer, or NULL.
 */
void *tw_vmem_map(size_t user_size, size_t user_off, int prot, uint32_t win_protect,
                  int kind);

int tw_vmem_protect(uint64_t addr, uint64_t len, int prot, uint32_t win_protect);
int tw_vmem_unmap(uint64_t addr, int kind);
void *tw_vmem_blob(size_t bytes);

/* Change the visible size of a heap block without moving it.
 * Fails if new_size exceeds the committed pages. */
int tw_vmem_heap_resize(uint64_t addr, size_t new_size);

#endif
