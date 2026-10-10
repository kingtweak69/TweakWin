#ifndef TWEAKWIN_LOAD_H
#define TWEAKWIN_LOAD_H

/*
 * PE32+ loader (Milestone 1).
 *
 * Parses with the M0 PE layer, maps SizeOfImage, copies sections, applies
 * IMAGE_REL_BASED_DIR64 relocations, patches the IAT through the module
 * registry, then applies final W^X-friendly protections.
 */

#include "../loader/pe/pe.h"

#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>

enum tw_base_policy {
    TW_BASE_PREFER = 0,          /* try ImageBase, else relocate */
    TW_BASE_FORCE_PREFERRED = 1, /* fail if ImageBase is unavailable */
    TW_BASE_FORCE_RELOCATE = 2   /* never map at ImageBase */
};

typedef enum {
    TW_LOAD_OK = 0,
    TW_LOAD_ERR_IO,
    TW_LOAD_ERR_NOMEM,
    TW_LOAD_ERR_MALFORMED,
    TW_LOAD_ERR_UNSUPPORTED,
    TW_LOAD_ERR_MAP,
    TW_LOAD_ERR_RELOC,
    TW_LOAD_ERR_UNRESOLVED_DLL,
    TW_LOAD_ERR_UNRESOLVED_SYMBOL,
    TW_LOAD_ERR_ENTRY,
    TW_LOAD_ERR_RUNTIME
} tw_load_status;

#define TW_MAX_REGIONS (TW_PE_MAX_SECTIONS + 4)

typedef struct {
    uint64_t start; /* inclusive VA */
    uint64_t end;   /* exclusive VA */
    int prot;       /* PROT_READ / PROT_WRITE / PROT_EXEC bits */
} tw_region;

typedef struct tw_loaded {
    tw_pe_image pe;

    uint8_t *map_ptr;   /* pointer passed to munmap */
    size_t map_len;
    uint8_t *image;     /* SizeOfImage view at `base` */
    uint32_t image_size;

    uint64_t base;
    uint64_t preferred;
    int64_t delta;

    uint8_t *stack;     /* usable stack (guard page not included) */
    size_t stack_len;
    uint8_t *stack_map; /* munmap pointer (includes guard page) */
    size_t stack_map_len;

    tw_region regions[TW_MAX_REGIONS];
    size_t nregions;

    jmp_buf exit_jmp;
    volatile uint32_t guest_exit;
    volatile int did_exit;

    /* Host stack recorded while the guest runs, so ASan can switch back. */
    void *asan_fake_stack;
    const void *host_stack_bottom;
    size_t host_stack_size;

    int is_dll;         /* mapped by tw_load_dll: no stack, no ExitProcess */
    void *mod_owner;    /* modules.c record that owns this image (DLLs) */

    tw_load_status status;
    char err[256];
} tw_loaded;

tw_load_status tw_load(const char *path, int base_policy, tw_loaded *out, tw_pe_error *perr);
void tw_unload(tw_loaded *im);

/*
 * Map a PE32+ DLL through the same parser/mapper as tw_load: sections,
 * relocations, imports (resolved through the module registry, which loads
 * dependencies), then W^X protections. No stack is created and the entry
 * point is not run; modules.c owns the DllMain lifecycle.
 */
tw_load_status tw_load_dll(const char *path, int base_policy, tw_loaded *out, tw_pe_error *perr);
void tw_unload_dll(tw_loaded *im);

/* Jump to AddressOfEntryPoint. On TW_LOAD_OK, *guest_exit is ExitProcess's code. */
tw_load_status tw_execute(tw_loaded *im, uint32_t *guest_exit);

/* longjmp back to tw_execute. Called from ExitProcess and from a guest RET. */
void tw_guest_exit_longjmp(tw_loaded *im) __attribute__((noreturn));

const char *tw_load_status_name(tw_load_status st);

/* Guest-pointer checks used by the Win32 implementations. */
int tw_guest_readable(const tw_loaded *im, uint64_t addr, uint64_t len);
int tw_guest_writable(const tw_loaded *im, uint64_t addr, uint64_t len);

tw_loaded *tw_current_process(void);

#endif
