#ifndef TWEAKWIN_PE_H
#define TWEAKWIN_PE_H

/*
 * TweakWin PE/COFF parser (Milestone 0).
 *
 * Parses Windows PE32+ images from an in-memory buffer. Every read is
 * bounds-checked against the buffer; nothing is mapped or executed.
 * Written from the published Microsoft PE/COFF specification only
 * (see docs/CLEANROOM.md).
 */

#include <stddef.h>
#include <stdint.h>

/* ---- well-known constants (PE/COFF spec) ---- */

#define TW_PE_MACHINE_UNKNOWN 0x0000
#define TW_PE_MACHINE_I386    0x014c
#define TW_PE_MACHINE_ARMNT   0x01c4
#define TW_PE_MACHINE_IA64    0x0200
#define TW_PE_MACHINE_AMD64   0x8664
#define TW_PE_MACHINE_ARM64EC 0xa641
#define TW_PE_MACHINE_ARM64   0xaa64

#define TW_PE_OPT_MAGIC_PE32     0x010b
#define TW_PE_OPT_MAGIC_PE32PLUS 0x020b
#define TW_PE_OPT_MAGIC_ROM      0x0107

#define TW_PE_FILE_RELOCS_STRIPPED    0x0001
#define TW_PE_FILE_EXECUTABLE_IMAGE   0x0002
#define TW_PE_FILE_LARGE_ADDRESS_AWARE 0x0020
#define TW_PE_FILE_SYSTEM             0x1000
#define TW_PE_FILE_DLL                0x2000

#define TW_PE_SCN_CNT_CODE           0x00000020u
#define TW_PE_SCN_CNT_INIT_DATA      0x00000040u
#define TW_PE_SCN_CNT_UNINIT_DATA    0x00000080u
#define TW_PE_SCN_MEM_DISCARDABLE    0x02000000u
#define TW_PE_SCN_MEM_SHARED         0x10000000u
#define TW_PE_SCN_MEM_EXECUTE        0x20000000u
#define TW_PE_SCN_MEM_READ           0x40000000u
#define TW_PE_SCN_MEM_WRITE          0x80000000u

enum tw_pe_dir_index {
    TW_PE_DIR_EXPORT = 0,
    TW_PE_DIR_IMPORT = 1,
    TW_PE_DIR_RESOURCE = 2,
    TW_PE_DIR_EXCEPTION = 3,
    TW_PE_DIR_SECURITY = 4,      /* file offset, not an RVA */
    TW_PE_DIR_BASERELOC = 5,
    TW_PE_DIR_DEBUG = 6,
    TW_PE_DIR_ARCHITECTURE = 7,
    TW_PE_DIR_GLOBALPTR = 8,
    TW_PE_DIR_TLS = 9,
    TW_PE_DIR_LOAD_CONFIG = 10,
    TW_PE_DIR_BOUND_IMPORT = 11,
    TW_PE_DIR_IAT = 12,
    TW_PE_DIR_DELAY_IMPORT = 13,
    TW_PE_DIR_CLR_RUNTIME = 14,
    TW_PE_DIR_RESERVED = 15,
    TW_PE_DIR_COUNT = 16
};

#define TW_PE_REL_ABSOLUTE 0
#define TW_PE_REL_HIGH     1
#define TW_PE_REL_LOW      2
#define TW_PE_REL_HIGHLOW  3
#define TW_PE_REL_HIGHADJ  4
#define TW_PE_REL_DIR64    10

/* ---- hard limits (defensive caps, documented in docs/PE-LIMITS.md) ---- */

#define TW_PE_MAX_FILE_SIZE     (1ull << 31)  /* 2 GiB */
#define TW_PE_MAX_SECTIONS      96
#define TW_PE_MAX_IMPORT_DLLS   4096
#define TW_PE_MAX_THUNKS_TOTAL  1000000
#define TW_PE_MAX_EXPORTS       65536
#define TW_PE_MAX_TLS_CALLBACKS 1024
#define TW_PE_MAX_RUNTIME_FUNCS (1u << 22)
#define TW_PE_MAX_RSRC_DEPTH    8
#define TW_PE_MAX_RSRC_NODES    100000
#define TW_PE_MAX_WARNINGS      64
#define TW_PE_MAX_NAME          4096

/* ---- result/error ---- */

typedef enum {
    TW_PE_OK = 0,
    TW_PE_ERR_IO,           /* could not read the file */
    TW_PE_ERR_NOMEM,
    TW_PE_ERR_MALFORMED,    /* structurally invalid; rejected */
    TW_PE_ERR_UNSUPPORTED,  /* valid PE, but not a v0.1 target (e.g. i386, ARM64) */
} tw_pe_status;

typedef struct {
    tw_pe_status status;
    uint64_t offset;        /* file offset or RVA the problem relates to, if known */
    int offset_is_rva;
    int has_offset;
    char msg[256];
} tw_pe_error;

/* ---- parsed structures ---- */

typedef struct {
    uint32_t rva;
    uint32_t size;
} tw_pe_datadir;

typedef struct {
    char name[9];           /* NUL-terminated, raw 8-byte name */
    const char *long_name;  /* resolved "/NNN" string-table name, or NULL */
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t raw_ptr;
    uint32_t characteristics;
} tw_pe_section;

typedef struct {
    const char *name;       /* NULL when imported by ordinal */
    uint16_t hint;
    uint16_t ordinal;       /* valid when by_ordinal */
    int by_ordinal;
    uint32_t iat_rva;       /* RVA of this function's IAT slot (0 if unknown) */
} tw_pe_import_fn;

typedef struct {
    const char *dll;
    tw_pe_import_fn *fns;
    size_t nfns;
    uint32_t iat_rva;
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    int delayed;            /* came from the delay-load directory */
} tw_pe_import_dll;

typedef struct {
    uint32_t ordinal;
    uint32_t rva;           /* 0 if forwarder */
    const char *name;       /* NULL = exported by ordinal only */
    const char *forwarder;  /* "DLL.Func" or "DLL.#123", NULL if not forwarded */
} tw_pe_export;

typedef struct {
    int present;
    const char *dll_name;
    uint32_t ordinal_base;
    uint32_t nfunctions;
    uint32_t nnames;
    tw_pe_export *entries;
    size_t nentries;
} tw_pe_exports;

typedef struct {
    int present;
    size_t nblocks;
    size_t nentries;
    size_t by_type[16];
} tw_pe_relocs;

typedef struct {
    int present;
    uint64_t raw_start_va;
    uint64_t raw_end_va;
    uint64_t index_va;
    uint64_t callbacks_va;
    uint32_t zero_fill;
    uint32_t characteristics;
    uint64_t *callbacks;    /* VAs */
    size_t ncallbacks;
} tw_pe_tls;

typedef struct {
    int present;
    size_t count;           /* RUNTIME_FUNCTION entries */
    size_t invalid_ranges;
    size_t bad_unwind_version;
    int sorted;
} tw_pe_exceptions;

typedef struct {
    uint32_t id;            /* valid when name == NULL */
    const char *name;       /* escaped ASCII rendering of a UTF-16 name */
    size_t leaves;          /* data entries under this type */
} tw_pe_rsrc_type;

typedef struct {
    int present;
    tw_pe_rsrc_type *types;
    size_t ntypes;
    size_t total_leaves;
} tw_pe_resources;

struct tw_arena;

typedef struct {
    const uint8_t *data;
    size_t size;
    uint8_t *owned;         /* non-NULL when loaded via tw_pe_load_file */

    uint32_t e_lfanew;

    /* COFF header */
    uint16_t machine;
    uint16_t nsections;
    uint32_t time_date_stamp;
    uint32_t symtab_ptr;
    uint32_t nsymbols;
    uint16_t opt_header_size;
    uint16_t characteristics;

    /* optional header (PE32+) */
    uint16_t opt_magic;
    uint8_t linker_major, linker_minor;
    uint32_t size_of_code;
    uint32_t entry_rva;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t os_major, os_minor;
    uint16_t subsystem_major, subsystem_minor;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t stack_reserve, stack_commit;
    uint64_t heap_reserve, heap_commit;
    uint32_t ndirs;
    tw_pe_datadir dirs[TW_PE_DIR_COUNT];

    tw_pe_section *sections;

    tw_pe_import_dll *imports;
    size_t nimports;

    tw_pe_exports exports;
    tw_pe_relocs relocs;
    tw_pe_tls tls;
    tw_pe_exceptions exceptions;
    tw_pe_resources resources;

    uint64_t overlay_offset;
    uint64_t overlay_size;

    const char **warnings;
    size_t nwarnings;
    size_t warnings_dropped;

    struct tw_arena *arena;
} tw_pe_image;

/* Parse an in-memory image. `data` must outlive `img`. */
tw_pe_status tw_pe_parse(const uint8_t *data, size_t size, tw_pe_image *img, tw_pe_error *err);

/* Read a file fully and parse it. The image owns the buffer. */
tw_pe_status tw_pe_load_file(const char *path, tw_pe_image *img, tw_pe_error *err);

void tw_pe_free(tw_pe_image *img);

/* ---- helpers ---- */

/* Copy `len` bytes at `rva` (zero-filling past raw data inside a section).
   Returns 1 on success, 0 if the range is not inside the headers or one section. */
int tw_pe_read_rva(const tw_pe_image *img, uint32_t rva, void *out, uint32_t len);

/* Index of the section containing `rva`, or -1. */
int tw_pe_section_for_rva(const tw_pe_image *img, uint32_t rva);

int tw_pe_is_dll(const tw_pe_image *img);

const char *tw_pe_machine_name(uint16_t machine);
const char *tw_pe_subsystem_name(uint16_t subsystem);
const char *tw_pe_dir_name(unsigned index);
const char *tw_pe_reloc_type_name(unsigned type);
const char *tw_pe_rsrc_type_name(uint32_t id);   /* NULL if not a standard RT_* id */
const char *tw_pe_status_name(tw_pe_status st);

#endif
