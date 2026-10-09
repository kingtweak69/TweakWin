#include "cli.h"

#include "../loader/pe/pe.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/* Print untrusted strings from the binary without letting them emit
   terminal control sequences. */
static void put_safe(const char *s)
{
    if (!s) { fputs("(null)", stdout); return; }
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p >= 0x20 && *p < 0x7f)
            putchar(*p);
        else
            printf("\\x%02x", *p);
    }
}

static void put_section_name(const tw_pe_section *s)
{
    put_safe(s->long_name ? s->long_name : s->name);
}

static const char *format_name(uint16_t magic)
{
    switch (magic) {
    case TW_PE_OPT_MAGIC_PE32PLUS: return "PE32+";
    case TW_PE_OPT_MAGIC_PE32:     return "PE32";
    case TW_PE_OPT_MAGIC_ROM:      return "ROM";
    default:                       return NULL;
    }
}

typedef struct { uint32_t bit; const char *name; } flag_name;

static void print_flags(uint32_t v, const flag_name *tab, size_t n)
{
    int any = 0;
    for (size_t i = 0; i < n; i++) {
        if (v & tab[i].bit) {
            printf("%s%s", any ? " " : "", tab[i].name);
            any = 1;
            v &= ~tab[i].bit;
        }
    }
    if (v) printf("%s0x%x", any ? " " : "", v);
    else if (!any) printf("none");
}

static void print_dll_chars(uint16_t v)
{
    static const flag_name tab[] = {
        { 0x0020, "HIGH_ENTROPY_VA" }, { 0x0040, "DYNAMIC_BASE" }, { 0x0080, "FORCE_INTEGRITY" },
        { 0x0100, "NX_COMPAT" }, { 0x0200, "NO_ISOLATION" }, { 0x0400, "NO_SEH" },
        { 0x0800, "NO_BIND" }, { 0x1000, "APPCONTAINER" }, { 0x2000, "WDM_DRIVER" },
        { 0x4000, "GUARD_CF" }, { 0x8000, "TERMINAL_SERVER_AWARE" },
    };
    print_flags(v, tab, sizeof(tab) / sizeof(tab[0]));
}

static void print_file_chars(uint16_t v)
{
    static const flag_name tab[] = {
        { 0x0001, "RELOCS_STRIPPED" }, { 0x0002, "EXECUTABLE_IMAGE" }, { 0x0004, "LINE_NUMS_STRIPPED" },
        { 0x0008, "LOCAL_SYMS_STRIPPED" }, { 0x0020, "LARGE_ADDRESS_AWARE" }, { 0x0100, "32BIT_MACHINE" },
        { 0x0200, "DEBUG_STRIPPED" }, { 0x0400, "REMOVABLE_RUN_FROM_SWAP" }, { 0x0800, "NET_RUN_FROM_SWAP" },
        { 0x1000, "SYSTEM" }, { 0x2000, "DLL" }, { 0x4000, "UP_SYSTEM_ONLY" },
    };
    print_flags(v, tab, sizeof(tab) / sizeof(tab[0]));
}

static void perms(uint32_t ch, char out[4])
{
    out[0] = (ch & TW_PE_SCN_MEM_READ) ? 'R' : '-';
    out[1] = (ch & TW_PE_SCN_MEM_WRITE) ? 'W' : '-';
    out[2] = (ch & TW_PE_SCN_MEM_EXECUTE) ? 'X' : '-';
    out[3] = '\0';
}

static void print_image(const char *path, const tw_pe_image *im)
{
    printf("TweakWin PE Inspector\n");
    printf("File: "); put_safe(path); putchar('\n');
    printf("Architecture: %s\n", tw_pe_machine_name(im->machine));
    printf("Format: PE32+\n");
    printf("Type: %s\n", tw_pe_is_dll(im) ? "DLL" : "Executable");
    printf("Subsystem: %s\n", tw_pe_subsystem_name(im->subsystem));
    printf("Image base: 0x%" PRIx64 "\n", im->image_base);
    if (im->entry_rva)
        printf("Entry point: 0x%" PRIx64 " (RVA 0x%x)\n", im->image_base + im->entry_rva, im->entry_rva);
    else
        printf("Entry point: none\n");
    printf("Image size: 0x%x\n", im->size_of_image);
    printf("Headers size: 0x%x\n", im->size_of_headers);
    printf("Alignment: section 0x%x, file 0x%x\n", im->section_alignment, im->file_alignment);
    printf("Linker: %u.%u\n", im->linker_major, im->linker_minor);
    printf("OS version: %u.%u, subsystem version: %u.%u\n",
           im->os_major, im->os_minor, im->subsystem_major, im->subsystem_minor);
    printf("Stack: reserve 0x%" PRIx64 ", commit 0x%" PRIx64 "\n", im->stack_reserve, im->stack_commit);
    printf("Heap: reserve 0x%" PRIx64 ", commit 0x%" PRIx64 "\n", im->heap_reserve, im->heap_commit);
    printf("File characteristics: "); print_file_chars(im->characteristics); putchar('\n');
    printf("DLL characteristics: "); print_dll_chars(im->dll_characteristics); putchar('\n');

    printf("Sections:\n");
    if (!im->nsections) printf("  (none)\n");
    for (uint16_t i = 0; i < im->nsections; i++) {
        const tw_pe_section *s = &im->sections[i];
        char p[4];
        perms(s->characteristics, p);
        printf("  ");
        put_section_name(s);
        int pad = 10 - (int)strlen(s->long_name ? s->long_name : s->name);
        printf("%*s %s  VA 0x%08x  vsize 0x%08x  raw 0x%08x+0x%08x\n",
               pad > 0 ? pad : 0, "", p, s->virtual_address, s->virtual_size, s->raw_ptr, s->raw_size);
    }

    printf("Data directories:\n");
    int anydir = 0;
    for (uint32_t i = 0; i < im->ndirs; i++) {
        if (!im->dirs[i].rva && !im->dirs[i].size) continue;
        anydir = 1;
        printf("  %-13s %s 0x%08x  size 0x%x\n", tw_pe_dir_name(i),
               i == TW_PE_DIR_SECURITY ? "off" : "RVA", im->dirs[i].rva, im->dirs[i].size);
    }
    if (!anydir) printf("  (none)\n");

    int have_normal = 0, have_delay = 0;
    for (size_t i = 0; i < im->nimports; i++) {
        if (im->imports[i].delayed) have_delay = 1; else have_normal = 1;
    }
    for (int pass = 0; pass < 2; pass++) {
        if (pass == 0) printf("Imports:\n");
        else if (have_delay) printf("Delay imports:\n");
        else break;
        if (pass == 0 && !have_normal) printf("  (none)\n");
        for (size_t i = 0; i < im->nimports; i++) {
            const tw_pe_import_dll *d = &im->imports[i];
            if (d->delayed != pass) continue;
            printf("  "); put_safe(d->dll); putchar('\n');
            for (size_t j = 0; j < d->nfns; j++) {
                const tw_pe_import_fn *f = &d->fns[j];
                printf("    ");
                if (f->by_ordinal) printf("#%u", f->ordinal);
                else put_safe(f->name);
                putchar('\n');
            }
        }
    }

    if (im->exports.present) {
        const tw_pe_exports *ex = &im->exports;
        printf("Exports: ");
        put_safe(ex->dll_name ? ex->dll_name : "(unnamed)");
        printf(" (%zu entr%s, ordinal base %u)\n", ex->nentries, ex->nentries == 1 ? "y" : "ies", ex->ordinal_base);
        for (size_t i = 0; i < ex->nentries; i++) {
            const tw_pe_export *e = &ex->entries[i];
            printf("  #%-5u ", e->ordinal);
            if (e->name) put_safe(e->name); else printf("(by ordinal)");
            if (e->forwarder) { printf(" -> "); put_safe(e->forwarder); }
            else printf(" @ RVA 0x%x", e->rva);
            putchar('\n');
        }
    }

    if (im->relocs.present) {
        printf("Relocations: %zu block%s, %zu entr%s (", im->relocs.nblocks, im->relocs.nblocks == 1 ? "" : "s",
               im->relocs.nentries, im->relocs.nentries == 1 ? "y" : "ies");
        int first = 1;
        for (unsigned t = 0; t < 16; t++) {
            if (!im->relocs.by_type[t]) continue;
            const char *n = tw_pe_reloc_type_name(t);
            printf("%s%s %zu", first ? "" : ", ", n ? n : "?", im->relocs.by_type[t]);
            first = 0;
        }
        printf(")\n");
    } else {
        printf("Relocations: none%s\n", (im->characteristics & TW_PE_FILE_RELOCS_STRIPPED) ? " (stripped; fixed base)" : "");
    }

    if (im->tls.present) {
        printf("TLS: data 0x%" PRIx64 "-0x%" PRIx64 ", zero-fill 0x%x, index @ 0x%" PRIx64 ", %zu callback%s\n",
               im->tls.raw_start_va, im->tls.raw_end_va, im->tls.zero_fill, im->tls.index_va,
               im->tls.ncallbacks, im->tls.ncallbacks == 1 ? "" : "s");
        for (size_t i = 0; i < im->tls.ncallbacks; i++)
            printf("  callback 0x%" PRIx64 "\n", im->tls.callbacks[i]);
    }

    if (im->exceptions.present)
        printf("Exception table: %zu RUNTIME_FUNCTION entr%s\n", im->exceptions.count,
               im->exceptions.count == 1 ? "y" : "ies");

    if (im->resources.present) {
        printf("Resources: %zu type%s, %zu entr%s\n", im->resources.ntypes, im->resources.ntypes == 1 ? "" : "s",
               im->resources.total_leaves, im->resources.total_leaves == 1 ? "y" : "ies");
        for (size_t i = 0; i < im->resources.ntypes; i++) {
            const tw_pe_rsrc_type *t = &im->resources.types[i];
            printf("  ");
            if (t->name) { putchar('"'); put_safe(t->name); putchar('"'); }
            else {
                const char *n = tw_pe_rsrc_type_name(t->id);
                if (n) printf("%s", n); else printf("#%u", t->id);
            }
            printf(": %zu\n", t->leaves);
        }
    }

    if (im->overlay_size)
        printf("Overlay: %" PRIu64 " bytes at file offset 0x%" PRIx64 "\n", im->overlay_size, im->overlay_offset);

    if (im->nwarnings) {
        printf("Warnings:\n");
        for (size_t i = 0; i < im->nwarnings; i++) { printf("  "); put_safe(im->warnings[i]); putchar('\n'); }
        if (im->warnings_dropped) printf("  (%zu more suppressed)\n", im->warnings_dropped);
    }
}

int tw_cmd_inspect(int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "usage: tweakwin inspect FILE.exe\n");
        return TW_EXIT_USAGE;
    }
    const char *path = argv[0];
    tw_pe_image im;
    tw_pe_error err;
    tw_pe_status st = tw_pe_load_file(path, &im, &err);

    if (st == TW_PE_ERR_UNSUPPORTED) {
        const char *fmt = format_name(im.opt_magic);
        printf("TweakWin PE Inspector\n");
        printf("File: "); put_safe(path); putchar('\n');
        printf("Architecture: %s (machine 0x%04x)\n", tw_pe_machine_name(im.machine), im.machine);
        if (fmt) printf("Format: %s\n", fmt);
    }
    if (st != TW_PE_OK) {
        fflush(stdout);
        fprintf(stderr, "tweakwin: ");
        for (const unsigned char *p = (const unsigned char *)path; *p; p++)
            fputc((*p >= 0x20 && *p < 0x7f) ? *p : '?', stderr);
        fprintf(stderr, ": %s: %s", tw_pe_status_name(st), err.msg);
        if (err.has_offset)
            fprintf(stderr, " (%s 0x%" PRIx64 ")", err.offset_is_rva ? "RVA" : "file offset", err.offset);
        fputc('\n', stderr);
        tw_pe_free(&im);
        switch (st) {
        case TW_PE_ERR_MALFORMED:   return TW_EXIT_MALFORMED;
        case TW_PE_ERR_UNSUPPORTED: return TW_EXIT_UNSUPPORTED;
        default:                    return TW_EXIT_FAILURE;
        }
    }

    print_image(path, &im);
    tw_pe_free(&im);
    return TW_EXIT_OK;
}
