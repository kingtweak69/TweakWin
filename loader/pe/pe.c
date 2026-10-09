/*
 * TweakWin PE32+ parser.
 *
 * Every byte this file touches goes through one of:
 *   in_file()     - raw file-offset range check
 *   find_region() - RVA -> (section|headers) lookup with file backing size
 *   tw_pe_read_rva() / ptr_rva() / read_cstr_rva()
 * All arithmetic on untrusted values is done in uint64_t so it cannot wrap.
 *
 * Policy: problems that would make an image unloadable (headers, sections,
 * imports, exports, relocations, TLS) are fatal (TW_PE_ERR_MALFORMED).
 * Problems in data only an application consumes (resources, exception
 * table) are recorded as warnings so the rest of the image can be inspected.
 */

#include "pe.h"

#include "../../common/arena.h"
#include "../../common/debug.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* little-endian readers (caller guarantees bounds)                    */

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t le64(const uint8_t *p) { return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32); }

static int is_pow2(uint32_t v) { return v != 0 && (v & (v - 1)) == 0; }

/* ------------------------------------------------------------------ */
/* parse context, errors, warnings                                      */

typedef struct {
    tw_pe_image *im;
    tw_pe_error *err;
    size_t thunks_total;
} ctx;

#if defined(__GNUC__)
#define PRINTF_LIKE(a, b) __attribute__((format(printf, a, b)))
#else
#define PRINTF_LIKE(a, b)
#endif

PRINTF_LIKE(6, 0)
static tw_pe_status set_err(tw_pe_error *err, tw_pe_status st, int has_off, int is_rva,
                            uint64_t off, const char *fmt, va_list ap)
{
    if (!err) return st;
    err->status = st;
    err->has_offset = has_off;
    err->offset_is_rva = is_rva;
    err->offset = off;
    vsnprintf(err->msg, sizeof(err->msg), fmt, ap);
    return st;
}

PRINTF_LIKE(3, 4)
static tw_pe_status bad_file(ctx *c, uint64_t off, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    tw_pe_status st = set_err(c->err, TW_PE_ERR_MALFORMED, 1, 0, off, fmt, ap);
    va_end(ap);
    return st;
}

PRINTF_LIKE(3, 4)
static tw_pe_status bad_rva(ctx *c, uint64_t rva, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    tw_pe_status st = set_err(c->err, TW_PE_ERR_MALFORMED, 1, 1, rva, fmt, ap);
    va_end(ap);
    return st;
}

PRINTF_LIKE(2, 3)
static tw_pe_status bad(ctx *c, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    tw_pe_status st = set_err(c->err, TW_PE_ERR_MALFORMED, 0, 0, 0, fmt, ap);
    va_end(ap);
    return st;
}

PRINTF_LIKE(2, 3)
static tw_pe_status unsupported(ctx *c, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    tw_pe_status st = set_err(c->err, TW_PE_ERR_UNSUPPORTED, 0, 0, 0, fmt, ap);
    va_end(ap);
    return st;
}

static tw_pe_status nomem(ctx *c)
{
    if (c->err) {
        c->err->status = TW_PE_ERR_NOMEM;
        c->err->has_offset = 0;
        snprintf(c->err->msg, sizeof(c->err->msg), "out of memory");
    }
    return TW_PE_ERR_NOMEM;
}

PRINTF_LIKE(2, 3)
static void warn(ctx *c, const char *fmt, ...)
{
    tw_pe_image *im = c->im;
    if (im->nwarnings >= TW_PE_MAX_WARNINGS) {
        im->warnings_dropped++;
        return;
    }
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    char *s = tw_arena_strndup(im->arena, buf, strlen(buf));
    if (!s) return;
    im->warnings[im->nwarnings++] = s;
    TW_DEBUG(TW_DBG_LOADER, "warning: %s", buf);
}

/* ------------------------------------------------------------------ */
/* address translation                                                  */

static int in_file(const tw_pe_image *im, uint64_t off, uint64_t len)
{
    return off <= im->size && len <= im->size - off;
}

typedef struct {
    uint64_t vstart;   /* first RVA of region */
    uint64_t vend;     /* one past last RVA */
    uint64_t foff;     /* file offset of vstart */
    uint64_t fbacked;  /* bytes from vstart that come from the file; rest is zero-fill */
} region;

static uint64_t section_vext(const tw_pe_section *s)
{
    return s->virtual_size ? s->virtual_size : s->raw_size;
}

static int find_region(const tw_pe_image *im, uint64_t rva, region *r)
{
    if (im->sections) {
        for (uint16_t i = 0; i < im->nsections; i++) {
            const tw_pe_section *s = &im->sections[i];
            uint64_t start = s->virtual_address;
            uint64_t ext = section_vext(s);
            if (rva >= start && rva < start + ext) {
                r->vstart = start;
                r->vend = start + ext;
                r->foff = s->raw_ptr;
                r->fbacked = s->raw_size < ext ? s->raw_size : ext;
                return 1;
            }
        }
    }
    if (rva < im->size_of_headers) {
        r->vstart = 0;
        r->vend = im->size_of_headers;
        r->foff = 0;
        r->fbacked = im->size_of_headers < im->size ? im->size_of_headers : im->size;
        return 1;
    }
    return 0;
}

int tw_pe_section_for_rva(const tw_pe_image *im, uint32_t rva)
{
    if (!im->sections) return -1;
    for (uint16_t i = 0; i < im->nsections; i++) {
        const tw_pe_section *s = &im->sections[i];
        uint64_t start = s->virtual_address;
        if (rva >= start && rva < start + section_vext(s)) return i;
    }
    return -1;
}

int tw_pe_read_rva(const tw_pe_image *im, uint32_t rva, void *out, uint32_t len)
{
    region r;
    if (!find_region(im, rva, &r)) return 0;
    if ((uint64_t)rva + len > r.vend) return 0;
    uint64_t rel = rva - r.vstart;
    uint8_t *o = out;
    uint64_t n = 0;
    if (rel < r.fbacked) {
        n = r.fbacked - rel;
        if (n > len) n = len;
        memcpy(o, im->data + r.foff + rel, (size_t)n);
    }
    if (n < len) memset(o + n, 0, (size_t)(len - n));
    return 1;
}

/* Direct pointer to `len` file-backed bytes at `rva`, or NULL. */
static const uint8_t *ptr_rva(const tw_pe_image *im, uint32_t rva, uint64_t len)
{
    region r;
    if (!find_region(im, rva, &r)) return NULL;
    uint64_t rel = rva - r.vstart;
    if (rel > r.fbacked || len > r.fbacked - rel) return NULL;
    return im->data + r.foff + rel;
}

static int rd32(const tw_pe_image *im, uint64_t rva, uint32_t *v)
{
    uint8_t b[4];
    if (rva > UINT32_MAX || !tw_pe_read_rva(im, (uint32_t)rva, b, 4)) return 0;
    *v = le32(b);
    return 1;
}

static int rd16(const tw_pe_image *im, uint64_t rva, uint16_t *v)
{
    uint8_t b[2];
    if (rva > UINT32_MAX || !tw_pe_read_rva(im, (uint32_t)rva, b, 2)) return 0;
    *v = le16(b);
    return 1;
}

static int rd64(const tw_pe_image *im, uint64_t rva, uint64_t *v)
{
    uint8_t b[8];
    if (rva > UINT32_MAX || !tw_pe_read_rva(im, (uint32_t)rva, b, 8)) return 0;
    *v = le64(b);
    return 1;
}

/* NUL-terminated string at rva, max `maxlen` bytes before the NUL.
   Returns NULL if unterminated / out of bounds / OOM (sets *oom). */
static const char *read_cstr_rva(ctx *c, uint64_t rva, size_t maxlen, int *oom)
{
    const tw_pe_image *im = c->im;
    region r;
    *oom = 0;
    if (rva > UINT32_MAX || !find_region(im, rva, &r)) return NULL;
    uint64_t rel = rva - r.vstart;
    uint64_t avail = r.vend - rva;
    size_t len = 0;
    for (;;) {
        if (len > maxlen || len >= avail) return NULL;
        uint64_t pos = rel + len;
        uint8_t ch = pos < r.fbacked ? im->data[r.foff + pos] : 0;
        if (ch == 0) break;
        len++;
    }
    const char *src = "";
    if (len > 0) {
        /* the whole string precedes the NUL; it is file-backed because
           zero-fill would have terminated it */
        src = (const char *)(im->data + r.foff + rel);
    }
    char *s = tw_arena_strndup(im->arena, src, len);
    if (!s) *oom = 1;
    return s;
}

static int va_to_rva(const tw_pe_image *im, uint64_t va, uint32_t *rva)
{
    if (va < im->image_base) return 0;
    uint64_t d = va - im->image_base;
    if (d >= im->size_of_image) return 0;
    *rva = (uint32_t)d;
    return 1;
}

/* ------------------------------------------------------------------ */
/* growable vector (malloc-backed, copied into the arena when done)     */

typedef struct {
    void *p;
    size_t n, cap, elem;
} vec;

static int vec_push(vec *v, const void *item)
{
    if (v->n == v->cap) {
        size_t ncap = v->cap ? v->cap * 2 : 8;
        if (ncap > SIZE_MAX / v->elem) return 0;
        void *np = realloc(v->p, ncap * v->elem);
        if (!np) return 0;
        v->p = np;
        v->cap = ncap;
    }
    memcpy((char *)v->p + v->n * v->elem, item, v->elem);
    v->n++;
    return 1;
}

static void *vec_finish(ctx *c, vec *v)
{
    void *out = NULL;
    if (v->n) {
        out = tw_arena_calloc(c->im->arena, v->n, v->elem);
        if (out) memcpy(out, v->p, v->n * v->elem);
    }
    free(v->p);
    v->p = NULL;
    return out;
}

/* ------------------------------------------------------------------ */
/* headers                                                              */

static tw_pe_status parse_headers(ctx *c)
{
    tw_pe_image *im = c->im;

    if (im->size < 64)
        return bad_file(c, 0, "file too small for a DOS header (%zu bytes)", im->size);
    if (im->data[0] != 'M' || im->data[1] != 'Z')
        return bad_file(c, 0, "missing MZ signature (not a DOS/PE executable)");

    im->e_lfanew = le32(im->data + 0x3c);
    TW_DEBUG(TW_DBG_LOADER, "e_lfanew=0x%x", im->e_lfanew);
    if (!in_file(im, im->e_lfanew, 4 + 20))
        return bad_file(c, 0x3c, "e_lfanew (0x%x) points past end of file", im->e_lfanew);

    const uint8_t *pe = im->data + im->e_lfanew;
    if (memcmp(pe, "PE\0\0", 4) != 0)
        return bad_file(c, im->e_lfanew, "missing PE signature at e_lfanew");

    const uint8_t *coff = pe + 4;
    im->machine = le16(coff + 0);
    im->nsections = le16(coff + 2);
    im->time_date_stamp = le32(coff + 4);
    im->symtab_ptr = le32(coff + 8);
    im->nsymbols = le32(coff + 12);
    im->opt_header_size = le16(coff + 16);
    im->characteristics = le16(coff + 18);

    uint64_t opt_off = (uint64_t)im->e_lfanew + 24;
    if (im->opt_header_size >= 2 && in_file(im, opt_off, 2))
        im->opt_magic = le16(im->data + opt_off);

    if (im->machine != TW_PE_MACHINE_AMD64) {
        return unsupported(c, "machine 0x%04x (%s) is not supported; TweakWin 0.1 runs x86-64 PE32+ images only",
                           im->machine, tw_pe_machine_name(im->machine));
    }

    if (im->opt_header_size == 0)
        return bad_file(c, im->e_lfanew + 20u, "no optional header (COFF object file, not an image)");
    if (!in_file(im, opt_off, im->opt_header_size))
        return bad_file(c, opt_off, "optional header (%u bytes) extends past end of file", im->opt_header_size);

    if (im->opt_magic == TW_PE_OPT_MAGIC_PE32)
        return unsupported(c, "PE32 (32-bit) optional header; 32-bit/WOW64 images are not supported in TweakWin 0.1");
    if (im->opt_magic == TW_PE_OPT_MAGIC_ROM)
        return unsupported(c, "ROM image optional header is not supported");
    if (im->opt_magic != TW_PE_OPT_MAGIC_PE32PLUS)
        return bad_file(c, opt_off, "unknown optional header magic 0x%04x", im->opt_magic);

    if (!(im->characteristics & TW_PE_FILE_EXECUTABLE_IMAGE))
        return bad_file(c, im->e_lfanew + 22u, "COFF header lacks IMAGE_FILE_EXECUTABLE_IMAGE");

    if (im->opt_header_size < 112)
        return bad_file(c, opt_off, "optional header too small for PE32+ (%u < 112 bytes)", im->opt_header_size);

    const uint8_t *o = im->data + opt_off;
    im->linker_major = o[2];
    im->linker_minor = o[3];
    im->size_of_code = le32(o + 4);
    im->entry_rva = le32(o + 16);
    im->image_base = le64(o + 24);
    im->section_alignment = le32(o + 32);
    im->file_alignment = le32(o + 36);
    im->os_major = le16(o + 40);
    im->os_minor = le16(o + 42);
    im->subsystem_major = le16(o + 48);
    im->subsystem_minor = le16(o + 50);
    im->size_of_image = le32(o + 56);
    im->size_of_headers = le32(o + 60);
    im->checksum = le32(o + 64);
    im->subsystem = le16(o + 68);
    im->dll_characteristics = le16(o + 70);
    im->stack_reserve = le64(o + 72);
    im->stack_commit = le64(o + 80);
    im->heap_reserve = le64(o + 88);
    im->heap_commit = le64(o + 96);
    uint32_t ndirs = le32(o + 108);

    if (ndirs > TW_PE_DIR_COUNT) {
        warn(c, "NumberOfRvaAndSizes is %u; only the first %d are used", ndirs, TW_PE_DIR_COUNT);
        ndirs = TW_PE_DIR_COUNT;
    }
    if (112u + (uint64_t)ndirs * 8 > im->opt_header_size)
        return bad_file(c, opt_off + 108, "optional header too small for %u data directories", ndirs);
    im->ndirs = ndirs;
    for (uint32_t i = 0; i < ndirs; i++) {
        im->dirs[i].rva = le32(o + 112 + i * 8);
        im->dirs[i].size = le32(o + 112 + i * 8 + 4);
    }

    /* alignment rules (PE/COFF spec, optional header Windows-specific fields) */
    if (!is_pow2(im->section_alignment))
        return bad_file(c, opt_off + 32, "SectionAlignment 0x%x is not a power of two", im->section_alignment);
    if (!is_pow2(im->file_alignment))
        return bad_file(c, opt_off + 36, "FileAlignment 0x%x is not a power of two", im->file_alignment);
    if (im->section_alignment < im->file_alignment)
        return bad_file(c, opt_off + 32, "SectionAlignment 0x%x is smaller than FileAlignment 0x%x",
                        im->section_alignment, im->file_alignment);
    if (im->section_alignment < 0x1000) {
        if (im->file_alignment != im->section_alignment)
            return bad_file(c, opt_off + 36,
                            "low-alignment image: FileAlignment must equal SectionAlignment (0x%x != 0x%x)",
                            im->file_alignment, im->section_alignment);
    } else if (im->file_alignment < 0x200 || im->file_alignment > 0x10000) {
        warn(c, "FileAlignment 0x%x is outside the documented 0x200-0x10000 range", im->file_alignment);
    }

    if (im->size_of_image == 0)
        return bad_file(c, opt_off + 56, "SizeOfImage is zero");
    if (im->size_of_image % im->section_alignment)
        warn(c, "SizeOfImage 0x%x is not a multiple of SectionAlignment", im->size_of_image);
    if (im->image_base > UINT64_MAX - im->size_of_image)
        return bad_file(c, opt_off + 24, "ImageBase + SizeOfImage overflows the address space");
    if (im->image_base % 0x10000)
        warn(c, "ImageBase 0x%llx is not a multiple of 64 KiB", (unsigned long long)im->image_base);
    if (im->size_of_headers == 0)
        return bad_file(c, opt_off + 60, "SizeOfHeaders is zero");
    if (im->size_of_headers > im->size_of_image)
        return bad_file(c, opt_off + 60, "SizeOfHeaders 0x%x exceeds SizeOfImage 0x%x",
                        im->size_of_headers, im->size_of_image);
    if (im->size_of_headers > im->size)
        warn(c, "SizeOfHeaders 0x%x exceeds file size", im->size_of_headers);
    if (im->entry_rva && im->entry_rva >= im->size_of_image)
        return bad_file(c, opt_off + 16, "entry point RVA 0x%x is outside the image (SizeOfImage 0x%x)",
                        im->entry_rva, im->size_of_image);
    if (im->stack_commit > im->stack_reserve)
        warn(c, "stack commit 0x%llx exceeds reserve 0x%llx",
             (unsigned long long)im->stack_commit, (unsigned long long)im->stack_reserve);
    if (im->heap_commit > im->heap_reserve)
        warn(c, "heap commit 0x%llx exceeds reserve 0x%llx",
             (unsigned long long)im->heap_commit, (unsigned long long)im->heap_reserve);

    TW_DEBUG(TW_DBG_LOADER, "PE32+ base=0x%llx entry=0x%x soi=0x%x soh=0x%x salign=0x%x falign=0x%x ndirs=%u",
             (unsigned long long)im->image_base, im->entry_rva, im->size_of_image, im->size_of_headers,
             im->section_alignment, im->file_alignment, im->ndirs);
    return TW_PE_OK;
}

/* ------------------------------------------------------------------ */
/* sections                                                             */

static void resolve_long_name(ctx *c, tw_pe_section *s)
{
    const tw_pe_image *im = c->im;
    if (s->name[0] != '/' || s->name[1] == '\0') return;
    uint64_t off = 0;
    for (int i = 1; i < 8 && s->name[i]; i++) {
        if (s->name[i] < '0' || s->name[i] > '9') return;
        off = off * 10 + (uint64_t)(s->name[i] - '0');
    }
    if (!im->symtab_ptr) return;
    uint64_t strtab = (uint64_t)im->symtab_ptr + (uint64_t)im->nsymbols * 18;
    if (!in_file(im, strtab, 4)) return;
    uint32_t strtab_size = le32(im->data + strtab);
    if (off < 4 || off >= strtab_size || !in_file(im, strtab, strtab_size)) return;
    const char *p = (const char *)im->data + strtab + off;
    size_t maxlen = strtab_size - off;
    const char *nul = memchr(p, 0, maxlen);
    if (!nul) return;
    s->long_name = tw_arena_strndup(im->arena, p, (size_t)(nul - p));
}

static tw_pe_status parse_sections(ctx *c)
{
    tw_pe_image *im = c->im;
    uint64_t sec_off = (uint64_t)im->e_lfanew + 24 + im->opt_header_size;

    if (im->nsections > TW_PE_MAX_SECTIONS)
        return bad_file(c, im->e_lfanew + 6u, "too many sections (%u > %d)", im->nsections, TW_PE_MAX_SECTIONS);
    if (im->nsections == 0)
        warn(c, "image has no sections");
    if (!in_file(im, sec_off, (uint64_t)im->nsections * 40))
        return bad_file(c, sec_off, "section table (%u entries) extends past end of file", im->nsections);
    if (sec_off + (uint64_t)im->nsections * 40 > im->size_of_headers)
        warn(c, "section table extends past SizeOfHeaders");

    if (im->nsections == 0) return TW_PE_OK;

    tw_pe_section *secs = tw_arena_calloc(im->arena, im->nsections, sizeof(*secs));
    if (!secs) return nomem(c);

    uint64_t prev_end = 0;
    uint64_t max_raw_end = im->size_of_headers < im->size ? im->size_of_headers : im->size;

    for (uint16_t i = 0; i < im->nsections; i++) {
        const uint8_t *h = im->data + sec_off + (uint64_t)i * 40;
        tw_pe_section *s = &secs[i];
        memcpy(s->name, h, 8);
        s->name[8] = '\0';
        s->virtual_size = le32(h + 8);
        s->virtual_address = le32(h + 12);
        s->raw_size = le32(h + 16);
        s->raw_ptr = le32(h + 20);
        s->characteristics = le32(h + 36);
        uint64_t hoff = sec_off + (uint64_t)i * 40;

        if (s->raw_size && !in_file(im, s->raw_ptr, s->raw_size))
            return bad_file(c, hoff + 16, "section %u (%.8s) raw data [0x%x+0x%x] extends past end of file",
                            i, s->name, s->raw_ptr, s->raw_size);
        if (s->virtual_address % im->section_alignment)
            return bad_file(c, hoff + 12, "section %u (%.8s) VirtualAddress 0x%x is not SectionAlignment-aligned",
                            i, s->name, s->virtual_address);
        uint64_t ext = section_vext(s);
        uint64_t end = (uint64_t)s->virtual_address + ext;
        if (end > im->size_of_image)
            return bad_file(c, hoff + 8, "section %u (%.8s) ends at RVA 0x%llx, past SizeOfImage 0x%x",
                            i, s->name, (unsigned long long)end, im->size_of_image);
        if (s->virtual_address < im->size_of_headers)
            return bad_file(c, hoff + 12, "section %u (%.8s) overlaps the headers", i, s->name);
        if (s->virtual_address < prev_end)
            return bad_file(c, hoff + 12, "section %u (%.8s) overlaps or precedes the previous section",
                            i, s->name);
        if (ext == 0)
            warn(c, "section %u (%.8s) is empty", i, s->name);
        if ((s->characteristics & TW_PE_SCN_MEM_WRITE) && (s->characteristics & TW_PE_SCN_MEM_EXECUTE))
            warn(c, "section %u (%.8s) is both writable and executable", i, s->name);
        prev_end = end;
        if (s->raw_size) {
            uint64_t re = (uint64_t)s->raw_ptr + s->raw_size;
            if (re > max_raw_end) max_raw_end = re;
        }
        TW_DEBUG(TW_DBG_LOADER, "section %u %.8s va=0x%x vsize=0x%x raw=0x%x+0x%x ch=0x%08x",
                 i, s->name, s->virtual_address, s->virtual_size, s->raw_ptr, s->raw_size, s->characteristics);
    }
    im->sections = secs;
    for (uint16_t i = 0; i < im->nsections; i++) resolve_long_name(c, &secs[i]);

    if (max_raw_end < im->size) {
        im->overlay_offset = max_raw_end;
        im->overlay_size = im->size - max_raw_end;
    }

    if (im->entry_rva) {
        int si = tw_pe_section_for_rva(im, im->entry_rva);
        if (si < 0)
            warn(c, "entry point RVA 0x%x is not inside any section", im->entry_rva);
        else if (!(secs[si].characteristics & TW_PE_SCN_MEM_EXECUTE))
            warn(c, "entry point is in non-executable section %.8s", secs[si].name);
    } else if (!tw_pe_is_dll(im)) {
        warn(c, "executable has no entry point");
    }
    return TW_PE_OK;
}

static void check_dirs(ctx *c)
{
    tw_pe_image *im = c->im;
    for (uint32_t i = 0; i < im->ndirs; i++) {
        const tw_pe_datadir *d = &im->dirs[i];
        if (!d->rva && !d->size) continue;
        if (i == TW_PE_DIR_SECURITY) {
            if (!in_file(im, d->rva, d->size))
                warn(c, "SECURITY directory (file offset 0x%x, size 0x%x) extends past end of file", d->rva, d->size);
            continue;
        }
        if ((uint64_t)d->rva + d->size > im->size_of_image)
            warn(c, "%s directory [0x%x+0x%x] extends past SizeOfImage", tw_pe_dir_name(i), d->rva, d->size);
    }
}

/* ------------------------------------------------------------------ */
/* imports                                                              */

/* Walk a thunk array (INT, or IAT if no INT). */
static tw_pe_status parse_thunks(ctx *c, uint32_t thunk_rva, uint32_t iat_rva, const char *dll,
                                 tw_pe_import_fn **out, size_t *nout)
{
    tw_pe_image *im = c->im;
    vec v = { .elem = sizeof(tw_pe_import_fn) };
    tw_pe_status st = TW_PE_OK;

    for (uint64_t j = 0;; j++) {
        uint64_t trva = (uint64_t)thunk_rva + j * 8;
        uint64_t val;
        if (!rd64(im, trva, &val)) {
            st = bad_rva(c, trva, "import thunk array for %s runs out of bounds", dll);
            goto out;
        }
        if (val == 0) break;
        if (++c->thunks_total > TW_PE_MAX_THUNKS_TOTAL) {
            st = bad(c, "more than %d imported functions", TW_PE_MAX_THUNKS_TOTAL);
            goto out;
        }

        tw_pe_import_fn fn = { 0 };
        fn.iat_rva = iat_rva ? (uint32_t)((uint64_t)iat_rva + j * 8) : 0;
        if (val & (1ull << 63)) {
            if (val & 0x7fffffffffff0000ull)
                warn(c, "ordinal import thunk in %s has reserved bits set", dll);
            fn.by_ordinal = 1;
            fn.ordinal = (uint16_t)(val & 0xffff);
        } else {
            if (val & 0x7fffffff80000000ull) {
                st = bad_rva(c, trva, "name import thunk in %s has reserved bits set (0x%llx)",
                             dll, (unsigned long long)val);
                goto out;
            }
            uint32_t hn = (uint32_t)val;
            uint16_t hint;
            int oom;
            if (!rd16(im, hn, &hint)) {
                st = bad_rva(c, hn, "hint/name entry for %s is out of bounds", dll);
                goto out;
            }
            const char *name = read_cstr_rva(c, (uint64_t)hn + 2, TW_PE_MAX_NAME, &oom);
            if (oom) { st = nomem(c); goto out; }
            if (!name) {
                st = bad_rva(c, (uint64_t)hn + 2, "import name in %s is unterminated or out of bounds", dll);
                goto out;
            }
            if (!name[0]) warn(c, "empty import name in %s", dll);
            fn.hint = hint;
            fn.name = name;
        }
        if (!vec_push(&v, &fn)) { st = nomem(c); goto out; }
    }
    *nout = v.n;
    *out = vec_finish(c, &v);
    if (v.n && !*out) return nomem(c);
    return TW_PE_OK;
out:
    free(v.p);
    return st;
}

static tw_pe_status parse_imports(ctx *c, vec *dlls)
{
    tw_pe_image *im = c->im;
    const tw_pe_datadir *d = &im->dirs[TW_PE_DIR_IMPORT];
    if (im->ndirs <= TW_PE_DIR_IMPORT || !d->rva) return TW_PE_OK;

    for (uint64_t i = 0;; i++) {
        if (i >= TW_PE_MAX_IMPORT_DLLS)
            return bad(c, "more than %d import descriptors (missing terminator?)", TW_PE_MAX_IMPORT_DLLS);
        uint64_t drva = (uint64_t)d->rva + i * 20;
        uint8_t desc[20];
        if (drva > UINT32_MAX || !tw_pe_read_rva(im, (uint32_t)drva, desc, 20))
            return bad_rva(c, drva, "import descriptor %llu is out of bounds", (unsigned long long)i);

        static const uint8_t zero[20];
        if (memcmp(desc, zero, 20) == 0) break;

        uint32_t oft = le32(desc + 0);
        uint32_t tds = le32(desc + 4);
        uint32_t fwd = le32(desc + 8);
        uint32_t name_rva = le32(desc + 12);
        uint32_t ft = le32(desc + 16);

        int oom;
        const char *name = read_cstr_rva(c, name_rva, 256, &oom);
        if (oom) return nomem(c);
        if (!name)
            return bad_rva(c, name_rva, "import descriptor %llu has an invalid DLL name", (unsigned long long)i);
        if (!ft)
            return bad_rva(c, drva, "import descriptor for %s has no import address table", name);

        tw_pe_import_dll dll = { 0 };
        dll.dll = name;
        dll.iat_rva = ft;
        dll.time_date_stamp = tds;
        dll.forwarder_chain = fwd;
        tw_pe_status st = parse_thunks(c, oft ? oft : ft, ft, name, &dll.fns, &dll.nfns);
        if (st != TW_PE_OK) return st;
        if (dll.nfns == 0) warn(c, "import descriptor for %s imports nothing", name);
        TW_DEBUG(TW_DBG_IMPORTS, "import %s: %zu function(s), IAT at 0x%x", name, dll.nfns, ft);
        if (!vec_push(dlls, &dll)) return nomem(c);
    }
    return TW_PE_OK;
}

static tw_pe_status parse_delay_imports(ctx *c, vec *dlls)
{
    tw_pe_image *im = c->im;
    const tw_pe_datadir *d = &im->dirs[TW_PE_DIR_DELAY_IMPORT];
    if (im->ndirs <= TW_PE_DIR_DELAY_IMPORT || !d->rva) return TW_PE_OK;

    for (uint64_t i = 0;; i++) {
        if (i >= TW_PE_MAX_IMPORT_DLLS)
            return bad(c, "more than %d delay-import descriptors", TW_PE_MAX_IMPORT_DLLS);
        uint64_t drva = (uint64_t)d->rva + i * 32;
        uint8_t desc[32];
        if (drva > UINT32_MAX || !tw_pe_read_rva(im, (uint32_t)drva, desc, 32))
            return bad_rva(c, drva, "delay-import descriptor %llu is out of bounds", (unsigned long long)i);

        uint32_t attrs = le32(desc + 0);
        uint32_t f[7];
        for (int k = 0; k < 7; k++) f[k] = le32(desc + 4 + k * 4);
        /* f: 0 DllName, 1 ModuleHandle, 2 IAT, 3 INT, 4 BoundIAT, 5 UnloadIAT, 6 TimeDateStamp */
        if (f[0] == 0) break;

        uint32_t name_rva = f[0], iat = f[2], intab = f[3];
        if (!(attrs & 1)) {
            /* legacy VA-based descriptor */
            uint32_t r;
            if (!va_to_rva(im, name_rva, &r)) return bad_rva(c, drva, "legacy delay-import name VA is outside the image");
            name_rva = r;
            if (iat) { if (!va_to_rva(im, iat, &r)) return bad_rva(c, drva, "legacy delay-import IAT VA is outside the image"); iat = r; }
            if (intab) { if (!va_to_rva(im, intab, &r)) return bad_rva(c, drva, "legacy delay-import INT VA is outside the image"); intab = r; }
            warn(c, "legacy VA-based delay-import descriptor");
        }

        int oom;
        const char *name = read_cstr_rva(c, name_rva, 256, &oom);
        if (oom) return nomem(c);
        if (!name) return bad_rva(c, name_rva, "delay-import descriptor %llu has an invalid DLL name", (unsigned long long)i);
        if (!intab) return bad_rva(c, drva, "delay-import descriptor for %s has no name table", name);

        tw_pe_import_dll dll = { 0 };
        dll.dll = name;
        dll.iat_rva = iat;
        dll.time_date_stamp = f[6];
        dll.delayed = 1;
        tw_pe_status st = parse_thunks(c, intab, iat, name, &dll.fns, &dll.nfns);
        if (st != TW_PE_OK) return st;
        TW_DEBUG(TW_DBG_IMPORTS, "delay-import %s: %zu function(s)", name, dll.nfns);
        if (!vec_push(dlls, &dll)) return nomem(c);
    }
    return TW_PE_OK;
}

/* ------------------------------------------------------------------ */
/* exports                                                              */

static int export_cmp(const void *a, const void *b)
{
    const tw_pe_export *x = a, *y = b;
    if (x->ordinal != y->ordinal) return x->ordinal < y->ordinal ? -1 : 1;
    if (!x->name || !y->name) return x->name ? 1 : (y->name ? -1 : 0);
    return strcmp(x->name, y->name);
}

static tw_pe_status parse_exports(ctx *c)
{
    tw_pe_image *im = c->im;
    const tw_pe_datadir *d = &im->dirs[TW_PE_DIR_EXPORT];
    if (im->ndirs <= TW_PE_DIR_EXPORT || !d->rva) return TW_PE_OK;

    uint8_t ed[40];
    if (!tw_pe_read_rva(im, d->rva, ed, 40))
        return bad_rva(c, d->rva, "export directory is out of bounds");

    tw_pe_exports *ex = &im->exports;
    ex->present = 1;
    uint32_t name_rva = le32(ed + 12);
    ex->ordinal_base = le32(ed + 16);
    ex->nfunctions = le32(ed + 20);
    ex->nnames = le32(ed + 24);
    uint32_t aof = le32(ed + 28);
    uint32_t aon = le32(ed + 32);
    uint32_t aoo = le32(ed + 36);

    if (ex->nfunctions > TW_PE_MAX_EXPORTS)
        return bad_rva(c, d->rva + 20, "export table claims %u functions (max %d)", ex->nfunctions, TW_PE_MAX_EXPORTS);
    if (ex->nnames > TW_PE_MAX_EXPORTS)
        return bad_rva(c, d->rva + 24, "export table claims %u names (max %d)", ex->nnames, TW_PE_MAX_EXPORTS);
    if (ex->nfunctions && (uint64_t)ex->ordinal_base + ex->nfunctions - 1 > 0xffff)
        warn(c, "export ordinals exceed 16 bits (base %u, %u functions)", ex->ordinal_base, ex->nfunctions);

    int oom;
    if (name_rva) {
        ex->dll_name = read_cstr_rva(c, name_rva, 256, &oom);
        if (oom) return nomem(c);
        if (!ex->dll_name) warn(c, "export directory DLL name is invalid");
    }

    uint64_t fwd_lo = d->rva, fwd_hi = (uint64_t)d->rva + d->size;
    uint8_t *named = NULL;
    vec v = { .elem = sizeof(tw_pe_export) };
    tw_pe_status st = TW_PE_OK;

    if (ex->nfunctions) {
        named = calloc(ex->nfunctions, 1);
        if (!named) return nomem(c);
    }

    for (uint32_t i = 0; i < ex->nnames; i++) {
        uint32_t nrva;
        uint16_t idx;
        if (!rd32(im, (uint64_t)aon + (uint64_t)i * 4, &nrva)) {
            st = bad_rva(c, (uint64_t)aon + (uint64_t)i * 4, "export name pointer %u is out of bounds", i);
            goto out;
        }
        if (!rd16(im, (uint64_t)aoo + (uint64_t)i * 2, &idx)) {
            st = bad_rva(c, (uint64_t)aoo + (uint64_t)i * 2, "export ordinal entry %u is out of bounds", i);
            goto out;
        }
        if (idx >= ex->nfunctions) {
            st = bad_rva(c, (uint64_t)aoo + (uint64_t)i * 2, "export name %u maps to function index %u (only %u functions)",
                         i, idx, ex->nfunctions);
            goto out;
        }
        const char *name = read_cstr_rva(c, nrva, TW_PE_MAX_NAME, &oom);
        if (oom) { st = nomem(c); goto out; }
        if (!name) { st = bad_rva(c, nrva, "export name %u is unterminated or out of bounds", i); goto out; }
        named[idx] = 1;

        uint32_t frva;
        if (!rd32(im, (uint64_t)aof + (uint64_t)idx * 4, &frva)) {
            st = bad_rva(c, (uint64_t)aof + (uint64_t)idx * 4, "export address %u is out of bounds", idx);
            goto out;
        }
        tw_pe_export e = { 0 };
        e.ordinal = (uint32_t)((uint64_t)ex->ordinal_base + idx);
        e.name = name;
        if (frva >= fwd_lo && frva < fwd_hi) {
            e.forwarder = read_cstr_rva(c, frva, TW_PE_MAX_NAME, &oom);
            if (oom) { st = nomem(c); goto out; }
            if (!e.forwarder) { st = bad_rva(c, frva, "forwarder string for %s is invalid", name); goto out; }
        } else {
            if (frva >= im->size_of_image) {
                st = bad_rva(c, frva, "export %s points outside the image", name);
                goto out;
            }
            e.rva = frva;
        }
        if (!vec_push(&v, &e)) { st = nomem(c); goto out; }
    }

    for (uint32_t i = 0; i < ex->nfunctions; i++) {
        if (named[i]) continue;
        uint32_t frva;
        if (!rd32(im, (uint64_t)aof + (uint64_t)i * 4, &frva)) {
            st = bad_rva(c, (uint64_t)aof + (uint64_t)i * 4, "export address %u is out of bounds", i);
            goto out;
        }
        if (frva == 0) continue; /* unused ordinal slot */
        tw_pe_export e = { 0 };
        e.ordinal = (uint32_t)((uint64_t)ex->ordinal_base + i);
        if (frva >= fwd_lo && frva < fwd_hi) {
            e.forwarder = read_cstr_rva(c, frva, TW_PE_MAX_NAME, &oom);
            if (oom) { st = nomem(c); goto out; }
            if (!e.forwarder) { st = bad_rva(c, frva, "forwarder string for ordinal %u is invalid", e.ordinal); goto out; }
        } else {
            if (frva >= im->size_of_image) {
                st = bad_rva(c, frva, "export ordinal %u points outside the image", e.ordinal);
                goto out;
            }
            e.rva = frva;
        }
        if (!vec_push(&v, &e)) { st = nomem(c); goto out; }
    }

    free(named);
    if (v.n > 1) qsort(v.p, v.n, sizeof(tw_pe_export), export_cmp);
    ex->nentries = v.n;
    ex->entries = vec_finish(c, &v);
    if (v.n && !ex->entries) return nomem(c);
    return TW_PE_OK;
out:
    free(named);
    free(v.p);
    return st;
}

/* ------------------------------------------------------------------ */
/* base relocations                                                     */

static tw_pe_status parse_relocs(ctx *c)
{
    tw_pe_image *im = c->im;
    const tw_pe_datadir *d = &im->dirs[TW_PE_DIR_BASERELOC];
    /* No relocation directory is legitimate: an image with no absolute
       addresses (all RIP-relative) needs no fixups at any base. */
    if (im->ndirs <= TW_PE_DIR_BASERELOC || !d->rva || !d->size) return TW_PE_OK;

    const uint8_t *base = ptr_rva(im, d->rva, d->size);
    if (!base)
        return bad_rva(c, d->rva, "relocation directory [0x%x+0x%x] is not backed by file data", d->rva, d->size);

    tw_pe_relocs *r = &im->relocs;
    r->present = 1;
    uint32_t off = 0;
    int warned_type = 0;
    while (off < d->size) {
        if (d->size - off < 8)
            return bad_rva(c, (uint64_t)d->rva + off, "truncated relocation block header");
        uint32_t page = le32(base + off);
        uint32_t bsize = le32(base + off + 4);
        if (bsize < 8 || bsize > d->size - off || (bsize & 1))
            return bad_rva(c, (uint64_t)d->rva + off, "relocation block has invalid size 0x%x", bsize);
        if (bsize & 3)
            warn(c, "relocation block at RVA 0x%x is not 32-bit aligned", d->rva + off);
        if (page >= im->size_of_image)
            return bad_rva(c, (uint64_t)d->rva + off, "relocation block page 0x%x is outside the image", page);

        uint32_t n = (bsize - 8) / 2;
        for (uint32_t k = 0; k < n; k++) {
            uint16_t e = le16(base + off + 8 + k * 2);
            unsigned type = e >> 12;
            uint32_t target = page + (e & 0xfff);
            r->by_type[type]++;
            r->nentries++;
            switch (type) {
            case TW_PE_REL_ABSOLUTE:
                break;
            case TW_PE_REL_DIR64:
                if ((uint64_t)target + 8 > im->size_of_image)
                    return bad_rva(c, target, "DIR64 relocation target 0x%x is outside the image", target);
                break;
            case TW_PE_REL_HIGHLOW:
            case TW_PE_REL_HIGH:
            case TW_PE_REL_LOW:
                if ((uint64_t)target + (type == TW_PE_REL_HIGHLOW ? 4 : 2) > im->size_of_image)
                    return bad_rva(c, target, "%s relocation target 0x%x is outside the image",
                                   tw_pe_reloc_type_name(type), target);
                if (!(warned_type & (1 << type))) {
                    warned_type |= 1 << type;
                    warn(c, "%s relocations are unusual in an x86-64 image", tw_pe_reloc_type_name(type));
                }
                break;
            default:
                return bad_rva(c, (uint64_t)d->rva + off + 8 + k * 2,
                               "relocation type %u is not valid for x86-64", type);
            }
        }
        r->nblocks++;
        off += bsize;
    }
    if (im->characteristics & TW_PE_FILE_RELOCS_STRIPPED)
        warn(c, "RELOCS_STRIPPED is set but a relocation directory is present");
    TW_DEBUG(TW_DBG_LOADER, "relocations: %zu blocks, %zu entries", r->nblocks, r->nentries);
    return TW_PE_OK;
}

/* ------------------------------------------------------------------ */
/* TLS                                                                  */

static tw_pe_status parse_tls(ctx *c)
{
    tw_pe_image *im = c->im;
    const tw_pe_datadir *d = &im->dirs[TW_PE_DIR_TLS];
    if (im->ndirs <= TW_PE_DIR_TLS || !d->rva) return TW_PE_OK;

    uint8_t t[40];
    if (!tw_pe_read_rva(im, d->rva, t, 40))
        return bad_rva(c, d->rva, "TLS directory is out of bounds");
    if (d->size && d->size < 40)
        warn(c, "TLS directory size 0x%x is smaller than IMAGE_TLS_DIRECTORY64", d->size);

    tw_pe_tls *tls = &im->tls;
    tls->present = 1;
    tls->raw_start_va = le64(t + 0);
    tls->raw_end_va = le64(t + 8);
    tls->index_va = le64(t + 16);
    tls->callbacks_va = le64(t + 24);
    tls->zero_fill = le32(t + 32);
    tls->characteristics = le32(t + 36);

    uint32_t tmp;
    if (tls->raw_start_va || tls->raw_end_va) {
        if (tls->raw_end_va < tls->raw_start_va)
            return bad_rva(c, d->rva, "TLS raw data end precedes start");
        if (!va_to_rva(im, tls->raw_start_va, &tmp))
            return bad_rva(c, d->rva, "TLS raw data start VA 0x%llx is outside the image",
                           (unsigned long long)tls->raw_start_va);
        if (tls->raw_end_va - im->image_base > im->size_of_image)
            return bad_rva(c, d->rva + 8, "TLS raw data end VA 0x%llx is outside the image",
                           (unsigned long long)tls->raw_end_va);
    }
    if (tls->index_va && !va_to_rva(im, tls->index_va, &tmp))
        return bad_rva(c, d->rva + 16, "TLS index VA 0x%llx is outside the image", (unsigned long long)tls->index_va);

    if (tls->callbacks_va) {
        uint32_t cb_rva;
        if (!va_to_rva(im, tls->callbacks_va, &cb_rva))
            return bad_rva(c, d->rva + 24, "TLS callback array VA 0x%llx is outside the image",
                           (unsigned long long)tls->callbacks_va);
        vec v = { .elem = sizeof(uint64_t) };
        for (uint64_t i = 0;; i++) {
            if (i >= TW_PE_MAX_TLS_CALLBACKS) {
                free(v.p);
                return bad_rva(c, cb_rva, "more than %d TLS callbacks (missing terminator?)", TW_PE_MAX_TLS_CALLBACKS);
            }
            uint64_t va;
            if (!rd64(im, (uint64_t)cb_rva + i * 8, &va)) {
                free(v.p);
                return bad_rva(c, (uint64_t)cb_rva + i * 8, "TLS callback array runs out of bounds");
            }
            if (va == 0) break;
            uint32_t r;
            if (!va_to_rva(im, va, &r)) {
                free(v.p);
                return bad_rva(c, (uint64_t)cb_rva + i * 8, "TLS callback VA 0x%llx is outside the image",
                               (unsigned long long)va);
            }
            if (!vec_push(&v, &va)) { free(v.p); return nomem(c); }
        }
        tls->ncallbacks = v.n;
        tls->callbacks = vec_finish(c, &v);
        if (v.n && !tls->callbacks) return nomem(c);
    }
    return TW_PE_OK;
}

/* ------------------------------------------------------------------ */
/* exception directory (.pdata) -- warnings only                        */

static void parse_exceptions(ctx *c)
{
    tw_pe_image *im = c->im;
    const tw_pe_datadir *d = &im->dirs[TW_PE_DIR_EXCEPTION];
    if (im->ndirs <= TW_PE_DIR_EXCEPTION || !d->rva || !d->size) return;

    tw_pe_exceptions *ex = &im->exceptions;
    if (d->size % 12)
        warn(c, "exception directory size 0x%x is not a multiple of 12", d->size);
    size_t n = d->size / 12;
    if (n > TW_PE_MAX_RUNTIME_FUNCS) {
        warn(c, "exception directory has %zu entries; not examined", n);
        return;
    }
    const uint8_t *p = ptr_rva(im, d->rva, (uint64_t)n * 12);
    if (!p) {
        warn(c, "exception directory [0x%x+0x%x] is not backed by file data", d->rva, d->size);
        return;
    }
    ex->present = 1;
    ex->count = n;
    ex->sorted = 1;
    uint32_t prev = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t begin = le32(p + i * 12);
        uint32_t end = le32(p + i * 12 + 4);
        uint32_t unwind = le32(p + i * 12 + 8);
        if (begin >= end || end > im->size_of_image) ex->invalid_ranges++;
        if (i && begin < prev) ex->sorted = 0;
        prev = begin;
        if (!(unwind & 1) && unwind < im->size_of_image) {
            uint8_t b;
            if (tw_pe_read_rva(im, unwind, &b, 1)) {
                unsigned ver = b & 7;
                if (ver != 1 && ver != 2) ex->bad_unwind_version++;
            } else {
                ex->bad_unwind_version++;
            }
        } else if (unwind >= im->size_of_image) {
            ex->bad_unwind_version++;
        }
    }
    if (ex->invalid_ranges)
        warn(c, "%zu RUNTIME_FUNCTION entries have invalid address ranges", ex->invalid_ranges);
    if (ex->bad_unwind_version)
        warn(c, "%zu RUNTIME_FUNCTION entries reference invalid unwind info", ex->bad_unwind_version);
    if (!ex->sorted)
        warn(c, "exception directory is not sorted by function start address");
}

/* ------------------------------------------------------------------ */
/* resources -- warnings only                                           */

typedef struct {
    ctx *c;
    uint32_t base;
    size_t nodes;
    int failed;
} rsrc_walk;

static void rsrc_fail(rsrc_walk *w, const char *what, uint64_t rva)
{
    if (!w->failed) warn(w->c, "resource tree: %s (RVA 0x%llx); resource summary is partial", what, (unsigned long long)rva);
    w->failed = 1;
}

static size_t rsrc_count(rsrc_walk *w, uint32_t dir_off, int depth)
{
    const tw_pe_image *im = w->c->im;
    if (w->failed) return 0;
    if (depth > TW_PE_MAX_RSRC_DEPTH) { rsrc_fail(w, "nesting too deep", (uint64_t)w->base + dir_off); return 0; }

    uint64_t drva = (uint64_t)w->base + dir_off;
    uint8_t h[16];
    if (drva > UINT32_MAX || !tw_pe_read_rva(im, (uint32_t)drva, h, 16)) { rsrc_fail(w, "directory out of bounds", drva); return 0; }
    uint32_t n = (uint32_t)le16(h + 12) + le16(h + 14);
    size_t leaves = 0;
    for (uint32_t i = 0; i < n && !w->failed; i++) {
        if (++w->nodes > TW_PE_MAX_RSRC_NODES) { rsrc_fail(w, "too many nodes (cycle?)", drva); return leaves; }
        uint8_t e[8];
        uint64_t erva = drva + 16 + (uint64_t)i * 8;
        if (erva > UINT32_MAX || !tw_pe_read_rva(im, (uint32_t)erva, e, 8)) { rsrc_fail(w, "entry out of bounds", erva); return leaves; }
        uint32_t od = le32(e + 4);
        if (od & 0x80000000u) {
            leaves += rsrc_count(w, od & 0x7fffffffu, depth + 1);
        } else {
            uint64_t lrva = (uint64_t)w->base + od;
            uint8_t de[16];
            if (lrva > UINT32_MAX || !tw_pe_read_rva(im, (uint32_t)lrva, de, 16)) { rsrc_fail(w, "data entry out of bounds", lrva); return leaves; }
            uint32_t data_rva = le32(de), data_size = le32(de + 4);
            if ((uint64_t)data_rva + data_size > im->size_of_image) { rsrc_fail(w, "data entry points outside the image", lrva); return leaves; }
            leaves++;
        }
    }
    return leaves;
}

static const char *rsrc_name(ctx *c, uint64_t rva)
{
    const tw_pe_image *im = c->im;
    uint16_t len;
    if (rva + 2 > UINT32_MAX || !rd16(im, rva, &len)) return NULL;
    size_t shown = len > 128 ? 128 : len;
    const uint8_t *p = ptr_rva(im, (uint32_t)(rva + 2), (uint64_t)shown * 2);
    if (!p) return NULL;
    /* escaped ASCII: printable ASCII as-is, everything else as \u{XXXX} */
    size_t cap = shown * 10 + 4;
    char *out = tw_arena_alloc(im->arena, cap);
    if (!out) return NULL;
    size_t o = 0;
    for (size_t i = 0; i < shown; i++) {
        uint32_t cp = le16(p + i * 2);
        if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < shown) {
            uint32_t lo = le16(p + (i + 1) * 2);
            if (lo >= 0xdc00 && lo <= 0xdfff) {
                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                i++;
            }
        }
        if (cp >= 0x20 && cp < 0x7f && cp != '\\')
            out[o++] = (char)cp;
        else
            o += (size_t)snprintf(out + o, cap - o, "\\u{%X}", cp);
    }
    if (len > shown) { memcpy(out + o, "...", 3); o += 3; }
    out[o] = '\0';
    return out;
}

static void parse_resources(ctx *c)
{
    tw_pe_image *im = c->im;
    const tw_pe_datadir *d = &im->dirs[TW_PE_DIR_RESOURCE];
    if (im->ndirs <= TW_PE_DIR_RESOURCE || !d->rva) return;

    rsrc_walk w = { .c = c, .base = d->rva };
    uint8_t h[16];
    if (!tw_pe_read_rva(im, d->rva, h, 16)) {
        warn(c, "resource directory is out of bounds");
        return;
    }
    uint32_t n = (uint32_t)le16(h + 12) + le16(h + 14);
    vec v = { .elem = sizeof(tw_pe_rsrc_type) };
    for (uint32_t i = 0; i < n && !w.failed; i++) {
        if (++w.nodes > TW_PE_MAX_RSRC_NODES) { rsrc_fail(&w, "too many nodes", d->rva); break; }
        uint8_t e[8];
        uint64_t erva = (uint64_t)d->rva + 16 + (uint64_t)i * 8;
        if (erva > UINT32_MAX || !tw_pe_read_rva(im, (uint32_t)erva, e, 8)) { rsrc_fail(&w, "type entry out of bounds", erva); break; }
        uint32_t nm = le32(e), od = le32(e + 4);
        tw_pe_rsrc_type t = { 0 };
        if (nm & 0x80000000u) {
            t.name = rsrc_name(c, (uint64_t)d->rva + (nm & 0x7fffffffu));
            if (!t.name) t.name = "<invalid name>";
        } else {
            t.id = nm;
        }
        if (od & 0x80000000u)
            t.leaves = rsrc_count(&w, od & 0x7fffffffu, 1);
        else
            t.leaves = 1;
        im->resources.total_leaves += t.leaves;
        if (!vec_push(&v, &t)) break;
    }
    im->resources.present = 1;
    im->resources.ntypes = v.n;
    im->resources.types = vec_finish(c, &v);
    if (v.n && !im->resources.types) im->resources.ntypes = 0;
}

/* ------------------------------------------------------------------ */
/* public entry points                                                  */

int tw_pe_is_dll(const tw_pe_image *im)
{
    return (im->characteristics & TW_PE_FILE_DLL) != 0;
}

tw_pe_status tw_pe_parse(const uint8_t *data, size_t size, tw_pe_image *img, tw_pe_error *err)
{
    tw_pe_error dummy;
    if (!err) err = &dummy;
    memset(err, 0, sizeof(*err));
    memset(img, 0, sizeof(*img));
    img->data = data;
    img->size = size;

    ctx c = { .im = img, .err = err };

    if (size > TW_PE_MAX_FILE_SIZE) return bad(&c, "file is larger than %llu bytes", (unsigned long long)TW_PE_MAX_FILE_SIZE);

    img->arena = tw_arena_new();
    if (!img->arena) return nomem(&c);
    img->warnings = tw_arena_calloc(img->arena, TW_PE_MAX_WARNINGS, sizeof(char *));
    if (!img->warnings) return nomem(&c);

    tw_pe_status st;
    if ((st = parse_headers(&c)) != TW_PE_OK) return st;
    if ((st = parse_sections(&c)) != TW_PE_OK) return st;
    check_dirs(&c);

    vec dlls = { .elem = sizeof(tw_pe_import_dll) };
    if ((st = parse_imports(&c, &dlls)) != TW_PE_OK) { free(dlls.p); return st; }
    if ((st = parse_delay_imports(&c, &dlls)) != TW_PE_OK) { free(dlls.p); return st; }
    img->nimports = dlls.n;
    img->imports = vec_finish(&c, &dlls);
    if (dlls.n && !img->imports) return nomem(&c);

    if ((st = parse_exports(&c)) != TW_PE_OK) return st;
    if ((st = parse_relocs(&c)) != TW_PE_OK) return st;
    if ((st = parse_tls(&c)) != TW_PE_OK) return st;
    parse_exceptions(&c);
    parse_resources(&c);

    if (img->ndirs > TW_PE_DIR_CLR_RUNTIME && img->dirs[TW_PE_DIR_CLR_RUNTIME].rva)
        warn(&c, "image is a .NET (CLR) assembly; managed code needs a CLR runtime");

    err->status = TW_PE_OK;
    return TW_PE_OK;
}

tw_pe_status tw_pe_load_file(const char *path, tw_pe_image *img, tw_pe_error *err)
{
    tw_pe_error dummy;
    if (!err) err = &dummy;
    memset(err, 0, sizeof(*err));
    memset(img, 0, sizeof(*img));

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        err->status = TW_PE_ERR_IO;
        snprintf(err->msg, sizeof(err->msg), "cannot open: %s", strerror(errno));
        return TW_PE_ERR_IO;
    }
    struct stat sb;
    if (fstat(fd, &sb) != 0) {
        int e = errno;
        close(fd);
        err->status = TW_PE_ERR_IO;
        snprintf(err->msg, sizeof(err->msg), "cannot stat: %s", strerror(e));
        return TW_PE_ERR_IO;
    }
    if (!S_ISREG(sb.st_mode)) {
        close(fd);
        err->status = TW_PE_ERR_IO;
        snprintf(err->msg, sizeof(err->msg), "not a regular file");
        return TW_PE_ERR_IO;
    }
    if ((uint64_t)sb.st_size > TW_PE_MAX_FILE_SIZE) {
        close(fd);
        err->status = TW_PE_ERR_MALFORMED;
        snprintf(err->msg, sizeof(err->msg), "file is larger than %llu bytes", (unsigned long long)TW_PE_MAX_FILE_SIZE);
        return TW_PE_ERR_MALFORMED;
    }
    size_t size = (size_t)sb.st_size;
    uint8_t *buf = malloc(size ? size : 1);
    if (!buf) {
        close(fd);
        err->status = TW_PE_ERR_NOMEM;
        snprintf(err->msg, sizeof(err->msg), "out of memory");
        return TW_PE_ERR_NOMEM;
    }
    size_t got = 0;
    while (got < size) {
        ssize_t r = read(fd, buf + got, size - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) {
            int e = errno;
            free(buf);
            close(fd);
            err->status = TW_PE_ERR_IO;
            snprintf(err->msg, sizeof(err->msg), "read failed: %s", r == 0 ? "unexpected end of file" : strerror(e));
            return TW_PE_ERR_IO;
        }
        got += (size_t)r;
    }
    close(fd);

    tw_pe_status st = tw_pe_parse(buf, size, img, err);
    img->owned = buf;
    return st;
}

void tw_pe_free(tw_pe_image *img)
{
    if (!img) return;
    tw_arena_free(img->arena);
    free(img->owned);
    memset(img, 0, sizeof(*img));
}
