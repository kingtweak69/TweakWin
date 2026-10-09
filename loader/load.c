#define _GNU_SOURCE
#include "load.h"

#include "../common/debug.h"
#include "../runtime/modules.h"
#include "../runtime/vmem.h"
#include "../rt/rt.h"
#include "../backend/kb.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
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
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

static tw_loaded *g_current;

tw_loaded *tw_current_process(void)
{
    return g_current;
}

const char *tw_load_status_name(tw_load_status st)
{
    switch (st) {
    case TW_LOAD_OK:                    return "ok";
    case TW_LOAD_ERR_IO:                return "i/o error";
    case TW_LOAD_ERR_NOMEM:             return "out of memory";
    case TW_LOAD_ERR_MALFORMED:         return "malformed";
    case TW_LOAD_ERR_UNSUPPORTED:       return "unsupported";
    case TW_LOAD_ERR_MAP:               return "loader";
    case TW_LOAD_ERR_RELOC:             return "relocation";
    case TW_LOAD_ERR_UNRESOLVED_DLL:    return "unresolved DLL";
    case TW_LOAD_ERR_UNRESOLVED_SYMBOL: return "unresolved symbol";
    case TW_LOAD_ERR_ENTRY:             return "entry point";
    case TW_LOAD_ERR_RUNTIME:           return "runtime";
    default:                            return "?";
    }
}

static tw_load_status fail(tw_loaded *im, tw_load_status st, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static tw_load_status fail(tw_loaded *im, tw_load_status st, const char *fmt, ...)
{
    va_list ap;
    im->status = st;
    va_start(ap, fmt);
    /* fail() is printf-format checked at its call sites. Clang's fortified
     * vsnprintf wrapper does not propagate that guarantee to fmt here. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
    vsnprintf(im->err, sizeof(im->err), fmt, ap);
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
    va_end(ap);
    return st;
}

#if defined(__GNUC__)
#pragma GCC diagnostic push
#endif

static size_t host_page(void)
{
    long n = sysconf(_SC_PAGESIZE);
    return n > 0 ? (size_t)n : 4096u;
}

static uint64_t align_up_u64(uint64_t v, uint64_t a)
{
    if (a <= 1) return v;
    uint64_t r = v % a;
    if (r == 0) return v;
    if (v > UINT64_MAX - (a - r)) return 0;
    return v + (a - r);
}

static int add_ovf(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a > UINT64_MAX - b) return 1;
    *out = a + b;
    return 0;
}

static uint16_t rd_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd_le64(const uint8_t *p)
{
    return (uint64_t)rd_le32(p) | ((uint64_t)rd_le32(p + 4) << 32);
}

static void wr_le64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

static uint32_t section_vsize(const tw_pe_section *s)
{
    return s->virtual_size ? s->virtual_size : s->raw_size;
}

static int pe_to_load(tw_pe_status st)
{
    switch (st) {
    case TW_PE_OK:             return TW_LOAD_OK;
    case TW_PE_ERR_IO:         return TW_LOAD_ERR_IO;
    case TW_PE_ERR_NOMEM:      return TW_LOAD_ERR_NOMEM;
    case TW_PE_ERR_MALFORMED:  return TW_LOAD_ERR_MALFORMED;
    case TW_PE_ERR_UNSUPPORTED:return TW_LOAD_ERR_UNSUPPORTED;
    default:                   return TW_LOAD_ERR_IO;
    }
}

static int add_region(tw_loaded *im, uint64_t start, uint64_t end, int prot)
{
    if (start >= end) return 1;
    if (im->nregions >= TW_MAX_REGIONS) return 0;
    im->regions[im->nregions].start = start;
    im->regions[im->nregions].end = end;
    im->regions[im->nregions].prot = prot;
    im->nregions++;
    return 1;
}

static int range_ok(const tw_loaded *im, uint64_t addr, uint64_t len, int need)
{
    if (len == 0) return 1;
    uint64_t end;
    if (add_ovf(addr, len, &end)) return 0;
    for (size_t i = 0; i < im->nregions; i++) {
        const tw_region *r = &im->regions[i];
        if (addr >= r->start && end <= r->end && (r->prot & need) == need)
            return 1;
    }
    if (tw_vmem_check(addr, len, need)) return 1;
    /* rt/ allocations (TEB, PEB, process parameters, TLS blocks, thread
     * stacks) live in the backend VM. Accept any span that is committed
     * there with the required protection; this is thread-safe and works
     * identically on the host and on TweakKernel M4. */
    if (tw_rt_guest_check(addr, len, need)) return 1;
    return 0;
}

int tw_guest_readable(const tw_loaded *im, uint64_t addr, uint64_t len)
{
    return im && range_ok(im, addr, len, PROT_READ);
}

int tw_guest_writable(const tw_loaded *im, uint64_t addr, uint64_t len)
{
    return im && range_ok(im, addr, len, PROT_READ | PROT_WRITE);
}

static tw_load_status check_runnable(tw_loaded *im)
{
    const tw_pe_image *pe = &im->pe;
    if (tw_pe_is_dll(pe))
        return fail(im, TW_LOAD_ERR_UNSUPPORTED, "DLLs cannot be used with 'tweakwin run'");
    if (pe->subsystem != 3)
        return fail(im, TW_LOAD_ERR_UNSUPPORTED, "only the Windows Console subsystem is implemented");
    if (pe->entry_rva == 0)
        return fail(im, TW_LOAD_ERR_ENTRY, "image has no entry point");
    int si = tw_pe_section_for_rva(pe, pe->entry_rva);
    if (si < 0)
        return fail(im, TW_LOAD_ERR_ENTRY, "entry point RVA 0x%x is not inside a section", pe->entry_rva);
    if (!(pe->sections[si].characteristics & TW_PE_SCN_MEM_EXECUTE))
        return fail(im, TW_LOAD_ERR_ENTRY, "entry point is not in an executable section");
    return TW_LOAD_OK;
}

static void *try_mmap_at(uint64_t addr, size_t len)
{
    if (addr != (uint64_t)(uintptr_t)addr) return MAP_FAILED;
    void *p = mmap((void *)(uintptr_t)addr, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    return p;
}

static tw_load_status map_image(tw_loaded *im, int policy)
{
    size_t page = host_page();
    uint64_t need = align_up_u64(im->pe.size_of_image, page);
    if (!need)
        return fail(im, TW_LOAD_ERR_MAP, "SizeOfImage 0x%x overflows when rounded to the page size",
                    im->pe.size_of_image);
    size_t len = (size_t)need;
    uint64_t preferred = im->pe.image_base;
    int preferred_ok = (preferred % page) == 0 && preferred == (uint64_t)(uintptr_t)preferred;

    void *p = MAP_FAILED;
    uint8_t *view = NULL;
    size_t map_len = len;
    void *map_ptr = NULL;

    if (policy != TW_BASE_FORCE_RELOCATE && preferred_ok) {
        p = try_mmap_at(preferred, len);
        if (p != MAP_FAILED) {
            map_ptr = p;
            view = p;
            im->base = preferred;
        } else if (policy == TW_BASE_FORCE_PREFERRED) {
            return fail(im, TW_LOAD_ERR_MAP, "cannot map at preferred ImageBase 0x%" PRIx64 ": %s",
                        preferred, strerror(errno));
        }
    }

    if (p == MAP_FAILED) {
        /* Pad by one page so we can slide off the preferred base if mmap hands it back. */
        map_len = len + page;
        p = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            return fail(im, TW_LOAD_ERR_MAP, "mmap failed: %s", strerror(errno));
        map_ptr = p;
        if ((uint64_t)(uintptr_t)p == preferred) {
            /* One pad page in front so the image is not at ImageBase. */
            if (munmap(p, page) != 0) {
                munmap(p, map_len);
                return fail(im, TW_LOAD_ERR_MAP, "munmap of relocation pad failed: %s", strerror(errno));
            }
            view = (uint8_t *)p + page;
            map_ptr = view;
            map_len = len;
            im->base = (uint64_t)(uintptr_t)view;
        } else {
            view = p;
            im->base = (uint64_t)(uintptr_t)p;
            if (munmap((uint8_t *)p + len, page) != 0) {
                munmap(p, map_len);
                return fail(im, TW_LOAD_ERR_MAP, "munmap of trailing pad failed: %s", strerror(errno));
            }
            map_ptr = p;
            map_len = len;
        }
        if (policy == TW_BASE_FORCE_RELOCATE && im->base == preferred) {
            munmap(p, map_len);
            return fail(im, TW_LOAD_ERR_MAP, "could not map away from preferred ImageBase 0x%" PRIx64, preferred);
        }
    }

    im->map_ptr = map_ptr;
    im->map_len = map_len;
    im->image = view;
    im->image_size = im->pe.size_of_image;
    im->preferred = preferred;
    im->delta = (int64_t)(im->base - preferred);
    TW_DEBUG(TW_DBG_MEMORY, "mapped SizeOfImage 0x%x at 0x%" PRIx64 " (preferred 0x%" PRIx64 ", delta %+lld)",
             im->pe.size_of_image, im->base, preferred, (long long)im->delta);
    return TW_LOAD_OK;
}

static tw_load_status copy_sections(tw_loaded *im)
{
    const tw_pe_image *pe = &im->pe;
    uint32_t hdr = pe->size_of_headers;
    if (hdr > pe->size_of_image) hdr = pe->size_of_image;
    if ((uint64_t)hdr > pe->size) hdr = (uint32_t)pe->size;
    memcpy(im->image, pe->data, hdr);

    for (uint16_t i = 0; i < pe->nsections; i++) {
        const tw_pe_section *s = &pe->sections[i];
        uint32_t vsz = section_vsize(s);
        uint64_t dest_end;
        if (add_ovf(s->virtual_address, vsz, &dest_end) || dest_end > pe->size_of_image)
            return fail(im, TW_LOAD_ERR_MALFORMED, "section %s extends past SizeOfImage",
                        s->long_name ? s->long_name : s->name);

        uint32_t copy = s->raw_size < vsz ? s->raw_size : vsz;
        if (copy) {
            uint64_t src_end;
            if (add_ovf(s->raw_ptr, copy, &src_end) || src_end > pe->size)
                return fail(im, TW_LOAD_ERR_MALFORMED, "section %s raw data extends past end of file",
                            s->long_name ? s->long_name : s->name);
            memcpy(im->image + s->virtual_address, pe->data + s->raw_ptr, copy);
        }
        /* Virtual tail is already zero from anonymous mmap. */
        TW_DEBUG(TW_DBG_MEMORY, "section %s: copied 0x%x bytes to RVA 0x%x (vsize 0x%x)",
                 s->long_name ? s->long_name : s->name, copy, s->virtual_address, vsz);
    }
    return TW_LOAD_OK;
}

static tw_load_status apply_relocs(tw_loaded *im)
{
    const tw_pe_image *pe = &im->pe;
    const tw_pe_datadir *d = &pe->dirs[TW_PE_DIR_BASERELOC];
    int64_t delta = im->delta;

    if (pe->ndirs <= TW_PE_DIR_BASERELOC || !d->rva || !d->size) {
        if (delta != 0)
            return fail(im, TW_LOAD_ERR_RELOC,
                        "image has no relocations but was not loaded at ImageBase 0x%" PRIx64, im->preferred);
        return TW_LOAD_OK;
    }
    if ((uint64_t)d->rva + d->size > pe->size_of_image)
        return fail(im, TW_LOAD_ERR_RELOC, "relocation directory extends past SizeOfImage");

    const uint8_t *base = im->image + d->rva;
    uint32_t off = 0;
    size_t applied = 0;
    while (off < d->size) {
        if (d->size - off < 8)
            return fail(im, TW_LOAD_ERR_RELOC, "truncated relocation block");
        uint32_t page = rd_le32(base + off);
        uint32_t bsize = rd_le32(base + off + 4);
        if (bsize < 8 || bsize > d->size - off || (bsize & 1))
            return fail(im, TW_LOAD_ERR_RELOC, "relocation block has invalid size 0x%x", bsize);
        uint32_t n = (bsize - 8) / 2;
        for (uint32_t k = 0; k < n; k++) {
            uint16_t e = rd_le16(base + off + 8 + k * 2);
            unsigned type = e >> 12;
            uint32_t target = page + (e & 0xfff);
            switch (type) {
            case TW_PE_REL_ABSOLUTE:
                break;
            case TW_PE_REL_DIR64:
                if ((uint64_t)target + 8 > pe->size_of_image)
                    return fail(im, TW_LOAD_ERR_RELOC, "DIR64 relocation target 0x%x is outside the image", target);
                {
                    uint64_t val = rd_le64(im->image + target);
                    wr_le64(im->image + target, (uint64_t)(val + (uint64_t)delta));
                    applied++;
                }
                break;
            default:
                return fail(im, TW_LOAD_ERR_UNSUPPORTED,
                            "relocation type %s (%u) is not applied by this loader",
                            tw_pe_reloc_type_name(type) ? tw_pe_reloc_type_name(type) : "unknown", type);
            }
        }
        off += bsize;
    }
    TW_DEBUG(TW_DBG_LOADER, "applied %zu DIR64 relocation(s), delta %+lld", applied, (long long)delta);
    return TW_LOAD_OK;
}

static tw_load_status patch_imports(tw_loaded *im)
{
    const tw_pe_image *pe = &im->pe;
    tw_modules_init();
    for (size_t i = 0; i < pe->nimports; i++) {
        const tw_pe_import_dll *d = &pe->imports[i];
        if (d->delayed) {
            TW_DEBUG(TW_DBG_IMPORTS, "skipping delay-load DLL %s", d->dll);
            continue;
        }
        if (!tw_modules_find(d->dll))
            return fail(im, TW_LOAD_ERR_UNRESOLVED_DLL, "unknown DLL '%s'", d->dll ? d->dll : "(null)");

        for (size_t j = 0; j < d->nfns; j++) {
            const tw_pe_import_fn *fn = &d->fns[j];
            char why[192];
            uint64_t addr = tw_modules_resolve(d->dll, fn->name, fn->ordinal, fn->by_ordinal, why, sizeof(why));
            if (!addr)
                return fail(im, TW_LOAD_ERR_UNRESOLVED_SYMBOL, "%s", why);
            uint32_t slot = fn->iat_rva;
            if (!slot || (uint64_t)slot + 8 > pe->size_of_image)
                return fail(im, TW_LOAD_ERR_MALFORMED, "IAT slot for %s is outside the image",
                            fn->name ? fn->name : "?");
            wr_le64(im->image + slot, addr);
            TW_DEBUG(TW_DBG_IMPORTS, "IAT %s!%s -> 0x%" PRIx64 " (RVA 0x%x)",
                     d->dll, fn->by_ordinal ? "(ordinal)" : fn->name, addr, slot);
        }
    }
    return TW_LOAD_OK;
}

static int section_prot(uint32_t ch)
{
    int prot = 0;
    if (ch & TW_PE_SCN_MEM_READ) prot |= PROT_READ;
    if (ch & TW_PE_SCN_MEM_WRITE) prot |= PROT_WRITE;
    if (ch & TW_PE_SCN_MEM_EXECUTE) prot |= PROT_EXEC;
    /* After relocations and IAT patching, drop W from W+X (W^X). */
    if ((prot & PROT_WRITE) && (prot & PROT_EXEC))
        prot &= ~PROT_WRITE;
    if (prot == 0) prot = PROT_READ;
    return prot;
}

static tw_load_status protect_image(tw_loaded *im)
{
    size_t page = host_page();
    const tw_pe_image *pe = &im->pe;
    uint8_t *base = im->image;

    /* Header pages, up to the first section (or SizeOfImage). */
    uint32_t hdr_end = pe->size_of_headers;
    if (pe->nsections) {
        uint32_t first = pe->sections[0].virtual_address;
        if (first < hdr_end) hdr_end = first;
        else hdr_end = first;
    }
    if (hdr_end == 0) hdr_end = (uint32_t)page;
    if (hdr_end > pe->size_of_image) hdr_end = pe->size_of_image;
    size_t hdr_len = (size_t)align_up_u64(hdr_end, page);
    if (hdr_len > pe->size_of_image) hdr_len = pe->size_of_image;
    if (hdr_len) {
        if (mprotect(base, hdr_len, PROT_READ) != 0)
            return fail(im, TW_LOAD_ERR_MAP, "mprotect headers failed: %s", strerror(errno));
        if (!add_region(im, im->base, im->base + hdr_len, PROT_READ))
            return fail(im, TW_LOAD_ERR_NOMEM, "too many memory regions");
    }

    for (uint16_t i = 0; i < pe->nsections; i++) {
        const tw_pe_section *s = &pe->sections[i];
        uint32_t vsz = section_vsize(s);
        if (!vsz) continue;
        uint64_t start = s->virtual_address;
        uint64_t end = align_up_u64(start + vsz, page);
        if (!end || end > align_up_u64(pe->size_of_image, page))
            end = align_up_u64(pe->size_of_image, page);
        /* Do not mprotect below the section RVA (would overlap previous page). */
        start &= ~(uint64_t)(page - 1);
        size_t len = (size_t)(end - start);
        if (!len) continue;
        int prot = section_prot(s->characteristics);
        if (mprotect(base + start, len, prot) != 0)
            return fail(im, TW_LOAD_ERR_MAP, "mprotect section %s failed: %s",
                        s->long_name ? s->long_name : s->name, strerror(errno));
        if (!add_region(im, im->base + start, im->base + start + len, prot))
            return fail(im, TW_LOAD_ERR_NOMEM, "too many memory regions");
        TW_DEBUG(TW_DBG_MEMORY, "protect %s RVA 0x%" PRIx64 "+0x%zx prot %c%c%c",
                 s->long_name ? s->long_name : s->name, start, len,
                 (prot & PROT_READ) ? 'R' : '-',
                 (prot & PROT_WRITE) ? 'W' : '-',
                 (prot & PROT_EXEC) ? 'X' : '-');
    }
    return TW_LOAD_OK;
}

static tw_load_status map_stack(tw_loaded *im)
{
    size_t page = host_page();
    uint64_t want = im->pe.stack_reserve ? im->pe.stack_reserve : (1ull << 20);
    if (want < 64ull * 1024) want = 64ull * 1024;
    if (want > 8ull * 1024 * 1024) want = 8ull * 1024 * 1024;
    want = align_up_u64(want, page);
    size_t usable = (size_t)want;
    size_t total = usable + page;
    uint8_t *p = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return fail(im, TW_LOAD_ERR_MAP, "stack mmap failed: %s", strerror(errno));
    if (mprotect(p, page, PROT_NONE) != 0) {
        munmap(p, total);
        return fail(im, TW_LOAD_ERR_MAP, "stack guard page failed: %s", strerror(errno));
    }
    im->stack_map = p;
    im->stack_map_len = total;
    im->stack = p + page;
    im->stack_len = usable;
    if (!add_region(im, (uint64_t)(uintptr_t)im->stack,
                    (uint64_t)(uintptr_t)im->stack + im->stack_len,
                    PROT_READ | PROT_WRITE))
        return fail(im, TW_LOAD_ERR_NOMEM, "too many memory regions");
    TW_DEBUG(TW_DBG_MEMORY, "guest stack %p size 0x%zx (guard page below)", (void *)im->stack, im->stack_len);
    return TW_LOAD_OK;
}

tw_load_status tw_load(const char *path, int base_policy, tw_loaded *out, tw_pe_error *perr)
{
    tw_pe_error dummy;
    if (!perr) perr = &dummy;
    memset(out, 0, sizeof(*out));

    tw_pe_status pst = tw_pe_load_file(path, &out->pe, perr);
    if (pst != TW_PE_OK) {
        out->status = (tw_load_status)pe_to_load(pst);
        snprintf(out->err, sizeof(out->err), "%s", perr->msg[0] ? perr->msg : tw_pe_status_name(pst));
        return out->status;
    }

    tw_load_status st;
    if ((st = check_runnable(out)) != TW_LOAD_OK) return st;
    if ((st = map_image(out, base_policy)) != TW_LOAD_OK) return st;
    if ((st = copy_sections(out)) != TW_LOAD_OK) return st;
    if ((st = apply_relocs(out)) != TW_LOAD_OK) return st;
    if ((st = patch_imports(out)) != TW_LOAD_OK) return st;
    if ((st = protect_image(out)) != TW_LOAD_OK) return st;
    if ((st = map_stack(out)) != TW_LOAD_OK) return st;
    /* Let the backend attribute faults in the image text and accept the
     * guest stack for exception records (no-op on TweakKernel M4). */
    tw_kb_fault_region_add(out->base, out->image_size, 0);
    tw_kb_fault_region_add((uint64_t)(uintptr_t)out->stack, out->stack_len, 1);
    out->status = TW_LOAD_OK;
    return TW_LOAD_OK;
}

void tw_unload(tw_loaded *im)
{
    if (!im) return;
    tw_kb_fault_region_clear();
    if (g_current == im) g_current = NULL;
    if (im->stack_map && im->stack_map_len)
        munmap(im->stack_map, im->stack_map_len);
    if (im->map_ptr && im->map_len)
        munmap(im->map_ptr, im->map_len);
    tw_pe_free(&im->pe);
    memset(im, 0, sizeof(*im));
}

/* ------------------------------------------------------------------ */
/* Guest entry (Microsoft x64 ABI).                                    */

#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
#define TW_ASAN 1
void __sanitizer_start_switch_fiber(void **fake_stack_save, const void *bottom, size_t size);
void __sanitizer_finish_switch_fiber(void *fake_stack_save, const void **bottom_old, size_t *size_old);
#else
#define TW_ASAN 0
#endif

__attribute__((no_sanitize("address"), noreturn))
void tw_guest_exit_longjmp(tw_loaded *im)
{
#if TW_ASAN
    __sanitizer_start_switch_fiber(&im->asan_fake_stack, im->host_stack_bottom, im->host_stack_size);
#endif
    longjmp(im->exit_jmp, 1);
}

__attribute__((noinline, used, no_sanitize("address")))
static void guest_returned(void)
{
    tw_loaded *im = g_current;
    if (!im) _exit(7);
    im->did_exit = 0;
    im->status = TW_LOAD_ERR_RUNTIME;
    snprintf(im->err, sizeof(im->err), "guest returned from the entry point without calling ExitProcess");
    tw_guest_exit_longjmp(im);
}

/*
 * Guest RET lands here with whatever alignment the guest left. Force
 * 16-byte alignment, then CALL the C helper (SysV entry wants RSP ≡ 8).
 */
__attribute__((naked, noreturn, used))
static void guest_return_thunk(void)
{
    __asm__ volatile(
        "andq $-16, %rsp\n\t"
        "call guest_returned\n\t"
        "ud2\n\t"
    );
}

/* Called on the guest stack, before the guest entry point runs. */
__attribute__((noinline, used, no_sanitize("address")))
static void asan_finish_on_guest(tw_loaded *im)
{
#if TW_ASAN
    __sanitizer_finish_switch_fiber(im->asan_fake_stack, &im->host_stack_bottom, &im->host_stack_size);
#else
    (void)im;
#endif
}

__attribute__((naked, noinline, noreturn))
static void jump_to_guest(uint64_t entry __attribute__((unused)),
                          uintptr_t guest_rsp __attribute__((unused)),
                          uint64_t ret_fn __attribute__((unused)),
                          tw_loaded *im __attribute__((unused)))
{
    /*
     * SysV arguments: entry in rdi, guest_rsp in rsi, ret_fn in rdx, im in rcx.
     * guest_rsp is 16-byte aligned. PUSH of the return address leaves
     * RSP ≡ 8 (mod 16), which is the Windows x64 function-entry state.
     * This function never returns; the guest calls ExitProcess or RETs
     * to guest_return_thunk, both of which longjmp back to tw_execute.
     */
    __asm__ volatile(
        "movq %rdi, %r12\n\t"
        "movq %rcx, %r13\n\t"
        "movq %rsi, %rsp\n\t"
        "pushq %rdx\n\t"
        "subq $8, %rsp\n\t"
        "movq %r13, %rdi\n\t"
        "call asan_finish_on_guest\n\t"
        "addq $8, %rsp\n\t"
        "cld\n\t"
        "xorl %eax, %eax\n\t"
        "xorl %ecx, %ecx\n\t"
        "xorl %edx, %edx\n\t"
        "xorl %esi, %esi\n\t"
        "xorl %edi, %edi\n\t"
        "xorl %ebp, %ebp\n\t"
        "xorq %rbx, %rbx\n\t"
        "xorq %r8, %r8\n\t"
        "xorq %r9, %r9\n\t"
        "xorq %r10, %r10\n\t"
        "xorq %r11, %r11\n\t"
        "xorq %r13, %r13\n\t"
        "jmpq *%r12\n\t"
    );
}

__attribute__((no_sanitize("address")))
tw_load_status tw_execute(tw_loaded *im, uint32_t *guest_exit)
{
    if (!im || !im->image) return TW_LOAD_ERR_ENTRY;
    uint64_t entry_va = im->base + im->pe.entry_rva;
    if (im->pe.entry_rva >= im->pe.size_of_image)
        return fail(im, TW_LOAD_ERR_ENTRY, "entry point is outside the mapped image");

    uintptr_t top = (uintptr_t)(im->stack + im->stack_len);
    top &= ~(uintptr_t)15;

    uint64_t ret_fn = 0;
    void (*retp)(void) = guest_return_thunk;
    memcpy(&ret_fn, &retp, sizeof retp);

    g_current = im;
    im->did_exit = 0;
    im->guest_exit = 0;
    TW_DEBUG(TW_DBG_LOADER, "entering guest at 0x%" PRIx64 " rsp=0x%llx",
             entry_va, (unsigned long long)top);

    if (setjmp(im->exit_jmp) != 0) {
#if TW_ASAN
        __sanitizer_finish_switch_fiber(im->asan_fake_stack, NULL, NULL);
#endif
        /* Drop the guest GS base before host code (which uses FS for its
         * own TLS) continues on this thread. */
        if (tw_rt_active()) {
            tw_kb_tls_set(TW_KB_TLS_GS, 0);
            tw_rt_set_current_teb(0);
        }
        g_current = NULL;
        if (!im->did_exit) {
            return im->status ? im->status : TW_LOAD_ERR_RUNTIME;
        }
        if (guest_exit) *guest_exit = im->guest_exit;
        return TW_LOAD_OK;
    }

    /* Point GS at the main-thread TEB, as a Windows x86-64 thread expects.
     * The host C library uses FS, so this does not disturb it. */
    if (tw_rt_active() && tw_rt_main_teb()) {
        tw_rt_set_current_teb(tw_rt_main_teb());
        tw_kb_tls_set(TW_KB_TLS_GS, tw_rt_main_teb());
        /* PE TLS process-attach callbacks run here, with GS pointing at the
         * TEB, so a callback that touches thread-local data is safe. */
        tw_rt_tls_run_callbacks(1 /* DLL_PROCESS_ATTACH */);
    }

#if TW_ASAN
    __sanitizer_start_switch_fiber(&im->asan_fake_stack, im->stack, im->stack_len);
#endif
    jump_to_guest(entry_va, top, ret_fn, im);
}

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
