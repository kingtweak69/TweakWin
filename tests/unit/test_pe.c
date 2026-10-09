/*
 * Unit tests for loader/pe. Run: build/test_pe FIXTURE_DIR
 * Built with ASan + UBSan by `make unit`.
 */

#include "../../loader/pe/pe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail, g_pass;
static const char *g_dir;

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (cond) g_pass++;                                                     \
        else { g_fail++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
    } while (0)

#define CHECK_EQ(a, b)                                                          \
    do {                                                                        \
        unsigned long long _a = (unsigned long long)(a), _b = (unsigned long long)(b); \
        if (_a == _b) g_pass++;                                                 \
        else { g_fail++; fprintf(stderr, "FAIL %s:%d: %s == %s (0x%llx != 0x%llx)\n", \
                                 __FILE__, __LINE__, #a, #b, _a, _b); }         \
    } while (0)

#define CHECK_STR(a, b)                                                         \
    do {                                                                        \
        const char *_a = (a), *_b = (b);                                        \
        if (_a && _b && strcmp(_a, _b) == 0) g_pass++;                          \
        else { g_fail++; fprintf(stderr, "FAIL %s:%d: %s == \"%s\" (got \"%s\")\n", \
                                 __FILE__, __LINE__, #a, _b ? _b : "(null)", _a ? _a : "(null)"); } \
    } while (0)

static char *fixture(const char *name)
{
    static char buf[4096];
    snprintf(buf, sizeof(buf), "%s/%s", g_dir, name);
    return buf;
}

static int has_warning(const tw_pe_image *im, const char *needle)
{
    for (size_t i = 0; i < im->nwarnings; i++)
        if (strstr(im->warnings[i], needle)) return 1;
    return 0;
}

static void test_hello(void)
{
    tw_pe_image im;
    tw_pe_error err;
    tw_pe_status st = tw_pe_load_file(fixture("hello.exe"), &im, &err);
    CHECK_EQ(st, TW_PE_OK);
    if (st != TW_PE_OK) { fprintf(stderr, "  %s\n", err.msg); tw_pe_free(&im); return; }

    CHECK_EQ(im.machine, TW_PE_MACHINE_AMD64);
    CHECK_EQ(im.opt_magic, TW_PE_OPT_MAGIC_PE32PLUS);
    CHECK_EQ(im.image_base, 0x140000000ull);
    CHECK_EQ(im.entry_rva, 0x1000);
    CHECK_EQ(im.subsystem, 3);
    CHECK_EQ(im.size_of_image, 0x6000);
    CHECK_EQ(im.nsections, 5);
    CHECK_STR(im.sections[0].name, ".text");
    CHECK_STR(im.sections[4].name, ".reloc");
    CHECK(im.sections[0].characteristics & TW_PE_SCN_MEM_EXECUTE);
    CHECK(!tw_pe_is_dll(&im));

    CHECK_EQ(im.nimports, 1);
    CHECK_STR(im.imports[0].dll, "KERNEL32.dll");
    CHECK_EQ(im.imports[0].nfns, 3);
    CHECK_STR(im.imports[0].fns[0].name, "GetStdHandle");
    CHECK_STR(im.imports[0].fns[1].name, "WriteFile");
    CHECK_STR(im.imports[0].fns[2].name, "ExitProcess");
    CHECK_EQ(im.imports[0].fns[1].iat_rva, im.imports[0].iat_rva + 8);
    CHECK(!im.imports[0].delayed);

    CHECK(im.relocs.present);
    CHECK_EQ(im.relocs.nblocks, 1);
    CHECK_EQ(im.relocs.by_type[TW_PE_REL_DIR64], 1);
    CHECK_EQ(im.relocs.by_type[TW_PE_REL_ABSOLUTE], 1);

    CHECK(im.exceptions.present);
    CHECK_EQ(im.exceptions.count, 1);
    CHECK_EQ(im.exceptions.bad_unwind_version, 0);
    CHECK(!im.exports.present);
    CHECK(!im.tls.present);
    CHECK_EQ(im.nwarnings, 0);

    /* RVA reads: header bytes, section bytes, zero-fill, out of range */
    uint8_t b[4];
    CHECK(tw_pe_read_rva(&im, 0, b, 2));
    CHECK(b[0] == 'M' && b[1] == 'Z');
    CHECK(tw_pe_read_rva(&im, 0x1000, b, 3));
    CHECK(b[0] == 0x31 && b[1] == 0xc0 && b[2] == 0xc3);
    CHECK(!tw_pe_read_rva(&im, 0x7000, b, 1));
    CHECK(!tw_pe_read_rva(&im, 0x100e, b, 4)); /* crosses end of .text's VirtualSize */
    CHECK_EQ(tw_pe_section_for_rva(&im, 0x2004), 1);
    CHECK_EQ(tw_pe_section_for_rva(&im, 0x2fff), -1);  /* past .rdata VirtualSize */

    tw_pe_free(&im);
}

static void test_dll(void)
{
    tw_pe_image im;
    tw_pe_error err;
    tw_pe_status st = tw_pe_load_file(fixture("tweaktest.dll"), &im, &err);
    CHECK_EQ(st, TW_PE_OK);
    if (st != TW_PE_OK) { fprintf(stderr, "  %s\n", err.msg); tw_pe_free(&im); return; }

    CHECK(tw_pe_is_dll(&im));
    CHECK_EQ(im.image_base, 0x180000000ull);

    /* imports: KERNEL32 by name, WS2_32 by ordinal, USER32 delayed */
    CHECK_EQ(im.nimports, 3);
    CHECK_STR(im.imports[0].dll, "KERNEL32.dll");
    CHECK_STR(im.imports[1].dll, "WS2_32.dll");
    CHECK(im.imports[1].fns[0].by_ordinal);
    CHECK_EQ(im.imports[1].fns[0].ordinal, 115);
    CHECK(im.imports[1].fns[0].name == NULL);
    CHECK_STR(im.imports[2].dll, "USER32.dll");
    CHECK(im.imports[2].delayed);
    CHECK_STR(im.imports[2].fns[0].name, "MessageBoxW");

    /* exports sorted by ordinal: 1 Alpha, 2 Beta, 4 (ordinal only), 5 Gamma forwarder */
    CHECK(im.exports.present);
    CHECK_STR(im.exports.dll_name, "tweaktest.dll");
    CHECK_EQ(im.exports.ordinal_base, 1);
    CHECK_EQ(im.exports.nfunctions, 5);
    CHECK_EQ(im.exports.nnames, 3);
    CHECK_EQ(im.exports.nentries, 4);
    if (im.exports.nentries == 4) {
        const tw_pe_export *e = im.exports.entries;
        CHECK_EQ(e[0].ordinal, 1); CHECK_STR(e[0].name, "Alpha"); CHECK_EQ(e[0].rva, 0x1000);
        CHECK_EQ(e[1].ordinal, 2); CHECK_STR(e[1].name, "Beta");  CHECK_EQ(e[1].rva, 0x1010);
        CHECK_EQ(e[2].ordinal, 4); CHECK(e[2].name == NULL);     CHECK_EQ(e[2].rva, 0x1020);
        CHECK_EQ(e[3].ordinal, 5); CHECK_STR(e[3].name, "Gamma");
        CHECK_STR(e[3].forwarder, "KERNEL32.GetTickCount");
        CHECK_EQ(e[3].rva, 0);
    }

    CHECK(im.tls.present);
    CHECK_EQ(im.tls.ncallbacks, 2);
    if (im.tls.ncallbacks == 2) {
        CHECK_EQ(im.tls.callbacks[0], 0x180001020ull);
        CHECK_EQ(im.tls.callbacks[1], 0x180001030ull);
    }
    CHECK_EQ(im.tls.raw_start_va, 0x180004000ull);
    CHECK_EQ(im.tls.zero_fill, 0x10);

    CHECK(im.resources.present);
    CHECK_EQ(im.resources.ntypes, 2);
    CHECK_EQ(im.resources.total_leaves, 2);
    if (im.resources.ntypes == 2) {
        CHECK_STR(im.resources.types[0].name, "TWEAK");
        CHECK(im.resources.types[1].name == NULL);
        CHECK_EQ(im.resources.types[1].id, 16);
    }
    CHECK_EQ(im.relocs.by_type[TW_PE_REL_DIR64], 6);
    CHECK_EQ(im.nwarnings, 0);
    tw_pe_free(&im);
}

/* Every manifest entry: parse must return the expected status and message. */
static void test_manifest(void)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/bad/manifest.tsv", g_dir);
    FILE *f = fopen(path, "r");
    CHECK(f != NULL);
    if (!f) return;
    char line[1024];
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        char *name = strtok(line, "\t");
        char *code = strtok(NULL, "\t");
        char *needle = strtok(NULL, "\t");
        if (!name || !code) continue;
        n++;
        char fp[4096];
        snprintf(fp, sizeof(fp), "%s/bad/%s", g_dir, name);
        tw_pe_image im;
        tw_pe_error err;
        tw_pe_status st = tw_pe_load_file(fp, &im, &err);
        int want = atoi(code);
        tw_pe_status want_st = want == 0 ? TW_PE_OK : want == 2 ? TW_PE_ERR_MALFORMED : TW_PE_ERR_UNSUPPORTED;
        if (st != want_st) {
            g_fail++;
            fprintf(stderr, "FAIL manifest %s: status %d, want %d (%s)\n", name, st, want_st, err.msg);
        } else if (needle && *needle) {
            int found = st == TW_PE_OK ? has_warning(&im, needle) : strstr(err.msg, needle) != NULL;
            if (found) g_pass++;
            else { g_fail++; fprintf(stderr, "FAIL manifest %s: \"%s\" not in \"%s\"\n", name, needle, err.msg); }
        } else {
            g_pass++;
        }
        tw_pe_free(&im);
    }
    fclose(f);
    CHECK(n >= 40);
}

/* Parsing from an in-memory buffer that is not NUL-terminated or padded. */
static void test_truncations(void)
{
    FILE *f = fopen(fixture("hello.exe"), "rb");
    CHECK(f != NULL);
    if (!f) return;
    uint8_t *buf = malloc(1 << 16);
    size_t n = fread(buf, 1, 1 << 16, f);
    fclose(f);
    size_t ok = 0;
    for (size_t len = 0; len <= n; len++) {
        uint8_t *copy = malloc(len ? len : 1);
        memcpy(copy, buf, len);
        tw_pe_image im;
        tw_pe_error err;
        tw_pe_status st = tw_pe_parse(copy, len, &im, &err);
        if (st == TW_PE_OK) ok++;
        CHECK(st == TW_PE_OK || st == TW_PE_ERR_MALFORMED);
        tw_pe_free(&im);
        free(copy);
    }
    CHECK_EQ(ok, 1); /* only the complete file parses */
    free(buf);
}

static void test_optional_real(const char *name, size_t min_imports)
{
    char *p = fixture(name);
    FILE *f = fopen(p, "rb");
    if (!f) { fprintf(stderr, "skip %s (run `make hello` to build it)\n", name); return; }
    fclose(f);
    tw_pe_image im;
    tw_pe_error err;
    tw_pe_status st = tw_pe_load_file(p, &im, &err);
    CHECK_EQ(st, TW_PE_OK);
    if (st == TW_PE_OK) {
        CHECK(im.nimports >= min_imports);
        CHECK_EQ(im.nwarnings, 0);
    } else {
        fprintf(stderr, "  %s: %s\n", name, err.msg);
    }
    tw_pe_free(&im);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: test_pe FIXTURE_DIR\n");
        return 64;
    }
    g_dir = argv[1];
    test_hello();
    test_dll();
    test_manifest();
    test_truncations();
    test_optional_real("hello-real.exe", 1);
    test_optional_real("hello-crt.exe", 5);
    test_optional_real("tweakdll.dll", 3);
    printf("unit: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
