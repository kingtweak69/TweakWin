/*
 * Unit tests for the PE32+ loader and the M1 kernel32 surface.
 * Run: build/test_loader FIXTURE_DIR
 * Built with ASan + UBSan by `make unit`.
 */

#include "../../loader/load.h"
#include "../../runtime/modules.h"
#include "../../runtime/winapi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

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
        if (_a && _b && strstr(_a, _b)) g_pass++;                               \
        else { g_fail++; fprintf(stderr, "FAIL %s:%d: %s contains \"%s\" (got \"%s\")\n", \
                                 __FILE__, __LINE__, #a, _b ? _b : "(null)", _a ? _a : "(null)"); } \
    } while (0)

static char *fixture(const char *name)
{
    static char buf[4096];
    snprintf(buf, sizeof(buf), "%s/%s", g_dir, name);
    return buf;
}

static int maps_prot(uint64_t addr, char prot[8])
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long a, b;
        char p[8];
        if (sscanf(line, "%lx-%lx %7s", &a, &b, p) == 3 && addr >= a && addr < b) {
            snprintf(prot, 8, "%s", p);
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static uint64_t rd64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

static void test_preferred_and_relocated(void)
{
    tw_loaded a, b;
    tw_pe_error err;

    tw_load_status st = tw_load(fixture("hello-m1.exe"), TW_BASE_FORCE_PREFERRED, &a, &err);
    CHECK_EQ(st, TW_LOAD_OK);
    if (st != TW_LOAD_OK) {
        fprintf(stderr, "  preferred: %s\n", a.err);
        tw_unload(&a);
        return;
    }
    CHECK_EQ(a.base, a.preferred);
    CHECK_EQ(a.delta, 0);
    CHECK_EQ(a.pe.entry_rva, 0x1000);
    CHECK(a.image[0] == 'M' && a.image[1] == 'Z');

    /* DIR64 slot at RVA 0x3000 holds ImageBase + msg RVA */
    uint64_t msg_va = rd64(a.image + 0x3000);
    CHECK(msg_va > a.base);
    CHECK(msg_va < a.base + a.image_size);
    CHECK(memcmp((void *)(uintptr_t)msg_va, "Hello from TweakWin M1\r\n", 24) == 0);

    /* BSS tail (written out-param at 0x3400) is zero */
    CHECK_EQ(a.image[0x3400], 0);
    CHECK_EQ(a.image[0x3401], 0);
    CHECK_EQ(a.image[0x3402], 0);
    CHECK_EQ(a.image[0x3403], 0);

    /* IAT patched to host functions */
    uint64_t iat0 = rd64(a.image + a.pe.imports[0].fns[0].iat_rva);
    CHECK(iat0 != 0);
    CHECK(iat0 != a.preferred);

    uint32_t code = 0xdead;
    st = tw_execute(&a, &code);
    CHECK_EQ(st, TW_LOAD_OK);
    CHECK_EQ(code, 0);

    st = tw_load(fixture("hello-m1.exe"), TW_BASE_FORCE_RELOCATE, &b, &err);
    CHECK_EQ(st, TW_LOAD_OK);
    if (st != TW_LOAD_OK) {
        fprintf(stderr, "  relocate: %s\n", b.err);
        tw_unload(&a);
        tw_unload(&b);
        return;
    }
    CHECK(b.base != b.preferred);
    CHECK(b.delta != 0);
    uint64_t msg_va_b = rd64(b.image + 0x3000);
    CHECK_EQ(msg_va_b, msg_va + (uint64_t)b.delta);
    CHECK(memcmp((void *)(uintptr_t)msg_va_b, "Hello from TweakWin M1\r\n", 24) == 0);

    code = 0xdead;
    st = tw_execute(&b, &code);
    CHECK_EQ(st, TW_LOAD_OK);
    CHECK_EQ(code, 0);

    tw_unload(&a);
    tw_unload(&b);
}

static void test_exit42(void)
{
    tw_loaded im;
    tw_pe_error err;
    tw_load_status st = tw_load(fixture("exit42.exe"), TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_OK);
    if (st != TW_LOAD_OK) { fprintf(stderr, "  %s\n", im.err); tw_unload(&im); return; }
    uint32_t code = 0;
    st = tw_execute(&im, &code);
    CHECK_EQ(st, TW_LOAD_OK);
    CHECK_EQ(code, 42);
    tw_unload(&im);
}

static void test_placeholder_returns(void)
{
    /* hello.exe .text is xor eax,eax; ret — no ExitProcess. */
    tw_loaded im;
    tw_pe_error err;
    tw_load_status st = tw_load(fixture("hello.exe"), TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_OK);
    if (st != TW_LOAD_OK) { fprintf(stderr, "  %s\n", im.err); tw_unload(&im); return; }
    uint32_t code = 0;
    st = tw_execute(&im, &code);
    CHECK_EQ(st, TW_LOAD_ERR_RUNTIME);
    CHECK_STR(im.err, "returned from the entry point");
    tw_unload(&im);
}

static void test_unknown_dll_and_sym(void)
{
    tw_loaded im;
    tw_pe_error err;
    tw_load_status st = tw_load(fixture("load/unknown-dll.exe"), TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_ERR_UNRESOLVED_DLL);
    CHECK_STR(im.err, "NOSUCH32.dll");
    tw_unload(&im);

    st = tw_load(fixture("load/unknown-sym.exe"), TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_ERR_UNRESOLVED_SYMBOL);
    CHECK_STR(im.err, "NoSuchProcX");
    tw_unload(&im);
}

static void test_unsupported_reloc(void)
{
    tw_loaded im;
    tw_pe_error err;
    tw_load_status st = tw_load(fixture("load/highlow-reloc.exe"), TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_ERR_UNSUPPORTED);
    CHECK_STR(im.err, "HIGHLOW");
    tw_unload(&im);
}

static void test_dll_rejected(void)
{
    tw_loaded im;
    tw_pe_error err;
    tw_load_status st = tw_load(fixture("tweaktest.dll"), TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_ERR_UNSUPPORTED);
    CHECK_STR(im.err, "DLL");
    tw_unload(&im);
}

static void test_malformed_still_malformed(void)
{
    tw_loaded im;
    tw_pe_error err;
    tw_load_status st = tw_load(fixture("bad/not-mz.exe"), TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_ERR_MALFORMED);
    tw_unload(&im);

    st = tw_load(fixture("bad/i386.exe"), TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_ERR_UNSUPPORTED);
    tw_unload(&im);
}

static void test_resolver(void)
{
    tw_modules_init();
    CHECK(tw_modules_find("kernel32.dll") != NULL);
    CHECK(tw_modules_find("KERNEL32.DLL") != NULL);
    CHECK(tw_modules_find("ntdll.dll") != NULL);
    CHECK(tw_modules_find("user32.dll") == NULL);

    char why[128];
    uint64_t p = tw_modules_resolve("kernel32.dll", "WriteFile", 0, 0, why, sizeof(why));
    CHECK(p != 0);
    p = tw_modules_resolve("kernel32.dll", "GetStdHandle", 0, 0, why, sizeof(why));
    CHECK(p != 0);
    p = tw_modules_resolve("kernel32.dll", "ExitProcess", 0, 0, why, sizeof(why));
    CHECK(p != 0);
    p = tw_modules_resolve("kernel32.dll", NULL, 2, 1, why, sizeof(why));
    CHECK(p != 0); /* WriteFile ordinal 2 */
    p = tw_modules_resolve("nosuch.dll", "WriteFile", 0, 0, why, sizeof(why));
    CHECK(p == 0);
    CHECK_STR(why, "unknown DLL");
    p = tw_modules_resolve("ntdll.dll", "NtClose", 0, 0, why, sizeof(why));
    CHECK(p == 0);
    CHECK_STR(why, "unknown symbol");
}

static void test_entry_and_noreloc(void)
{
    tw_loaded im;
    tw_pe_error err;
    tw_load_status st = tw_load(fixture("load/entry-zero.exe"), TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_ERR_ENTRY);
    CHECK_STR(im.err, "no entry point");
    tw_unload(&im);

    st = tw_load(fixture("load/entry-nx.exe"), TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_ERR_ENTRY);
    CHECK_STR(im.err, "not in an executable section");
    tw_unload(&im);

    /* Parser rejects a DIR64 target outside the image before the loader maps it. */
    st = tw_load(fixture("bad/reloc-target-oob.exe"), TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_ERR_MALFORMED);
    tw_unload(&im);

    st = tw_load(fixture("load/no-reloc.exe"), TW_BASE_FORCE_PREFERRED, &im, &err);
    CHECK_EQ(st, TW_LOAD_OK);
    if (st == TW_LOAD_OK) {
        CHECK_EQ(im.delta, 0);
        uint32_t code = 1;
        st = tw_execute(&im, &code);
        CHECK_EQ(st, TW_LOAD_OK);
        CHECK_EQ(code, 0);
    }
    tw_unload(&im);

    st = tw_load(fixture("load/no-reloc.exe"), TW_BASE_FORCE_RELOCATE, &im, &err);
    CHECK_EQ(st, TW_LOAD_ERR_RELOC);
    CHECK_STR(im.err, "no relocations");
    tw_unload(&im);
}

static void test_guest_range(void)
{
    tw_loaded im;
    tw_pe_error err;
    tw_load_status st = tw_load(fixture("hello-m1.exe"), TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_OK);
    if (st != TW_LOAD_OK) { tw_unload(&im); return; }

    CHECK(tw_guest_readable(&im, im.base, 2));
    CHECK(tw_guest_readable(&im, im.base + 0x1000, 16));
    CHECK(!tw_guest_writable(&im, im.base + 0x1000, 16)); /* .text is RX, not W */
    CHECK(tw_guest_writable(&im, im.base + 0x3000, 8));
    CHECK(!tw_guest_readable(&im, im.base + im.image_size, 1));
    CHECK(!tw_guest_readable(&im, 0x1, 8));
    CHECK(tw_guest_writable(&im, (uint64_t)(uintptr_t)im.stack, 16));
    CHECK(!tw_guest_readable(&im, (uint64_t)(uintptr_t)im.stack - 8, 16)); /* guard page */
    for (size_t i = 0; i < im.nregions; i++)
        CHECK((im.regions[i].prot & (PROT_WRITE | PROT_EXEC)) != (PROT_WRITE | PROT_EXEC));
    char prot[8];
    CHECK(maps_prot(im.base + 0x1000, prot) && strcmp(prot, "r-xp") == 0);
    CHECK(maps_prot(im.base + 0x3000, prot) && strcmp(prot, "rw-p") == 0);
    CHECK(maps_prot(im.base, prot) && prot[0] == 'r' && prot[1] == '-' && prot[2] == '-');
    tw_unload(&im);
}

static void test_optional_real(void)
{
    char *p = fixture("hello-m1-real.exe");
    FILE *f = fopen(p, "rb");
    if (!f) { fprintf(stderr, "skip hello-m1-real.exe (run `make hello`)\n"); return; }
    fclose(f);
    tw_loaded im;
    tw_pe_error err;
    tw_load_status st = tw_load(p, TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_OK);
    if (st != TW_LOAD_OK) { fprintf(stderr, "  real: %s\n", im.err); tw_unload(&im); return; }
    uint32_t code = 1;
    st = tw_execute(&im, &code);
    CHECK_EQ(st, TW_LOAD_OK);
    CHECK_EQ(code, 0);
    tw_unload(&im);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: test_loader FIXTURE_DIR\n");
        return 64;
    }
    g_dir = argv[1];
    test_resolver();
    test_preferred_and_relocated();
    test_exit42();
    test_placeholder_returns();
    test_unknown_dll_and_sym();
    test_unsupported_reloc();
    test_dll_rejected();
    test_malformed_still_malformed();
    test_guest_range();
    test_entry_and_noreloc();
    test_optional_real();
    printf("loader: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
