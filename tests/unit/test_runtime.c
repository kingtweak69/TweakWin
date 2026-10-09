/*
 * M2 runtime: handles, LastError, guest pointers, VirtualAlloc, heap,
 * environment, command line, files, timing, and the M2 guest fixtures.
 */

#include "../../kernel32/kernel32.h"
#include "../../loader/load.h"
#include "../../runtime/modules.h"
#include "../../runtime/process.h"
#include "../../runtime/utf.h"
#include "../../runtime/vmem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static char *fixture(const char *name)
{
    static char buf[4096];
    snprintf(buf, sizeof buf, "%s/%s", g_dir, name);
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

static void *gbytes(size_t n)
{
    void *p = tw_vmem_blob(n ? n : 1);
    CHECK(p != NULL);
    return p;
}

static char *gstr(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = gbytes(n);
    if (p) memcpy(p, s, n);
    return p;
}

static void test_utf(void)
{
    uint32_t cp = 0;
    size_t used = 0;
    const uint8_t ok[] = {0xF0, 0x9F, 0x92, 0xA9};
    CHECK(tw_utf8_decode(ok, 4, &cp, &used) == 0);
    CHECK_EQ(cp, 0x1F4A9);
    CHECK_EQ(used, 4);
    const uint8_t bad[] = {0xC0, 0x80};
    CHECK(tw_utf8_decode(bad, 2, &cp, &used) != 0);

    uint16_t w[8];
    size_t need = 0;
    const uint8_t hi[] = "A";
    CHECK(tw_utf8_to_utf16(hi, -1, w, 8, &need, 1) == 0);
    CHECK_EQ(need, 2);
    CHECK_EQ(w[0], 'A');
    CHECK_EQ(w[1], 0);

    uint8_t back[8];
    CHECK(tw_utf16_to_utf8(w, -1, back, 8, &need, 1) == 0);
    CHECK_EQ(back[0], 'A');
    CHECK(tw_cp_ok(65001));
    CHECK(!tw_cp_ok(1252));
}

static int load_hello(tw_loaded *im)
{
    tw_pe_error err;
    tw_load_status st = tw_load(fixture("hello-m1.exe"), TW_BASE_PREFER, im, &err);
    CHECK_EQ(st, TW_LOAD_OK);
    return st == TW_LOAD_OK ? 0 : -1;
}

static void test_cmdline_env_modules(tw_loaded *im)
{
    setenv("TWEAKWIN_GUEST_FROMHOST", "from-host", 1);
    setenv("NOT_FOR_GUEST", "secret", 1);
    char *argv[] = {"dir/prog.exe", "hello", "a b", "say\"x\"", "foo\\", "end \\", NULL};
    CHECK(tw_runtime_bind(im, argv[0], 6, argv) == 0);

    const char *cmd = tw_k32_GetCommandLineA();
    CHECK(cmd != NULL);
    CHECK(strcmp(cmd, "dir\\prog.exe hello \"a b\" \"say\\\"x\\\"\" foo\\ \"end \\\\\"") == 0);

    const uint16_t *wcmd = tw_k32_GetCommandLineW();
    CHECK(wcmd != NULL);
    CHECK_EQ(wcmd[0], 'd');
    CHECK_EQ(wcmd[3], '\\');

    CHECK_EQ(tw_k32_GetStdHandle(TW_STD_OUTPUT_HANDLE), (unsigned long long)(uintptr_t)TW_HANDLE_STDOUT);
    CHECK(tw_k32_GetStdHandle((TW_DWORD)-11) != (TW_HANDLE)(uintptr_t)1);

    char *name = gstr("FROMHOST");
    char *buf = gbytes(64);
    TW_DWORD n = tw_k32_GetEnvironmentVariableA(name, buf, 64);
    CHECK_EQ(n, 9);
    CHECK(buf && strcmp(buf, "from-host") == 0);

    char *secret = gstr("NOT_FOR_GUEST");
    n = tw_k32_GetEnvironmentVariableA(secret, buf, 64);
    CHECK_EQ(n, 0);
    CHECK_EQ(tw_k32_GetLastError(), TW_ERROR_ENVVAR_NOT_FOUND);

    char *cname = gstr("AbC");
    char *cval = gstr("One");
    CHECK(tw_k32_SetEnvironmentVariableA(cname, cval) == TW_TRUE);
    char *lower = gstr("abc");
    n = tw_k32_GetEnvironmentVariableA(lower, buf, 64);
    CHECK_EQ(n, 3);
    CHECK(buf && strcmp(buf, "One") == 0);

    char *empty = gstr("");
    CHECK(tw_k32_SetEnvironmentVariableA(cname, empty) == TW_TRUE);
    n = tw_k32_GetEnvironmentVariableA(lower, buf, 64);
    CHECK_EQ(n, 0);
    CHECK_EQ(tw_k32_GetLastError(), TW_ERROR_SUCCESS);

    CHECK(tw_k32_SetEnvironmentVariableA(cname, NULL) == TW_TRUE);
    n = tw_k32_GetEnvironmentVariableA(lower, buf, 64);
    CHECK_EQ(n, 0);
    CHECK_EQ(tw_k32_GetLastError(), TW_ERROR_ENVVAR_NOT_FOUND);

    char *block = tw_k32_GetEnvironmentStringsA();
    CHECK(block != NULL);
    CHECK(strstr(block, "FROMHOST=from-host") != NULL);
    CHECK(strstr(block, "NOT_FOR_GUEST") == NULL);
    CHECK(tw_k32_FreeEnvironmentStringsA(block) == TW_TRUE);
    CHECK(tw_k32_FreeEnvironmentStringsA(block) == TW_FALSE);
    uint16_t *wblock = tw_k32_GetEnvironmentStringsW();
    CHECK(wblock != NULL && wblock[0] != 0);
    CHECK(tw_k32_FreeEnvironmentStringsW(wblock) == TW_TRUE);

    CHECK((uint64_t)(uintptr_t)tw_k32_GetModuleHandleA(NULL) == im->base);
    char *k32 = gstr("Kernel32.dll");
    void *mh = tw_k32_GetModuleHandleA(k32);
    CHECK(mh != NULL);
    CHECK((uint64_t)(uintptr_t)mh == tw_runtime_k32_base());
    char *modbuf = gbytes(128);
    n = tw_k32_GetModuleFileNameA(mh, modbuf, 128);
    CHECK(n > 0);
    CHECK(modbuf && strcmp(modbuf, "C:\\TweakWin\\kernel32.dll") == 0);
    char *missing = gstr("user32.dll");
    CHECK(tw_k32_GetModuleHandleA(missing) == NULL);
    CHECK_EQ(tw_k32_GetLastError(), TW_ERROR_MOD_NOT_FOUND);

    tw_k32_SetLastError(87);
    CHECK_EQ(tw_k32_GetLastError(), 87);

    tw_runtime_unbind();
}

static void test_memory(tw_loaded *im)
{
    char *argv[] = {"mem.exe", NULL};
    CHECK(tw_runtime_bind(im, argv[0], 1, argv) == 0);

    CHECK(tw_k32_VirtualAlloc((void *)(uintptr_t)0x1000, 4096, TW_MEM_COMMIT | TW_MEM_RESERVE,
                              TW_PAGE_READWRITE) == NULL);
    CHECK_EQ(tw_k32_GetLastError(), TW_ERROR_INVALID_ADDRESS);
    CHECK(tw_k32_VirtualAlloc(NULL, 4096, TW_MEM_COMMIT | TW_MEM_RESERVE,
                              TW_PAGE_EXECUTE_READWRITE) == NULL);

    uint8_t *p = tw_k32_VirtualAlloc(NULL, 100, TW_MEM_COMMIT | TW_MEM_RESERVE, TW_PAGE_READWRITE);
    CHECK(p != NULL);
    p[0] = 0x11;
    p[99] = 0x22;
    char prot[8];
    CHECK(maps_prot((uint64_t)(uintptr_t)p, prot) && strcmp(prot, "rw-p") == 0);

    TW_DWORD *old = gbytes(4);
    CHECK(tw_k32_VirtualProtect(p, 4096, TW_PAGE_EXECUTE_READ, old) == TW_TRUE);
    CHECK_EQ(*old, TW_PAGE_READWRITE);
    CHECK(maps_prot((uint64_t)(uintptr_t)p, prot) && prot[0] == 'r' && prot[2] == 'x' && prot[1] == '-');
    CHECK((prot[0] == 'r' && prot[1] == 'w' && prot[2] == 'x') == 0);

    uint8_t *mbi = gbytes(48);
    TW_SIZE_T qn = tw_k32_VirtualQuery(p, mbi, 48);
    CHECK_EQ(qn, 48);
    uint32_t state = 0, page = 0;
    memcpy(&state, mbi + 32, 4);
    memcpy(&page, mbi + 36, 4);
    CHECK_EQ(state, TW_MEM_COMMIT);
    CHECK_EQ(page, TW_PAGE_EXECUTE_READ);

    CHECK(tw_k32_VirtualFree(p, 0, TW_MEM_RELEASE) == TW_TRUE);
    CHECK(tw_k32_VirtualFree(p, 0, TW_MEM_RELEASE) == TW_FALSE);

    TW_HANDLE heap = tw_k32_GetProcessHeap();
    CHECK(heap != NULL);
    CHECK(tw_k32_CloseHandle(heap) == TW_FALSE);
    uint8_t *b = tw_k32_HeapAlloc(heap, TW_HEAP_ZERO_MEMORY, 32);
    CHECK(b != NULL);
    CHECK_EQ(b[0], 0);
    CHECK_EQ(tw_k32_HeapSize(heap, 0, b), 32);
    b[0] = 0x5A;
    uint8_t *b2 = tw_k32_HeapReAlloc(heap, TW_HEAP_ZERO_MEMORY, b, 64);
    CHECK(b2 != NULL);
    CHECK_EQ(b2[0], 0x5A);
    CHECK_EQ(b2[32], 0);
    CHECK_EQ(tw_k32_HeapSize(heap, 0, b2), 64);
    CHECK(tw_k32_HeapFree(heap, 0, b2) == TW_TRUE);
    CHECK(tw_k32_HeapFree(heap, 0, b2) == TW_FALSE);
    CHECK(tw_k32_HeapFree(heap, 0, NULL) == TW_TRUE);

    char stack_msg[] = "nope";
    TW_DWORD *got = gbytes(4);
    CHECK(tw_k32_WriteFile(TW_HANDLE_STDOUT, stack_msg, 4, got, NULL) == TW_FALSE);
    CHECK_EQ(tw_k32_GetLastError(), TW_ERROR_NOACCESS);
    CHECK(tw_k32_WriteFile(TW_HANDLE_STDOUT, p, 1, got, (void *)1) == TW_FALSE);
    CHECK_EQ(tw_k32_GetLastError(), TW_ERROR_INVALID_PARAMETER);
    CHECK(tw_k32_WriteFile((TW_HANDLE)(uintptr_t)0x1, gstr("x"), 1, got, NULL) == TW_FALSE);
    CHECK_EQ(tw_k32_GetLastError(), TW_ERROR_INVALID_HANDLE);

    /* A VirtualAlloc buffer is a legal WriteFile source. */
    uint8_t *src = tw_k32_VirtualAlloc(NULL, 16, TW_MEM_COMMIT | TW_MEM_RESERVE, TW_PAGE_READWRITE);
    CHECK(src != NULL);
    memcpy(src, "ok", 2);
    CHECK(tw_k32_WriteFile(TW_HANDLE_STDOUT, src, 0, got, NULL) == TW_TRUE);
    tw_k32_VirtualFree(src, 0, TW_MEM_RELEASE);

    tw_runtime_unbind();
}

static void test_files(tw_loaded *im)
{
    char *argv[] = {"file.exe", NULL};
    CHECK(tw_runtime_bind(im, argv[0], 1, argv) == 0);
    unlink("build/m2-unit.txt");

    char *bad1 = gstr("../outside.txt");
    char *bad2 = gstr("/etc/passwd");
    char *bad3 = gstr("C:\\Windows\\note.txt");
    TW_HANDLE h = tw_k32_CreateFileA(bad1, TW_GENERIC_WRITE, 0, NULL, TW_CREATE_ALWAYS,
                                     TW_FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h == TW_INVALID_HANDLE_VALUE);
    CHECK_EQ(tw_k32_GetLastError(), TW_ERROR_INVALID_NAME);
    h = tw_k32_CreateFileA(bad2, TW_GENERIC_READ, 0, NULL, TW_OPEN_EXISTING, 0, NULL);
    CHECK(h == TW_INVALID_HANDLE_VALUE);
    h = tw_k32_CreateFileA(bad3, TW_GENERIC_READ, 0, NULL, TW_OPEN_EXISTING, 0, NULL);
    CHECK(h == TW_INVALID_HANDLE_VALUE);

    char *path = gstr("build/m2-unit.txt");
    h = tw_k32_CreateFileA(path, TW_GENERIC_WRITE, 0, NULL, TW_CREATE_ALWAYS,
                           TW_FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h != TW_INVALID_HANDLE_VALUE);
    CHECK(h != TW_HANDLE_STDOUT);
    CHECK_EQ(tw_k32_GetFileType(h), TW_FILE_TYPE_DISK);
    char *payload = gstr("unit-file");
    TW_DWORD *got = gbytes(4);
    CHECK(tw_k32_WriteFile(h, payload, 9, got, NULL) == TW_TRUE);
    CHECK_EQ(*got, 9);
    CHECK(tw_k32_CloseHandle(h) == TW_TRUE);
    CHECK(tw_k32_WriteFile(h, payload, 1, got, NULL) == TW_FALSE);

    h = tw_k32_CreateFileA(path, TW_GENERIC_READ, 0, NULL, TW_OPEN_EXISTING,
                           TW_FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h != TW_INVALID_HANDLE_VALUE);
    char *rd = gbytes(16);
    CHECK(tw_k32_ReadFile(h, rd, 16, got, NULL) == TW_TRUE);
    CHECK_EQ(*got, 9);
    CHECK(memcmp(rd, "unit-file", 9) == 0);
    CHECK(tw_k32_CloseHandle(h) == TW_TRUE);
    unlink("build/m2-unit.txt");

    int64_t freq = 0, a = 0, b = 0;
    int64_t *gf = gbytes(8);
    int64_t *ga = gbytes(8);
    int64_t *gb = gbytes(8);
    CHECK(tw_k32_QueryPerformanceFrequency(gf) == TW_TRUE);
    memcpy(&freq, gf, 8);
    CHECK_EQ((unsigned long long)freq, 1000000000ull);
    CHECK(tw_k32_QueryPerformanceCounter(ga) == TW_TRUE);
    tw_k32_Sleep(5);
    CHECK(tw_k32_QueryPerformanceCounter(gb) == TW_TRUE);
    memcpy(&a, ga, 8);
    memcpy(&b, gb, 8);
    CHECK(b > a);
    uint64_t t0 = tw_k32_GetTickCount64();
    tw_k32_Sleep(5);
    uint64_t t1 = tw_k32_GetTickCount64();
    CHECK(t1 >= t0);

    char *mb = gstr("A\xC3\xA9");
    uint16_t *wide = gbytes(16);
    int32_t wn = tw_k32_MultiByteToWideChar(65001, 0, mb, -1, wide, 8);
    CHECK_EQ(wn, 3);
    CHECK_EQ(wide[0], 'A');
    CHECK_EQ(wide[1], 0xE9);
    char *back = gbytes(8);
    int32_t bn = tw_k32_WideCharToMultiByte(0, 0, wide, -1, back, 8, NULL, NULL);
    CHECK_EQ(bn, 4);
    CHECK_EQ((unsigned char)back[0], 'A');
    CHECK_EQ((unsigned char)back[1], 0xC3);
    CHECK_EQ((unsigned char)back[2], 0xA9);

    char *badutf = gbytes(2);
    if (badutf) { badutf[0] = (char)0xFF; badutf[1] = 0; }
    CHECK(tw_k32_MultiByteToWideChar(65001, TW_MB_ERR_INVALID_CHARS, badutf, -1, wide, 8) == 0);
    CHECK_EQ(tw_k32_GetLastError(), TW_ERROR_NO_UNICODE_TRANSLATION);
    CHECK(tw_k32_MultiByteToWideChar(1252, 0, mb, -1, wide, 8) == 0);

    tw_runtime_unbind();
}

static void test_resolver(void)
{
    tw_modules_init();
    char why[128];
    uint64_t by_name = tw_modules_resolve("kernel32.dll", "WriteFile", 0, 0, why, sizeof why);
    uint64_t by_ord = tw_modules_resolve("kernel32.dll", NULL, 2, 1, why, sizeof why);
    CHECK(by_name != 0 && by_name == by_ord);
    CHECK(tw_modules_resolve("kernel32.dll", "GetCommandLineW", 0, 0, why, sizeof why) != 0);
    CHECK(tw_modules_resolve("kernel32.dll", "VirtualAlloc", 0, 0, why, sizeof why) != 0);
    CHECK(tw_modules_resolve("kernel32.dll", "CreateFileW", 0, 0, why, sizeof why) != 0);
    CHECK(tw_modules_resolve("KERNEL32.DLL", NULL, 1, 1, why, sizeof why) != 0);
    CHECK(tw_modules_resolve("kernel32.dll", NULL, 99, 1, why, sizeof why) == 0);
    CHECK(tw_modules_resolve("ntdll.dll", "NtClose", 0, 0, why, sizeof why) == 0);
    CHECK(tw_modules_resolve("user32.dll", "MessageBoxW", 0, 0, why, sizeof why) == 0);
}

static void run_guest(const char *name, int argc, char **argv, uint32_t expect)
{
    tw_loaded im;
    tw_pe_error err;
    tw_load_status st = tw_load(fixture(name), TW_BASE_PREFER, &im, &err);
    CHECK_EQ(st, TW_LOAD_OK);
    if (st != TW_LOAD_OK) {
        fprintf(stderr, "  %s: %s\n", name, im.err);
        tw_unload(&im);
        return;
    }
    CHECK(tw_runtime_bind(&im, argv[0], argc, argv) == 0);
    uint32_t code = 99;
    st = tw_execute(&im, &code);
    CHECK_EQ(st, TW_LOAD_OK);
    CHECK_EQ(code, expect);
    tw_runtime_unbind();
    tw_unload(&im);
}

static void test_guests(void)
{
    char *args[] = {fixture("args-m2.exe"), "hello", "a b", NULL};
    run_guest("args-m2.exe", 3, args, 0);

    setenv("TWEAKWIN_GUEST_TWTEST", "hello-env", 1);
    char *envv[] = {fixture("env-m2.exe"), NULL};
    run_guest("env-m2.exe", 1, envv, 0);

    char *mem[] = {fixture("mem-m2.exe"), NULL};
    run_guest("mem-m2.exe", 1, mem, 0);
    char *heap[] = {fixture("heap-m2.exe"), NULL};
    run_guest("heap-m2.exe", 1, heap, 0);

    unlink("build/m2-out.txt");
    char *file[] = {fixture("file-m2.exe"), NULL};
    run_guest("file-m2.exe", 1, file, 0);
    FILE *f = fopen("build/m2-out.txt", "rb");
    CHECK(f != NULL);
    if (f) {
        char buf[32] = {0};
        size_t n = fread(buf, 1, sizeof buf, f);
        fclose(f);
        CHECK_EQ(n, 12);
        CHECK(memcmp(buf, "tweakwin-m2\n", 12) == 0);
        unlink("build/m2-out.txt");
    }

    char *timer[] = {fixture("timer-m2.exe"), NULL};
    run_guest("timer-m2.exe", 1, timer, 0);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: test_runtime FIXTURE_DIR\n");
        return 64;
    }
    g_dir = argv[1];
    test_utf();
    test_resolver();

    tw_loaded im;
    if (load_hello(&im) == 0) {
        test_cmdline_env_modules(&im);
        test_memory(&im);
        test_files(&im);
        tw_unload(&im);
    }
    test_guests();

    printf("runtime: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
