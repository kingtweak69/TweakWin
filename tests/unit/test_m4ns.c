/*
 * M4 unit tests: the contained Windows namespace (confinement, symlinks,
 * case handling, enumeration, DLL search order) and the virtual registry.
 */
#define _GNU_SOURCE
#include "../../runtime/registry.h"
#include "../../runtime/winapi.h"
#include "../../runtime/winfs.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_fail, g_pass;

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (cond) g_pass++;                                                     \
        else { g_fail++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
    } while (0)
#define CHECK_EQ(a, b)                                                          \
    do {                                                                        \
        unsigned long long _a = (unsigned long long)(a), _b = (unsigned long long)(b); \
        if (_a == _b) g_pass++;                                                 \
        else { g_fail++; fprintf(stderr, "FAIL %s:%d: %s == %s (%llu != %llu)\n", \
                                 __FILE__, __LINE__, #a, #b, _a, _b); }         \
    } while (0)

static void touch(const char *dir, const char *name)
{
    char p[512];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    int fd = open(p, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
}

static void sub(const char *dir, const char *name)
{
    char p[512];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    (void)mkdir(p, 0755);
}

static void test_namespace(void)
{
    char root[] = "/tmp/tw-ns-XXXXXX", outside[] = "/tmp/tw-out-XXXXXX";
    CHECK(mkdtemp(root) && mkdtemp(outside));
    char p[600], host[TW_WINFS_PATH_MAX], v[TW_WINFS_PATH_MAX];
    uint32_t attrs, err;

    sub(root, "Dir");
    sub(root, "Dir/Inner");
    touch(root, "Dir/File.txt");
    touch(root, "Dir/a.dll");
    touch(outside, "secret");
    snprintf(p, sizeof p, "%s/link", root);
    CHECK(symlink(outside, p) == 0);
    snprintf(p, sizeof p, "%s/flink", root);
    CHECK(symlink("/etc/passwd", p) == 0);
    snprintf(p, sizeof p, "%s/Dir/dl", root);
    CHECK(symlink("../../", p) == 0);
    sub(root, "Dir/Case");
    touch(root, "Dir/Case/x");
    sub(root, "Dir/case");
    touch(root, "Dir/case/y");
    touch(root, "Dir/Clash.TXT");
    touch(root, "Dir/clash.txt");

    tw_winfs_reset();
    CHECK(tw_winfs_set_root("/does/not/exist") != 0);
    CHECK_EQ(tw_winfs_set_root(root), 0);

    /* normalisation */
    CHECK_EQ(tw_winfs_normalize("C:\\a\\b\\..\\c", 0, v, sizeof v), 0);
    CHECK(strcmp(v, "C:\\a\\c") == 0);
    CHECK_EQ(tw_winfs_normalize("c:/a/./b", 0, v, sizeof v), 0);
    CHECK(strcmp(v, "C:\\a\\b") == 0);
    CHECK_EQ(tw_winfs_normalize("C:\\..\\..\\x", 0, v, sizeof v), 0);
    CHECK(strcmp(v, "C:\\x") == 0);
    CHECK(tw_winfs_normalize("\\\\server\\share", 0, v, sizeof v) != 0);
    CHECK(tw_winfs_normalize("\\\\?\\C:\\x", 0, v, sizeof v) != 0);
    CHECK(tw_winfs_normalize("C:\\a:b", 0, v, sizeof v) != 0);
    CHECK(tw_winfs_normalize("C:\\a*", 0, v, sizeof v) != 0);
    CHECK_EQ(tw_winfs_normalize("C:\\a*", 1, v, sizeof v), 0);
    CHECK(tw_winfs_normalize("C:\\a\\b", 0, v, 4) != 0);

    /* lookup, case-insensitivity */
    CHECK_EQ(tw_winfs_resolve("C:\\dir\\FILE.TXT", host, sizeof host, &attrs), 0);
    CHECK(strstr(host, "/Dir/File.txt") != NULL);
    CHECK_EQ(tw_winfs_attributes("C:\\Dir", &err), 0x10);
    CHECK_EQ(tw_winfs_attributes("C:\\Dir\\File.txt", &err), 0x80);
    CHECK_EQ(tw_winfs_attributes("C:\\Dir\\nope", &err), TW_WINFS_INVALID_ATTRS);
    CHECK_EQ(err, TW_ERROR_FILE_NOT_FOUND);
    CHECK_EQ(tw_winfs_attributes("C:\\nope\\x", &err), TW_WINFS_INVALID_ATTRS);
    CHECK_EQ(err, TW_ERROR_PATH_NOT_FOUND);

    /* traversal never leaves the root */
    CHECK_EQ(tw_winfs_attributes("C:\\..\\..\\..\\etc\\passwd", &err), TW_WINFS_INVALID_ATTRS);
    CHECK_EQ(tw_winfs_attributes("..\\..\\..\\etc", &err), TW_WINFS_INVALID_ATTRS);

    /* symlinks are never followed */
    CHECK_EQ(tw_winfs_attributes("C:\\link", &err), TW_WINFS_INVALID_ATTRS);
    CHECK_EQ(err, TW_ERROR_ACCESS_DENIED);
    CHECK_EQ(tw_winfs_attributes("C:\\link\\secret", &err), TW_WINFS_INVALID_ATTRS);
    CHECK_EQ(err, TW_ERROR_ACCESS_DENIED);
    CHECK_EQ(tw_winfs_attributes("C:\\flink", &err), TW_WINFS_INVALID_ATTRS);
    CHECK_EQ(err, TW_ERROR_ACCESS_DENIED);
    CHECK_EQ(tw_winfs_attributes("C:\\Dir\\dl\\Dir", &err), TW_WINFS_INVALID_ATTRS);
    CHECK_EQ(err, TW_ERROR_ACCESS_DENIED);

    /* ambiguous case collisions are refused, exact case still works */
    CHECK_EQ(tw_winfs_attributes("C:\\Dir\\CASE\\x", &err), TW_WINFS_INVALID_ATTRS);
    CHECK_EQ(err, TW_ERROR_ACCESS_DENIED);
    CHECK_EQ(tw_winfs_attributes("C:\\Dir\\Case\\x", &err), 0x80);
    CHECK_EQ(tw_winfs_attributes("C:\\Dir\\case\\y", &err), 0x80);
    CHECK_EQ(tw_winfs_attributes("C:\\Dir\\clash.txt", &err), 0x80);
    CHECK_EQ(tw_winfs_attributes("C:\\Dir\\CLASH.TXT", &err), TW_WINFS_INVALID_ATTRS);

    /* current directory */
    CHECK_EQ(tw_winfs_getcwd(v, sizeof v), 0);
    CHECK(strcmp(v, "C:\\") == 0);
    CHECK_EQ(tw_winfs_setcwd("dir\\inner"), 0);
    CHECK_EQ(tw_winfs_getcwd(v, sizeof v), 0);
    CHECK(strcasecmp(v, "C:\\Dir\\Inner") == 0);
    CHECK_EQ(tw_winfs_attributes("..\\file.txt", &err), 0x80);
    CHECK(tw_winfs_setcwd("C:\\link") != 0);
    CHECK(tw_winfs_setcwd("C:\\Dir\\File.txt") != 0);
    CHECK(tw_winfs_setcwd("C:\\nope") != 0);
    CHECK_EQ(tw_winfs_setcwd("C:\\"), 0);

    /* enumeration */
    tw_winfs_find *f = NULL;
    tw_winfs_entry e;
    CHECK_EQ(tw_winfs_find_open("C:\\Dir\\*.DLL", &f, &e), 0);
    CHECK(strcmp(e.name, "a.dll") == 0);
    CHECK(!tw_winfs_find_next(f, &e));
    tw_winfs_find_close(f);
    CHECK_EQ(tw_winfs_find_open("C:\\Dir\\*", &f, &e), 0);
    int n = 1, dots = strcmp(e.name, ".") == 0 || strcmp(e.name, "..") == 0;
    while (tw_winfs_find_next(f, &e)) {
        n++;
        if (!strcmp(e.name, ".") || !strcmp(e.name, "..")) dots++;
    }
    tw_winfs_find_close(f);
    CHECK_EQ(dots, 2);
    CHECK(n >= 8);
    CHECK_EQ(tw_winfs_find_open("C:\\Dir\\*.zip", &f, &e), TW_ERROR_FILE_NOT_FOUND);
    CHECK(tw_winfs_find_open("C:\\link\\*", &f, &e) != 0);
    CHECK_EQ(tw_winfs_find_open("C:\\*", &f, &e), 0);
    do { CHECK(strcmp(e.name, "link") != 0 && strcmp(e.name, "flink") != 0); } while (tw_winfs_find_next(f, &e));
    tw_winfs_find_close(f);

    /* DLL search order: app dir, cwd, configured path */
    touch(root, "app.dll");
    touch(root, "Dir/Inner/cwd.dll");
    touch(root, "Dir/extra.dll");
    CHECK_EQ(tw_winfs_search_dll("APP", host, sizeof host, v, sizeof v), 0);
    CHECK(strcasecmp(v, "C:\\app.dll") == 0);
    CHECK(tw_winfs_search_dll("cwd.dll", host, sizeof host, v, sizeof v) != 0);
    CHECK_EQ(tw_winfs_setcwd("C:\\Dir\\Inner"), 0);
    CHECK_EQ(tw_winfs_search_dll("cwd.dll", host, sizeof host, v, sizeof v), 0);
    CHECK(tw_winfs_search_dll("extra.dll", host, sizeof host, v, sizeof v) != 0);
    CHECK_EQ(tw_winfs_search_add("C:\\Dir"), 0);
    CHECK_EQ(tw_winfs_search_dll("extra.dll", host, sizeof host, v, sizeof v), 0);
    CHECK(strcmp(v, "C:\\Dir\\extra.dll") == 0);
    CHECK_EQ(tw_winfs_search_dll("C:\\Dir\\extra.dll", host, sizeof host, v, sizeof v), 0);
    CHECK(tw_winfs_search_dll("C:\\Dir", host, sizeof host, v, sizeof v) != 0);
    CHECK(tw_winfs_search_dll("..\\..\\..\\..\\lib\\libc.so.6", host, sizeof host, v, sizeof v) != 0);
    CHECK(tw_winfs_search_dll("", host, sizeof host, v, sizeof v) != 0);
    tw_winfs_search_clear();
    CHECK(tw_winfs_search_dll("extra.dll", host, sizeof host, v, sizeof v) != 0);

    tw_winfs_reset();
    snprintf(p, sizeof p, "rm -rf %s %s", root, outside);
    if (system(p) != 0) fprintf(stderr, "cleanup failed\n");
}

static void test_registry(void)
{
    uint64_t k = 0, k2 = 0;
    uint32_t disp = 0, type = 0, len = 0, dw = 77;
    uint8_t *d = NULL;
    tw_reg_reset();

    CHECK_EQ(tw_reg_open(TW_HKEY_CURRENT_USER, "Software\\Nope", 0, &k, NULL), TW_ERROR_FILE_NOT_FOUND);
    CHECK_EQ(tw_reg_open(TW_HKEY_CURRENT_USER, "Software\\A\\B", 1, &k, &disp), 0);
    CHECK_EQ(disp, TW_REG_CREATED_NEW_KEY);
    CHECK_EQ(tw_reg_open(0xFFFFFFFF80000001ull, "software\\a\\b", 0, &k2, &disp), 0);
    CHECK_EQ(disp, TW_REG_OPENED_EXISTING_KEY);
    CHECK_EQ(tw_reg_set(k, "V", TW_REG_DWORD, &dw, 4), 0);
    CHECK_EQ(tw_reg_get(k2, "v", &type, &d, &len), 0);
    CHECK(type == TW_REG_DWORD && len == 4 && memcmp(d, &dw, 4) == 0);
    free(d);
    CHECK_EQ(tw_reg_set(k, "V", TW_REG_DWORD, &dw, 3), TW_ERROR_INVALID_PARAMETER);
    CHECK_EQ(tw_reg_set(k, "Q", TW_REG_QWORD, &dw, 4), TW_ERROR_INVALID_PARAMETER);
    CHECK_EQ(tw_reg_set(k, "Bin", TW_REG_BINARY, NULL, 4), TW_ERROR_NOACCESS);
    CHECK_EQ(tw_reg_set(k, "Big", TW_REG_BINARY, &dw, TW_REG_MAX_DATA + 1), TW_ERROR_NOT_ENOUGH_MEMORY);
    CHECK_EQ(tw_reg_set(k, "E", TW_REG_BINARY, NULL, 0), 0);
    CHECK_EQ(tw_reg_get(k, "missing", &type, &d, &len), TW_ERROR_FILE_NOT_FOUND);
    CHECK_EQ(tw_reg_delete_value(k, "V"), 0);
    CHECK_EQ(tw_reg_delete_value(k, "V"), TW_ERROR_FILE_NOT_FOUND);

    /* HKLM is a separate tree; unsupported roots and stale handles fail */
    CHECK_EQ(tw_reg_open(TW_HKEY_LOCAL_MACHINE, "Software\\A", 0, &k2, NULL), TW_ERROR_FILE_NOT_FOUND);
    CHECK_EQ(tw_reg_open(0x80000003u, "x", 0, &k2, NULL), TW_ERROR_INVALID_HANDLE);
    CHECK_EQ(tw_reg_open(0xDEAD, "x", 0, &k2, NULL), TW_ERROR_INVALID_HANDLE);
    CHECK_EQ(tw_reg_close(k), 0);
    CHECK_EQ(tw_reg_close(k), TW_ERROR_INVALID_HANDLE);
    CHECK_EQ(tw_reg_set(k, "x", TW_REG_SZ, "a", 2), TW_ERROR_INVALID_HANDLE);
    char longname[600];
    memset(longname, 'a', sizeof longname - 1);
    longname[sizeof longname - 1] = 0;
    CHECK(tw_reg_open(TW_HKEY_CURRENT_USER, longname, 1, &k2, NULL) != 0);
    tw_reg_reset();
    CHECK_EQ(tw_reg_open_handles(), 0);
    CHECK_EQ(tw_reg_open(TW_HKEY_CURRENT_USER, "Software\\A\\B", 0, &k2, NULL), TW_ERROR_FILE_NOT_FOUND);
}

int main(void)
{
    test_namespace();
    test_registry();
    printf("test_m4ns: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
