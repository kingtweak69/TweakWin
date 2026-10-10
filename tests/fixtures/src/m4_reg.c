/* Virtual registry exercise (HKCU, in-memory). */
#include "m4_common.h"
K32 long RegCreateKeyExA(void *, const char *, DWORD, char *, DWORD, DWORD, void *, void **, DWORD *);
K32 long RegOpenKeyExA(void *, const char *, DWORD, DWORD, void **);
K32 long RegSetValueExA(void *, const char *, DWORD, DWORD, const void *, DWORD);
K32 long RegQueryValueExA(void *, const char *, DWORD *, DWORD *, void *, DWORD *);
K32 long RegDeleteValueA(void *, const char *);
K32 long RegCloseKey(void *);
K32 long RegCreateKeyExW(void *, const WORD *, DWORD, WORD *, DWORD, DWORD, void *, void **, DWORD *);
K32 long RegSetValueExW(void *, const WORD *, DWORD, DWORD, const void *, DWORD);
K32 long RegQueryValueExW(void *, const WORD *, DWORD *, DWORD *, void *, DWORD *);
#define HKCU ((void *)(INT64)(int)0x80000001)
#define HKU ((void *)(INT64)(int)0x80000003)

void start(void)
{
    void *k = 0, *k2 = 0;
    DWORD disp = 0, type = 0, sz;
    char buf[32];
    DWORD dw = 1234, dwo = 0;
    m4_num("open-missing", RegOpenKeyExA(HKCU, "Software\\Nope", 0, 0x20019, &k2));
    m4_num("create", RegCreateKeyExA(HKCU, "Software\\TweakWin\\Test", 0, 0, 0, 0xF003F, 0, &k, &disp));
    m4_num("disposition", disp);
    m4_num("set-dword", RegSetValueExA(k, "Count", 0, 4, &dw, 4));
    m4_num("set-sz", RegSetValueExA(k, "Name", 0, 1, "tweak", 6));
    m4_num("set-bad-dword", RegSetValueExA(k, "Bad", 0, 4, &dw, 3));
    sz = 4;
    m4_num("get-dword", RegQueryValueExA(k, "COUNT", 0, &type, &dwo, &sz));
    m4_num("  value", dwo);
    m4_num("  type", type);
    sz = 3;
    m4_num("get-small", RegQueryValueExA(k, "Name", 0, &type, buf, &sz));
    m4_num("  needed", sz);
    sz = sizeof buf;
    m4_num("get-sz", RegQueryValueExA(k, "name", 0, &type, buf, &sz));
    m4_out(buf); m4_out("\n");
    m4_num("  size", sz);
    sz = 0;
    m4_num("get-size-only", RegQueryValueExA(k, "Name", 0, &type, 0, &sz));
    m4_num("  size", sz);
    static const WORD wn[] = { 'W', 'i', 'd', 'e', 0 };
    static const WORD wv[] = { 'x', 'y', 0 };
    m4_num("set-w", RegSetValueExW(k, wn, 0, 1, wv, 6));
    sz = sizeof buf;
    m4_num("get-w-as-a", RegQueryValueExA(k, "Wide", 0, &type, buf, &sz));
    m4_out(buf); m4_out("\n");
    m4_num("reopen", RegOpenKeyExA(HKCU, "software\\TWEAKWIN\\test", 0, 0x20019, &k2));
    sz = 4;
    m4_num("get-via-reopen", RegQueryValueExA(k2, "Count", 0, 0, &dwo, &sz));
    m4_num("delete", RegDeleteValueA(k, "Count"));
    m4_num("delete-again", RegDeleteValueA(k, "Count"));
    sz = 4;
    m4_num("get-deleted", RegQueryValueExA(k2, "Count", 0, 0, &dwo, &sz));
    m4_num("close", RegCloseKey(k));
    m4_num("close-again", RegCloseKey(k));
    m4_num("use-closed", RegSetValueExA(k, "X", 0, 1, "a", 2));
    m4_num("bad-root", RegOpenKeyExA(HKU, "x", 0, 0x20019, &k2));
    m4_num("bad-reserved", RegOpenKeyExA(HKCU, "Software", 5, 0x20019, &k2));
    m4_num("close-root", RegCloseKey(HKCU));
    RegCloseKey(k2);
    ExitProcess(0);
}
