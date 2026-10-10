/* Loader robustness probe: load m4_base.dll, look its exports up, never call
 * them. Used by the malformed-DLL mutation test. */
#include "m4_common.h"
K32 void *LoadLibraryA(const char *);
K32 void *GetProcAddress(void *, const char *);
K32 BOOL FreeLibrary(void *);

void start(void)
{
    void *h = LoadLibraryA("m4_base.dll");
    if (!h) { m4_num("load-failed", GetLastError()); ExitProcess(1); }
    m4_num("add", GetProcAddress(h, "m4_add") != 0);
    m4_num("ord", GetProcAddress(h, (const char *)(UINT64)12) != 0);
    m4_num("none", GetProcAddress(h, "nope") != 0);
    m4_num("free", FreeLibrary(h));
    ExitProcess(0);
}
