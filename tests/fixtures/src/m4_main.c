/* Primary acceptance gate: a real EXE loads a separately compiled DLL via
 * LoadLibraryA and calls real exported functions. */
#include "m4_common.h"
K32 void *LoadLibraryA(const char *);
K32 void *GetProcAddress(void *, const char *);
K32 BOOL FreeLibrary(void *);
K32 void *GetModuleHandleA(const char *);
typedef int (*binop)(int, int);

void start(void)
{
    void *h = LoadLibraryA("m4_base.dll");
    if (!h) { m4_num("load-failed", GetLastError()); ExitProcess(1); }
    binop add = (binop)GetProcAddress(h, "m4_add");
    binop mul = (binop)GetProcAddress(h, (const char *)(UINT64)11);
    if (!add || !mul) ExitProcess(2);
    m4_num("m4_add(40,2)", add(40, 2));
    m4_num("m4_mul(6,7)", mul(6, 7));
    m4_num("handle-match", GetModuleHandleA("M4_BASE.DLL") == h);
    m4_num("missing-proc", GetProcAddress(h, "nope") == 0);
    m4_num("missing-proc-err", GetLastError());
    m4_num("free", FreeLibrary(h));
    m4_num("gone", GetModuleHandleA("m4_base.dll") == 0);
    m4_num("missing-dll", LoadLibraryA("no_such_lib.dll") == 0);
    m4_num("missing-dll-err", GetLastError());
    ExitProcess(0);
}
