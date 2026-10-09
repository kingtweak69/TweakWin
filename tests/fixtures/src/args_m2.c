/* Compiler-built M2 fixture: print the guest command line. */
#include <windows.h>

static DWORD slen(const char *s)
{
    DWORD n = 0;
    while (s[n]) n++;
    return n;
}

void __stdcall start(void)
{
    const char *cmd = GetCommandLineA();
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = slen(cmd), w = 0;
    WriteFile(out, cmd, n, &w, NULL);
    ExitProcess(0);
}
