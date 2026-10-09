/* Compiler-built M2 fixture: print TWEAKWIN_GUEST_TWTEST. */
#include <windows.h>

void __stdcall start(void)
{
    char buf[64];
    DWORD n = GetEnvironmentVariableA("TWTEST", buf, sizeof buf);
    if (n == 0 || n >= sizeof buf) ExitProcess(3);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD w = 0;
    WriteFile(out, buf, n, &w, NULL);
    ExitProcess(0);
}
