/* Compiler-built M2 fixture: VirtualAlloc / VirtualProtect / VirtualFree. */
#include <windows.h>

void __stdcall start(void)
{
    DWORD old = 0;
    BYTE *p = (BYTE *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) ExitProcess(1);
    p[0] = 'A';
    if (!VirtualProtect(p, 4096, PAGE_READONLY, &old)) ExitProcess(2);
    if (p[0] != 'A') ExitProcess(3);
    if (!VirtualFree(p, 0, MEM_RELEASE)) ExitProcess(4);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    char msg[] = "mem-ok\r\n";
    DWORD w = 0;
    WriteFile(out, msg, sizeof msg - 1, &w, NULL);
    ExitProcess(0);
}
