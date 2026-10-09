/* Compiler-built M2 fixture: process heap alloc/free. */
#include <windows.h>

void __stdcall start(void)
{
    HANDLE heap = GetProcessHeap();
    BYTE *p = (BYTE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, 16);
    if (!p) ExitProcess(1);
    p[0] = 'H';
    if (!HeapFree(heap, 0, p)) ExitProcess(2);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    char msg[] = "heap-ok\r\n";
    DWORD w = 0;
    WriteFile(out, msg, sizeof msg - 1, &w, NULL);
    ExitProcess(0);
}
