/* Compiler-built M2 fixture: QPC moves forward across Sleep. */
#include <windows.h>

void __stdcall start(void)
{
    LARGE_INTEGER freq, a, b;
    if (!QueryPerformanceFrequency(&freq)) ExitProcess(1);
    if (!QueryPerformanceCounter(&a)) ExitProcess(1);
    Sleep(5);
    if (!QueryPerformanceCounter(&b)) ExitProcess(1);
    if (b.QuadPart <= a.QuadPart) ExitProcess(2);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    char msg[] = "timer-ok\r\n";
    DWORD w = 0;
    WriteFile(out, msg, sizeof msg - 1, &w, NULL);
    ExitProcess(0);
}
