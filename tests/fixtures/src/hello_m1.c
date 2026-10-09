/* Compiler-generated M1 execution fixture. Built with no CRT so the
   import table is exactly GetStdHandle / WriteFile / ExitProcess.
   Distinct from tests/fixtures/src/hello.c (parser-only zig fixture). */
#include <windows.h>

void __stdcall start(void)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    const char msg[] = "Hello from TweakWin M1\r\n";
    DWORD written;
    WriteFile(out, msg, sizeof(msg) - 1, &written, NULL);
    ExitProcess(0);
}
