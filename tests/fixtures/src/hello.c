/* M1 acceptance program from the TweakWin spec. Built with no CRT so the
   import table is exactly GetStdHandle / WriteFile / ExitProcess. */
#include <windows.h>

void __stdcall start(void)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    const char msg[] = "Hello from TweakWin!\r\n";
    DWORD written;
    WriteFile(out, msg, sizeof(msg) - 1, &written, NULL);
    ExitProcess(0);
}
