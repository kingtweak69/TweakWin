/* Compiler-built M2 fixture: CreateFileA / WriteFile / CloseHandle. */
#include <windows.h>

void __stdcall start(void)
{
    HANDLE h = CreateFileA("build/m2-out.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) ExitProcess(4);
    char payload[] = "tweakwin-m2\n";
    DWORD w = 0;
    if (!WriteFile(h, payload, sizeof payload - 1, &w, NULL)) ExitProcess(5);
    CloseHandle(h);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    char msg[] = "file-ok\r\n";
    WriteFile(out, msg, sizeof msg - 1, &w, NULL);
    ExitProcess(0);
}
