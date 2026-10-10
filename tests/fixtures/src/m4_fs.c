/* Windows namespace exercise. The harness runs it from a prepared host root:
 *   data/Hello.TXT  data/sub/  link -> outside dir  evil.txt -> outside file */
#include "m4_common.h"
K32 DWORD GetFileAttributesA(const char *);
K32 HANDLE FindFirstFileA(const char *, void *);
K32 BOOL FindNextFileA(HANDLE, void *);
K32 BOOL FindClose(HANDLE);
K32 DWORD GetCurrentDirectoryA(DWORD, char *);
K32 BOOL SetCurrentDirectoryA(const char *);
K32 void *LoadLibraryA(const char *);

static void attr(const char *p)
{
    DWORD a = GetFileAttributesA(p);
    m4_out(p);
    m4_num(a == 0xFFFFFFFFu ? " err" : " attr", a == 0xFFFFFFFFu ? (INT64)GetLastError() : (INT64)a);
}
static void list(const char *pat)
{
    char fd[320];
    m4_out("list ");
    m4_out(pat);
    m4_out("\n");
    HANDLE h = FindFirstFileA(pat, fd);
    if (h == (HANDLE)-1) { m4_num("  find-err", GetLastError()); return; }
    do {
        m4_out("  ");
        m4_out(fd + 44);
        m4_out("\n");
    } while (FindNextFileA(h, fd));
    m4_num("  end-err", GetLastError());
    FindClose(h);
}
void start(void)
{
    char cwd[260];
    attr("C:\\data\\Hello.TXT");
    attr("c:\\DATA\\hello.txt");
    attr("data\\sub");
    attr("C:\\data\\missing.txt");
    attr("C:\\..\\..\\..\\etc\\passwd");
    attr("C:\\link");
    attr("C:\\link\\passwd");
    attr("C:\\evil.txt");
    attr("\\\\?\\C:\\data");
    attr("D:\\data");
    attr("C:\\da|ta");
    list("C:\\data\\*");
    list("data\\*.txt");
    list("C:\\link\\*");
    list("C:\\nothing\\*");
    GetCurrentDirectoryA(sizeof cwd, cwd);
    m4_out("cwd="); m4_out(cwd); m4_out("\n");
    m4_num("setcwd", SetCurrentDirectoryA("C:\\data\\sub"));
    GetCurrentDirectoryA(sizeof cwd, cwd);
    m4_out("cwd="); m4_out(cwd); m4_out("\n");
    m4_num("setcwd-bad", SetCurrentDirectoryA("C:\\link"));
    attr("..\\Hello.txt");
    m4_num("dll-outside", LoadLibraryA("C:\\..\\..\\lib\\x86_64-linux-gnu\\libc.so.6") == 0);
    ExitProcess(0);
}
