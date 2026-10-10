/* Shared helpers for the M4 fixtures. Freestanding, no CRT. */
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef void *HANDLE;
typedef int BOOL;
typedef long long INT64;
typedef unsigned long long UINT64;
#define K32 __declspec(dllimport) __stdcall
K32 HANDLE GetStdHandle(DWORD);
K32 BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
K32 __declspec(noreturn) void ExitProcess(unsigned);
K32 DWORD GetLastError(void);

static void m4_out(const char *s)
{
    DWORD n = 0, w;
    while (s[n]) n++;
    WriteFile(GetStdHandle((DWORD)-11), s, n, &w, 0);
}
__attribute__((unused)) static void m4_num(const char *label, INT64 v)
{
    char b[24];
    int i = 23;
    int neg = v < 0;
    UINT64 u = neg ? (UINT64)(-v) : (UINT64)v;
    b[i] = 0;
    do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u);
    if (neg) b[--i] = '-';
    m4_out(label);
    m4_out("=");
    m4_out(b + i);
    m4_out("\n");
}

/* An absolute pointer in writable data forces a base relocation table, so the
 * image can be rebased when its preferred base is unavailable (sanitizer
 * builds reserve 0x140000000 for shadow memory). */
const char *volatile m4_reloc_anchor = "m4";
