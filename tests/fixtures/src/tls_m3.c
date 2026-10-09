/* Dynamic TLS (TlsAlloc/TlsSetValue/TlsGetValue) across two threads:
 * each thread stores a distinct value in the same TLS index and reads back
 * its own, proving the slots are per-thread. Also checks implicit
 * __declspec(thread) independence. Prints "tls-ok". No CRT. */
typedef unsigned long DWORD;
typedef void *HANDLE;
typedef int BOOL;
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *, unsigned long long, void *, void *, DWORD, DWORD *);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE, DWORD);
__declspec(dllimport) BOOL __stdcall GetExitCodeThread(HANDLE, DWORD *);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE);
__declspec(dllimport) DWORD __stdcall TlsAlloc(void);
__declspec(dllimport) BOOL __stdcall TlsFree(DWORD);
__declspec(dllimport) void *__stdcall TlsGetValue(DWORD);
__declspec(dllimport) BOOL __stdcall TlsSetValue(DWORD, void *);

static HANDLE g_out;
static DWORD g_slot;
__declspec(thread) int t_impl = 100;

static void emit(const char *s)
{
    unsigned n = 0;
    while (s[n]) n++;
    DWORD wrote;
    WriteFile(g_out, s, n, &wrote, 0);
}

static DWORD __stdcall worker(void *param)
{
    unsigned long long which = (unsigned long long)param;
    /* Freshly entered thread: the dynamic slot must read back as 0. */
    if (TlsGetValue(g_slot) != 0) return 0xBAD1;
    TlsSetValue(g_slot, (void *)(unsigned long long)(0x1000 + which));
    t_impl = (int)(200 + which);
    /* Small spin so both threads interleave. */
    for (volatile int i = 0; i < 100000; i++) {
    }
    if (TlsGetValue(g_slot) != (void *)(unsigned long long)(0x1000 + which)) return 0xBAD2;
    if (t_impl != (int)(200 + which)) return 0xBAD3;
    return (DWORD)(0x1000 + which);
}

void start(void)
{
    g_out = GetStdHandle((DWORD)-11);
    g_slot = TlsAlloc();
    if (g_slot == 0xFFFFFFFF) ExitProcess(0xE0);
    TlsSetValue(g_slot, (void *)0x9999);

    DWORD id1, id2;
    HANDLE t1 = CreateThread(0, 0, (void *)worker, (void *)1, 0, &id1);
    HANDLE t2 = CreateThread(0, 0, (void *)worker, (void *)2, 0, &id2);
    if (!t1 || !t2) ExitProcess(0xE1);
    WaitForSingleObject(t1, 0xFFFFFFFF);
    WaitForSingleObject(t2, 0xFFFFFFFF);
    DWORD c1 = 0, c2 = 0;
    GetExitCodeThread(t1, &c1);
    GetExitCodeThread(t2, &c2);
    CloseHandle(t1);
    CloseHandle(t2);

    /* Main thread's slot and implicit TLS untouched by workers. */
    if (TlsGetValue(g_slot) != (void *)0x9999) ExitProcess(0xE2);
    if (t_impl != 100) ExitProcess(0xE3);
    if (c1 != 0x1001 || c2 != 0x1002) ExitProcess(0xE4);
    TlsFree(g_slot);
    emit("tls-ok\n");
    ExitProcess(0);
}
