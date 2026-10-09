/* Two Windows threads with independent __declspec(thread) TLS, coordinated
 * by an auto-reset event and a semaphore, writing a line each. Proves:
 * CreateThread, Windows TLS differs per thread, event + semaphore waits,
 * thread join + exit code. No CRT. */
typedef unsigned long DWORD;
typedef void *HANDLE;
typedef int BOOL;
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *, unsigned long long, void *, void *, DWORD, DWORD *);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE, DWORD);
__declspec(dllimport) BOOL __stdcall GetExitCodeThread(HANDLE, DWORD *);
__declspec(dllimport) HANDLE __stdcall CreateEventA(void *, BOOL, BOOL, const char *);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE);
__declspec(dllimport) HANDLE __stdcall CreateSemaphoreA(void *, int, int, const char *);
__declspec(dllimport) BOOL __stdcall ReleaseSemaphore(HANDLE, int, int *);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE);

static HANDLE g_out, g_ev, g_sem;
__declspec(thread) int t_val = 0xAA; /* implicit PE TLS */

static void emit(const char *s)
{
    unsigned n = 0;
    while (s[n]) n++;
    DWORD wrote;
    WriteFile(g_out, s, n, &wrote, 0);
}

static DWORD __stdcall worker(void *param)
{
    int which = (int)(unsigned long long)param;
    t_val = which == 1 ? 0x11 : 0x22; /* each thread's own TLS copy */
    WaitForSingleObject(g_sem, 0xFFFFFFFF);   /* gate on the semaphore */
    emit(which == 1 ? "worker1\n" : "worker2\n");
    if (which == 1) SetEvent(g_ev);
    return (DWORD)t_val; /* exit code carries this thread's TLS value */
}

void start(void)
{
    g_out = GetStdHandle((DWORD)-11);
    g_ev = CreateEventA(0, 0, 0, 0);    /* auto-reset, unset */
    g_sem = CreateSemaphoreA(0, 0, 2, 0);
    if (!g_ev || !g_sem) ExitProcess(0xE0);

    DWORD id1, id2;
    HANDLE t1 = CreateThread(0, 0, (void *)worker, (void *)1, 0, &id1);
    HANDLE t2 = CreateThread(0, 0, (void *)worker, (void *)2, 0, &id2);
    if (!t1 || !t2) ExitProcess(0xE1);

    ReleaseSemaphore(g_sem, 2, 0); /* let both run */
    WaitForSingleObject(t1, 0xFFFFFFFF);
    WaitForSingleObject(t2, 0xFFFFFFFF);

    DWORD c1 = 0, c2 = 0;
    GetExitCodeThread(t1, &c1);
    GetExitCodeThread(t2, &c2);
    CloseHandle(t1);
    CloseHandle(t2);
    CloseHandle(g_ev);
    CloseHandle(g_sem);

    /* Main thread's own TLS must be untouched by the workers. */
    if (t_val != 0xAA) ExitProcess(0xE2);
    if (c1 != 0x11 || c2 != 0x22) ExitProcess(0xE3);
    emit("main\n");
    ExitProcess(0);
}
