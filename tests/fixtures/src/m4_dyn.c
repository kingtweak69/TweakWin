/* Dynamic loader scenarios: refcounts, cycles, forwarders, failures, TLS. */
#include "m4_common.h"
K32 void *LoadLibraryA(const char *);
K32 void *LoadLibraryExA(const char *, void *, DWORD);
K32 void *GetProcAddress(void *, const char *);
K32 BOOL FreeLibrary(void *);
K32 void *GetModuleHandleA(const char *);
K32 HANDLE CreateThread(void *, unsigned long long, void *, void *, DWORD, DWORD *);
K32 DWORD WaitForSingleObject(HANDLE, DWORD);
K32 BOOL CloseHandle(HANDLE);
typedef int (*binop)(int, int);
typedef int (*nullary)(void);
typedef void (*setter)(void *);
typedef void *(*getter)(void);

static getter g_tget;
static setter g_tset;
static void *g_tres;

static DWORD __stdcall worker(void *arg)
{
    (void)arg;
    m4_num("thread-initial-tls", (INT64)(UINT64)g_tget());
    g_tset((void *)(UINT64)222);
    g_tres = g_tget();
    return 0;
}

void start(void)
{
    /* chain: top -> mid -> base */
    void *top = LoadLibraryA("m4_top.dll");
    m4_num("top-loaded", top != 0);
    m4_num("top_calc(5)", ((int (*)(int))GetProcAddress(top, "top_calc"))(5));
    void *mid = GetModuleHandleA("m4_mid.dll");
    m4_num("mid-loaded", mid != 0);
    binop fadd = (binop)GetProcAddress(mid, "mid_fwd_add");
    m4_num("forwarded(3,4)", fadd ? fadd(3, 4) : -1);
    m4_num("forwarded-is-base", fadd == (binop)GetProcAddress(GetModuleHandleA("m4_base.dll"), "m4_add"));
    m4_num("free-top", FreeLibrary(top));
    m4_num("base-gone", GetModuleHandleA("m4_base.dll") == 0);

    /* refcount */
    void *a = LoadLibraryA("m4_base.dll");
    void *b = LoadLibraryA("m4_base.dll");
    m4_num("same-handle", a == b);
    m4_num("pick", GetProcAddress(a, "m4_pick") != 0);
    FreeLibrary(a);
    m4_num("still-loaded", GetModuleHandleA("m4_base.dll") == b);
    FreeLibrary(b);
    m4_num("unloaded", GetModuleHandleA("m4_base.dll") == 0);
    m4_num("extra-free", FreeLibrary(b));
    m4_num("extra-free-err", GetLastError());

    /* load/unload cycles: DLL state restarts each time */
    for (int i = 0; i < 3; i++) {
        void *h = LoadLibraryA("m4_base.dll");
        nullary nx = (nullary)GetProcAddress(h, "m4_next");
        nx();
        m4_num("cycle-next", nx());
        FreeLibrary(h);
    }

    /* TLS across DLL and thread boundaries + thread notifications */
    void *h = LoadLibraryA("m4_base.dll");
    g_tset = (setter)GetProcAddress(h, "m4_tls_set");
    g_tget = (getter)GetProcAddress(h, "m4_tls_get");
    g_tset((void *)(UINT64)111);
    HANDLE t = CreateThread(0, 0, (void *)worker, 0, 0, 0);
    WaitForSingleObject(t, (DWORD)-1);
    CloseHandle(t);
    m4_num("thread-tls", (INT64)(UINT64)g_tres);
    m4_num("main-tls", (INT64)(UINT64)g_tget());
    m4_num("thread-events", ((nullary)GetProcAddress(h, "m4_thread_events"))());
    FreeLibrary(h);

    /* failures */
    m4_num("fail-dll", LoadLibraryA("m4_fail.dll") == 0);
    m4_num("fail-dll-err", GetLastError());
    m4_num("fail-not-resident", GetModuleHandleA("m4_fail.dll") == 0);
    m4_num("missing-dep", LoadLibraryA("m4_missing.dll") == 0);
    m4_num("missing-dep-err", GetLastError());
    m4_num("bad-symbol", LoadLibraryA("m4_badsym.dll") == 0);
    m4_num("bad-symbol-err", GetLastError());
    m4_num("bad-symbol-dep-rolled-back", GetModuleHandleA("m4_base.dll") == 0);
    m4_num("exe-as-dll", LoadLibraryA("m4-main.exe") == 0);
    m4_num("exe-as-dll-err", GetLastError());
    m4_num("tls-dll", LoadLibraryA("m4_tlsdll.dll") == 0);
    m4_num("tls-dll-err", GetLastError());
    m4_num("ex-unsupported", LoadLibraryExA("m4_base.dll", 0, 0x1) == 0);
    m4_num("ex-unsupported-err", GetLastError());
    m4_num("ex-badflags", LoadLibraryExA("m4_base.dll", 0, 0x40000) == 0);
    m4_num("ex-badflags-err", GetLastError());
    void *ex = LoadLibraryExA("m4_base.dll", 0, 0x8);
    m4_num("ex-altered", ex != 0);
    FreeLibrary(ex);

    /* forwarder loop */
    void *la = LoadLibraryA("m4_loop_a.dll");
    m4_num("loop-loaded", la != 0);
    m4_num("loop-proc", GetProcAddress(la, "a_f") == 0);
    m4_num("loop-proc-err", GetLastError());

    /* base conflict */
    void *d1 = LoadLibraryA("m4_dupa.dll");
    void *d2 = LoadLibraryA("m4_dupb.dll");
    m4_num("dup-loaded", d1 && d2);
    if (!d1 || !d2) { m4_num("dup-err", GetLastError()); ExitProcess(9); }
    m4_num("dup-ids", ((nullary)GetProcAddress(d1, "dup_id"))() * 10 + ((nullary)GetProcAddress(d2, "dup_id"))());
    m4_num("dup-bases-differ", d1 != d2);
    m4_out("[exe] exit with DLLs resident\n");
    ExitProcess(0);
}
