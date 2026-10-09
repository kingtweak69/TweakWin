/* Installs a vectored exception handler, dereferences a null pointer to
 * raise an access violation, and the handler fixes RIP past the faulting
 * instruction and supplies a value so execution continues. Proves backend
 * fault -> EXCEPTION_RECORD/CONTEXT -> VEH dispatch -> continue. No CRT. */
typedef unsigned long DWORD;
typedef long LONG;
typedef void *HANDLE;
typedef int BOOL;
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) void *__stdcall AddVectoredExceptionHandler(DWORD, void *);
__declspec(dllimport) DWORD __stdcall RemoveVectoredExceptionHandler(void *);

/* EXCEPTION_POINTERS { PEXCEPTION_RECORD; PCONTEXT; } */
struct EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    void *ExceptionRecord;
    void *ExceptionAddress;
    DWORD NumberParameters;
    unsigned long long ExceptionInformation[15];
};
struct EXCEPTION_POINTERS {
    struct EXCEPTION_RECORD *ExceptionRecord;
    unsigned char *ContextRecord;
};
#define EXCEPTION_ACCESS_VIOLATION 0xC0000005u
#define EXCEPTION_CONTINUE_EXECUTION (-1)
#define EXCEPTION_CONTINUE_SEARCH (0)
#define CTX_Rip 0xF8
#define CTX_Rax 0x78

static HANDLE g_out;
static volatile int g_caught;

static void emit(const char *s)
{
    unsigned n = 0;
    while (s[n]) n++;
    DWORD wrote;
    WriteFile(g_out, s, n, &wrote, 0);
}

/* The faulting instruction `mov eax,[rcx]` (rcx=0) is 2 bytes; skip it and
 * set rax so the load appears to have produced 0x1234. */
static LONG __stdcall handler(struct EXCEPTION_POINTERS *ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->ExceptionInformation[1] != 0) /* fault address */
        return EXCEPTION_CONTINUE_SEARCH;
    g_caught = 1;
    emit("caught-av\n");
    unsigned long long *rip = (unsigned long long *)(ep->ContextRecord + CTX_Rip);
    unsigned long long *rax = (unsigned long long *)(ep->ContextRecord + CTX_Rax);
    *rip += 2;       /* step over the faulting mov */
    *rax = 0x1234;   /* what the load should have yielded */
    return EXCEPTION_CONTINUE_EXECUTION;
}

static int do_fault(void)
{
    volatile int *p = 0;
    int v;
    __asm__ volatile("movl (%%rcx), %%eax\n\t" : "=a"(v) : "c"(p) : );
    return v;
}

void start(void)
{
    g_out = GetStdHandle((DWORD)-11);
    void *cookie = AddVectoredExceptionHandler(1, (void *)handler);
    if (!cookie) ExitProcess(0xE0);
    int r = do_fault();
    RemoveVectoredExceptionHandler(cookie);
    if (!g_caught) ExitProcess(0xE1);
    if (r != 0x1234) ExitProcess(0xE2);
    emit("continued\n");
    ExitProcess(0);
}
