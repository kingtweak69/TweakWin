/* Leaf DLL: plain exports, ordinal exports, reloc-bearing data, DllMain
 * logging, a dynamic TLS slot and thread-notification counters. */
#include "m4_common.h"
K32 DWORD TlsAlloc(void);
K32 BOOL TlsFree(DWORD);
K32 void *TlsGetValue(DWORD);
K32 BOOL TlsSetValue(DWORD, void *);

static const char *volatile g_names[] = { "alpha", "beta", "gamma" };
static int g_counter;
static DWORD g_tls = 0xFFFFFFFFu;
static int g_tattach, g_tdetach;

int m4_add(int a, int b) { return a + b; }
int m4_mul(int a, int b) { return a * b; }
int m4_next(void) { return ++g_counter; }
const char *m4_pick(int i) { return (i >= 0 && i < 3) ? g_names[i] : 0; }
void m4_tls_set(void *v) { TlsSetValue(g_tls, v); }
void *m4_tls_get(void) { return TlsGetValue(g_tls); }
int m4_thread_events(void) { return g_tattach * 100 + g_tdetach; }
const char *m4_name_ptr(void) { return g_names[0]; }

BOOL __stdcall DllMain(void *h, DWORD reason, void *reserved)
{
    (void)h;
    switch (reason) {
    case 1:
        m4_out("[base] attach\n");
        g_tls = TlsAlloc();
        break;
    case 0:
        m4_out(reserved ? "[base] detach-exit\n" : "[base] detach\n");
        if (g_tls != 0xFFFFFFFFu) TlsFree(g_tls);
        break;
    case 2: g_tattach++; break;
    case 3: g_tdetach++; break;
    }
    return 1;
}
