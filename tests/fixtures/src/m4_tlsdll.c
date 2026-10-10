/* DLL with an implicit TLS directory: unsupported by the M3 TLS model. */
#include "m4_common.h"
__declspec(thread) int t_val = 5;
int tlsdll_get(void) { return t_val; }
BOOL __stdcall DllMain(void *h, DWORD reason, void *reserved)
{
    (void)h; (void)reason; (void)reserved;
    return 1;
}
