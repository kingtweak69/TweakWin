/* Export-less helper DLLs (forwarder loops, missing dependencies). */
#include "m4_common.h"
int stub_fn(void) { return 7; }
BOOL __stdcall DllMain(void *h, DWORD reason, void *reserved)
{
    (void)h; (void)reason; (void)reserved;
    return 1;
}
