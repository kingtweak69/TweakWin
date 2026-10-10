#include "m4_common.h"
int fail_fn(void) { return 1; }
BOOL __stdcall DllMain(void *h, DWORD reason, void *reserved)
{
    (void)h; (void)reserved;
    if (reason == 1) { m4_out("[fail] attach\n"); return 0; }
    if (reason == 0) m4_out("[fail] detach\n");
    return 1;
}
