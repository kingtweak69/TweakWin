/* Top DLL: chain top -> mid -> base. */
#include "m4_common.h"
__declspec(dllimport) int mid_calc(int, int);
int top_calc(int x) { return mid_calc(x, 2); }
BOOL __stdcall DllMain(void *h, DWORD reason, void *reserved)
{
    (void)h; (void)reserved;
    if (reason == 1) m4_out("[top] attach\n");
    if (reason == 0) m4_out("[top] detach\n");
    return 1;
}
