/* Middle DLL: imports m4_base by name and by ordinal; forwards one export. */
#include "m4_common.h"
__declspec(dllimport) int m4_add(int, int);
__declspec(dllimport) int m4_mul(int, int);
int mid_calc(int a, int b) { return m4_add(a, b) * m4_mul(a, b); }
BOOL __stdcall DllMain(void *h, DWORD reason, void *reserved)
{
    (void)h; (void)reserved;
    if (reason == 1) m4_out("[mid] attach\n");
    if (reason == 0) m4_out("[mid] detach\n");
    return 1;
}
