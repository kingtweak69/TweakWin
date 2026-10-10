/* DLL importing a function that cannot be bound (IMPORT_FN). */
#include "m4_common.h"
__declspec(dllimport) int IMPORT_FN(void);
int imp_fn(void) { return IMPORT_FN(); }
BOOL __stdcall DllMain(void *h, DWORD reason, void *reserved)
{
    (void)h; (void)reason; (void)reserved;
    return 1;
}
