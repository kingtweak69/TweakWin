/* Built twice with the same preferred base (DUPID 1 / 2): the second must be
 * relocated. Pointer tables need DIR64 relocations to work. */
#include "m4_common.h"
#ifndef DUPID
#define DUPID 1
#endif
static int g_id = DUPID;
static int *volatile g_ptrs[2] = { &g_id, &g_id };
int dup_id(void) { return *g_ptrs[1]; }
INT64 dup_base(void) { return (INT64)(UINT64)(void *)&g_id; }
BOOL __stdcall DllMain(void *h, DWORD reason, void *reserved)
{
    (void)h; (void)reason; (void)reserved;
    return 1;
}
