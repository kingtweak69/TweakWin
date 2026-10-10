/* Implicit imports: EXE imports the m4_top.dll chain at load time. */
#include "m4_common.h"
__declspec(dllimport) int top_calc(int);
__declspec(dllimport) int m4_add(int, int);
void start(void)
{
    m4_out("[exe] start\n");
    m4_num("top_calc(5)", top_calc(5));
    m4_num("m4_add(1,2)", m4_add(1, 2));
    ExitProcess(3);
}
