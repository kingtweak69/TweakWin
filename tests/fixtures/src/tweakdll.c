/* Small DLL with named exports and a thread-local variable. Parse-only fixture. */
#include <windows.h>

static __thread int counter;

__declspec(dllexport) int tweak_add(int a, int b) { return a + b; }
__declspec(dllexport) int tweak_count(void) { return ++counter; }
__declspec(dllexport) const char *tweak_name(void) { return "tweakdll"; }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    (void)h; (void)reason; (void)reserved;
    return TRUE;
}
