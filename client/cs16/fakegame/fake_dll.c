/* An empty, unsigned DLL for the fake game to load. */
#include <windows.h>
__declspec(dllexport) int carthago_fake_export(void) { return 16; }
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) { (void)h; (void)reason; (void)reserved; return TRUE; }
