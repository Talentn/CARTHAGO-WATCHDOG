/* Test stand-in for hl.exe: a 32-bit process that looks, from outside, the way a GoldSrc
 * client does. It loads two unsigned DLLs from its own folder and maps one executable
 * region with a PE header that the Windows loader knows nothing about, as build 4554 does
 * with its encrypted hw.dll. It contains no game code and is never shipped.
 *
 *   hl.exe [-game cstrike] [-secs N]      runs N seconds (default 20), then exits with 0
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int secs = 20;
    for (int i = 1; i + 1 < argc; i++)
        if (!strcmp(argv[i], "-secs")) secs = atoi(argv[i + 1]);

    HMODULE hw = LoadLibraryA("fake_hw.dll");
    HMODULE mp = LoadLibraryA("cstrike\\dlls\\fake_mp.dll");

    unsigned char *blob = VirtualAlloc(NULL, 0x40000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (blob) {
        memset(blob, 0xC3, 0x40000);
        memcpy(blob, "MZ", 2);
        *(DWORD *)(blob + 0x3c) = 0x80;
        memcpy(blob + 0x80, "PE\0\0", 4);
    }
    printf("fake hl.exe pid %lu: hw=%p mp=%p blob=%p, running %d s\n", GetCurrentProcessId(), (void *)hw, (void *)mp, (void *)blob, secs);
    fflush(stdout);
    for (int i = 0; i < secs * 10; i++) {
        if (GetFileAttributesA("fake_hl.quit") != INVALID_FILE_ATTRIBUTES) break;
        Sleep(100);
    }
    return 0;
}
