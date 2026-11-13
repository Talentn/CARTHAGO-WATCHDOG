/* Test stand-in for another program on the PC that has the game open: it opens a handle to
 * a process and keeps it, and with "overlay" also shows a transparent, click-through,
 * topmost window across the screen. It never reads or writes the other process and never
 * draws anything; the handle and the window are all the companion can see of such a
 * program, and they are all this one has. It is unsigned and is never shipped.
 *
 *   fake_holder.exe <pid> <read|write> [overlay] [secs]
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("usage: fake_holder <pid> <read|write> [overlay] [secs]\n");
        return 2;
    }
    DWORD pid = strtoul(argv[1], NULL, 10);
    DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    if (!strcmp(argv[2], "write")) access |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
    int overlay = argc > 3 && !strcmp(argv[3], "overlay");
    int secs = argc > 3 + overlay ? atoi(argv[3 + overlay]) : 60;

    HANDLE h = OpenProcess(access, FALSE, pid);
    if (!h) {
        printf("stand-in holder: process %lu could not be opened (error %lu)\n", pid, GetLastError());
        return 1;
    }
    printf("stand-in holder pid %lu: holds a %#lx handle to process %lu%s for %d s\n", GetCurrentProcessId(), access, pid, overlay ? " and a transparent window" : "", secs);
    fflush(stdout);
    if (overlay) {
        WNDCLASSA wc = {0};
        wc.lpfnWndProc = DefWindowProcA;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.lpszClassName = "CarthagoStandInOverlay";
        RegisterClassA(&wc);
        HWND w = CreateWindowExA(WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_NOACTIVATE, wc.lpszClassName, "", WS_POPUP, 0, 0,
            GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), NULL, NULL, wc.hInstance, NULL);
        if (w) {
            SetLayeredWindowAttributes(w, 0, 0, LWA_ALPHA);
            ShowWindow(w, SW_SHOWNOACTIVATE);
        }
    }
    for (int i = 0; i < secs * 10 && WaitForSingleObject(h, 0) == WAIT_TIMEOUT; i++) {
        MSG msg;
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) DispatchMessageA(&msg);
        Sleep(100);
    }
    CloseHandle(h);
    return 0;
}
