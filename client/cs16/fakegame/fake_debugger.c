/* Test stand-in for a debugger: attaches to a process with the Windows debugging API, lets
 * it run for N seconds, and detaches again. It reads and changes nothing in the process. It
 * exists so the check can show that a debugger on the game is reported; it is never shipped.
 *
 *   fake_debugger.exe <pid> [seconds, default 20]
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: fake_debugger <pid> [seconds]\n");
        return 1;
    }
    DWORD pid = (DWORD)strtoul(argv[1], NULL, 10);
    int secs = argc > 2 ? atoi(argv[2]) : 20;
    if (!DebugActiveProcess(pid)) {
        fprintf(stderr, "cannot attach to pid %lu: error %lu\n", pid, GetLastError());
        return 2;
    }
    DebugSetProcessKillOnExit(FALSE);
    printf("attached to pid %lu for %d s\n", pid, secs);
    fflush(stdout);
    DWORD end = GetTickCount() + (DWORD)secs * 1000;
    int gone = 0;
    while (!gone && (int)(end - GetTickCount()) > 0) {
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev, 200)) continue;
        DWORD status = DBG_CONTINUE;
        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
            break;
        case EXCEPTION_DEBUG_EVENT:
            /* The attach breakpoint is the debugger's own; anything else is the program's. */
            if (ev.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT) status = DBG_EXCEPTION_NOT_HANDLED;
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            gone = 1;
            break;
        }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);
    }
    if (!gone) DebugActiveProcessStop(pid);
    printf("%s\n", gone ? "the process ended" : "detached");
    return 0;
}
