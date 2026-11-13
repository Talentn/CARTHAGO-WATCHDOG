/* Test stand-in for a game launcher: a program that is not the game and starts it. It runs
 * cstrike.exe from its own folder with the arguments it was given and exits at once.
 *
 *   launcher.exe [-launcher-stay] [-launcher-nothing] [game arguments]
 *     -launcher-stay      stay until the game has ended, as some launchers do
 *     -launcher-nothing   start nothing and exit: a launcher whose game never comes up
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char dir[MAX_PATH], cmd[4096];
    int stay = 0, nothing = 0;
    GetModuleFileNameA(NULL, dir, sizeof dir);
    char *slash = strrchr(dir, '\\');
    if (slash) *slash = 0;
    int n = snprintf(cmd, sizeof cmd, "\"%s\\cstrike.exe\"", dir);
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-launcher-stay")) stay = 1;
        else if (!strcmp(argv[i], "-launcher-nothing")) nothing = 1;
        else n += snprintf(cmd + n, sizeof cmd - n, " %s", argv[i]);
    }
    if (nothing) return 0;

    STARTUPINFOA si = { sizeof si };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, dir, &si, &pi)) {
        printf("launcher: could not start %s (error %lu)\n", cmd, GetLastError());
        return 1;
    }
    printf("launcher pid %lu started game pid %lu\n", GetCurrentProcessId(), pi.dwProcessId);
    fflush(stdout);
    if (stay) WaitForSingleObject(pi.hProcess, INFINITE);
    return 0;
}
