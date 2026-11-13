/* Test stand-in for the game program (hl.exe, or cstrike.exe in builds that name it so): a
 * 32-bit process that looks, from outside, the way a GoldSrc client does. It loads two
 * unsigned DLLs from its own folder, named like the engine and the game DLL (hw.dll,
 * cstrike\dlls\mp.dll; both are built from fake_dll.c), and maps one executable
 * region with a PE header that the Windows loader knows nothing about, as build 4554 does
 * with its encrypted hw.dll. It contains no game code and is never shipped.
 *
 *   hl.exe [-game cstrike] [-secs N]      runs N seconds (default 20), then exits with 0
 *
 * With "+map <name>" it also writes what the kit's AMX Mod X plugin would write, so that the
 * script's staged check can be tested without the game: when the plugin file is installed and
 * listed, it reads cstrike\addons\amxmodx\configs\carthago_cs16.ini and appends the plugin's
 * step lines to cstrike\addons\amxmodx\logs\carthago_cs16.log; with a selftest time it ends
 * by itself; with -condebug it appends to cstrike\qconsole.log. Two environment variables
 * stand for a game the plugin does not get along with:
 *   FAKE_CS16_CRASH_STAGE=n      the process ends in the middle of the first step of stage n
 *                                (1: while the plugin loads), with exit code 0 as after a
 *                                game error
 *   FAKE_CS16_IGNORE_EXTRA_INI=1 only configs\plugins.ini is read, not plugins-*.ini
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AMXX "cstrike\\addons\\amxmodx\\"

static int condebug;

static void append(const char *path, const char *prefix, const char *text) {
    FILE *f = fopen(path, "ab");
    if (!f) return;
    fprintf(f, "%s%s\r\n", prefix, text);
    fclose(f);
}
static void console(const char *text) {
    if (condebug) append("cstrike\\qconsole.log", "", text);
}
static void mark(const char *text) {
    SYSTEMTIME t;
    char prefix[64], line[400];
    GetLocalTime(&t);
    snprintf(prefix, sizeof prefix, "L %02d/%02d/%04d - %02d:%02d:%02d: ", t.wMonth, t.wDay, t.wYear, t.wHour, t.wMinute, t.wSecond);
    append(AMXX "logs\\carthago_cs16.log", prefix, text);
    snprintf(line, sizeof line, "[Carthago] %s", text);
    console(line);
}
static int lists_plugin(const char *path) {
    char line[256];
    int found = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "carthago_cs16.amxx", 18)) found = 1;
    fclose(f);
    return found;
}
static int env_int(const char *name) {
    const char *v = getenv(name);
    return v ? atoi(v) : 0;
}

/* Returns the seconds after which the game is to close by itself (0: not), or -1 when the
 * process is to end at once, as after a game error. */
static int plugin(const char *map) {
    char token[64] = "-", line[256], text[400];
    int stage = 4, selftest = 0, crash = env_int("FAKE_CS16_CRASH_STAGE");
    FILE *f;

    if (GetFileAttributesA(AMXX "plugins\\carthago_cs16.amxx") == INVALID_FILE_ATTRIBUTES) return 0;
    if (!lists_plugin(AMXX "configs\\plugins.ini") &&
        (env_int("FAKE_CS16_IGNORE_EXTRA_INI") || !lists_plugin(AMXX "configs\\plugins-carthago.ini")))
        return 0;
    f = fopen(AMXX "configs\\carthago_cs16.ini", "rb");
    if (f) {
        while (fgets(line, sizeof line, f)) {
            line[strcspn(line, "\r\n")] = 0;
            if (!strncmp(line, "token=", 6)) snprintf(token, sizeof token, "%s", line + 6);
            if (!strncmp(line, "stage=", 6)) stage = atoi(line + 6);
            if (!strncmp(line, "selftest=", 9)) selftest = atoi(line + 9);
        }
        fclose(f);
    }
    if (crash == 1) return -1;
    snprintf(text, sizeof text, "load token=%s plugin=0.2.0 stage=%d amxx=1.9.0.5294 built_with=1.8.2 metamod=1.21p38 engine=1.1.2.7/Stdio,48,8684 mod=cstrike map=%s maxplayers=12 dedicated=0 selftest=%d",
        token, stage, map, selftest);
    mark(text);
    console("Protocol version 48");
    console("Exe version 1.1.2.7/Stdio (cstrike)");
    console("Exe build: 19:53:27 Aug  3 2020 (8684)");
    console("Currently loaded plugins:");
    console(" [ 1] AMX Mod X  RUN  -  amxmodx_mm.dll  v1.9.0.5294  ini  Start ANY");
    console(" Fakemeta  1.9.0.5294  AMX Mod X Dev Team  running");
    console(" Sockets  1.9.0.5294  AMX Mod X Dev Team  running");
    console(" [ 12] Carthago CS 1.6  0.2.0  Carthago  carthago_cs16.amxx  running");
    if (stage >= 2) {
        mark("step 1 socket: opening UDP 127.0.0.1:27991");
        if (crash == 2) return -1;
        mark("step 1 socket: ok");
        mark("step 2 positions: hooking StartFrame, 32 samples/s, match cs16-stand-in");
        mark("step 2 positions: ok");
        mark("first sample: begin");
        mark("first sample: ok");
    }
    if (stage >= 3) {
        mark("step 3 commands: hooking CmdStart");
        if (crash == 3) return -1;
        mark("step 3 commands: ok");
        mark("step 4 sight: world traces on, at most 24 per sample");
    }
    if (stage >= 4) {
        mark("step 5 shots: hooking PlaybackEvent and PlayerPreThink");
        if (crash == 4) {
            console("Host_Error: PF_playback_event: event index out of range");
            return -1;
        }
        mark("step 5 shots: ok");
    }
    snprintf(text, sizeof text, "all parts of stage %d are on", stage);
    mark(text);
    if (selftest) {
        Sleep(selftest * 1000);
        snprintf(text, sizeof text, "selftest passed: stage %d ran %d s; frames=%d datagrams=%d commands=0 traces=0 shots=0 hits=0 players=1 bots=%d",
            stage, selftest, selftest * 100, stage >= 2 ? selftest * 32 : 0, stage >= 2 ? 6 : 0);
        mark(text);
        mark("selftest: closing the game");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    int secs = 20;
    const char *map = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-condebug")) condebug = 1;
        if (i + 1 < argc && !strcmp(argv[i], "-secs")) secs = atoi(argv[i + 1]);
        if (i + 1 < argc && !strcmp(argv[i], "+map")) map = argv[i + 1];
    }

    HMODULE hw = LoadLibraryA("hw.dll");
    HMODULE mp = LoadLibraryA("cstrike\\dlls\\mp.dll");

    unsigned char *blob = VirtualAlloc(NULL, 0x40000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (blob) {
        memset(blob, 0xC3, 0x40000);
        memcpy(blob, "MZ", 2);
        *(DWORD *)(blob + 0x3c) = 0x80;
        memcpy(blob + 0x80, "PE\0\0", 4);
    }
    printf("stand-in game pid %lu: hw=%p mp=%p blob=%p, running %d s\n", GetCurrentProcessId(), (void *)hw, (void *)mp, (void *)blob, secs);
    fflush(stdout);
    if (map) {
        /* The companion needs a moment to see the engine module before the game ends. */
        Sleep(1500);
        if (plugin(map) < 0) return 0;
    }
    for (int i = 0; i < secs * 10; i++) {
        if (GetFileAttributesA("fake_hl.quit") != INVALID_FILE_ATTRIBUTES) break;
        Sleep(100);
    }
    return 0;
}
