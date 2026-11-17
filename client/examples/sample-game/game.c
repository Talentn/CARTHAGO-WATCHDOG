/* Carthago Watchdog sample game: the smallest host program that uses the client SDK the
 * way a studio's game does, through carthago_sentinel.h and carthago_sentinel.dll only.
 *
 *   carthago-sample-game --server-key-hex HEX [--gateway wss://127.0.0.1:8750/v1/client]
 *                        [--gateway-pin HEX[,HEX]] [--tenant demo] [--player NAME] [--secs 12]
 *                        [--load FILE.dll] [--no-tpm] [--no-window]
 *
 * It opens a session (TPM attestation where the PC has one), prints the trust level the
 * gateway gave it, plays a "match" (a frame loop that calls carthago_tick), and shows its own
 * screen when the gateway flags, kicks or bans it.
 *
 * --load makes the game load one more library itself, a few seconds into the match. The
 * test loads a harmless marker file that way, after putting the marker's hash on the
 * studio's list of known cheat files.
 *
 * Exit codes: 0 the match ran to its end, 3 banned (the banned screen was shown),
 * 4 kicked without a ban, 1 setup or handshake failure. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "carthago_sentinel.h"

static volatile LONG g_ready = -1;   /* CarthagoResult of the session request, -1 while waiting */
static volatile LONG g_trust = 0;
static volatile LONG64 g_flags = 0;
static volatile LONG g_kicked = 0;
static volatile LONG g_notice = 0;   /* CARTHAGO_NOTICE_* of the last notice, 0 for none */

/* Callbacks run on the SDK's thread: they only record what happened; the game thread acts. */
static void on_log(int32_t level, const char* msg, void* user) {
    static const char* names[] = {"debug", "info", "warn", "error"};
    (void)user;
    printf("[sdk:%s] %s\n", names[level < 0 || level > 3 ? 1 : level], msg);
}

static void on_ready(CarthagoResult result, uint32_t trust, uint64_t flags, void* user) {
    (void)user;
    InterlockedExchange(&g_trust, (LONG)trust);
    InterlockedExchange64(&g_flags, (LONG64)flags);
    InterlockedExchange(&g_ready, result);
}

static void on_kick(const char* reason, void* user) {
    (void)user;
    printf("[game] the gateway ended this session: %s\n", reason);
    InterlockedExchange(&g_kicked, 1);
}

static void on_notice(const CarthagoNotice* n, void* user) {
    (void)user;
    InterlockedExchange(&g_notice, (LONG)n->category);
}

static const char* arg(int argc, char** argv, const char* name, const char* def) {
    int i;
    for (i = 1; i + 1 < argc; i++)
        if (strcmp(argv[i], name) == 0) return argv[i + 1];
    return def;
}

static int has(int argc, char** argv, const char* name) {
    int i;
    for (i = 1; i < argc; i++)
        if (strcmp(argv[i], name) == 0) return 1;
    return 0;
}

static const char* trust_name(uint32_t level) {
    switch (level) {
    case 0: return "Software (a software device key, no TPM)";
    case 1: return "TPM key (the device key is in the TPM)";
    case 2: return "Attested (the TPM proved the device key and the boot record)";
    case 3: return "Ranked boot (attested, with Secure Boot and memory integrity on)";
    default: return "unknown";
    }
}

static void print_trust(uint32_t level, uint64_t f) {
    static const struct { uint64_t bit; const char* name; } bits[] = {
        {CARTHAGO_ATTEST_TPM_DEVICE_KEY, "device key in the TPM"},
        {CARTHAGO_ATTEST_DEVICE_KEY_CERTIFIED, "device key certified by the TPM"},
        {CARTHAGO_ATTEST_AK_BOUND_TO_EK, "attestation key bound to the TPM's endorsement key"},
        {CARTHAGO_ATTEST_EK_CHAIN_VERIFIED, "TPM maker's certificate chain verified"},
        {CARTHAGO_ATTEST_QUOTE_VERIFIED, "boot record quote verified"},
        {CARTHAGO_ATTEST_SECURE_BOOT, "Secure Boot on"},
        {CARTHAGO_ATTEST_HVCI, "memory integrity (HVCI) on"},
        {CARTHAGO_ATTEST_TEST_SIGNING_OFF, "test signing off"},
        {CARTHAGO_ATTEST_KERNEL_DEBUG_OFF, "kernel debugging off"},
        {CARTHAGO_ATTEST_CODE_INTEGRITY, "code integrity on"},
    };
    size_t i;
    printf("TRUST LEVEL %u: %s\n", level, trust_name(level));
    for (i = 0; i < sizeof bits / sizeof bits[0]; i++)
        if (f & bits[i].bit) printf("    proved to the gateway: %s\n", bits[i].name);
    if (f == 0) printf("    nothing proved: the gateway treats this PC as unattested\n");
}

static const char* notice_name(uint32_t category) {
    switch (category) {
    case CARTHAGO_NOTICE_TEST: return "test notice";
    case CARTHAGO_NOTICE_GAME_INTEGRITY: return "game integrity";
    case CARTHAGO_NOTICE_DEBUGGER: return "debugger";
    case CARTHAGO_NOTICE_TIME_MANIPULATION: return "time manipulation";
    case CARTHAGO_NOTICE_AIM_ASSISTANCE: return "aim assistance";
    case CARTHAGO_NOTICE_VISIBILITY: return "visibility";
    default: return "flagged";
    }
}

/* Calls carthago_tick once per frame until the session request is answered. */
static CarthagoResult wait_session(void) {
    ULONGLONG deadline = GetTickCount64() + 90000;
    while (g_ready < 0 && GetTickCount64() < deadline) {
        carthago_tick();
        Sleep(16);
    }
    return g_ready < 0 ? CARTHAGO_ERR_SESSION_FAILED : (CarthagoResult)g_ready;
}

/* The game's own banned screen: the reference is all the gateway tells a player. */
static int banned_screen(int window) {
    char ref[64] = "";
    char text[256];
    size_t len = sizeof ref;
    if (carthago_get_ban(ref, &len, NULL, NULL) != CARTHAGO_OK) strcpy(ref, "(no reference)");
    printf("\n");
    printf("  +--------------------------------------------------+\n");
    printf("  |                    YOU ARE BANNED                |\n");
    printf("  |  This account and this PC cannot play.           |\n");
    printf("  |  Reference: %-36s |\n", ref);
    printf("  |  Quote the reference to support to appeal.       |\n");
    printf("  +--------------------------------------------------+\n\n");
    printf("BANNED SCREEN shown, reference %s\n", ref);
    if (window) {
        snprintf(text, sizeof text, "You are banned.\n\nThis account and this PC cannot play.\nReference: %s\n\nQuote the reference to support to appeal.", ref);
        MessageBoxA(NULL, text, "Sample Game", MB_OK | MB_ICONSTOP | MB_SETFOREGROUND);
    }
    return 3;
}

int game_main(int argc, char** argv) {
    const char* key_hex = arg(argc, argv, "--server-key-hex", NULL);
    const char* player = arg(argc, argv, "--player", "sample-player");
    const char* load = arg(argc, argv, "--load", NULL);
    const double secs = atof(arg(argc, argv, "--secs", "12"));
    const int window = !has(argc, argv, "--no-window");
    CarthagoConfig cfg;
    CarthagoResult r;
    CarthagoStatus st;
    char token[1024];
    size_t token_len = sizeof token;
    ULONGLONG start, last_status;
    int loaded = 0, exit_code = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (!key_hex) {
        fprintf(stderr, "--server-key-hex is required (server_identity.public_key of the gateway's public-keys.json)\n");
        return 1;
    }

    /* 1. Start the SDK. Returns at once; scanning and the device key start on its thread. */
    memset(&cfg, 0, sizeof cfg);
    cfg.abi_version = CARTHAGO_ABI_VERSION;
    cfg.struct_size = sizeof cfg;
    cfg.tenant_id = arg(argc, argv, "--tenant", "demo");
    cfg.build_id = "sample-game-1.0";
    cfg.gateway_url = arg(argc, argv, "--gateway", "wss://127.0.0.1:8750/v1/client");
    cfg.server_identity_key_hex = key_hex;
    cfg.tls_pins_hex = arg(argc, argv, "--gateway-pin", NULL);
    cfg.log = on_log;
    cfg.flags = has(argc, argv, "--no-tpm") ? CARTHAGO_FLAG_NO_TPM : 0;
    if ((r = carthago_init(&cfg)) != CARTHAGO_OK) {
        printf("[game] carthago_init failed: %d\n", r);
        return 1;
    }
    carthago_set_kick_callback(on_kick, NULL);
    carthago_set_notice_callback(on_notice, NULL);
    carthago_set_activity(CARTHAGO_MENU);

    /* 2. Open the session for the signed-in player. */
    printf("[game] player %s signs in\n", player);
    if ((r = carthago_begin_session(player, on_ready, NULL)) != CARTHAGO_OK) {
        printf("[game] carthago_begin_session failed: %d\n", r);
        carthago_shutdown();
        return 1;
    }
    r = wait_session();
    if (r == CARTHAGO_ERR_BANNED) {
        exit_code = banned_screen(window);
        carthago_shutdown();
        return exit_code;
    }
    if (r != CARTHAGO_OK) {
        printf("[game] no session (result %d): the game would not start a ranked match\n", r);
        carthago_shutdown();
        return 1;
    }
    print_trust((uint32_t)g_trust, (uint64_t)g_flags);

    /* 3. The token goes to the studio's game server, which verifies it offline. */
    if (carthago_get_session_token(token, &token_len) != CARTHAGO_OK) {
        printf("[game] carthago_get_session_token failed\n");
        carthago_shutdown();
        return 1;
    }
    printf("SESSION TOKEN %u bytes, for the game server: %.24s...\n", (unsigned)token_len, token);

    /* 4. The match: one carthago_tick per frame, nothing else. */
    carthago_set_activity(CARTHAGO_IN_MATCH);
    printf("[game] match started\n");
    start = last_status = GetTickCount64();
    while ((GetTickCount64() - start) / 1000.0 < secs) {
        ULONGLONG now = GetTickCount64();
        carthago_tick();
        Sleep(16);
        if (load && !loaded && now - start >= 3000) {
            loaded = 1;
            printf("[game] loading %s\n", load);
            if (!LoadLibraryA(load)) printf("[game] could not load %s (error %lu)\n", load, GetLastError());
        }
        if (g_notice) {
            printf("FLAGGED the gateway flagged this session: %s. The game shows its own warning here.\n", notice_name((uint32_t)g_notice));
            InterlockedExchange(&g_notice, 0);
        }
        if (g_kicked) break;
        if (now - last_status >= 3000) {
            last_status = now;
            memset(&st, 0, sizeof st);
            st.struct_size = sizeof st;
            if (carthago_get_status(&st) == CARTHAGO_OK)
                printf("[game] playing: heartbeats %llu sent, %llu answered; scanner used %.2f ms of CPU in %llu slices\n",
                       (unsigned long long)st.heartbeats_sent, (unsigned long long)st.heartbeats_acked,
                       st.sched_worker_cpu_ns / 1e6, (unsigned long long)st.sched_slices);
        }
    }

    /* 5. Kicked: leave the match and ask for a session again. A banned player is refused. */
    if (g_kicked) {
        printf("[game] match left\n");
        InterlockedExchange(&g_ready, -1);
        exit_code = 4;
        if (carthago_begin_session(player, on_ready, NULL) == CARTHAGO_OK && wait_session() == CARTHAGO_ERR_BANNED)
            exit_code = banned_screen(window);
    } else {
        printf("MATCH FINISHED nothing was flagged\n");
    }
    carthago_shutdown();
    return exit_code;
}
