// Minimal "game" using sentinel.dll: init, session, per-frame sn_tick, forward the session
// token to the game server (gs-stub), and react to a kick.
//
//   sentinel-sample --server-key-hex HEX [--gateway ws://127.0.0.1:8750/v1/client]
//                   [--gateway-pin HEX[,HEX]] [--gs 127.0.0.1:8760] [--tenant demo] [--player HASH] [--no-tpm]
//                   [--run-secs 10] [--suppress-heartbeats-after SECS] [--token-out FILE]
//
// Exit codes: 0 ran to completion, 10 kicked by the game server, 1 setup/handshake failure,
// 2 game server rejected the token.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "sentinel.h"

using Clock = std::chrono::steady_clock;

namespace {

std::atomic<int> g_session_result{-1};
std::atomic<uint32_t> g_trust{0};
std::atomic<uint64_t> g_flags{0};

void on_log(int32_t level, const char* msg, void*) {
    static const char* names[] = {"debug", "info", "warn", "error"};
    std::printf("[sdk:%s] %s\n", names[level < 0 || level > 3 ? 1 : level], msg);
    std::fflush(stdout);
}

void on_ready(SnResult result, uint32_t trust, uint64_t flags, void*) {
    g_trust = trust;
    g_flags = flags;
    g_session_result = result;
}

void on_kick(const char* reason, void*) {
    std::printf("[game] SDK reports the gateway ended our session: %s\n", reason);
    std::fflush(stdout);
}

const char* arg(int argc, char** argv, const char* name, const char* def) {
    for (int i = 1; i + 1 < argc; i++)
        if (std::strcmp(argv[i], name) == 0) return argv[i + 1];
    return def;
}

bool flag(int argc, char** argv, const char* name) {
    for (int i = 1; i < argc; i++)
        if (std::strcmp(argv[i], name) == 0) return true;
    return false;
}

SOCKET connect_gs(const std::string& hostport) {
    auto colon = hostport.rfind(':');
    std::string host = hostport.substr(0, colon), port = hostport.substr(colon + 1);
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) return INVALID_SOCKET;
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s != INVALID_SOCKET && connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return s;
}

// Blocking read of one '\n'-terminated line (handshake reply only).
bool read_line(SOCKET s, std::string& line) {
    line.clear();
    char c;
    while (recv(s, &c, 1, 0) == 1) {
        if (c == '\n') return true;
        line.push_back(c);
    }
    return false;
}

}  // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    const char* key_hex = arg(argc, argv, "--server-key-hex", nullptr);
    if (!key_hex) {
        std::fprintf(stderr, "--server-key-hex is required (gateway-data/public-keys.json server_identity.public_key)\n");
        return 1;
    }
    const std::string gs = arg(argc, argv, "--gs", "127.0.0.1:8760");
    const char* player = arg(argc, argv, "--player", "player-hash-demo-0001");
    const double run_secs = std::atof(arg(argc, argv, "--run-secs", "10"));
    const double suppress_after = std::atof(arg(argc, argv, "--suppress-heartbeats-after", "-1"));
    const char* token_out = arg(argc, argv, "--token-out", nullptr);

    SnConfig cfg{};
    cfg.abi_version = SN_ABI_VERSION;
    cfg.struct_size = sizeof(SnConfig);
    cfg.tenant_id = arg(argc, argv, "--tenant", "demo");
    cfg.build_id = "sample-0.0.1";
    cfg.gateway_url = arg(argc, argv, "--gateway", "ws://127.0.0.1:8750/v1/client");
    cfg.server_identity_key_hex = key_hex;
    cfg.log = on_log;
    cfg.flags = flag(argc, argv, "--no-tpm") ? SN_FLAG_NO_TPM : 0;
    cfg.tls_pins_hex = arg(argc, argv, "--gateway-pin", nullptr); // required with a wss:// --gateway

    auto t0 = Clock::now();
    SnResult r = sn_init(&cfg);
    if (r != SN_OK) {
        std::printf("[game] sn_init failed: %d\n", r);
        return 1;
    }
    std::printf("[game] sn_init returned in %.2f ms\n", std::chrono::duration<double, std::milli>(Clock::now() - t0).count());
    sn_set_kick_callback(on_kick, nullptr);
    sn_set_activity(SN_MENU);
    if ((r = sn_begin_session(player, on_ready, nullptr)) != SN_OK) {
        std::printf("[game] sn_begin_session failed: %d\n", r);
        sn_shutdown();
        return 1;
    }

    // Frame loop at ~144 Hz; the SDK never blocks it.
    const auto frame = std::chrono::microseconds(6944);
    auto next = Clock::now();
    auto tick_frame = [&] {
        sn_tick();
        next += frame;
        std::this_thread::sleep_until(next);
    };
    auto deadline = Clock::now() + std::chrono::seconds(60);
    while (g_session_result < 0 && Clock::now() < deadline) tick_frame();
    if (g_session_result != SN_OK) {
        std::printf("[game] session failed (result %d)\n", g_session_result.load());
        sn_shutdown();
        return 1;
    }
    std::printf("[game] session ready in %.0f ms: trust_level %u attest_flags 0x%llx\n",
                std::chrono::duration<double, std::milli>(Clock::now() - t0).count(), g_trust.load(),
                (unsigned long long)g_flags.load());

    std::vector<char> buf(256);
    size_t len = buf.size();
    r = sn_get_session_token(buf.data(), &len);
    if (r == SN_ERR_BUFFER_TOO_SMALL) {
        buf.resize(len);
        r = sn_get_session_token(buf.data(), &len);
    }
    if (r != SN_OK) {
        std::printf("[game] sn_get_session_token failed: %d\n", r);
        sn_shutdown();
        return 1;
    }
    std::string token(buf.data(), len);
    std::printf("[game] session token (%zu bytes): %.40s...\n", token.size(), token.c_str());
    if (token_out) std::ofstream(token_out, std::ios::binary) << token;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET s = connect_gs(gs);
    if (s == INVALID_SOCKET) {
        std::printf("[game] cannot reach game server %s\n", gs.c_str());
        sn_shutdown();
        return 1;
    }
    std::string hello = "TOKEN " + token + "\n", reply;
    send(s, hello.data(), (int)hello.size(), 0);
    if (!read_line(s, reply) || reply.rfind("OK ", 0) != 0) {
        std::printf("[game] game server rejected us: %s\n", reply.c_str());
        closesocket(s);
        sn_shutdown();
        return 2;
    }
    std::printf("[game] game server admitted us: %s\n", reply.c_str());
    u_long nonblocking = 1;
    ioctlsocket(s, FIONBIO, &nonblocking);

    sn_set_activity(SN_IN_MATCH);
    auto match_start = Clock::now(), last_status = match_start;
    bool suppressed = false;
    int exit_code = 0;
    std::string gs_in;
    while (Clock::now() - match_start < std::chrono::duration<double>(run_secs)) {
        tick_frame();
        auto elapsed = std::chrono::duration<double>(Clock::now() - match_start).count();
        if (suppress_after >= 0 && !suppressed && elapsed >= suppress_after) {
#ifdef SN_DEV_HOOKS
            std::printf("[game] (test) suppressing heartbeats from now on\n");
            sn_dev_suppress_heartbeats(1);
#else
            std::printf("[game] built without SN_DEV_HOOKS; cannot suppress heartbeats\n");
#endif
            suppressed = true;
        }
        char tmp[256];
        int n = recv(s, tmp, sizeof tmp, 0);
        if (n > 0) gs_in.append(tmp, n);
        auto nl = gs_in.find('\n');
        if (nl != std::string::npos || n == 0) {
            std::string msg = gs_in.substr(0, nl);
            std::printf("[game] game server: %s\n", n == 0 && msg.empty() ? "(closed connection)" : msg.c_str());
            exit_code = msg.rfind("KICK", 0) == 0 ? 10 : 0;
            break;
        }
        if (Clock::now() - last_status >= std::chrono::seconds(2)) {
            last_status = Clock::now();
            SnStatus st{};
            st.struct_size = sizeof st;
            if (sn_get_status(&st) == SN_OK)
                std::printf("[game] status: state %u heartbeats %llu sent / %llu acked, scheduler %llu slices %.2f ms CPU, %llu frames\n",
                            st.state, (unsigned long long)st.heartbeats_sent, (unsigned long long)st.heartbeats_acked,
                            (unsigned long long)st.sched_slices, st.sched_worker_cpu_ns / 1e6, (unsigned long long)st.frames);
        }
    }
    closesocket(s);
    WSACleanup();
    sn_shutdown();
    std::printf("[game] exit %d\n", exit_code);
    return exit_code;
}
