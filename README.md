# Carthago Watchdog

**Strong enough for ranked, light enough that players never notice, and no kernel driver in
your store-page disclosure.**

Carthago Watchdog is a user-mode anti-cheat for PC games. A small, fast client SDK acts as a
tamper-resistant sensor inside the game process. A Go backend makes every decision: it
verifies hardware-backed identity, analyses what the client reports and what the game server
saw, and shows the studio exactly why a player was flagged.

There is no ring-0 component and nothing that runs at boot. Instead, the system compensates
for the missing kernel access in four ways:

1. **Server authority.** The client only observes. Thresholds, allowlists and verdicts all
   live on the server, and the game server enforces kicks.
2. **Behavioural and statistical detection** on server-observed gameplay. This doesn't care
   how a cheat is built, so it also catches cheats that never touch the game process.
3. **Platform attestation from user mode.** TPM-bound device keys plus a TPM quote over the
   Windows measured-boot log prove Secure Boot, HVCI, no test signing and no kernel debugger.
4. **Integrity scanning on a strict budget.** Client scans run inside a scheduler that
   guarantees the frame never pays for them.

![Carthago Watchdog studio dashboard](docs/images/dashboard-overview.png)

<sub>The studio dashboard with synthetic demo traffic: live sessions by trust level, flagged
players ranked by risk, and the evidence behind each detection.</sub>

---

## Key features

| | |
| --- | --- |
| **TPM attestation** | Per-device keys that live in the TPM; the attestation key (AK) is bound to the TPM's endorsement key (EK); the quote is verified and the boot log replayed server-side. Trust levels go from 0 (software key) to 3 (attested, and the boot state meets the ranked policy). Machines without a usable TPM fall back to lower levels instead of failing. |
| **Signed sessions** | The gateway issues PASETO v4 session tokens that game servers verify **offline** against published keys. If the gateway is unreachable, verified players keep playing. |
| **Pinned transport** | The handshake is signed by a gateway identity key pinned in the client. After the handshake, every message rides an AEAD channel whose keys are bound to the handshake transcript, with strict sequence numbers. rustls TLS with pinning for the client transport is being integrated. |
| **Heartbeat deadlines** | A client that stops reporting is kicked by the server. The game server's watch channel delivers the kick even when it starts watching late. |
| **Client integrity scans** | Module inventory; executable memory with no backing image; thread start addresses; timing and loader API integrity; graphics-module `.text` compared with disk; external process handles; overlay windows; debugger signals; known-vulnerable drivers; time-source samples; injected-input counters. Plus a mitigation-policy profile applied at startup. |
| **Server-side detections** | Snap-and-lock aim; headshot rate against an MMR baseline (binomial z-test); time-to-damage against the lobby (robust z-score); sustained command rate; trigger-interval regularity; time-source divergence; scanner stalls. Client findings are classified against an allowlist of common overlays and capture tools (Steam, Discord, OBS, RTSS, NVIDIA). |
| **Studio dashboard** | Sessions and trust levels, flagged players ranked by severity × confidence, a per-player history and the raw evidence for every verdict. Read-only, tenant-isolated, and served on its own listener. |
| **No false-ban defaults** | Behavioural evidence is advisory and goes to review. Automatic kicks can be enabled only for critical client-integrity evidence, and are off by default. |

---

## Architecture

```
          ┌────────────────────────────── player PC ───────────────────────────────┐
          │  Game process                                                          │
          │  ┌──────────────┐   carthago_sentinel.dll (C ABI)                      │
          │  │  game loop   │──▶ tick() ≤ 20 µs ─┐                                 │
          │  └──────────────┘                    ▼                                 │
          │        carthago-core ── carthago-sched (budgeted worker, ≤ 3 ms/slice) │
          │              │             └─ carthago-scan jobs · carthago-harden     │
          │              │  carthago-attest (TPM device key, AK, quote, boot log)  │
          └──────────────┼─────────────────────────────────────────────────────────┘
                         │  handshake + AEAD heartbeats (findings, telemetry, coverage)
                         ▼
┌──── Carthago Gateway (Go) ───────────────────────────────────────────────────────┐
│  /v1/client   handshake · attestation verify · session tokens · deadlines        │
│  /v1/gs       game-server watch channel ──▶ kicks                                │
│  /v1/ingest   gameplay batches (idempotent on batch_seq)                         │
│        │                                                                         │
│        ▼                                                                         │
│  pipeline (bounded queue) ──▶ analyzer rules ──▶ evidence store (SQLite)         │
│                                                         │                        │
│  dashboard listener (per-tenant login) ◀────────────────┘                        │
└──────────────────────────────────────────────────────────────────────────────────┘
          ▲  offline token check · watch/kick              ▲  gameplay telemetry
          │                                                │
┌──── game server ─────────────────────────────────────────────────────────────────┐
│  carthago-server: offline Verifier · KickListener · MatchRecorder, GameplayStream│
└──────────────────────────────────────────────────────────────────────────────────┘
```

The client never decides anything about itself: it reports what it observes, and the
gateway turns reports into evidence. The game server is the enforcement point. It admits
players by verifying their token offline and removes them when the gateway sends a kick.

---

## Repository layout

The product was renamed from its working title. New code already uses the Carthago names;
**several existing crates still carry their old `sn-` names until the dedicated rename step**
(see the right-hand column).

| Path | Component | Carthago name |
| --- | --- | --- |
| `proto/` | Wire protocol (`sentinel/v1/*.proto`), spec in `proto/README.md`, golden vectors in `proto/testvectors/` | package `carthago.v1` |
| `client/crates/sn-client-ffi` | Game-facing DLL with a C ABI; header `sdk/native/include/sentinel.h` | `carthago-sentinel` → `carthago_sentinel.dll` / `carthago_sentinel.h` |
| `client/crates/sn-client-core` | SDK runtime: device identity, gateway session, scan scheduling, heartbeats | `carthago-core` |
| `client/crates/sn-sched` | Budgeted scan scheduler (token bucket, slice caps, job quarantine) | `carthago-sched` |
| `client/crates/sn-attest` | TPM device key, AK enrollment, quote and boot-log fetch via the Platform Crypto Provider | `carthago-attest` |
| `client/crates/sn-proto`, `sn-crypto` | Generated messages; handshake, AEAD and token crypto | `carthago-proto`, `carthago-crypto` |
| `client/crates/sn-server` | Game-server SDK: offline verification, kick listener, gameplay stream | `carthago-server` |
| `client/crates/carthago-scan` | Phase 1 client integrity scans as budgeted jobs | — |
| `client/crates/carthago-harden` | Mitigation-policy profiles applied at SDK init | — |
| `client/examples/gs-stub` | Game-server stub: `serve`, `verify`, `simulate` | — |
| `client/spikes/` | Phase 0 measurement harnesses (scheduler, attestation) | — |
| `backend/cmd/gateway` | The gateway, analysis pipeline and dashboard in one binary | `carthago-gateway` |
| `backend/internal/gateway` | Handshake, attestation glue, sessions, heartbeats, `/v1/gs`, `/v1/ingest` | |
| `backend/internal/attest` | Attestation verification on `google/go-attestation` | |
| `backend/internal/analyzer` | Pure detection rules (no I/O); every threshold lives here | |
| `backend/internal/pipeline` | Bounded queue from gateway to analyzer and evidence store | |
| `backend/internal/store` | Store interface; SQLite (pure Go, no cgo) and in-memory | |
| `backend/internal/dashboard` | Studio dashboard (server-rendered, no JavaScript) | |
| `backend/cmd/carthago-sim` | Simulated clients sending synthetic telemetry (demo, tests) | |
| `sdk/native/sample` | Minimal C++ game using the SDK (CMake) | |
| `tools/` | `carthago-e2e.sh` (Linux), `run-e2e.ps1` and `run-tpm-spike.ps1` (Windows) | |

---

## Quick start

### Prerequisites

- **Go 1.27+** and **Rust stable**.
- **Windows** client builds: MSVC toolchain, CMake for the C++ sample, and a TPM 2.0 for
  attested trust levels (the SDK falls back to a software key without one).
- **Linux** works for the backend, the game-server SDK, the portable crates and the e2e check.

### Build and test

```bash
cd backend && go test ./... && go build -o bin/carthago-gateway ./cmd/gateway
cd client  && cargo build --workspace          # on Windows: the full workspace
cd client  && cargo test --workspace --exclude sched-spike --exclude sn-attest \
                --exclude attest-spike --exclude sn-client-core --exclude sn-client-ffi   # on Linux
cd client  && cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu   # type-check the Windows code from Linux
```

### Run the gateway and the dashboard

```bash
cd backend
go run ./cmd/gateway -data gateway-data
#   client and game-server endpoints   ws://127.0.0.1:8750   (/v1/client, /v1/gs, /v1/ingest)
#   dashboard                           http://127.0.0.1:8751
#   dashboard login                     studio "demo", key "demo-dashboard-key"
```

Useful flags: `-tenant id=server-key` and `-dashboard-key id=login-key` (both repeatable),
`-store memory`, `-auto-kick` (critical integrity evidence only),
`-dashboard-listen ""` (disables the dashboard), `-dashboard-secure-cookie` (behind HTTPS),
and `-hb-interval` / `-hb-timeout`.

To fill the dashboard with synthetic traffic:

```bash
cd backend && go run ./cmd/carthago-sim -keys gateway-data/public-keys.json -sessions-out /tmp/sessions.txt &
cd client  && cargo run -p gs-stub -- simulate --sessions /tmp/sessions.txt \
                 --anomaly 2=snap+headshot --anomaly 6=fast --anomaly 7=cmdrate
```

### End-to-end checks

**Linux** (synthetic traffic through the gateway, pipeline and dashboard; about 80 s):

```bash
tools/carthago-e2e.sh
```

**Windows** (the real SDK in a C++ sample, the game-server stub, token tampering and expiry,
and a heartbeat-deadline kick):

```powershell
powershell -ExecutionPolicy Bypass -File tools\run-e2e.ps1          # TPM path (trust 2/3 on an attestable PC)
powershell -ExecutionPolicy Bypass -File tools\run-e2e.ps1 -NoTpm   # software device key (trust 0)
```

---

## SDK integration

### Native C++ (available)

Link the import library, ship the DLL next to the game, and call four functions. The C ABI
still uses the `sn_` prefix and `sentinel.h` until the rename step, after which it becomes
`carthago_` / `carthago_sentinel.h`. Flags added since then already use the `CARTHAGO_`
prefix.

```cpp
#include "sentinel.h"

SnConfig cfg{};
cfg.abi_version = SN_ABI_VERSION;
cfg.struct_size = sizeof(SnConfig);
cfg.tenant_id = "your-studio";
cfg.build_id = "1.4.2";
cfg.gateway_url = "wss://gateway.example.com/v1/client";
cfg.server_identity_key_hex = kGatewayIdentityKey;   // from public-keys.json, pinned in the build
cfg.flags = 0;                                       // or CARTHAGO_FLAG_STRICT_MITIGATIONS, ...
sn_init(&cfg);                                       // ≤ 50 ms, work happens off the main thread

sn_set_kick_callback(on_kick, nullptr);
sn_begin_session(player_id_hmac, on_session_ready, nullptr);   // async; you get trust level + flags

// every frame, on the game thread:
sn_tick();                                           // ≤ 20 µs p99
sn_set_activity(SN_IN_MATCH);                        // scans slow down in matches, catch up in menus

// when joining a server: hand the token to your game server
sn_get_session_token(buf, &len);
```

The game server checks the token offline with `carthago-server` (Rust) and keeps the kick
channel open:

```rust
let verifier = Verifier::new(PublicKeys::load("public-keys.json")?.token_keys, "your-studio").with_min_trust(2);
let claims = verifier.verify(&token)?;                 // no network round-trip
let (kicks, events) = KickListener::start("wss://gateway.example.com/v1/gs", SERVER_KEY);
kicks.watch(&claims.session_id);                       // events yields GsEvent::Kick { session_id, reason, .. }
```

For the behavioural rules, record gameplay with `MatchRecorder` (view angles, shots,
visibility changes, command counts, trigger timestamps) and send each flushed batch through
`GameplayStream`. `send` never blocks the tick.

### Unity and Unreal (coming)

- **Unreal Engine**: plugin with the `PreLogin` token check, kick handling and a gameplay
  stream from the server. *Coming.*
- **Unity**: package for the client SDK plus a Netcode for GameObjects server sample.
  *Coming.*
- C# and Go server wrappers for the token check and kick channel. *Coming.*

---

## Performance budgets

Overhead is a product feature, and the budgets are enforced by design rather than hoped for.

| Budget | Target | How it is held |
| --- | --- | --- |
| Game-thread cost | `tick()` ≤ 20 µs p99 | `tick` only drains a lock-free findings queue and updates counters; it never scans |
| Background CPU | ≤ 1% of one core during play | Token-bucket scheduler with per-activity CPU shares (0.8% in a match; more in menus and loading screens); below-normal priority and EcoQoS |
| Scan slice | ≤ 3 ms wall per slice | Each job declares a per-step cap; steps run in small slices (0.5 ms on 2-core machines). A job that overruns 3 times is quarantined and the server sees the lost coverage |
| Frame time | p99 delta ≤ 1% | Most scanning happens outside matches; after a frame hitch, the worker starts no new slices for 100 ms |
| Memory | ≤ 25 MB | Bounded snapshots (for example, a 1 MB cap on the handle snapshot); no unbounded caches |
| Network | ≤ 2 KB/s average | Heartbeats every 15 s, at most 96 findings each; findings are deduplicated at the source |
| Startup | ≤ 50 ms, off the main thread | One 2 ms clock calibration; the TPM work runs on the SDK thread |

Every heartbeat reports scheduler counters, per-job coverage, slices over 3 ms and the CPU
used by the input thread. The dashboard shows each session's background CPU against the 1%
budget. The published benchmark report (PresentMon frame times with the SDK on and off, on a
mid-range PC and a low-end laptop) ships with the pilot release.

---

## Security model

**Trust boundaries.** The client runs on hardware the cheater controls, so it is treated as an
observer that can be lied to, never as an authority.
- Verdicts, thresholds and allowlists live only on the server.
- Kicks are carried out by the game server, never by the client.
- Losing contact is itself a signal: a missed heartbeat deadline kicks the session.

**Identity.**
- Each install holds a device key: TPM-resident where possible, software otherwise.
- The handshake proves possession of that key over a transcript signed by the pinned
  gateway identity.
- TPM evidence raises the session's trust level. Studios gate ranked queues on the trust
  level carried in the token.

**Sessions.**
- Session tokens are PASETO v4 (Ed25519), short-lived and renewed through heartbeats.
- Game servers verify tokens offline against published key IDs.
- All client↔gateway traffic after the handshake is AEAD-sealed with direction-separated
  keys and strict sequence numbers, so a replayed or reordered frame is a protocol violation
  and kicks the session.

**Tenancy.**
- Game servers authenticate with a per-tenant server key, and their gameplay can only link
  to sessions of the same tenant.
- Dashboard logins are per tenant. The tenant comes from an HMAC-signed, `HttpOnly`,
  `SameSite=Strict` cookie, and every query is scoped to it.
- The dashboard has no JavaScript and sends a strict `Content-Security-Policy`.
- Failed logins are throttled per client IP.

**What user mode can't see, and the answer.** Kernel, DMA and hardware cheats can hide from
an in-process scanner. They can't hide their effects on gameplay, so they are caught by the
server-side behavioural rules, while attestation closes the cheap kernel paths (test
signing, kernel debugging, HVCI off).

**False bans.** Statistical evidence is flag-for-review only. The overlay and capture-tool
allowlist keeps common software from being flagged. Automatic action is opt-in and limited
to critical integrity evidence.

**Privacy.**
- The client reports codes, addresses, sizes and module or process *base names*, never
  memory contents, full paths, screenshots or keystrokes.
- Only derived attestation booleans are stored, not raw boot logs.
- Player identifiers are studio-side HMACs of platform IDs.

---

## Roadmap

Phases are defined by scope and exit criteria, not dates.

- **Phase 0: Foundations** (done). Wire protocol with shared golden vectors for Rust and Go;
  gateway handshake with TPM attestation; offline-verifiable tokens; client SDK and C++
  sample; game-server SDK; risk spikes for TPM attestation from user mode and for the
  budgeted scheduler.
- **Phase 1: MVP** (this branch).
  - Client integrity scans on the budgeted scheduler, plus the mitigation-policy profile.
  - Gameplay ingest and the server-side behavioural rules.
  - Evidence store and the studio dashboard.
  - Synthetic end-to-end checks.
  - Still to come in this phase:
    - pinned TLS on the client transport (in progress);
    - code-range challenges against uploaded build ground truth;
    - Unreal and Unity samples;
    - dashboard ban, appeal and webhook workflow;
    - a performance panel;
    - light client hardening.
- **Phase 2: First paying pilot.**
  - Launcher and helper.
  - Signed, streamed detection modules with a kill switch.
  - Per-queue attestation policy.
  - Honeypot entities in the server SDK.
  - A first flag-only ML model.
  - Ban waves and a device graph.
  - Billing, a privacy package, and the published benchmark report.
- **Phase 3: Depth of detection.** Sequence models on aim trajectories, per-game
  calibration, hardware-aim and colorbot classifiers, ESP behavioural models with replay
  evidence, an external security review.
- **Phase 4: Scale.** An opt-in cross-studio intelligence network, in-house obfuscation, and
  regional expansion.

---

## Development notes

- **Protobuf:** regenerate the Go code with `buf generate` in `proto/` (needs
  `protoc-gen-go`). Run `go run ./cmd/gen-testvectors` in `backend/` to check the golden
  vectors; it must be a no-op.
- **TPM attestation spike** (Windows, normal PowerShell, TPM 2.0):
  `.\tools\run-tpm-spike.ps1` (options `-Activation pcp`, `-NoFetchEK`). Exit code 0 means
  every cryptographic check passed; evidence lands in `attest-out\` and `attest-reports\`.
- **Windows build output:** builds put cargo output in `$env:CARGO_TARGET_DIR`. The
  PowerShell scripts default it to a scratch directory.
