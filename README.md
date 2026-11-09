# Sentinel anti-cheat (monorepo)

Layout follows the architecture plan §12. Phase 0: both risk spikes plus the foundations
(protocol, handshake gateway, client SDK, game-server SDK).

## Phase 0 foundations

| Path | What |
| --- | --- |
| `proto/` | Wire protocol (`sentinel/v1/*.proto`), spec in `proto/README.md`, golden vectors in `proto/testvectors/` |
| `client/crates/sn-proto`, `sn-crypto` | Rust: generated messages (prost + protox) and the handshake / AEAD / PASETO v4 token crypto |
| `backend/internal/protocol` | Go: the same crypto; both sides pass `proto/testvectors` |
| `backend/internal/gateway`, `cmd/gateway` | Go: Hello/Challenge/Prove handshake with TPM attestation, session tokens, heartbeats and kicks, game-server channel `/v1/gs` |
| `backend/internal/store` | Store interface with in-memory and SQLite (modernc, no cgo) implementations |
| `client/crates/sn-client-core` | Rust: SDK runtime (device identity, gateway session, sn-sched scan scheduler) |
| `client/crates/sn-client-ffi` | `sentinel.dll`, C ABI; header `sdk/native/include/sentinel.h` |
| `client/crates/sn-server` | Rust game-server SDK: offline token verification and the kick listener |
| `client/examples/gs-stub` | Game-server stub (`serve` / one-shot `verify`) |
| `sdk/native/sample` | Minimal C++ game using `sentinel.dll` (CMake) |
| `tools/run-e2e.ps1` | Builds everything and runs the end-to-end demo |

```powershell
.\tools\run-e2e.ps1            # TPM path (trust level 2/3 on an attestable PC)
.\tools\run-e2e.ps1 -NoTpm     # software device key (trust level 0)
cd client; cargo test --workspace
cd backend; go test ./...
cd backend; go run ./cmd/gen-testvectors   # regenerate proto/testvectors (must be a no-op)
```

Regenerate Go protobuf code with `buf generate` in `proto/` (needs `protoc-gen-go` on PATH).
Builds put cargo output in `$env:CARGO_TARGET_DIR` (the e2e script defaults it to
`E:\sentinel-spike-scratch\cargo-target` when E: exists).

## Risk spikes

| Path | What |
| --- | --- |
| `client/crates/sn-sched`, `client/spikes/sched-spike` | Rust: budgeted scan scheduler and its measurement harness |
| `client/crates/sn-attest` | Rust: TPM device key, AK enrollment, TBS quote and WBCL fetch via the Windows Platform Crypto Provider (no driver, no admin) |
| `client/spikes/attest-spike` | Rust CLI driving the spike against the verifier |
| `backend/internal/attest` | Go: verification on top of `google/go-attestation` (AK checks, AK-to-EK binding, quote, event-log replay, Secure Boot / HVCI / test-signing / debug state, ranked policy) |
| `backend/cmd/attest-spike` | Go: local HTTP verifier (`127.0.0.1:8740`) |
| `backend/cmd/attest-refclient` | Go: same flow using go-attestation's own Windows client, as a reference |
| `tools/run-tpm-spike.ps1` | Builds both and runs one attestation end to end |

## Run the TPM spike (Windows, normal non-elevated PowerShell)

Needs Rust (stable MSVC), Go 1.27+, and a TPM 2.0.

```powershell
.\tools\run-tpm-spike.ps1                      # default: --activation auto
.\tools\run-tpm-spike.ps1 -Activation pcp      # PCP credential activation (needs an elevated shell)
.\tools\run-tpm-spike.ps1 -NoFetchEK           # don't contact the TPM vendor for EK certs
```

Exit code 0 means every cryptographic check passed. Evidence lands in `attest-out\`
(requests, `wbcl.bin`, `report.json`) and `attest-reports\`.

Protocol: `POST /v1/enroll` (EK public + certs, AK creation evidence, device key) returns a
credential-activation blob and a decryption-EK challenge; `POST /v1/activate` takes either proof
and returns a 32-byte nonce; `POST /v1/attest` takes the quote over PCRs 0,2,4,7,11,12,13,14,
the PCR values, the WBCL and a device-key signature, and returns the report.

The spike creates per-user PCP keys `sentinel-spike-ak` and `sentinel-spike-device` and caches the
AK creation blob under `%LOCALAPPDATA%\Sentinel\spike\`.
