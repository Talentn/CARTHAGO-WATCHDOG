# Sentinel anti-cheat (monorepo)

Layout follows the architecture plan §12. Only Phase 0 risk spike 1 exists so far.

| Path | What |
| --- | --- |
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
