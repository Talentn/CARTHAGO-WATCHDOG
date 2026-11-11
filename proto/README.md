# Carthago Watchdog wire protocol v1

Single source of truth for the client (`client/crates/carthago-proto`, `carthago-crypto`) and the backend
(`backend/gen`, `backend/internal/protocol`). Any change here must regenerate the golden vectors
in `testvectors/`, and both test suites must pass them:

```powershell
cd proto;   buf lint; buf generate                      # Go code -> backend/gen (Rust uses protox at build time)
cd backend; go run ./cmd/gen-testvectors; go test ./internal/protocol/
cd client;  cargo test -p carthago-crypto
```

## Transport and frames

One WebSocket (`/v1/client`). Every binary message is one frame whose first byte is its type:

| Type | Payload |
| --- | --- |
| `0x01` Hello | protobuf `Hello`, plaintext |
| `0x02` Challenge | protobuf `Challenge`, plaintext |
| `0x03` Sealed | `seq` (u64 BE) followed by ChaCha20-Poly1305 ciphertext and tag of a `ClientMsg` or `ServerMsg` |

Phase 0 runs `ws://` on loopback. TLS 1.3 with SPKI pinning goes on top in Phase 1 (§5.1). The
handshake doesn't depend on TLS: the server identity key is pinned in the client, and all
traffic after the Challenge is AEAD under ephemeral keys.

## Handshake

```
C->S Hello      { eph_pub_c, device_key, tenant, build, player_id_hash, env, tpm_enrollment? }
S->C Challenge  { body = ChallengeBody{ nonce_s, eph_pub_s, session_id, attest_req?, heartbeat timing },
                  server_sig = Ed25519_identity("carthago/v1/challenge-sig" || th) }
C->S Sealed#0   ClientMsg{ Prove{ device_sig(prove_digest), TpmEvidence? } }
S->C Sealed#0   ServerMsg{ Session{ token, trust_level, attest_flags, exp } }
then Heartbeat / HeartbeatAck (and Kicked) both ways, seq strictly +1 per direction
```

- `th = SHA-256("carthago/v1/transcript" || u32be(len H) || H || u32be(len B) || B)`, where `H` is the
  exact Hello bytes and `B` the exact ChallengeBody bytes received. Nothing is ever re-encoded.
- Keys: `shared = X25519(eph_c, eph_s)` (low-order points are rejected);
  `prk = HKDF-Extract(SHA-256, salt = th, ikm = shared)`;
  `k_c2s = HKDF-Expand(prk, "carthago/v1/key/c2s", 32)` and `k_s2c = HKDF-Expand(prk, "carthago/v1/key/s2c", 32)`.
- `prove_digest = SHA-256("carthago/v1/prove" || th)`. Ed25519 signs it as the message; ECDSA P-256
  (TPM key) signs it as a prehashed digest, output raw `r || s`.
- `quote_nonce = SHA-256("carthago/v1/quote" || th)` is the qualifying data of the TPM2_Quote and of
  TPM2_Certify(device key by AK), which binds the attestation to this handshake.
- `device_id = hex(SHA-256("carthago/v1/device-id" || alg_u8 || device_public_key)[..16])`.

## Sealed frames

`nonce = u32be(direction) || u64be(seq)`, where direction is 0 for client to server and 1 for server
to client. `AAD = "carthago/v1/aead" || session_id(16) || 0x03 || u64be(seq)`. The receiver
accepts only `seq == expected` (it starts at 0 and increments by 1), so replays, gaps and
reordering all fail. The plaintext `ClientMsg`/`ServerMsg` repeats `seq`, `session_id` and a
timestamp, and the gateway checks that they match.

## Attestation in the handshake

- **First contact (no AK on record for this device key):** the Hello carries `TpmEnrollment`
  (EK public, EK certs, EK chain certs, AK creation evidence). The Challenge asks for the go-attestation
  decryption-EK challenge (`ek_challenge`), a quote over PCRs 0,2,4,7,11,12,13,14 and a device-key
  certify. This takes no elevation; see `tpm-spike-findings.md`.
- **Later sessions:** the gateway already has the bound AK and skips `ek_challenge`.
- `ek_chain_certs` holds the certificates from the TPM's EK certificate chain NV indices
  (0x01C00100-0x01C001FF, TCG EK Credential Profile 2.2.1.5.2). Intel PTT on 11th gen Core and
  later keeps its per-device PTT, Kernel and ROM CAs there. The gateway uses them, at most 16,
  only as untrusted intermediates towards the bundled roots, never as the EK certificate.
- Every certificate on the EK chain must be within its validity period at the gateway's clock.
- Prove carries the EK-challenge certify, the quote and PCRs, the WBCL, and
  TPM2_Certify(device key) signed by the AK. All three are bound to `quote_nonce(th)`.

## Session token

PASETO **v4.public** (Ed25519) of the form `v4.public.<b64url(claims_json || sig)>.<b64url(footer)>`,
where the footer is `{"kid":"<hex(SHA-256(pub)[..8])>"}` and the implicit assertion is empty. Claims (in
this order): `iss, tenant, player_hash, device_id, session_id, iat, exp, trust_level, attest_flags`.
`iat` and `exp` are RFC 3339 UTC strings in whole seconds. Verifiers allow 30 s of clock-skew
leeway on `iat` and `exp`. The TTL is 15 minutes, and the gateway renews the token in a
`HeartbeatAck` once less than 5 minutes remain.

| `attest_flags` bit | Meaning |
| --- | --- |
| 0 `tpm_device_key` | the device key is declared as a PCP (TPM) key |
| 1 `device_key_certified` | TPM2_Certify by the AK proves the device key lives in the TPM |
| 2 `ak_bound_to_ek` | the AK is proven to share a TPM with the EK |
| 3 `quote_verified` | the quote is bound to this handshake and the WBCL replays to it |
| 4-9 | from the verified log: Secure Boot on, HVCI on, test-signing off, kernel debug off, boot debug off, code integrity on |
| 10 `ek_cert_matches` | an EK certificate for this EK was found (NV or the manufacturer service) |
| 11 `ek_chain_verified` | the EK certificate chains to a bundled manufacturer root (Intel, AMD, Infineon, STMicro, Nuvoton) |
| 12 `ek_chain_unknown_vendor` | an EK certificate exists, but no issuer path reaches a bundled root (unbundled vendor, self-issued, or missing intermediate) |
| 13 `ek_chain_invalid` | the EK certificate does not certify this EK, or a signature, CA constraint or validity period on its chain fails |

No bit among 10-13 set means no EK certificate was available.

`trust_level`: 0 software key; 1 TPM key claimed, but attestation is missing or failed, or the EK
chain is not verified; 2 attested (bits 0-3 plus 10 and 11); 3 attested and the ranked boot policy
holds (bits 0-11). Bit 13 caps the level at 1 whatever else is set. A software key is always 0.

## Game-server channel

`/v1/gs` WebSocket, authenticated with `Authorization: Bearer <tenant server key>`. It carries
`GsClientMsg{Watch|Unwatch}` and `GsServerMsg{Kick|WatchAck}`, one protobuf message per binary
frame. The gateway pushes `Kick` when a watched session misses its heartbeat deadline.

## Heartbeat telemetry (Phase 1)

A `Heartbeat` carries, besides the scheduler summary:

- `findings`: client scan observations, `code` from `FindingCode`. The client reports what it
  saw and nothing else; allowlists, thresholds and verdicts are server-side (plan §8.6).
  `detail` holds at most 47 bytes: a module or process base name, never a path or a window
  title (plan §10).
- `time`: QPC, `GetTickCount64` and `KUSER_SHARED_DATA.InterruptTime` read together. The
  server compares their rates with each other and with its own clock.
- `input`: cumulative low-level mouse hook counters (events, `LLMHF_INJECTED`,
  `LLMHF_LOWER_IL_INJECTED`, focused time).
- `coverage`: completed passes per scan job, so the server can tell a client that never scans.

## Gameplay ingest

`/v1/ingest` WebSocket, same `Authorization: Bearer <tenant server key>` as `/v1/gs`. The game
server sends one `GameplayBatch` per binary frame (per-match slots, view-angle tracks, shots,
visibility transitions, command counts, semi-auto trigger timestamps) and the gateway answers
each with an `IngestAck`. `batch_seq` must increase per match; a duplicate or older batch is
acknowledged with `accepted=false` and dropped.

### Telemetry v2

v2 adds what the information-leak scorer needs to decide what each player could legitimately
know. All v2 fields are new field numbers on `GameplayBatch` and `MatchPlayer`, so a v1 sender
leaves them empty and keeps working unchanged; `schema_version = 2` marks a v2 sender (0 or 1
is v1). `buf breaking` against the v1 schema passes.

| Field | Content |
| --- | --- |
| `MatchPlayer.team`, `input_device`, `aim_assist` | Team membership; mouse and keyboard, controller or touch; whether the game assists this player's aim |
| `mode` | `GAME_MODE_COMPETITIVE_SHOOTER` or `GAME_MODE_EXTRACTION` |
| `map` (`MapRef`) | `map_id` and `version` of the geometry the match is played on |
| `map_geometry` | The geometry itself (occluder prisms, named zones, loot spawns), sent once with a match's first batch |
| `motion` (`MotionTrack`) | Eye position (cm) and velocity (cm/s) per slot every `stride` ticks; within a track the first value is absolute and the rest are deltas (zigzag varints). View direction comes from the existing view-angle tracks |
| `sounds` (`SoundEvent`) | Footsteps, gunshots, reloads, abilities and interactions with their position and audible `radius_cm` |
| `team_info` (`TeamInfo`) | Pings, game-spotted enemies and radar reveals, with the team they were shared with and how long they last |
| `items` (`ItemEvent`) | Loot appearing, moving or being removed, with a value tier |
| `dropped_events` | Samples or events the recorder dropped at its per-batch caps |

**Map geometry is immutable per version.** The gateway stores a `(tenant, map_id, version)`
the first time it sees it and refuses different geometry under the same key; ship a new
version instead. Later matches may send only the `MapRef`. The gateway rejects version 0,
non-convex occluders, empty height ranges, and geometry over its limits (4,096 occluders of at
most 32 vertices, 256 zones, 1,024 loot spawns, 512 KiB encoded).

**Warnings.** A v2 problem never rejects the batch: v1 rules still run on it. Instead the ack
carries `IngestAck.warning` (field 5), for example an unknown map reference, conflicting
geometry, or invalid geometry; information-leak scoring is skipped for that match until the
map resolves. The Rust server SDK reports it in `IngestEvent::Acked { warning, .. }`.

**Recorder caps** (`carthago-server`, per flush): 16,384 motion samples, 4,096 sounds, 1,024
team-info events and 1,024 item events; anything past a cap is counted in `dropped_events`.
Motion is kept every 4th tick by default (`set_motion_stride`), which measures about 2.2 bytes
per player-tick on the wire at 64 Hz.

**Scoring** happens once per match, at `match_over`, and only produces flag-only evidence
(`information_leak`) that is never used for automatic kicks. The rule, its knowledge model and
its per-segment thresholds are documented in the `backend/internal/knowledge` package.
