# Driver list

Kernel cheats run as drivers, below anything a user-mode anti-cheat can read. Carthago has
no driver of its own and does not add one. Instead the client asks Windows for the list
Windows itself keeps: every kernel driver loaded since boot, signed by the Windows secure
kernel. The gateway checks the signature, keeps the list with the session, and raises for
review what should not be there. It covers part of the kernel-cheat gap, not all of it
(see Limits).

## What is checked

- **Client (Windows, user mode).** At every handshake the client calls
  `GetRuntimeAttestationReport` for the driver report, with a nonce derived from the
  handshake (`driver_list_nonce`, `proto/README.md`), and puts the package it gets back in
  `Prove.driver_list`, unread. It reads only: no driver, no elevation, no setting changed.
  When Windows has no list the client says why (no such function, memory integrity off,
  VBS not running, or the Windows error code) and the session opens all the same.
- **Gateway.** `internal/attest/driverlist.go` checks the package: layout, the nonce of
  this handshake, the SHA-512 digest of the driver report, and the RSA-PSS signature. The
  signing key is the secure kernel's key of that boot; its public half is measured by the
  boot loader into TPM PCR 12, so the gateway takes it from the session's TPM-verified
  boot record and from nowhere else. The result is one of:

  | Status | Meaning |
  | --- | --- |
  | `verified` | Signature checked with the key from the session's verified boot record |
  | `unverified` | The list parses, and the session has no verified boot record with the key in it (no TPM quote, or a quote that did not verify). The list is kept as the client's claim |
  | `unavailable` | The client had no list; the reason is stored |
  | `rejected` | Malformed, made for another handshake, empty, or badly signed |
  | `not_sent` | A client from before this feature |

- **Review signals.** Never a ban, a kick or a notice to the player; all three rules are
  of the suspicious tier (`analyzer/tiers.go`):

  | Rule | Raised when |
  | --- | --- |
  | `driver_vulnerable` | A listed driver's internal name is on the built-in list of 34 known vulnerable drivers (`internal/gateway/drivers.go`; the names the client's own scan uses). Several ship with ordinary tools, such as RTCore64 with MSI Afterburner |
  | `driver_unsigned` | A listed driver carries no signer certificate thumbprint |
  | `driver_test_signing` | The session's verified boot record says Windows was started accepting test-signed drivers. The list has no per-driver signing level, so this is per PC, not per driver |

- **Session page.** The card "Kernel drivers" shows the status and its reason, the number
  of drivers, the drivers raised, and the whole list (name, signer, image hash, load
  count) in a fold-out. `carthago-gateway drivers show -tenant ID -player P` prints the
  same reading in one line.

The list holds driver names, image hashes, signer thumbprints and the signer's program
name. It holds no paths, no user names and no file contents. It is the whole list, not
only matches, because the signature covers the whole list.

## Which Windows has it

| Windows | Result |
| --- | --- |
| Windows 11 24H2 or 25H2, build 26100.7705 / 26200.7705 (January 2026 update) or later, with memory integrity on | The list |
| The same with memory integrity (HVCI) off | Unavailable: Windows error 50, it keeps no list |
| The same with virtualization-based security not running | Unavailable: Windows error 1167 |
| Windows 11 24H2 builds 26100.7309 to 7704 | The function exists and returns a signed empty list, which the gateway rejects as "lists no driver" |
| Older Windows 11, Windows 10 | Unavailable: the function does not exist |

For `verified` the PC also needs a TPM 2.0 the gateway accepts a quote from, because the
key comes from the boot record. Sources: Microsoft Learn (`GetRuntimeAttestationReport`,
winnt.h `RUNTIME_REPORT_PACKAGE_HEADER`, `DRIVER_INFO_ENTRY`), Andrea Allievi's
description of the feature (January 2026), and an independent analysis of the package and
its signing key.

## What a studio turns on

Collection, verification, the review signals and the session card are always on; they
decide nothing by themselves.

The **unattested pool** is a setting of the studio, off by default:

```
carthago-gateway drivers pool -tenant ID -on      (-off; without either it shows the state)
```

While it is on, the game-server status call the studio's matchmaking already uses also
answers per player:

```
POST /v1/shadow/status {"players":["a","b"]}
{"players":[{"player":"a","status":"normal","attestation":"attested"},
            {"player":"b","status":"normal","attestation":"unattested"}]}
```

`attested` means the player's latest session reached trust level 3 (TPM-attested boot with
Secure Boot, memory integrity, test signing and debugging off) and sent a verified,
complete driver list with nothing raised in it. Everything else is `unattested`, including
a player the gateway has never seen. The studio decides what to do with it, for example
ranked queues for attested players only. It is not a ban and not a label, and nothing is
sent to the player.

`attestation` is worked out from the session's own evidence and never from the shadow
pool, so it is the same for a player in the shadow pool as for any other, and `status`
does not change. With the setting off the field is absent.

## Limits

- Nothing here was run against a real Windows package. The parser and the signature check
  are written from the published structures and tested with packages built the same way,
  plus the header and one entry of a published real package. A real PC may show that a
  detail is off; the session page then says `rejected` with the reason, and nothing else
  happens.
- A cheat driver that is loaded by exploiting an already loaded signed driver (manual
  mapping) is not in Windows' list. The vulnerable driver it came in through is.
- Boot-start drivers are not in the list. A full table (384 entries) is marked incomplete
  and counts as unattested.
- DMA hardware and hypervisors are out of scope.
- The vulnerable-driver list matches names, which a cheat author can change; the image
  hash in the list is what identifies a driver, and a hash list is the next step.
- Without a verified boot record the list is the client's claim. A cheater on such a PC
  can send any list; the session is then `unverified` and unattested.

## Test on a PC

```
powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -DriverList
```

prints one line and starts nothing:

```
DRIVER LIST: supported on this PC (Windows build 26100.7705). Windows returned its signed list of 182 kernel drivers loaded since boot (19793 bytes).
DRIVER LIST: not available on this PC (Windows build 22631.4317). This Windows has no signed driver list (...). The session works without it.
```

A normal run of the kit prints the same line before the game starts and, after the
session, the gateway's reading (`DRIVER LIST of session ...: 182 drivers loaded since
boot, signature verified; 0 raised for review; this session counts as attested`).
