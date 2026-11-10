<#
.SYNOPSIS
  Phase 0 end-to-end demo: gateway + game-server stub + C++ sample on this PC.

.DESCRIPTION
  Builds carthago_sentinel.dll (release, dev-hooks), gs-stub, the Go gateway and the CMake sample, then:
    1. sample obtains a signed session token (TPM-attested where available) and the game-server
       stub admits it after offline verification;
    2. the stub rejects a tampered token and an expired one (clock moved past exp + leeway);
    3. the sample stops heartbeating while staying connected; the gateway's deadline kicks the
       session and the stub disconnects the player;
    4. (TLS) a client pinning the wrong gateway key is refused before any handshake data flows.
  Gateway heartbeats are shortened to 2 s interval / 6 s timeout for the demo.
  The gateway serves wss:// (TLS 1.3) with a self-signed development certificate kept in the run
  directory; the sample and the stub pin its SPKI hash from public-keys.json (tls_spki_sha256).
  -Plaintext runs the Phase 0 ws:// loopback setup instead.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\carthago-e2e.ps1
  powershell -ExecutionPolicy Bypass -File tools\carthago-e2e.ps1 -NoTpm -SkipBuild
  powershell -ExecutionPolicy Bypass -File tools\carthago-e2e.ps1 -Plaintext
#>
param(
    [string]$Scratch = $(if (Test-Path E:\) { "E:\carthago-spike-scratch" } else { Join-Path $env:TEMP "carthago-e2e" }),
    [switch]$NoTpm,
    [switch]$SkipBuild,
    [switch]$Plaintext
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = Join-Path $Scratch "cargo-target" }
$rel = Join-Path $env:CARGO_TARGET_DIR "release"
$bin = Join-Path $Scratch "bin"
$sampleBuild = Join-Path $Scratch "sample-build"
$run = Join-Path $Scratch ("e2e-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
New-Item -ItemType Directory -Force $bin, $run | Out-Null

function Step($m) { Write-Host "`n=== $m" -ForegroundColor Cyan }
function Die($m) { Write-Host "FATAL: $m" -ForegroundColor Red; Cleanup; exit 1 }
$procs = @()
function Cleanup { $procs | Where-Object { $_ -and -not $_.HasExited } | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } }

if (-not $SkipBuild) {
    Step "build carthago_sentinel.dll + gs-stub (cargo, release)"
    Push-Location (Join-Path $root "client")
    cargo build --release -p carthago-sentinel --features dev-hooks
    if ($LASTEXITCODE) { Pop-Location; Die "cargo build carthago-sentinel" }
    cargo build --release -p gs-stub
    if ($LASTEXITCODE) { Pop-Location; Die "cargo build gs-stub" }
    Pop-Location

    Step "build gateway (go)"
    Push-Location (Join-Path $root "backend")
    go build -o (Join-Path $bin "carthago-gateway.exe") ./cmd/carthago-gateway
    if ($LASTEXITCODE) { Pop-Location; Die "go build carthago-gateway" }
    Pop-Location

    Step "build C++ sample (cmake)"
    cmake -S (Join-Path $root "sdk\native\sample") -B $sampleBuild "-DCARTHAGO_SENTINEL_LIB_DIR=$($rel -replace '\\','/')" | Out-Null
    if ($LASTEXITCODE) { Die "cmake configure" }
    cmake --build $sampleBuild --config Release
    if ($LASTEXITCODE) { Die "cmake build" }
}
$gatewayExe = Join-Path $bin "carthago-gateway.exe"
$gsExe = Join-Path $rel "gs-stub.exe"
$sampleExe = Join-Path $sampleBuild "Release\carthago-sample.exe"
foreach ($f in $gatewayExe, $gsExe, $sampleExe) { if (-not (Test-Path $f)) { Die "missing $f (run without -SkipBuild)" } }

$scheme = if ($Plaintext) { "ws" } else { "wss" }
Step "start gateway ($($scheme)://127.0.0.1:8750, heartbeat 2s / timeout 6s, sqlite store in $run)"
$gwLog = Join-Path $run "gateway.log"
$gwArgs = @("-data", "`"$run\gateway-data`"", "-hb-interval", "2s", "-hb-timeout", "6s")
if (-not $Plaintext) { $gwArgs += "-tls-dev-cert" }
$procs += Start-Process $gatewayExe -ArgumentList $gwArgs `
    -RedirectStandardError $gwLog -RedirectStandardOutput (Join-Path $run "gateway.out") -NoNewWindow -PassThru
$keys = Join-Path $run "gateway-data\public-keys.json"
for ($i = 0; $i -lt 100 -and -not (Test-Path $keys); $i++) { Start-Sleep -Milliseconds 100 }
if (-not (Test-Path $keys)) { Die "gateway did not start; see $gwLog" }
$published = Get-Content $keys -Raw | ConvertFrom-Json
$identity = $published.server_identity.public_key
Write-Host "gateway identity key (pinned in the sample): $identity"
$pinArgs = @()
if (-not $Plaintext) {
    $pins = @($published.tls_spki_sha256) -join ","
    if (-not $pins) { Die "gateway published no tls_spki_sha256 pins; see $gwLog" }
    Write-Host "gateway TLS key pin(s) (SHA-256 of the SPKI): $pins"
    $pinArgs = @("--gateway-pin", $pins)
}

Step "start game-server stub (127.0.0.1:8760)"
$gsLog = Join-Path $run "gs-stub.log"
$procs += Start-Process $gsExe -ArgumentList (@("serve", "--keys", "`"$keys`"", "--gateway", "$($scheme)://127.0.0.1:8750/v1/gs") + $pinArgs) -RedirectStandardOutput $gsLog `
    -RedirectStandardError (Join-Path $run "gs-stub.err") -NoNewWindow -PassThru
for ($i = 0; $i -lt 50 -and -not (Select-String -Path $gsLog -Pattern "kick channel connected" -Quiet -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 100 }

$common = @("--server-key-hex", $identity, "--gateway", "$($scheme)://127.0.0.1:8750/v1/client") + $pinArgs
if ($NoTpm) { $common += "--no-tpm" }
$results = [ordered]@{}

Step "scenario 1: sample obtains a signed token; game server verifies it offline"
$token = Join-Path $run "token.txt"
& $sampleExe @common --player "e2e-player-1" --run-secs 6 --token-out $token
$results["1. sample obtains a signed token end to end; game server admits it"] =
    ($LASTEXITCODE -eq 0) -and (Test-Path $token) -and (Select-String -Path $gsLog -Pattern "ADMIT player e2e-player-1" -Quiet)

Step "scenario 2: offline verification rejects tampered / expired tokens"
& $gsExe verify --keys $keys --token-file $token; $okValid = $LASTEXITCODE -eq 0
& $gsExe verify --keys $keys --token-file $token --tamper; $okTamper = $LASTEXITCODE -eq 2
& $gsExe verify --keys $keys --token-file $token --skew 960; $okExpired = $LASTEXITCODE -eq 2
$results["2a. valid token accepted offline"] = $okValid
$results["2b. tampered token rejected"] = $okTamper
$results["2c. expired token rejected (clock +16 min > 15 min TTL + 30 s leeway)"] = $okExpired

Step "scenario 3: heartbeats stop (client stays connected) -> gateway kicks -> game server drops the player"
$t3 = Get-Date
& $sampleExe @common --player "e2e-player-kick" --run-secs 30 --suppress-heartbeats-after 1
$kickExit = $LASTEXITCODE
Start-Sleep -Milliseconds 300
$results["3. heartbeat timeout triggers a server-side kick"] =
    ($kickExit -eq 10) -and (Select-String -Path $gsLog -Pattern "gateway KICK .*e2e-player-kick.*heartbeat_timeout" -Quiet) `
    -and (Select-String -Path $gwLog -Pattern 'session kicked.*reason=heartbeat_timeout player=e2e-player-kick game_servers_notified=1' -Quiet)
Write-Host ("kick observed {0:N1} s after scenario start" -f ((Get-Date) - $t3).TotalSeconds)

if (-not $Plaintext) {
    Step "scenario 4: a client pinning the wrong gateway TLS key is refused"
    $wrongPin = "00" * 32
    $wrong = @("--server-key-hex", $identity, "--gateway", "wss://127.0.0.1:8750/v1/client", "--gateway-pin", $wrongPin)
    if ($NoTpm) { $wrong += "--no-tpm" }
    & $sampleExe @wrong --player "e2e-player-wrong-pin" --run-secs 5
    $wrongExit = $LASTEXITCODE
    Start-Sleep -Milliseconds 300
    $results["4. wrong TLS pin: handshake refused, no session issued"] =
        ($wrongExit -eq 1) -and -not (Select-String -Path $gwLog -Pattern "session issued.*player=e2e-player-wrong-pin" -Quiet) `
        -and -not (Select-String -Path $gsLog -Pattern "ADMIT player e2e-player-wrong-pin" -Quiet)
}

$issued = Select-String -Path $gwLog -Pattern "session issued.*player=e2e-player-1 .*trust_level=(\d+) attest_flags=(\S+)" | Select-Object -First 1
if ($issued) { Write-Host ("scenario 1 session: trust_level {0}, attest_flags {1}" -f $issued.Matches[0].Groups[1].Value, $issued.Matches[0].Groups[2].Value) }

Cleanup
Step "game-server stub log"
Get-Content $gsLog
Step "gateway log"
Get-Content $gwLog

Step "results (logs in $run)"
$fail = 0
foreach ($k in $results.Keys) {
    if ($results[$k]) { Write-Host "PASS  $k" -ForegroundColor Green } else { Write-Host "FAIL  $k" -ForegroundColor Red; $fail++ }
}
exit $fail
