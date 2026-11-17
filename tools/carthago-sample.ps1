<#
.SYNOPSIS
  Prove Carthago Watchdog on this PC with the sample game: no real game is needed.

.DESCRIPTION
  The sample game (client\examples\sample-game\game.c) is a small C program that uses the
  client SDK the way a studio's game does: carthago_sentinel.h and carthago_sentinel.dll,
  nothing else. This script

    1. builds the SDK, the sample game, a harmless marker library and the gateway;
    2. starts a gateway and its dashboard on this PC only (127.0.0.1), with a new, empty
       database for this run, and puts the marker library's SHA-256 on the studio's list
       of known cheat files;
    3. runs the game three times:
         honest   the player signs in with the TPM handshake and plays. Shows the trust
                  level, what the TPM proved, and Windows' signed driver list as the
                  gateway read it;
         cheat    the game loads the marker library itself, a few seconds into the match.
                  The gateway matches the file's hash, bans the account and this PC's
                  device key on certain evidence, and the game shows its banned screen;
         again    the banned player starts the game again and is refused at sign-in;
    4. prints PASS or FAIL per check and one RESULT line, then keeps the dashboard up
       until Enter is pressed.

  The marker library does nothing: no code runs when it is loaded. Nothing is installed,
  no setting of Windows is changed, and the ban lives only in this run's database.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\carthago-sample.ps1
  powershell -ExecutionPolicy Bypass -File tools\carthago-sample.ps1 -SkipBuild -NoWindow -NoWait
#>
param(
    # Build output of the gateway, logs and this run's database.
    [string]$Scratch = $(Join-Path ([IO.Path]::GetTempPath()) "carthago-sample"),
    # Use a software device key instead of the TPM (trust level 0).
    [switch]$NoTpm,
    [switch]$SkipBuild,
    # Banned screen in the console only, without the message box that waits for OK.
    [switch]$NoWindow,
    # Stop the gateway and the dashboard at the end instead of waiting for Enter.
    [switch]$NoWait,
    [switch]$NoBrowser
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$gatewayPort = 8750
$dashboardPort = 8751
$dashboardUrl = "http://127.0.0.1:$dashboardPort"
function J { [IO.Path]::Combine([string[]]$args) }
$exeSuffix = $(if ([IO.Path]::DirectorySeparatorChar -eq '\') { ".exe" } else { "" })
$bin = J $Scratch "bin"
$run = J $Scratch ("run-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
$data = J $run "gateway-data"
$gwLog = J $run "gateway.log"
$gatewayExe = J $bin "carthago-gateway$exeSuffix"
$target = $(if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { J $root "client" "target" })
$gameExe = J $target "release" "carthago-sample-game$exeSuffix"
$marker = J $target "release" "carthago_sample_marker.dll"
New-Item -ItemType Directory -Force $bin, $run | Out-Null

function Step($m) { Write-Host "`n=== $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" }
$script:gateway = $null
function StopGateway { if ($script:gateway -and -not $script:gateway.HasExited) { Stop-Process -Id $script:gateway.Id -Force -ErrorAction SilentlyContinue } }
function Die($m) {
    Write-Host "`nFAILED: $m" -ForegroundColor Red
    Write-Host "Send back everything printed above and the folder $run" -ForegroundColor Yellow
    StopGateway
    Write-Host "RESULT: FAIL, $m"
    exit 1
}
function PortOpen($port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try { $c.Connect("127.0.0.1", $port); return $true } catch { return $false } finally { $c.Close() }
}
function Gateway { @(& $gatewayExe @args 2>&1 | ForEach-Object { "$_" }) }

if (-not $SkipBuild) {
    foreach ($tool in "cargo", "go") {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { Die "'$tool' is not on PATH" }
    }
    Step "build the SDK, the sample game and the marker library (cargo, release; the first build takes a few minutes)"
    Push-Location (J $root "client")
    cargo build --release -p carthago-sentinel -p carthago-sample-game -p carthago-sample-marker 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath (J $run "build-client.log")
    $code = $LASTEXITCODE
    Pop-Location
    if ($code) { Die "cargo build (see $(J $run 'build-client.log'))" }
    Step "build the gateway (go)"
    Push-Location (J $root "backend")
    go build -o $gatewayExe ./cmd/carthago-gateway 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath (J $run "build-gateway.log")
    $code = $LASTEXITCODE
    Pop-Location
    if ($code) { Die "go build carthago-gateway (see $(J $run 'build-gateway.log'))" }
}
foreach ($f in $gatewayExe, $gameExe, $marker) { if (-not (Test-Path -LiteralPath $f)) { Die "missing $f (run without -SkipBuild)" } }
foreach ($port in $gatewayPort, $dashboardPort) {
    if (PortOpen $port) { Die "port $port is in use: close the other Carthago gateway (the window of an earlier test) and run this again" }
}

Step "the studio puts one file on its list of known cheat files"
$added = Gateway cheats add -data $data -tenant demo -file $marker -name "sample marker (harmless)" -note "carthago-sample.ps1"
if ($LASTEXITCODE) { $added | ForEach-Object { Note $_ }; Die "could not add the marker library to the list of known cheat files" }
$added | ForEach-Object { Note $_ }
Note "The file is $marker. It does nothing; only its SHA-256 is on the list."

Step "start the gateway (wss://127.0.0.1:$gatewayPort) and the dashboard ($dashboardUrl)"
$gwArgs = @("-data", "`"$data`"", "-listen", "127.0.0.1:$gatewayPort", "-dashboard-listen", "127.0.0.1:$dashboardPort",
    "-tls-dev-cert", "-client-notices", "-hb-interval", "2s", "-hb-timeout", "15s")
$script:gateway = Start-Process $gatewayExe -ArgumentList $gwArgs -RedirectStandardError $gwLog `
    -RedirectStandardOutput (J $run "gateway.out") -NoNewWindow -PassThru
$keys = J $data "public-keys.json"
for ($i = 0; $i -lt 150; $i++) {
    if ($script:gateway.HasExited) { break }
    if ((Test-Path -LiteralPath $keys) -and (PortOpen $gatewayPort) -and (PortOpen $dashboardPort)) { break }
    Start-Sleep -Milliseconds 100
}
if ($script:gateway.HasExited -or -not (PortOpen $dashboardPort)) {
    Get-Content $gwLog -ErrorAction SilentlyContinue | Select-Object -Last 20
    Die "the gateway did not start (see $gwLog)"
}
$published = Get-Content $keys -Raw | ConvertFrom-Json
$pins = @($published.tls_spki_sha256) -join ","
if (-not $pins) { Die "the gateway published no TLS key pin; see $gwLog" }
$common = @("--server-key-hex", $published.server_identity.public_key, "--gateway", "wss://127.0.0.1:$gatewayPort/v1/client", "--gateway-pin", $pins)
if ($NoTpm) { $common += "--no-tpm" }

# Runs the game, shows what it prints, and returns its lines and its exit code.
function Play($name, $more) {
    $lines = @(& $gameExe @common @more 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath (J $run "$name.log"))
    $code = $LASTEXITCODE
    $lines | ForEach-Object { Write-Host "    $_" }
    return @{ Lines = $lines; Code = $code }
}
function Has($played, $pattern) { [bool]($played.Lines | Where-Object { $_ -match $pattern } | Select-Object -First 1) }
$results = [ordered]@{}

Step "honest: the player signs in and plays 12 seconds"
$honest = Play "honest" @("--player", "sample-honest", "--secs", "12")
$trust = ($honest.Lines | Where-Object { $_ -match '^TRUST LEVEL (\d)' } | Select-Object -First 1)
$level = $(if ($trust -match '^TRUST LEVEL (\d)') { [int]$Matches[1] } else { -1 })
$results["honest: a session with the gateway, trust level reported"] = ($level -ge 0)
$results["honest: played to the end, nothing flagged, exit code 0"] = ($honest.Code -eq 0) -and (Has $honest '^MATCH FINISHED')
$drivers = Gateway drivers show -data $data -tenant demo -player sample-honest
$drivers | ForEach-Object { Write-Host $_ -ForegroundColor $(if ($_ -match 'signature verified') { "Green" } else { "Yellow" }) }
$results["honest: the gateway recorded how it read the driver list"] = [bool]($drivers | Where-Object { $_ -match '^DRIVER LIST' })

Step "cheat: the game loads the marker library during the match"
$window = $(if ($NoWindow) { @("--no-window") } else { @() })
if (-not $NoWindow) { Note "A message box with the banned screen will open: press OK to continue." }
$cheat = Play "cheat" (@("--player", "sample-cheater", "--secs", "40", "--load", $marker) + $window)
$bans = Gateway bans list -data $data -tenant demo
$bans | ForEach-Object { Write-Host $_ -ForegroundColor Red }
$results["cheat: the gateway banned the player automatically on rule known_cheat"] = [bool]($bans | Where-Object { $_ -match 'player sample-cheater .*by automatic\s+rule known_cheat\s+active' })
$results["cheat: the game was told, left the match and showed the banned screen with the reference"] = ($cheat.Code -eq 3) -and (Has $cheat '^BANNED SCREEN shown, reference CW-')

Step "again: the banned player starts the game again"
$again = Play "again" @("--player", "sample-cheater", "--secs", "5", "--no-window")
$results["again: refused at sign-in with the same reference, no match"] = ($again.Code -eq 3) -and (Has $again '^BANNED SCREEN shown, reference CW-') -and -not (Has $again 'match started')

Step "results (logs in $run)"
$fail = 0
foreach ($k in $results.Keys) {
    if ($results[$k]) { Write-Host "PASS  $k" -ForegroundColor Green } else { Write-Host "FAIL  $k" -ForegroundColor Red; $fail++ }
}
if ($trust) { Write-Host $trust }
if ($level -ge 0 -and $level -lt 2 -and -not $NoTpm) { Note "Below trust level 2: the lines of the honest run that start with [sdk:warn] say what the TPM step could not do." }
Write-Host ""
Write-Host "  DASHBOARD          $dashboardUrl" -ForegroundColor Green
Write-Host "  Studio             demo" -ForegroundColor Green
Write-Host "  Dashboard key      demo-dashboard-key" -ForegroundColor Green
Note "Bans shows the ban and its reason; the session page of sample-honest shows the trust level and, under Kernel drivers, the driver list."
if ($fail) { Write-Host "RESULT: FAIL, $fail of $($results.Count) checks failed" } else { Write-Host "RESULT: PASS, $($results.Count) of $($results.Count) checks, trust level $level" }
if (-not $NoWait) {
    if (-not $NoBrowser) { Start-Process $dashboardUrl }
    Read-Host "Press Enter to stop the dashboard" | Out-Null
}
StopGateway
exit $fail
