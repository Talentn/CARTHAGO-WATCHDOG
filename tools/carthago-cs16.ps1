<#
.SYNOPSIS
  Try Carthago Watchdog on Counter-Strike 1.6 on this PC: gateway + dashboard + companion.

.DESCRIPTION
  1. finds the game (-GameDir, else searches E:\ for hl.exe next to a cstrike folder);
  2. builds the companion (carthago-cs16.exe, cargo release) and the gateway (go);
  3. starts the gateway and the dashboard on this PC only (127.0.0.1), auto-kick off;
  4. opens the dashboard in the browser and prints its address and login;
  5. starts the game through the companion, which opens an attested session (TPM where
     available, pinned TLS) and watches hl.exe from outside with read-only access;
  6. when the game closes, keeps the dashboard up until Enter is pressed.

  This stage changes nothing in the game folder: no file is added, edited or replaced, and
  nothing is injected into the game. Everything the script writes goes to the scratch folder
  (-Scratch). -Uninstall stops what the script started and, with -Purge, deletes the scratch
  folder.

  Not in this stage yet: per-tick match data (aim, shots, visibility) from the server plugin.
  The dashboard shows the session, its trust level and what the companion sees.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -GameDir "E:\Games\Counter-Strike 1.6"
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -DashboardOnly
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -Uninstall
#>
param(
    [string]$GameDir,
    [string]$Scratch = $(if (Test-Path E:\) { "E:\carthago-cs16-scratch" } else { Join-Path $env:TEMP "carthago-cs16" }),
    [string[]]$GameArgs = @("-game", "cstrike"),
    [string]$Player = "cs16-local-player",
    [switch]$NoTpm,
    [switch]$InputMonitor,
    [switch]$SkipBuild,
    [switch]$DashboardOnly,
    [switch]$NoBrowser,
    [switch]$Uninstall,
    [switch]$Purge
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$gatewayPort = 8750
$dashboardPort = 8751
$dashboardUrl = "http://127.0.0.1:$dashboardPort"
$bin = Join-Path $Scratch "bin"
$data = Join-Path $Scratch "gateway-data"
$pidFile = Join-Path $Scratch "gateway.pid"
$gatewayExe = Join-Path $bin "carthago-gateway.exe"

function Step($m) { Write-Host "`n=== $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" }
$script:gateway = $null
function StopGateway {
    if ($script:gateway -and -not $script:gateway.HasExited) { Stop-Process -Id $script:gateway.Id -Force -ErrorAction SilentlyContinue }
    if (Test-Path $pidFile) {
        $old = Get-Content $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($old -match '^\d+$') {
            $p = Get-Process -Id ([int]$old) -ErrorAction SilentlyContinue
            if ($p -and $p.ProcessName -eq "carthago-gateway") { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
        }
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }
}
function Die($m) {
    Write-Host "`nFAILED: $m" -ForegroundColor Red
    Write-Host "Send back everything printed above and the files in: $Scratch\logs" -ForegroundColor Yellow
    StopGateway
    exit 1
}
function PortOpen($port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try { $c.Connect("127.0.0.1", $port); return $true } catch { return $false } finally { $c.Close() }
}

if ($Uninstall) {
    Step "stop the gateway and dashboard started by this script"
    StopGateway
    Note "This stage installed nothing in the game folder, so there is nothing to restore there."
    if ($Purge) {
        if ((Test-Path $Scratch) -and ((Split-Path -Leaf $Scratch) -like "carthago*")) {
            Remove-Item -Recurse -Force $Scratch
            Note "deleted $Scratch"
        } else {
            Note "not deleting '$Scratch': the folder name does not start with 'carthago'"
        }
    } else {
        Note "Build output, logs and the dashboard database are kept in $Scratch (add -Purge to delete them)."
    }
    exit 0
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logs = Join-Path $Scratch "logs\$stamp"
New-Item -ItemType Directory -Force $bin, $logs | Out-Null
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = Join-Path $Scratch "cargo-target" }
$companionExe = Join-Path $env:CARGO_TARGET_DIR "release\carthago-cs16.exe"

if (-not $DashboardOnly) {
    Step "find Counter-Strike 1.6"
    if ($GameDir) {
        if (-not (Test-Path (Join-Path $GameDir "hl.exe"))) { Die "no hl.exe in -GameDir '$GameDir'" }
        if (-not (Test-Path (Join-Path $GameDir "cstrike"))) { Die "no cstrike folder in -GameDir '$GameDir'" }
    } else {
        if (-not (Test-Path E:\)) { Die "no E: drive; pass -GameDir `"<folder that contains hl.exe>`"" }
        Note "searching E:\ for hl.exe next to a cstrike folder (this can take a minute)"
        $found = @(Get-ChildItem -Path E:\ -Filter hl.exe -File -Recurse -Depth 6 -ErrorAction SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.DirectoryName "cstrike") } | ForEach-Object { $_.DirectoryName })
        if ($found.Count -eq 0) { Die "hl.exe with a cstrike folder was not found on E:\; pass -GameDir `"<folder that contains hl.exe>`"" }
        if ($found.Count -gt 1) {
            Write-Host "More than one game folder found:" -ForegroundColor Yellow
            $found | ForEach-Object { Write-Host "    $_" }
            Die "run again with -GameDir `"<one of the folders above>`""
        }
        $GameDir = $found[0]
    }
    $GameDir = (Resolve-Path $GameDir).Path
    Note "game folder: $GameDir"
    if (Get-Process -Name hl -ErrorAction SilentlyContinue) { Die "hl.exe is already running; close the game first" }
}

if (-not $SkipBuild) {
    foreach ($tool in "cargo", "go") {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { Die "'$tool' is not on PATH (the Rust and Go toolchains used for the earlier demos are needed)" }
    }
    if (-not $DashboardOnly) {
        Step "build the companion (cargo, release; the first build takes a few minutes)"
        Push-Location (Join-Path $root "client")
        cargo build --release -p carthago-cs16-companion 2>&1 | Tee-Object -FilePath (Join-Path $logs "build-companion.log")
        $code = $LASTEXITCODE
        Pop-Location
        if ($code) { Die "cargo build carthago-cs16-companion (see $logs\build-companion.log)" }
    }
    Step "build the gateway (go)"
    StopGateway
    Push-Location (Join-Path $root "backend")
    go build -o $gatewayExe ./cmd/carthago-gateway 2>&1 | Tee-Object -FilePath (Join-Path $logs "build-gateway.log")
    $code = $LASTEXITCODE
    Pop-Location
    if ($code) { Die "go build carthago-gateway (see $logs\build-gateway.log)" }
}
if (-not (Test-Path $gatewayExe)) { Die "missing $gatewayExe (run without -SkipBuild)" }
if (-not $DashboardOnly -and -not (Test-Path $companionExe)) { Die "missing $companionExe (run without -SkipBuild)" }

Step "start the gateway (wss://127.0.0.1:$gatewayPort) and the dashboard ($dashboardUrl)"
StopGateway
foreach ($port in $gatewayPort, $dashboardPort) {
    if (PortOpen $port) { Die "port $port on this PC is already in use by another program; close it (or run this script with -Uninstall) and try again" }
}
$keys = Join-Path $data "public-keys.json"
$gwLog = Join-Path $logs "gateway.log"
# Loopback only, self-signed development certificate kept in the scratch folder, and no
# -auto-kick: nothing the gateway sees can end the session or close the game.
$gwArgs = @("-data", "`"$data`"", "-listen", "127.0.0.1:$gatewayPort", "-dashboard-listen", "127.0.0.1:$dashboardPort", "-tls-dev-cert")
$script:gateway = Start-Process $gatewayExe -ArgumentList $gwArgs -RedirectStandardError $gwLog `
    -RedirectStandardOutput (Join-Path $logs "gateway.out") -NoNewWindow -PassThru
Set-Content -Path $pidFile -Value $script:gateway.Id
for ($i = 0; $i -lt 150; $i++) {
    if ($script:gateway.HasExited) { break }
    if ((Test-Path $keys) -and (PortOpen $gatewayPort) -and (PortOpen $dashboardPort)) { break }
    Start-Sleep -Milliseconds 100
}
if ($script:gateway.HasExited -or -not (PortOpen $dashboardPort)) {
    Get-Content $gwLog -ErrorAction SilentlyContinue | Select-Object -Last 20
    Die "the gateway did not start (see $gwLog)"
}
$published = Get-Content $keys -Raw | ConvertFrom-Json
if (-not $published.tls_spki_sha256) { Die "the gateway published no TLS key pin; see $gwLog" }
Note "gateway identity key: $($published.server_identity.public_key)"
Note "gateway TLS key pin : $(@($published.tls_spki_sha256) -join ',')"

Write-Host ""
Write-Host "  DASHBOARD      $dashboardUrl" -ForegroundColor Green
Write-Host "  Studio         demo" -ForegroundColor Green
Write-Host "  Dashboard key  demo-dashboard-key" -ForegroundColor Green
Write-Host ""
if (-not $NoBrowser) { Start-Process $dashboardUrl }

$exit = 0
if (-not $DashboardOnly) {
    Step "start the game through the companion"
    Note "The companion opens the session first, then starts hl.exe. Leave this window open."
    Note "After about 20 seconds in the game, open Sessions in the dashboard."
    $session = Join-Path $logs "session.json"
    $compLog = Join-Path $logs "companion.log"
    $compArgs = @("--keys", $keys, "--gateway", "wss://127.0.0.1:$gatewayPort/v1/client", "--game-dir", $GameDir,
        "--player", $Player, "--session-file", $session, "--log", $compLog)
    if ($NoTpm) { $compArgs += "--no-tpm" }
    if ($InputMonitor) { $compArgs += "--input-monitor" }
    $compArgs += "--"
    $compArgs += $GameArgs
    & $companionExe @compArgs
    $exit = $LASTEXITCODE
    Step "result"
    switch ($exit) {
        0 { Write-Host "OK    the session stayed up while the game ran" -ForegroundColor Green }
        2 { Write-Host "FAIL  no session with the gateway; the game was not started (see $compLog)" -ForegroundColor Red }
        3 { Write-Host "FAIL  the session opened but hl.exe could not be started (see $compLog)" -ForegroundColor Red }
        4 { Write-Host "FAIL  the session was lost and could not be re-established (see $compLog)" -ForegroundColor Red }
        default { Write-Host "FAIL  the companion exited with code $exit (see $compLog)" -ForegroundColor Red }
    }
    Note "logs: $logs"
}

Write-Host ""
Write-Host "The dashboard is still running at $dashboardUrl (studio demo, key demo-dashboard-key)." -ForegroundColor Green
Read-Host "Press Enter to stop it" | Out-Null
StopGateway
exit $exit
