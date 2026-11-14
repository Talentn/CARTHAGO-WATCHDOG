<#
.SYNOPSIS
  Try Carthago Watchdog on Counter-Strike 1.6 on this PC: gateway, dashboard, companion
  beside the game, and match data from your own game server.

.DESCRIPTION
  1. finds the game: a folder with a cstrike folder and the game program, which is hl.exe
     or, in builds that have no hl.exe, cstrike.exe. -GameDir names the folder and -GameExe
     the program; without them E:\ is searched, folders with likely names first;
  2. builds the companion, the telemetry bridge (cargo, release) and the gateway (go);
  3. installs the server plugin into the game's AMX Mod X, reversibly (see below);
  4. starts the gateway and the dashboard on this PC only (127.0.0.1), auto-kick off, and
     the bridge that receives the plugin's data on 127.0.0.1;
  5. opens the dashboard in the browser and prints its address and login;
  6. starts the game through the companion, which opens an attested session (TPM where
     available, pinned TLS) and watches the game from outside with read-only access;
  7. if the gateway flags the session, the companion shows a full-screen red alert in a
     window of its own. The game is left running unless -EndMatchOnDetect is given.
     The companion takes a picture of the game once it has finished starting and records
     the first start of each game folder in the scratch folder. What is flagged: a
     debugger on the game, and changes against that picture (a replaced renderer or
     system library, an unsigned library from outside the game folder, an image mapped by
     hand, rewritten renderer, engine or client code, an unsigned program holding the
     game open for writing, or reading it while drawing over it). What the game build has
     shown since its first recorded start is not flagged unless -AlertOnIntegrity is
     given; the result names what was held back;
  8. with the plugin running, reads the map being played from the game's maps folder and
     sends its walls with the match data, so the gateway can score information leaks:
     aim and shots that follow enemies the player's team could not see, hear or be told
     about. That score is evidence for review at the end of a match and raises no alert.
     -AlertOnWallhackScore lets a strong score in two separate four-minute stretches of
     one match raise the alert during the match: an opt-in for a test on your own server,
     since it is a behaviour score and not proof;
  9. when the game closes, keeps the dashboard up until Enter is pressed.

  The Carthago Oracle (a score for each session and, for flagged ones, a written opinion,
  both on the dashboard only) is switched on whenever a trained bundle exists in
  -OracleDir, else CARTHAGO_ORACLE_DIR, else %LOCALAPPDATA%\Carthago\oracle-bundle.
  -Oracle makes that happen with one command: on first use it trains a bundle there (about
  8 minutes) and downloads the analyst's language model (about 1.2 GB); later runs start
  at once. The Oracle never raises the alert. See tools\carthago-cs16-oracle.ps1.

  What is changed in the game folder, and only there:
    - cstrike\addons\amxmodx\plugins\carthago_cs16.amxx           (added)
    - cstrike\addons\amxmodx\configs\plugins-carthago.ini         (added)
    - cstrike\addons\amxmodx\configs\carthago_cs16.ini            (added)
    - cstrike\addons\amxmodx\logs\carthago_cs16.log               (written by the plugin)
    - cstrike\qconsole.log        (the game's console log; the game runs with -condebug)
    - cstrike\addons\amxmodx\configs\plugins.ini  (only if AMX Mod X ignores the file above)
    - cstrike\liblist.gam                    (only if the game does not load Metamod yet)
    - cstrike\addons\metamod\plugins.ini     (only if Metamod does not load AMX Mod X yet)
    - Metamod / AMX Mod X files, only if the game has none and you answer "y" to the
      download question (official amxmodx.org releases, SHA-256 checked).
  Every file that is changed is first copied to <game>\carthago-cs16-backup, every file
  that is added is listed there, and -Uninstall puts everything back. No game binary is
  replaced or patched and nothing is injected into the game.

  Everything else the script writes goes to the scratch folder (-Scratch).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -GameDir "E:\Counter-Strike WaRzOnE Edition"
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -GameDir "E:\Games\CS" -GameExe cstrike.exe
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -Map de_dust2
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -GameArgs:"-game cstrike -nomaster"
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -NoPlugin
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -TestAlert
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -NoPlugin -TestAlertAfter 60
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -NoPlugin -TestAlertAfter 60 -EndMatchOnDetect
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -NoPlugin -AlertOnIntegrity
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -NoPlugin -ResetStartProfile
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -NoPlugin -Unban
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -NoPlugin -NoAutoBan
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -NoPlugin -KnownCheat "E:\Counter-Strike\OPENGL32.dll" -KnownCheatName "My wallhack"
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -Map de_dust2 -AlertOnWallhackScore
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -Diagnose
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -Stage 2
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -DashboardOnly
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -NoPlugin -Oracle
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -Uninstall
#>
param(
    [string]$GameDir,
    # The program that starts the game, when it is not hl.exe or cstrike.exe: a file name in
    # -GameDir, or a full path.
    [string]$GameExe,
    # Where to look for the game when -GameDir is not given.
    [string]$SearchRoot = "E:\",
    [string]$Scratch = $(if (Test-Path E:\) { "E:\carthago-cs16-scratch" } else { Join-Path ([IO.Path]::GetTempPath()) "carthago-cs16" }),
    # Options for the game program. From cmd.exe write them as one value joined to the name
    # with a colon:  -GameArgs:"-game cstrike -nomaster"
    [string[]]$GameArgs = @("-game", "cstrike"),
    # Start a listen server on this map straight away (otherwise use New Game in the menu).
    [string]$Map,
    [string]$Player = "cs16-local-player",
    [switch]$NoTpm,
    [switch]$InputMonitor,
    [switch]$SkipBuild,
    # Companion and dashboard only: do not touch the game folder, no match data.
    [switch]$NoPlugin,
    # How much of the plugin to install: 0 none, 1 loads and reports versions only,
    # 2 + positions, 3 + user commands and line of sight, 4 + shots and hits (everything).
    # Default: what the last -Diagnose run found to work, else 4.
    [int]$Stage = -1,
    # Find out which part of the plugin the game cannot run: four short runs, one stage
    # each, on -Map (default de_dust2). The game closes by itself after each run.
    [switch]$Diagnose,
    [int]$DiagnoseSecs = 0,
    # Use the prebuilt plugin even when the game ships its own AMX Mod X compiler.
    [switch]$NoLocalCompile,
    # Show the alert screen now, as a preview: no gateway, no game, nothing is detected.
    [switch]$TestAlert,
    # Have the gateway send a test notice this many seconds after the session opens, so the
    # alert appears over the running game. It is labelled as a test.
    [int]$TestAlertAfter = 0,
    # When the session is flagged, also close the game this script started (the alert alone
    # is the default). The server never kicks.
    [switch]$EndMatchOnDetect,
    # Seconds until the alert closes by itself; 0 keeps it until Esc or a click.
    [int]$AlertSecs = 20,
    # Log a flagged session only; show no alert screen.
    [switch]$NoAlert,
    # Also alert on what is held back by default because an honest, modified game build
    # shows the same: things present since the first recorded start of this game (its own
    # replacement libraries, images its loader maps, programs that start it), changed or
    # new files of the game folder, read-only handles of unsigned programs, engine code
    # rewritten while server add-ons are loaded. Expect alerts on a clean game.
    [switch]$AlertOnIntegrity,
    # For a game build that ships its own renderer library. By default an unsigned
    # opengl32.dll, d3d9.dll, ddraw.dll or glu32.dll that the game loads in place of the
    # Windows one raises the alert in every run, the first one included: it is how a
    # wallhack is delivered. With this switch such a file is excused when the first
    # recorded start had it.
    [switch]$AllowRendererLibrary,
    # Automatic bans are on: evidence that is certain (an unsigned renderer library, an
    # unsigned DLL injected from outside the game folder, rewritten code of opengl32.dll or
    # client.dll, an image mapped by hand, an unsigned outside program with a handle that
    # writes the game's memory) bans the test player and this PC's device key in the local
    # gateway. The alert still shows first; the next start shows the BANNED screen instead
    # of the game. Statistical evidence never bans. This switch turns automatic bans off.
    [switch]$NoAutoBan,
    # Lift every ban in the local test gateway before this run, so you can keep testing.
    [switch]$Unban,
    # A cheat's file, to put on the local test gateway's list of known cheat files before
    # this run. The file is only read, to take its SHA-256. A game that loads a file with
    # that hash, under any name and from any folder, signed or not, is banned on rule
    # known_cheat. -KnownCheatName is what the cheat is called in the evidence and the ban.
    [string]$KnownCheat = "",
    [string]$KnownCheatName = "",
    # Opt-in, for a test on your own server: also raise the alert when the information-leak
    # (wallhack) score of the player on this PC is strong in two separate four-minute
    # stretches of one match. Without it that score is evidence for review only. It is a
    # behaviour score, not proof, and needs the plugin's match data.
    [switch]$AlertOnWallhackScore,
    # Forget the map hashes recorded for this game folder; this run records them anew. Use
    # it after a map file was replaced on purpose.
    [switch]$ResetMapPins,
    # Forget the recorded first start of this game folder; this run records it anew. Use
    # it after the game was updated or reinstalled, and only with no cheat running.
    [switch]$ResetStartProfile,
    # Seconds after the engine has loaded before the picture of the started game is taken.
    [int]$BaselineSecs = 20,
    # Start the game in a borderless window (-window -noborder), where the alert is always
    # visible. The game remembers this; start it once with -full to go back.
    [switch]$Windowed,
    # Install the plugin and stop, without starting anything.
    [switch]$InstallOnly,
    [switch]$DashboardOnly,
    # Carthago Oracle: train a bundle and download the analyst's language model if they are
    # not there yet, then run with the Oracle. Without the switch the Oracle is on only
    # when a trained bundle already exists.
    [switch]$Oracle,
    # With -Oracle: do not download the language model (sessions are scored, no opinions).
    [switch]$OracleNoModel,
    # Run without the Oracle even when a trained bundle exists.
    [switch]$NoOracle,
    # The bundle folder. Default: CARTHAGO_ORACLE_DIR, else %LOCALAPPDATA%\Carthago\oracle-bundle.
    [string]$OracleDir,
    # For training: the seed (default: a random one that is not kept) and the number of
    # simulated matches (default: the training tool's own).
    [string]$OracleSeed,
    [int]$OracleMatches = 0,
    [switch]$NoBrowser,
    [switch]$Uninstall,
    [switch]$Purge
)
$ErrorActionPreference = "Continue"
# powershell -File passes a list as one string; accept "a b" and "a,b" as well as a list.
$GameArgs = @($GameArgs | ForEach-Object { $_ -split '[\s,]+' } | Where-Object { $_ })
$root = Split-Path -Parent $PSScriptRoot
$gatewayPort = 8750
$dashboardPort = 8751
$bridgePort = 27991
$dashboardUrl = "http://127.0.0.1:$dashboardPort"
function J { [IO.Path]::Combine([string[]]$args) }
$bin = J $Scratch "bin"
$data = J $Scratch "gateway-data"
$pidFile = J $Scratch "gateway.pid"
$lastGameFile = J $Scratch "last-game.txt"
$exeSuffix = $(if ([IO.Path]::DirectorySeparatorChar -eq '\') { ".exe" } else { "" })
$gatewayExe = J $bin "carthago-gateway$exeSuffix"

# Official releases, pinned. Used only when the game has no Metamod or AMX Mod X and the
# user agrees to the download.
$official = @{
    metamod = @{ name = "Metamod 1.21.1-am"; url = "https://www.amxmodx.org/release/metamod-1.21.1-am.zip"
        sha256 = "1b441c97131f643fd7590bc568a8547ca3d7420ff4534e78a50d04e35fdf4a84" }
    amxxCstrike = @{ name = "AMX Mod X 1.8.2 Counter-Strike addon"; url = "https://www.amxmodx.org/release/amxmodx-1.8.2-cstrike-windows.zip"
        sha256 = "58173075840b676c99e84a4a6b4bb54546a3a0ac578a4c44560e7b9eea39a698" }
    amxxBase = @{ name = "AMX Mod X 1.8.2 base"; url = "https://www.amxmodx.org/release/amxmodx-1.8.2-base-windows.zip"
        sha256 = "5c0b7d8b311dbc4f0ab70c0a11b100fcb45101ef81b3dc7aa4247a972f20d498" }
}
# The compiled plugin in the repo, one file per stage (client\cs16\plugin\carthago_cs16.sma,
# AMX Mod X 1.8.2 compiler, STAGE=1..4).
$pluginSha256 = @("",
    "a905fe2e738b7759621bfd0e4cea88789fe5798aefe00859c4b5bb4a3d54f87b",
    "ce53e128a27016a63c1eb21f356472ee8e4fd75f4ce68937736236e0e71daa24",
    "ad80a158ef8aadd8297d822cc4352e09e801bbc74aedccf7a7788fb8a84e239b",
    "5bee0f187b6c91377a6044826d4cc80847952e4e6467ab9b10992412875c3f50")
$stageNames = @("no plugin", "plugin loaded, nothing switched on", "players and positions", "user commands and line of sight", "shots and hits (everything)")
$stageFile = J $Scratch "plugin-stage.txt"
$script:listInMain = $false

function Step($m) { Write-Host "`n=== $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" }
# Lines that are the same every time the plugin is installed: printed the first time only.
function Quiet($m) { if (-not $script:installedOnce) { Note $m } }
$script:gateway = $null
$script:bridge = $null
function StopProc($p) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
function StopGateway {
    StopProc $script:gateway
    if (Test-Path -LiteralPath $pidFile) {
        $old = Get-Content $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($old -match '^\d+$') {
            $p = Get-Process -Id ([int]$old) -ErrorAction SilentlyContinue
            if ($p -and $p.ProcessName -like "carthago-gatewa*") { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
        }
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }
}
function Die($m) {
    Write-Host "`nFAILED: $m" -ForegroundColor Red
    Write-Host "Send back everything printed above and the newest folder in: $(J $Scratch 'logs')" -ForegroundColor Yellow
    StopProc $script:bridge
    StopGateway
    exit 1
}
function PortOpen($port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try { $c.Connect("127.0.0.1", $port); return $true } catch { return $false } finally { $c.Close() }
}

# The game program is hl.exe; builds without one name the same program cstrike.exe.
$engineNames = @("hl.exe", "cstrike.exe")
# Programs that sit in a game folder and are never the game.
$notGame = '^(crashpad_handler|hltv|hlds|hlds_run|unins\d*|uninst.*|setup.*|install.*)\.exe$'
$likelyFolder = 'counter.?strike|warzone|cs.?1\.?6|cstrike|half.?life'
function IsDir($p) { Test-Path -LiteralPath $p -PathType Container }
function IsFile($p) { Test-Path -LiteralPath $p -PathType Leaf }
function EngineExe($dir) {
    foreach ($n in $engineNames) { if (IsFile (J $dir $n)) { return $n } }
    return $null
}
function ExeNames($dir) {
    $n = @(Get-ChildItem -LiteralPath $dir -Filter *.exe -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    if ($n.Count) { return ($n -join ", ") }
    return "none"
}
function SubDirs($dir) {
    @(Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '^(\$Recycle\.Bin|System Volume Information|carthago-cs16.*)$' })
}
# Folders on the drive that have a cstrike folder. Folders with likely names are looked at
# first (two levels down, and one level inside them); the whole drive is scanned only when
# none of those holds a game.
function SearchGame($drive) {
    $seen = @()
    $top = @(SubDirs $drive)
    $second = @($top | ForEach-Object { SubDirs $_.FullName })
    $likely = @(@($top + $second) | Where-Object { $_.Name -match $likelyFolder })
    foreach ($d in $likely) {
        foreach ($c in @($d) + @(SubDirs $d.FullName)) {
            if ((IsDir (J $c.FullName "cstrike")) -and ($seen -notcontains $c.FullName)) { $seen += $c.FullName }
        }
    }
    if (-not @($seen | Where-Object { EngineExe $_ }).Count) {
        Note "no game in the folders with likely names; scanning all of $drive (this can take a minute)"
        Get-ChildItem -LiteralPath $drive -Directory -Filter cstrike -Recurse -Depth 6 -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch 'carthago-cs16|\$Recycle\.Bin' } |
            ForEach-Object { $p = Split-Path -Parent $_.FullName; if ($seen -notcontains $p) { $seen += $p } }
    }
    $script:likelySeen = @($likely | ForEach-Object { $_.FullName } | Where-Object { $seen -notcontains $_ })
    return $seen
}
function GameRunning {
    $names = @("hl", "cstrike")
    if ($script:GameExePath) { $names += [IO.Path]::GetFileNameWithoutExtension($script:GameExePath) }
    foreach ($p in @(Get-Process -Name $names -ErrorAction SilentlyContinue)) {
        $path = $null
        try { $path = $p.Path } catch {}
        if (-not $path -or $path.StartsWith($script:GameDir, [StringComparison]::OrdinalIgnoreCase)) { return $p.ProcessName }
    }
    return $null
}

function FindGame {
    $why = ""
    if ($GameExe -and [IO.Path]::IsPathRooted($GameExe) -and -not $GameDir) { $script:GameDir = Split-Path -Parent $GameExe }
    if ($script:GameDir) {
        if (-not (IsDir $script:GameDir)) { Die "-GameDir '$script:GameDir' is not a folder" }
        if (-not (IsDir (J $script:GameDir "cstrike"))) { Die "no cstrike folder in '$script:GameDir' (programs there: $(ExeNames $script:GameDir))" }
    } else {
        if (-not (IsDir $SearchRoot)) { Die "$SearchRoot does not exist; pass -GameDir `"<folder that contains the game program and the cstrike folder>`"" }
        Note "searching $SearchRoot for a folder with a cstrike folder and hl.exe or cstrike.exe"
        $seen = @(SearchGame $SearchRoot)
        $found = @($seen | Where-Object { if ($GameExe) { IsFile (J $_ $GameExe) } else { EngineExe $_ } })
        if ($found.Count -ne 1) {
            if ($found.Count) { Write-Host "More than one game folder found:" -ForegroundColor Yellow }
            else { Write-Host "No folder on $SearchRoot has both a cstrike folder and hl.exe or cstrike.exe." -ForegroundColor Yellow }
            if ($seen.Count) { Write-Host "Folders with a cstrike folder:" }
            foreach ($d in $seen) { Write-Host "    $d    (programs: $(ExeNames $d))" }
            if ($script:likelySeen.Count) { Write-Host "Folders with a likely name but no cstrike folder:" }
            foreach ($d in $script:likelySeen) { Write-Host "    $d" }
            if ($found.Count) { Die "run again with -GameDir `"<one of the folders above>`"" }
            Die "run again with -GameDir `"<the game folder>`"; if its game program has another name, add -GameExe <name>.exe"
        }
        $script:GameDir = $found[0]
    }
    $script:GameDir = (Resolve-Path -LiteralPath $script:GameDir).Path.TrimEnd('\', '/')
    if ($GameExe) {
        $exe = $GameExe
        if (-not [IO.Path]::IsPathRooted($exe)) { $exe = J $script:GameDir $exe }
        if (-not (IsFile $exe)) { Die "-GameExe: '$exe' does not exist (programs in the game folder: $(ExeNames $script:GameDir))" }
        if ((Split-Path -Leaf $exe) -match $notGame) { Die "-GameExe: $(Split-Path -Leaf $exe) is not the game (it is a crash reporter, a TV proxy, a server or an installer)" }
        if ((Split-Path -Leaf $exe) -notmatch '\.exe$') { Die "-GameExe: '$exe' is not an .exe file" }
        $why = "named with -GameExe"
    } else {
        $name = EngineExe $script:GameDir
        if (-not $name) { Die "no hl.exe or cstrike.exe in '$script:GameDir' (programs there: $(ExeNames $script:GameDir)). If one of them starts the game, add -GameExe <name>.exe" }
        $exe = J $script:GameDir $name
        if ($name -ieq "hl.exe") { $why = "the usual name" } else { $why = "this folder has no hl.exe; this build names the game program $name" }
    }
    $script:GameExePath = (Resolve-Path -LiteralPath $exe).Path
    Note "game folder : $script:GameDir"
    Note "game program: $(Split-Path -Leaf $script:GameExePath)  ($why)"
    $running = GameRunning
    if ($running) { Die "the game ($running) is running; close it first" }
}

# ---- reversible changes in the game folder -------------------------------------------------
# manifest.json lists every file and folder this script added and every file it changed;
# the originals of changed files are under files\ with the same relative path.
function BackupDir { J $script:GameDir "carthago-cs16-backup" }
function ManifestPath { J (BackupDir) "manifest.json" }
function LoadManifest {
    $script:created = @(); $script:modified = @(); $script:dirs = @()
    if (Test-Path -LiteralPath (ManifestPath)) {
        $m = Get-Content (ManifestPath) -Raw | ConvertFrom-Json
        $script:created = @($m.created | Where-Object { $_ })
        $script:modified = @($m.modified | Where-Object { $_ })
        $script:dirs = @($m.dirs | Where-Object { $_ })
    }
}
function SaveManifest {
    New-Item -ItemType Directory -Force (BackupDir) | Out-Null
    $m = [ordered]@{ note = "Written by tools\carthago-cs16.ps1. Run it with -Uninstall to undo these changes."
        created = @($script:created); modified = @($script:modified); dirs = @($script:dirs) }
    ConvertTo-Json $m -Depth 3 | Set-Content -Path (ManifestPath) -Encoding UTF8
}
function InGame($path) {
    $full = [IO.Path]::GetFullPath($path)
    $base = $script:GameDir + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { Die "refusing to touch '$full': it is outside the game folder" }
    return $full.Substring($base.Length)
}
function EnsureDir($dir) {
    $missing = @()
    $d = $dir
    while ($d -and -not (Test-Path -LiteralPath $d)) { $missing += $d; $d = Split-Path -Parent $d }
    [array]::Reverse($missing)
    foreach ($m in $missing) {
        $rel = InGame $m
        New-Item -ItemType Directory -Path $m | Out-Null
        if ($script:dirs -notcontains $rel) { $script:dirs += $rel }
    }
}
# Call before writing a file in the game folder: records an added file, or keeps the
# original of an existing one (once).
function Track($path) {
    $rel = InGame $path
    if (($script:created -contains $rel) -or ($script:modified -contains $rel)) { return }
    if (Test-Path -LiteralPath $path) {
        $copy = J (BackupDir) "files" $rel
        New-Item -ItemType Directory -Force (Split-Path -Parent $copy) | Out-Null
        Copy-Item -LiteralPath $path -Destination $copy -Force
        $script:modified += $rel
        Note "backed up   $rel"
    } else {
        EnsureDir (Split-Path -Parent $path)
        $script:created += $rel
    }
    SaveManifest
}
$latin1 = [Text.Encoding]::GetEncoding(28591)
function ReadText($path) { [IO.File]::ReadAllText($path, $latin1) }
function WriteText($path, $text) {
    Track $path
    if (Test-Path -LiteralPath $path) { Set-ItemProperty -LiteralPath $path -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue }
    [IO.File]::WriteAllText($path, $text, $latin1)
}
function CopyIn($from, $to) {
    Track $to
    if (Test-Path -LiteralPath $to) { Set-ItemProperty -LiteralPath $to -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue }
    Copy-Item -LiteralPath $from -Destination $to -Force
}

function Fetch($pkg) {
    $dl = J $Scratch "downloads"
    New-Item -ItemType Directory -Force $dl | Out-Null
    $zip = J $dl (Split-Path -Leaf $pkg.url)
    $ok = (Test-Path -LiteralPath $zip) -and ((Get-FileHash $zip -Algorithm SHA256).Hash -ieq $pkg.sha256)
    if (-not $ok) {
        Note "downloading $($pkg.url)"
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
        try { Invoke-WebRequest -Uri $pkg.url -OutFile $zip -UseBasicParsing } catch { Die "download of $($pkg.url) failed: $_" }
        $got = (Get-FileHash $zip -Algorithm SHA256).Hash
        if ($got -ine $pkg.sha256) {
            Remove-Item $zip -Force
            Die "$($pkg.name): SHA-256 is $got, expected $($pkg.sha256). The file was deleted and nothing was installed."
        }
    }
    Note "verified    $($pkg.name)  sha256 $($pkg.sha256)"
    $out = J $dl ([IO.Path]::GetFileNameWithoutExtension($zip))
    if (Test-Path -LiteralPath $out) { Remove-Item -Recurse -Force $out }
    Expand-Archive -LiteralPath $zip -DestinationPath $out
    return $out
}
# Copies an extracted release into cstrike\, adding files that are not there and never
# replacing one that is.
function AddMissing($extracted) {
    $cs = J $script:GameDir "cstrike"
    $src = (Resolve-Path $extracted).Path.TrimEnd('\', '/')
    $n = 0
    Get-ChildItem -LiteralPath $src -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($src.Length + 1)
        if ($rel -match '\.(so|dylib)$') { return }
        $to = J $cs $rel
        if (-not (Test-Path -LiteralPath $to)) { CopyIn $_.FullName $to; $n++ }
    }
    Note "added $n files from $(Split-Path -Leaf $src)"
}

# The plugin file for a stage: built here with the game's own AMX Mod X compiler when it
# ships one (the build then matches the AMX Mod X that will load it), else the prebuilt one.
function PluginBinary($stage) {
    $prebuilt = J $root "client" "cs16" "plugin" "carthago_cs16_stage$stage.amxx"
    if (-not (Test-Path -LiteralPath $prebuilt)) { Die "missing $prebuilt" }
    if ((Get-FileHash $prebuilt -Algorithm SHA256).Hash -ine $pluginSha256[$stage]) { Die "$prebuilt does not match the hash pinned in this script" }
    $scripting = J $script:GameDir "cstrike" "addons" "amxmodx" "scripting"
    $amxxpc = J $scripting "amxxpc.exe"
    $include = J $scripting "include"
    if ($NoLocalCompile -or -not (IsFile $amxxpc) -or -not (IsFile (J $include "fakemeta.inc")) -or -not (IsFile (J $include "sockets.inc"))) {
        Note "plugin      prebuilt, stage $stage (built with the AMX Mod X 1.8.2 compiler)"
        return $prebuilt
    }
    # Source, output and working directory are in the scratch folder; the compiler only
    # reads its include files from the game folder.
    $work = J $Scratch "plugin-build"
    New-Item -ItemType Directory -Force $work | Out-Null
    $sma = J $work "carthago_cs16.sma"
    Copy-Item -LiteralPath (J $root "client" "cs16" "plugin" "carthago_cs16.sma") -Destination $sma -Force
    $out = J $work "carthago_cs16_stage$stage.amxx"
    Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    $log = J $work "compile-stage$stage.log"
    Push-Location $work
    & $amxxpc $sma "STAGE=$stage" "-i$include" "-o$out" 2>&1 | ForEach-Object { "$_" } | Set-Content -Path $log
    Pop-Location
    if ((IsFile $out) -and (Get-Item -LiteralPath $out).Length -gt 0) {
        Note "plugin      built here with the game's own AMX Mod X compiler, stage $stage"
        return $out
    }
    Note "plugin      the game's AMX Mod X compiler could not build it; using the prebuilt stage $stage. Its output:"
    Get-Content $log -ErrorAction SilentlyContinue | Where-Object { $_.Trim() } | Select-Object -Last 6 | ForEach-Object { Note "  $_" }
    return $prebuilt
}

# $stage 1..4, $token marks this run's lines in the plugin's log, $selftest > 0 makes the
# plugin close the game after that many seconds (the staged check).
function InstallPlugin($stage, $token, $selftest, $bots) {
    $cs = J $script:GameDir "cstrike"
    $mmDll = J $cs "addons" "metamod" "dlls" "metamod.dll"
    $amx = J $cs "addons" "amxmodx"
    $amxDll = J $amx "dlls" "amxmodx_mm.dll"
    $modules = @("fakemeta_amxx.dll", "sockets_amxx.dll")
    LoadManifest

    $needMm = -not (Test-Path -LiteralPath $mmDll)
    $missingModules = @($modules | Where-Object { -not (Test-Path -LiteralPath (J $amx "modules" $_)) })
    $needAmx = (-not (Test-Path -LiteralPath $amxDll)) -or ($missingModules.Count -gt 0)
    if ($needMm -or $needAmx) {
        Write-Host ""
        Write-Host "The game folder lacks:" -ForegroundColor Yellow
        if ($needMm) { Write-Host "    Metamod (cstrike\addons\metamod\dlls\metamod.dll)" }
        if (-not (Test-Path -LiteralPath $amxDll)) { Write-Host "    AMX Mod X (cstrike\addons\amxmodx\dlls\amxmodx_mm.dll)" }
        elseif ($missingModules.Count) { Write-Host "    AMX Mod X modules: $($missingModules -join ', ')" }
        Write-Host "They can be downloaded from the official release site, checked against pinned SHA-256 hashes:"
        if ($needMm) { Write-Host "    $($official.metamod.url)" }
        if ($needAmx) { Write-Host "    $($official.amxxCstrike.url)"; Write-Host "    $($official.amxxBase.url)" }
        Write-Host "Only missing files are added; nothing that exists is replaced. -Uninstall removes them again."
        $answer = Read-Host "Download and add them now? (y/N)"
        if ($answer -notmatch '^(y|yes)$') {
            Write-Host "Not downloading. Continuing without match data (companion and dashboard only)." -ForegroundColor Yellow
            return $false
        }
        if ($needMm) { AddMissing (Fetch $official.metamod) }
        if ($needAmx) {
            # The Counter-Strike addon first, so its configs win over the base package's.
            AddMissing (Fetch $official.amxxCstrike)
            AddMissing (Fetch $official.amxxBase)
        }
    } else {
        Quiet "found       Metamod and AMX Mod X with the fakemeta and sockets modules"
    }

    # The engine loads the game DLL named in liblist.gam; Metamod sits in that place and
    # loads the real game DLL itself.
    $liblist = J $cs "liblist.gam"
    if (-not (Test-Path -LiteralPath $liblist)) { Die "no $liblist" }
    $text = ReadText $liblist
    $re = New-Object Text.RegularExpressions.Regex('(?im)^([ \t]*gamedll[ \t]+)"([^"\r\n]*)"')
    $m = $re.Match($text)
    if (-not $m.Success) { Die "no gamedll line in $liblist" }
    $gamedll = $m.Groups[2].Value
    if ($gamedll -notmatch 'metamod') {
        $new = $text.Substring(0, $m.Index) + $m.Groups[1].Value + '"addons\metamod\dlls\metamod.dll"' + $text.Substring($m.Index + $m.Length)
        WriteText $liblist $new
        Note "changed     cstrike\liblist.gam: gamedll `"$gamedll`" -> `"addons\metamod\dlls\metamod.dll`""
        if (($gamedll -replace '/', '\') -ine 'dlls\mp.dll') {
            $cfg = J $cs "addons" "metamod" "config.ini"
            if (-not (Test-Path -LiteralPath $cfg)) {
                WriteText $cfg "gamedll $gamedll`r`n"
                Note "added       cstrike\addons\metamod\config.ini (tells Metamod the game DLL is $gamedll)"
            }
        }
    } else {
        Quiet "unchanged   cstrike\liblist.gam already loads Metamod"
    }

    $mmPlugins = J $cs "addons" "metamod" "plugins.ini"
    $line = 'win32 addons\amxmodx\dlls\amxmodx_mm.dll'
    $have = ""
    if (Test-Path -LiteralPath $mmPlugins) { $have = ReadText $mmPlugins }
    $active = @($have -split "`r?`n" | Where-Object { ($_ -match 'amxmodx_mm\.dll') -and ($_ -notmatch '^\s*(;|#|//)') })
    if ($active.Count -eq 0) {
        $sep = ""
        if ($have -and -not $have.EndsWith("`n")) { $sep = "`r`n" }
        WriteText $mmPlugins ($have + $sep + $line + "`r`n")
        Note "changed     cstrike\addons\metamod\plugins.ini: Metamod now loads AMX Mod X"
    } else {
        Quiet "unchanged   Metamod already loads AMX Mod X"
    }

    CopyIn (PluginBinary $stage) (J $amx "plugins" "carthago_cs16.amxx")
    $own = J $amx "configs" "plugins-carthago.ini"
    $main = J $amx "configs" "plugins.ini"
    $entry = "; Carthago Watchdog telemetry (added by tools\carthago-cs16.ps1; remove with -Uninstall)`r`ncarthago_cs16.amxx`r`n"
    if ($script:listInMain) {
        # For an AMX Mod X that does not read plugins-*.ini: list the plugin in plugins.ini.
        $have = ""
        if (IsFile $main) { $have = ReadText $main }
        if ($have -notmatch '(?m)^\s*carthago_cs16\.amxx') {
            $sep = ""
            if ($have -and -not $have.EndsWith("`n")) { $sep = "`r`n" }
            WriteText $main ($have + $sep + $entry)
            Note "changed     cstrike\addons\amxmodx\configs\plugins.ini: lists carthago_cs16.amxx"
        }
        if (IsFile $own) { WriteText $own "; listed in plugins.ini instead`r`n" }
    } else {
        WriteText $own $entry
    }
    WriteText (J $amx "configs" "carthago_cs16.ini") "; Written by tools\carthago-cs16.ps1 for this run.`r`ntoken=$token`r`nstage=$stage`r`nselftest=$selftest`r`nbots=$bots`r`n"
    # Files the game writes while the plugin is installed: -Uninstall removes them, or puts
    # back the ones that were there before.
    Track (J $amx "logs" "carthago_cs16.log")
    Track (J $cs "qconsole.log")
    Note "installed   cstrike\addons\amxmodx\plugins\carthago_cs16.amxx (stage ${stage}: $($stageNames[$stage]))"
    Quiet "undo with   powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -Uninstall"
    $script:installedOnce = $true
    return $true
}

function UninstallPlugin {
    LoadManifest
    if (-not (Test-Path -LiteralPath (ManifestPath))) {
        Note "nothing of this kit is installed in $script:GameDir"
        return
    }
    foreach ($rel in $script:modified) {
        $copy = J (BackupDir) "files" $rel
        $to = J $script:GameDir $rel
        InGame $to | Out-Null
        if (Test-Path -LiteralPath $copy) {
            if (Test-Path -LiteralPath $to) { Set-ItemProperty -LiteralPath $to -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue }
            Copy-Item -LiteralPath $copy -Destination $to -Force
            Note "restored    $rel"
        } else {
            Write-Host "    backup of $rel is missing; left as it is" -ForegroundColor Yellow
        }
    }
    $n = 0
    foreach ($rel in $script:created) {
        $p = J $script:GameDir $rel
        InGame $p | Out-Null
        if (Test-Path -LiteralPath $p) {
            Set-ItemProperty -LiteralPath $p -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $p -Force
            $n++
        }
    }
    Note "removed     $n added files"
    foreach ($rel in ($script:dirs | Sort-Object { $_.Length } -Descending)) {
        $p = J $script:GameDir $rel
        InGame $p | Out-Null
        if ((Test-Path -LiteralPath $p) -and -not (Get-ChildItem -LiteralPath $p -Force | Select-Object -First 1)) { Remove-Item -LiteralPath $p -Force }
    }
    Remove-Item -Recurse -Force (BackupDir)
    Note "the game folder is as it was before the kit"
}

# ---- what the game wrote during a run ------------------------------------------------------
function ConsoleLength {
    $p = J $script:GameDir "cstrike" "qconsole.log"
    if (IsFile $p) { return (Get-Item -LiteralPath $p).Length }
    return 0
}
# Copies what the game, Metamod, AMX Mod X and the plugin wrote since $since into $dir and
# returns the lines worth printing. Reads only; nothing in the game folder is changed.
function CollectGame($dir, $since, $consoleFrom, $token) {
    $cs = J $script:GameDir "cstrike"
    $info = @{ steps = @(); amxx = @(); console = @(); versions = @(); dumps = @(); events = @() }

    # The plugin's own step log: the lines of this run start at its token.
    $stepLog = J $cs "addons" "amxmodx" "logs" "carthago_cs16.log"
    if (IsFile $stepLog) {
        $all = @(Get-Content -LiteralPath $stepLog | ForEach-Object { $_ -replace '^L \S+ - \S+: ', '' })
        $start = -1
        for ($i = 0; $i -lt $all.Count; $i++) { if ($all[$i] -like "load token=$token *") { $start = $i } }
        if ($start -ge 0) { $info.steps = @($all[$start..($all.Count - 1)]) }
        $info.steps | Set-Content -Path (J $dir "plugin-steps.txt")
    }

    # AMX Mod X logs written during the run.
    $amxLogs = J $cs "addons" "amxmodx" "logs"
    if (IsDir $amxLogs) {
        $to = J $dir "amxmodx-logs"
        foreach ($f in @(Get-ChildItem -LiteralPath $amxLogs -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $since })) {
            New-Item -ItemType Directory -Force $to | Out-Null
            Copy-Item -LiteralPath $f.FullName -Destination (J $to $f.Name) -Force
            if ($f.Name -ne "carthago_cs16.log") {
                $info.amxx += @(Get-Content -LiteralPath $f.FullName | Where-Object { $_ -match 'carthago|error|bad load|failed|unknown|not found|invalid' } | Select-Object -Last 8)
            }
        }
    }

    # The console (the game ran with -condebug): the part written during this run.
    $console = J $cs "qconsole.log"
    if (IsFile $console) {
        try {
            $fs = [IO.File]::Open($console, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            if ($consoleFrom -gt $fs.Length) { $consoleFrom = 0 }
            [void]$fs.Seek($consoleFrom, [IO.SeekOrigin]::Begin)
            $bytes = New-Object byte[] ([Math]::Min($fs.Length - $consoleFrom, 4MB))
            [void]$fs.Read($bytes, 0, $bytes.Length)
            $fs.Close()
            $text = $latin1.GetString($bytes)
            [IO.File]::WriteAllText((J $dir "console.log"), $text, $latin1)
            $info.console = @($text -split "`r?`n" | Where-Object { $_.Trim() })
            # The plugin asks the console for "version", "meta list", "amxx modules" and
            # "amxx plugins" right after it has loaded.
            $at = -1
            for ($i = 0; $i -lt $info.console.Count; $i++) { if ($info.console[$i] -like "*load token=$token *") { $at = $i; break } }
            if ($at -ge 0) {
                $info.versions = @($info.console[$at..([Math]::Min($at + 120, $info.console.Count - 1))] |
                    Where-Object { $_ -match '(?i)version|build|metamod|amx ?mod ?x|amxx|_mm\.dll|running|carthago_cs16' -and $_ -notmatch '^\[Carthago\]' } | Select-Object -First 40)
                $info.versions | Set-Content -Path (J $dir "versions.txt")
            }
        } catch {}
    }

    # Crash dumps: names only.
    $places = @($script:GameDir)
    if ($env:LOCALAPPDATA) { $places += (J $env:LOCALAPPDATA "CrashDumps") }
    foreach ($p in $places) {
        if (-not (IsDir $p)) { continue }
        $info.dumps += @(Get-ChildItem -LiteralPath $p -Recurse -Depth 3 -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '^\.(dmp|mdmp)$' -and $_.LastWriteTime -ge $since -and $_.FullName -notmatch 'carthago-cs16-backup' } |
            ForEach-Object { "$($_.FullName)  ($($_.Length) bytes)" })
    }
    $info.dumps | Set-Content -Path (J $dir "crash-dumps.txt")

    # What Windows recorded about a crash of the game program.
    $exe = [IO.Path]::GetFileName($script:GameExePath)
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = "Application"; StartTime = $since; Id = 1000, 1001, 1002 } -MaxEvents 30 -ErrorAction Stop |
            Where-Object { $_.Message -and $_.Message.ToLower().Contains($exe.ToLower()) })
        $ev | ForEach-Object { "---- $($_.TimeCreated) $($_.ProviderName) $($_.Id)`r`n$($_.Message)" } | Set-Content -Path (J $dir "windows-events.txt")
        $info.events = @($ev | ForEach-Object { $_.Message -split "`r?`n" } |
            Where-Object { $_ -match 'Faulting module name|Exception code|Fault offset|Faulting application name' } | ForEach-Object { $_.Trim() } | Select-Object -First 8)
    } catch {}
    return $info
}
function PrintGameReport($info, $full) {
    if ($info.steps.Count) {
        Write-Host "    what the plugin wrote:"
        $show = $info.steps
        if (-not $full) { $show = @($info.steps | Where-Object { $_ -match '^(load |off:|selftest|all parts|unload)' }) }
        $show | ForEach-Object { Write-Host "      $_" }
    } else {
        Write-Host "    the plugin wrote nothing to addons\amxmodx\logs\carthago_cs16.log"
    }
    if ($info.versions.Count -and -not $script:versionsShown) {
        $script:versionsShown = $true
        Write-Host "    versions and modules (from the game console):"
        $info.versions | ForEach-Object { Write-Host "      $_" }
    }
    if ($info.amxx.Count) {
        Write-Host "    AMX Mod X log:"
        $info.amxx | Select-Object -Last 12 | ForEach-Object { Write-Host "      $_" }
    }
    if ($full -and $info.console.Count) {
        $errors = @($info.console | Where-Object { $_ -match 'Host_Error|Sys_Error|FATAL|Error:|ERROR|could not|couldn''t|bad load|failed' } | Select-Object -Last 8)
        if ($errors.Count) {
            Write-Host "    errors in the game console:"
            $errors | ForEach-Object { Write-Host "      $_" }
        }
        Write-Host "    last lines of the game console:"
        $info.console | Select-Object -Last 12 | ForEach-Object { Write-Host "      $_" }
    }
    foreach ($d in $info.dumps) { Write-Host "    crash dump: $d" }
    if ($info.events.Count) {
        Write-Host "    Windows recorded a crash of the game:"
        $info.events | ForEach-Object { Write-Host "      $_" }
    }
}

. (J $PSScriptRoot "carthago-cs16-oracle.ps1")

# ---- uninstall ------------------------------------------------------------------------------
if ($Uninstall) {
    Step "stop the gateway and dashboard started by this script"
    StopGateway
    Step "undo the changes in the game folder"
    if (-not $GameDir -and (Test-Path -LiteralPath $lastGameFile)) {
        $last = @(Get-Content $lastGameFile)
        $GameDir = $last[0]
        if ($last.Count -gt 1) { $script:GameExePath = $last[1] }
    }
    if ($GameDir -and (Test-Path -LiteralPath (J $GameDir "carthago-cs16-backup"))) {
        $GameDir = (Resolve-Path -LiteralPath $GameDir).Path.TrimEnd('\', '/')
        $running = GameRunning
        if ($running) { Die "the game ($running) is running; close it first" }
        UninstallPlugin
    } elseif ($GameDir) {
        Note "nothing of this kit is installed in $GameDir"
    } else {
        Note "no game folder known; if the plugin was installed, run again with -GameDir `"<game folder>`""
    }
    if ($Purge) {
        if ((Test-Path -LiteralPath $Scratch) -and ((Split-Path -Leaf $Scratch) -like "carthago*")) {
            Remove-Item -Recurse -Force $Scratch
            Note "deleted $Scratch"
        } else {
            Note "not deleting '$Scratch': the folder name does not start with 'carthago'"
        }
    } else {
        Note "Build output, logs and the dashboard database are kept in $Scratch (add -Purge to delete them)."
    }
    OracleKeptNote
    exit 0
}

# ---- find, build, install -------------------------------------------------------------------
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logs = J $Scratch "logs" $stamp
New-Item -ItemType Directory -Force $bin, $logs | Out-Null
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = J $Scratch "cargo-target" }
$companionExe = J $env:CARGO_TARGET_DIR "release" "carthago-cs16$exeSuffix"
$bridgeExe = J $env:CARGO_TARGET_DIR "release" "carthago-cs16-bridge$exeSuffix"

if ($AlertSecs -lt 0 -or $AlertSecs -gt 600) { Die "-AlertSecs is 0 to 600" }
if ($TestAlertAfter -lt 0 -or $TestAlertAfter -gt 3600) { Die "-TestAlertAfter is 0 to 3600 seconds" }
if ($BaselineSecs -lt 2 -or $BaselineSecs -gt 600) { Die "-BaselineSecs is 2 to 600" }

# ---- preview of the alert screen ------------------------------------------------------------
if ($TestAlert) {
    if (-not $SkipBuild) {
        if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { Die "'cargo' is not on PATH (the Rust toolchain used for the earlier demos is needed)" }
        Step "build the companion (cargo, release; the first build takes a few minutes)"
        Push-Location (J $root "client")
        cargo build --release -p carthago-cs16-companion 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath (J $logs "build-client.log")
        $code = $LASTEXITCODE
        Pop-Location
        if ($code) { Die "cargo build (see $(J $logs 'build-client.log'))" }
    }
    if (-not (Test-Path -LiteralPath $companionExe)) { Die "missing $companionExe (run without -SkipBuild)" }
    Step "preview of the alert screen"
    Note "This is what the companion shows when the gateway flags a session. Nothing is started and nothing is detected."
    Note "Esc, Enter, Space or a click closes it$(if ($AlertSecs) { "; it closes by itself after $AlertSecs seconds" })."
    $previewArgs = @("--test-alert", "--player", $Player, "--alert-secs", "$AlertSecs")
    if ($EndMatchOnDetect) { $previewArgs += "--end-match-on-detect" }
    & $companionExe @previewArgs | Out-Host
    $code = $LASTEXITCODE
    if ($code) { Write-Host "FAIL  the preview exited with code $code" -ForegroundColor Red }
    else { Write-Host "OK    the alert screen was shown and closed" -ForegroundColor Green }
    exit $code
}

if (-not $DashboardOnly) {
    Step "find Counter-Strike 1.6"
    FindGame
    Set-Content -Path $lastGameFile -Value @($GameDir, $script:GameExePath)
}

# Which parts of the plugin to install: -Stage, else what the last -Diagnose found, else all.
if ($NoPlugin) { $Stage = 0 }
elseif ($Stage -lt 0) {
    $Stage = 4
    if (Test-Path -LiteralPath $stageFile) {
        $found = @((Get-Content $stageFile | Select-Object -First 1) -split ' ')
        if ($found[0] -match '^[0-4]$') {
            $Stage = [int]$found[0]
            if ($found.Count -gt 1 -and $found[1] -eq "main") { $script:listInMain = $true }
            if (-not $Diagnose -and -not $DashboardOnly) { Note "plugin stage $Stage ($($stageNames[$Stage])), as found by the last -Diagnose run" }
        }
    }
}
if ($Stage -gt 4) { Die "-Stage is 0 to 4" }

if (-not $SkipBuild -and -not $InstallOnly) {
    foreach ($tool in "cargo", "go") {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { Die "'$tool' is not on PATH (the Rust and Go toolchains used for the earlier demos are needed)" }
    }
    if (-not $DashboardOnly) {
        Step "build the companion and the bridge (cargo, release; the first build takes a few minutes)"
        Push-Location (J $root "client")
        cargo build --release -p carthago-cs16-companion -p carthago-cs16-bridge 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath (J $logs "build-client.log")
        $code = $LASTEXITCODE
        Pop-Location
        if ($code) { Die "cargo build (see $(J $logs 'build-client.log'))" }
    }
    Step "build the gateway (go)"
    StopGateway
    Push-Location (J $root "backend")
    go build -o $gatewayExe ./cmd/carthago-gateway 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath (J $logs "build-gateway.log")
    $code = $LASTEXITCODE
    Pop-Location
    if ($code) { Die "go build carthago-gateway (see $(J $logs 'build-gateway.log'))" }
}

$plugin = $false
if (-not $DashboardOnly -and -not $Diagnose -and $Stage -gt 0) {
    Step "install the server plugin into the game (reversible)"
    $plugin = InstallPlugin $Stage $stamp 0 0
    if (-not $plugin) { $Stage = 0 }
}
if ($InstallOnly) { exit 0 }
OraclePrepare

if (-not (Test-Path -LiteralPath $gatewayExe)) { Die "missing $gatewayExe (run without -SkipBuild)" }
if (-not $DashboardOnly) {
    if (-not (Test-Path -LiteralPath $companionExe)) { Die "missing $companionExe (run without -SkipBuild)" }
    if (($plugin -or $Diagnose) -and -not (Test-Path -LiteralPath $bridgeExe)) { Die "missing $bridgeExe (run without -SkipBuild)" }
}

# The folders the game loads maps from, in the order the game looks in them.
function MapDirs {
    $mod = "cstrike"
    for ($i = 0; $i -lt $GameArgs.Count - 1; $i++) { if ($GameArgs[$i] -eq "-game") { $mod = $GameArgs[$i + 1] } }
    $names = @("${mod}_addon", $mod, "${mod}_downloads")
    if ($mod -ne "valve") { $names += "valve" }
    foreach ($n in $names) {
        $d = J $script:GameDir $n "maps"
        if (IsDir $d) { $d }
    }
}
function GameKey {
    $sha = [Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($script:GameDir.TrimEnd('\', '/').ToLowerInvariant()))
    $sha.Dispose()
    return -join ($hash[0..5] | ForEach-Object { $_.ToString("x2") })
}
# Records the hash of every map's walls the first time the map is seen in this game folder
# and gives the gateway that list: a map whose file changes later is refused there and the
# match is not scored for information leaks. This cannot tell whether a file was already
# changed when it was first seen.
function PinMaps {
    if (-not $script:mapDirs.Count) {
        Note "no maps folder in the game folder: information-leak scoring is off"
        return $null
    }
    $file = J $Scratch "map-pins-$(GameKey).txt"
    if ($ResetMapPins) { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    if (-not (Test-Path -LiteralPath $file)) { Note "maps: reading the map files in $($script:mapDirs -join ', ') (once; this can take a moment)" }
    $pinArgs = @("map-pins")
    foreach ($d in $script:mapDirs) { $pinArgs += @("--maps", $d) }
    $now = [ordered]@{}
    & $bridgeExe @pinArgs 2>$null | ForEach-Object { if ("$_" -match '^([a-z0-9_-]+) ([0-9a-f]{64})$') { $now[$Matches[1]] = $Matches[2] } }
    $known = [ordered]@{}
    if (Test-Path -LiteralPath $file) {
        Get-Content -LiteralPath $file | ForEach-Object { if ($_ -match '^([a-z0-9_-]+) ([0-9a-f]{64})$') { $known[$Matches[1]] = $Matches[2] } }
    }
    $first = -not $known.Count
    $added = 0
    $script:changedMaps = @()
    foreach ($m in $now.Keys) {
        if (-not $known.Contains($m)) { $known[$m] = $now[$m]; $added++ }
        elseif ($known[$m] -ne $now[$m]) { $script:changedMaps += $m }
    }
    if (-not $known.Count) {
        Note "no usable map file in $($script:mapDirs -join ', '): information-leak scoring is off"
        return $null
    }
    Set-Content -LiteralPath $file -Value @($known.Keys | ForEach-Object { "$_ $($known[$_])" })
    if ($first) { Note "maps: the walls of $($known.Count) maps were hashed and recorded in $file; a map file that changes later is refused" }
    else { Note "maps: $($known.Count) recorded in $file$(if ($added) { ", $added of them new" })" }
    foreach ($m in $script:changedMaps) {
        Write-Host "NOTE  the file of map $m is not the one recorded for this game folder: matches on it are not scored for information leaks." -ForegroundColor Yellow
        Note "      If you replaced that map on purpose, run once with -ResetMapPins."
    }
    return $file
}
# ---- gateway, dashboard, bridge -------------------------------------------------------------
Step "start the gateway (wss://127.0.0.1:$gatewayPort) and the dashboard ($dashboardUrl)"
StopGateway
foreach ($port in $gatewayPort, $dashboardPort) {
    if (PortOpen $port) { Die "port $port on this PC is already in use by another program; close it (or run this script with -Uninstall) and try again" }
}
$keys = J $data "public-keys.json"
$gwLog = J $logs "gateway.log"
# Loopback only, self-signed development certificate kept in the scratch folder, and no
# -auto-kick. -client-notices lets the gateway tell the companion that the session was
# flagged, which is what raises the alert. A ban ends the banned player's session and
# refuses the next one; it never closes the game.
if ($Unban) {
    $lifted = @(& $gatewayExe bans lift -data $data -tenant demo -all -note "carthago-cs16.ps1 -Unban" 2>&1 | ForEach-Object { "$_" })
    if ($LASTEXITCODE) { Die "-Unban: $($lifted -join ' ')" }
    $n = @($lifted | Where-Object { $_ -match '^lifted ' }).Count
    if ($n) { Write-Host "UNBAN $n ban$(if ($n -ne 1) { 's' }) lifted in the local test gateway: $((($lifted | Where-Object { $_ -match '^lifted ' }) -replace '^lifted ', '') -join ', ')" -ForegroundColor Green }
    else { Note "-Unban: nobody was banned in the local test gateway" }
}
if ($KnownCheat) {
    if (-not (Test-Path -LiteralPath $KnownCheat -PathType Leaf)) { Die "-KnownCheat: there is no file $KnownCheat" }
    $cheatName = $(if ($KnownCheatName) { $KnownCheatName } else { "test cheat ($(Split-Path -Leaf $KnownCheat))" })
    $added = @(& $gatewayExe cheats add -data $data -tenant demo -file $KnownCheat -name $cheatName -note "carthago-cs16.ps1 -KnownCheat" 2>&1 | ForEach-Object { "$_" })
    if ($LASTEXITCODE) { Die "-KnownCheat: $($added -join ' ')" }
    Write-Host "KNOWN CHEAT $($added -join ' ')" -ForegroundColor Green
    Note "      A game that loads this file, under any name and from any folder, is banned on rule known_cheat."
    Note "      The list is on the dashboard's Known cheats page; entries are removed there."
}
$gwArgs = @("-data", "`"$data`"", "-listen", "127.0.0.1:$gatewayPort", "-dashboard-listen", "127.0.0.1:$dashboardPort", "-tls-dev-cert", "-client-notices")
if ($AlertOnIntegrity) { $gwArgs += "-client-notices-strict" }
if ($AllowRendererLibrary) { $gwArgs += "-allow-renderer-library" }
# The staged check starts the game several times in a row; a ban would refuse the later ones.
if ($NoAutoBan -or $Diagnose) { $gwArgs += "-auto-ban=false" }
$script:mapDirs = @()
if ($plugin -and -not $DashboardOnly) {
    $script:mapDirs = @(MapDirs)
    $pins = PinMaps
    if ($pins) { $gwArgs += @("-map-pins", "`"$pins`"") }
    if ($AlertOnWallhackScore -and -not $Diagnose) { $gwArgs += "-leak-alert" }
}
if ($TestAlertAfter -gt 0 -and -not $Diagnose -and -not $DashboardOnly) { $gwArgs += @("-test-notice-after", "${TestAlertAfter}s") }
$gwArgs += @(OracleGatewayArgs)
$script:gateway = Start-Process $gatewayExe -ArgumentList $gwArgs -RedirectStandardError $gwLog `
    -RedirectStandardOutput (J $logs "gateway.out") -NoNewWindow -PassThru
Set-Content -Path $pidFile -Value $script:gateway.Id
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
if (-not $published.tls_spki_sha256) { Die "the gateway published no TLS key pin; see $gwLog" }
Note "gateway identity key: $($published.server_identity.public_key)"
Note "gateway TLS key pin : $(@($published.tls_spki_sha256) -join ',')"
OracleStatus $gwLog

function StartBridge($dir) {
    $script:bridgeStop = J $dir "bridge.stop"
    $script:bridgeOut = J $dir "bridge.out"
    Remove-Item -LiteralPath $script:bridgeStop -Force -ErrorAction SilentlyContinue
    $brArgs = @("run", "--keys", "`"$keys`"", "--listen", "127.0.0.1:$bridgePort", "--ingest", "wss://127.0.0.1:$gatewayPort/v1/ingest",
        "--session-file", "`"$(J $dir 'session.json')`"", "--record", "`"$(J $dir 'plugin-stream.txt')`"", "--stop-file", "`"$script:bridgeStop`"", "--log", "`"$(J $dir 'bridge.log')`"")
    foreach ($d in $script:mapDirs) { $brArgs += @("--maps", "`"$d`"") }
    $script:bridge = Start-Process $bridgeExe -ArgumentList $brArgs -RedirectStandardOutput $script:bridgeOut `
        -RedirectStandardError (J $dir "bridge.err") -NoNewWindow -PassThru
    Start-Sleep -Milliseconds 700
    if ($script:bridge.HasExited) {
        Get-Content (J $dir "bridge.err") -ErrorAction SilentlyContinue | Select-Object -Last 5
        Die "the bridge did not start (is another copy of this script still running?)"
    }
}
function StopBridge {
    Set-Content -Path $script:bridgeStop -Value "stop"
    for ($i = 0; $i -lt 300 -and -not $script:bridge.HasExited; $i++) { Start-Sleep -Milliseconds 100 }
    StopProc $script:bridge
    return @(Get-Content $script:bridgeOut -ErrorAction SilentlyContinue)
}
# The record of the first start of this game folder, one file per folder, in the scratch
# folder.
function StartProfilePath { return J $Scratch "start-profile-$(GameKey).txt" }
# Starts the game through the companion and waits until the game has closed.
function RunGame($dir, $extra) {
    $script:compLog = J $dir "companion.log"
    $compArgs = @("--keys", $keys, "--gateway", "wss://127.0.0.1:$gatewayPort/v1/client", "--exe", $script:GameExePath,
        "--player", $Player, "--session-file", (J $dir "session.json"), "--log", $script:compLog,
        "--start-profile", (StartProfilePath), "--baseline-secs", "$BaselineSecs")
    if ($NoTpm) { $compArgs += "--no-tpm" }
    if ($InputMonitor) { $compArgs += "--input-monitor" }
    # The staged check closes the game by itself; an alert has no place in it.
    if ($NoAlert -or $Diagnose) { $compArgs += "--no-alert" } else { $compArgs += @("--alert-secs", "$AlertSecs") }
    if ($EndMatchOnDetect -and -not $Diagnose) { $compArgs += "--end-match-on-detect" }
    $compArgs += "--"
    $compArgs += $GameArgs
    $compArgs += $extra
    & $companionExe @compArgs | Out-Host
    return $LASTEXITCODE
}
# Says whether the session was flagged during the run, and why, from the companion's log.
function AlertVerdict {
    $lines = @(Get-Content -LiteralPath $script:compLog -ErrorAction SilentlyContinue)
    $raised = @($lines | Where-Object { $_ -match 'ALERT notice=' })
    if (-not $raised.Count) {
        Write-Host "OK    no alert: the gateway did not flag this session" -ForegroundColor Green
        if ($TestAlertAfter -gt 0) { Note "the test notice is sent $TestAlertAfter seconds after the session opens; the game closed before that" }
        return
    }
    foreach ($line in $raised) {
        if ($line -match 'ALERT notice=(\S+) category=(\S+) severity=(\S+) test=(\S+): (.*)$') {
            if ($Matches[4] -eq 'true') { Write-Host "ALERT (test) $($Matches[5])" -ForegroundColor Yellow }
            else { Write-Host "ALERT the session was flagged: $($Matches[5]) [category $($Matches[2]), severity $($Matches[3]), notice $($Matches[1])]" -ForegroundColor Red }
        }
    }
    if ($NoAlert) { Note "the alert screen was not shown (-NoAlert)" }
    $lines | Where-Object { $_ -match 'END MATCH' } | ForEach-Object { Note (($_ -replace '^\[[^\]]*\]\s*\S+\s+', '')) }
    if (-not $EndMatchOnDetect) { Note "the game was left running (alert only; -EndMatchOnDetect also closes the game)" }
}
# What the gateway recorded about the game's integrity in this run, from its log: the
# evidence above "info", and what would have raised the alert but was held back.
function IntegrityReport {
    $lines = @(Get-Content -LiteralPath $gwLog -ErrorAction SilentlyContinue)
    $text = '"((?:[^"\\]|\\.)*)"'
    $clean = { param($t) $t -replace '\\"', '"' -replace '\\\\', '\' }
    $own = 'known_cheat|renderer_replaced|system_library_replaced|foreign_module|mapped_image|code_changed|external_writer|external_reader|memory_tool|overlay_reader|game_file_changed|new_game_module|debugger'
    $shown = @{}
    foreach ($line in $lines) {
        if ($line -match "msg=detection .* rule=($own) severity=(medium|high|critical) summary=$text") {
            $shown[$Matches[3]] = $true
            Write-Host "      evidence  $($Matches[1]) ($($Matches[2])): $(& $clean $Matches[3])" -ForegroundColor $(if ($Matches[2] -eq 'medium') { 'Yellow' } else { 'Red' })
        }
    }
    foreach ($line in $lines) {
        if ($line -match "msg=""notice raised by"" .* rule=(\S+) category=\S+ summary=$text" -and -not $shown[$Matches[2]]) {
            $shown[$Matches[2]] = $true
            Write-Host "      raised by $($Matches[1]): $(& $clean $Matches[2])" -ForegroundColor Red
        }
    }
    $held = @($lines | Where-Object { $_ -match 'msg="notice withheld"' })
    foreach ($line in $held) {
        if ($line -match "rule=(\S+) category=(\S+) why=$text summary=$text") {
            Write-Host "NOTE  no alert by default for: $(& $clean $Matches[4])" -ForegroundColor Yellow
            Note "      why: $(& $clean $Matches[3]). Category $($Matches[2]), rule $($Matches[1])."
        }
    }
    if ($held.Count) { Note "-AlertOnIntegrity raises the alert for these as well." }
    # A renderer library of the game's own in the first recorded run: said plainly, because
    # the first run cannot tell a build that ships one from a wallhack that replaces it.
    $said = @{}
    foreach ($line in $held) {
        if ($line -match 'rule=renderer_replaced .*summary="renderer library (\S+) is not the Windows one.*this run is the first recorded start' -and -not $said[$Matches[1]]) {
            $lib = $Matches[1]
            $said[$lib] = $true
            $at = J $script:GameDir $lib
            $where = if (Test-Path -LiteralPath $at) { "sits in the game folder ($at)" } else { "was loaded from outside the Windows system folder" }
            Write-Host "NOTE  an unsigned $lib $where and the game loaded it in place of the Windows renderer library." -ForegroundColor Yellow
            Write-Host "      It is excused only because this is the first recorded run$(if ($AllowRendererLibrary) { ' and -AllowRendererLibrary is given' }). Unless this game build ships that file, it is a wallhack." -ForegroundColor Yellow
            Note "      If it does not belong to the build: remove it and run once with -ResetStartProfile$(if ($AllowRendererLibrary) { ', or run without -AllowRendererLibrary, which alerts on it in every run' })."
        }
    }
    $comp = @(Get-Content -LiteralPath $script:compLog -ErrorAction SilentlyContinue)
    if ($comp | Where-Object { $_ -match 'START PROFILE written' }) {
        if ($script:firstStart) { Note "the first start of this game was recorded in $(StartProfilePath); later runs are compared with it" }
    } elseif ($script:firstStart) {
        Note "the game closed before its start could be recorded; the next run records it"
    }
    if ($comp | Where-Object { $_ -match 'START PROFILE incomplete' }) {
        Note "the game was closed before the companion had looked at everything a clean start shows (about $($BaselineSecs + 25) seconds after the game opens); the next run still records the rest, so keep that one clean as well"
    }
    if (-not ($comp | Where-Object { $_ -match 'BASELINE taken' })) {
        Note "the game closed before the companion had taken its picture of the started game (about $BaselineSecs seconds after the engine loads, $(4 * $BaselineSecs) seconds after the game opens at the latest): changes were not looked for"
    }
    if ($comp | Where-Object { $_ -match 'BASELINE was taken by the clock' }) {
        Note "the picture of the started game was taken by the clock: the companion's module scan had not got through the game's module list by then. Please send the BASELINE and JOB lines of $script:compLog"
    }
}
# What the bridge and the gateway said about the map and the information-leak scores.
function LeakReport($matchData) {
    $text = '"((?:[^"\\]|\\.)*)"'
    $clean = { param($t) $t -replace '\\"', '"' -replace '\\\\', '\' }
    foreach ($line in $matchData) {
        $m = $line -replace '^\[[^\]]*\]\s*', ''
        if ($m -match '^MAP (\S+): read (.*) \((\d+) splits.*geometry hash ([0-9a-f]{16})') {
            Write-Host "OK    map $($Matches[1]): walls read from $($Matches[2]) (geometry $($Matches[4])...)" -ForegroundColor Green
        } elseif ($m -match '^MAP not sent: (.*)$') {
            Write-Host "NOTE  the map's walls were not sent: $($Matches[1])" -ForegroundColor Yellow
        } elseif ($m -match '^MAP check .*does not match') {
            Write-Host "NOTE  $m" -ForegroundColor Yellow
        } elseif ($m -match '^MAP check') {
            Note $m
        }
    }
    $lines = @(Get-Content -LiteralPath $gwLog -ErrorAction SilentlyContinue)
    $off = $false
    foreach ($line in $lines) {
        if ($line -match "msg=""map in use"" .* map=(\S+) .* note=$text") {
            Note "map $($Matches[1]) at the gateway: $((& $clean $Matches[2]) -replace 'pinned by the operator', 'the one recorded when this script first saw the map file')"
        } elseif ($line -match "msg=""map geometry refused"" .* map=(\S+) err=$text") {
            $off = $true
            Write-Host "NOTE  the gateway refused the walls of $($Matches[1]): $(& $clean $Matches[2]). No information-leak score for that match." -ForegroundColor Yellow
        } elseif ($line -match 'msg="leak scores withheld') {
            $off = $true
            Write-Host "NOTE  information-leak scores withheld: the map file does not match where the players were" -ForegroundColor Yellow
        }
    }
    $scores = @($lines | Where-Object { $_ -match 'msg="leak score"' })
    $mine = 0
    $others = 0
    $flaggedOthers = @()
    foreach ($line in $scores) {
        if ($line -notmatch "match=(\S+) slot=(\d+) player=(?:$text|(\S+)) bound=(\w+) score=(\S+) flag_at=(\S+) flagged=(\w+) scored_features=(\d+) strong_windows=(\S+) .* features=(?:$text|(\S*))") { continue }
        $who = "$($Matches[3])$($Matches[4])"
        if ($Matches[5] -ne 'true') {
            $others++
            if ($Matches[8] -eq 'true') { $flaggedOthers += "$who (score $($Matches[6]))" }
            continue
        }
        $mine++
        $features = "$($Matches[11])$($Matches[12])"
        if ($Matches[9] -eq '0') {
            Write-Host "NOTE  information-leak score for you in match $($Matches[1]): not enough play to score (it needs about a minute of fights with enemies behind walls, more is better)" -ForegroundColor Yellow
        } elseif ($Matches[8] -eq 'true') {
            Write-Host "FLAG  information-leak score for you in match $($Matches[1]): $($Matches[6]), flagged for review (flag at $($Matches[7]))" -ForegroundColor Red
        } else {
            Write-Host "OK    information-leak score for you in match $($Matches[1]): $($Matches[6]), not flagged (flag at $($Matches[7]))" -ForegroundColor Green
        }
        if ($features) { Note "      $($features -replace 'hidden_aim', 'aim' -replace 'hidden_shots', 'shots' -replace 'hidden_route', 'routes' -replace 'true=', 'on hidden enemies ' -replace 'control=', 'against shifted in time ')" }
        if ($Matches[10] -match '^(\d+)/(\d+)$') { Note "      -AlertOnWallhackScore: $($Matches[1]) of $($Matches[2]) four-minute stretches were strong; the alert needs 2" }
    }
    if ($scores.Count) {
        if (-not $mine) { Note "no information-leak score for you: your player slot was not tied to the companion's session" }
        if ($others) { Note "$others other players (bots included) were scored as well$(if ($flaggedOthers.Count) { '; flagged for review: ' + ($flaggedOthers -join ', ') })" }
        Note "The score compares where you aimed and shot with where hidden enemies really were, against the same play shifted in time."
        Note "It is evidence for review, not proof: see Evidence in the dashboard (rule information_leak)."
    } elseif (-not $off -and ($matchData | Where-Object { $_ -match '\] MAP \S+: read' })) {
        Note "no information-leak score yet: scores are made when a match ends (map change or leaving the game)"
    }
    # The local player's own is printed with the alert it raised; these are the others'.
    foreach ($line in $lines) {
        if ($line -match "msg=detection .* player=(?:$text|(\S+)) rule=information_leak_live severity=(\w+) summary=$text" -and "$($Matches[1])$($Matches[2])" -ne $Player) {
            Write-Host "      evidence  information_leak_live ($($Matches[3])) for $($Matches[1])$($Matches[2]): $(& $clean $Matches[4])" -ForegroundColor Yellow
        }
    }
    if ($AlertOnWallhackScore) { Note "-AlertOnWallhackScore was on: a strong score in two four-minute stretches of one match raises the alert (opt-in, your own server; a behaviour score, not proof)." }
    else { Note "The score raises no alert by default; -AlertOnWallhackScore lets it (opt-in, for a test on your own server)." }
}
# The companion's own line about a ban, if it logged one: the reference, and whether the
# game was started at all.
function BannedLine {
    $line = @(Get-Content -LiteralPath $script:compLog -ErrorAction SilentlyContinue | Where-Object { $_ -match 'BANNED reference=(\S+)' }) | Select-Object -Last 1
    if ($line -and $line -match 'BANNED reference=(\S+)') { return @{ Ref = $Matches[1]; AtStart = ($line -match 'The game was not started') } }
    return $null
}
$script:unbanHint = "To lift it and keep testing: run the same command with -Unban added. The dashboard's Bans page lifts it too."
# What the gateway banned in this run, from its log, and how to lift it.
function BanReport {
    $text = '"((?:[^"\\]|\\.)*)"'
    $made = $false
    foreach ($line in @(Get-Content -LiteralPath $gwLog -ErrorAction SilentlyContinue)) {
        if ($line -notmatch "^time=(\S+) .* msg=ban ref=(\S+) tenant=\S+ player=(?:$text|(\S+)) device=\S* device_tpm=(\w+) by=(?:$text|(\S+)) rule=(\S*) session=\S* effective_in=(\S+)") { continue }
        $made = $true
        $at = $Matches[1]
        try { $at = ([datetime]::Parse($Matches[1])).ToString("HH:mm:ss") } catch { }
        $who = "$($Matches[3])$($Matches[4])"
        $by = "$($Matches[6])$($Matches[7])"
        $key = $(if ($Matches[5] -eq 'true') { "this PC's device key (in its TPM)" } else { "this PC's device key (a software key: this run had no TPM key)" })
        $how = $(if ($by -eq 'automatic') { "automatically, on rule $($Matches[8])" } else { "by $by in the dashboard" })
        if ($Matches[9] -eq '0s') {
            Write-Host "BANNED at ${at}: player $who and $key were banned $how. Reference $($Matches[2])." -ForegroundColor Red
            Note "      The session was ended; the game was left running. The next start shows the BANNED screen and does not start the game."
        } else {
            Write-Host "BAN PENDING since ${at}: player $who and $key are to be banned $how. The ban takes effect in $($Matches[9] -replace '(?<=[hm])0s$', '') (the automatic ban delay). Reference $($Matches[2])." -ForegroundColor Yellow
            Note "      Until then the player can play; after that the next start shows the BANNED screen and does not start the game."
        }
    }
    if ($made) {
        Note "      $script:unbanHint"
        Note "      With the cheat still in place the next run bans again; -NoAutoBan runs without automatic bans."
    } elseif ($NoAutoBan) {
        Note "-NoAutoBan: nobody is banned automatically in this run; Ban player on the session page of the dashboard still works."
    }
}
function CompanionVerdict($code, $exeName) {
    switch ($code) {
        0 { Write-Host "OK    the session stayed up while the game ran" -ForegroundColor Green }
        2 { Write-Host "FAIL  no session with the gateway; the game was not started (see $script:compLog)" -ForegroundColor Red }
        3 { Write-Host "FAIL  the session opened but $exeName could not be started (see $script:compLog)" -ForegroundColor Red }
        4 { Write-Host "FAIL  the session was lost and could not be re-established (see $script:compLog)" -ForegroundColor Red }
        5 { Write-Host "FAIL  $exeName ended within seconds and no game appeared; the game did not start (see $script:compLog)" -ForegroundColor Red }
        6 {
            $b = BannedLine
            if ($b -and $b.AtStart) {
                Write-Host "BANNED the gateway refused the session: this player or this PC's device key is banned (reference $($b.Ref)). The game was not started." -ForegroundColor Red
                Note "      The gateway tells a banned player only that, never why. The reason is on the dashboard's Bans page."
                Note "      $script:unbanHint"
            } else {
                Write-Host "BANNED the session was ended by a ban and a new one is refused; the game was left running" -ForegroundColor Red
            }
        }
        default { Write-Host "FAIL  the companion exited with code $code (see $script:compLog)" -ForegroundColor Red }
    }
}

if ($DashboardOnly) {
    Write-Host ""
    Write-Host "  DASHBOARD          $dashboardUrl" -ForegroundColor Green
    Write-Host "  Studio (tenant id) demo" -ForegroundColor Green
    Write-Host "  Dashboard key      demo-dashboard-key" -ForegroundColor Green
    Write-Host ""
    if (-not $NoBrowser) { Start-Process $dashboardUrl }
    Read-Host "Press Enter to stop the dashboard" | Out-Null
    StopGateway
    exit 0
}
$exeName = Split-Path -Leaf $script:GameExePath

# ---- staged check of the plugin -------------------------------------------------------------
if ($Diagnose) {
    $map = $(if ($Map) { $Map } else { "de_dust2" })
    $secs = @(0, 15, 20, 30, 45)
    $passed = 0
    $rows = @()
    Step "staged check of the plugin: four short runs on $map, each adding one part"
    Note "Each run starts the game on $map and closes it again by itself. Do not play; just wait."
    Note "If the game shows an error box, close the box. If the game is still open after two minutes, close it."
    for ($s = 1; $s -le 4; $s++) {
        $dir = J $logs "stage$s"
        New-Item -ItemType Directory -Force $dir | Out-Null
        $token = "$stamp-s$s"
        $wait = $(if ($DiagnoseSecs -gt 0) { $DiagnoseSecs } else { $secs[$s] })
        Step "run $s of 4: $($stageNames[$s]) (the game closes by itself about $($wait + 15) seconds after the map has loaded)"
        if (-not (InstallPlugin $s $token $wait $(if ($s -ge 2) { 6 } else { 0 }))) { Die "the plugin cannot be installed without Metamod and AMX Mod X" }
        if ($s -ge 2) { StartBridge $dir }
        $from = ConsoleLength
        $since = Get-Date
        $code = RunGame $dir @("-condebug", "+maxplayers", "12", "+map", $map)
        $matchData = @()
        if ($s -ge 2) { $matchData = StopBridge }
        $info = CollectGame $dir $since $from $token
        $ok = [bool]($info.steps | Where-Object { $_ -match 'selftest passed' })
        # No line from the plugin at all: some AMX Mod X builds do not read plugins-*.ini.
        # List the plugin in the main plugins.ini and try the same run once more.
        if (-not $ok -and $s -eq 1 -and -not $info.steps.Count -and -not $script:listInMain) {
            Write-Host "NOTE  the plugin wrote nothing: AMX Mod X did not load it from plugins-carthago.ini, or no map started." -ForegroundColor Yellow
            Note "trying once more with the plugin listed in configs\plugins.ini"
            PrintGameReport $info $true
            $script:listInMain = $true
            $s = 0
            continue
        }
        $status = $matchData | Where-Object { $_ -match 'STATUS' } | Select-Object -Last 1
        if ($status) { Note ($status -replace '^\[[^\]]*\]\s*', '') }
        PrintGameReport $info (-not $ok)
        if ($ok) {
            Write-Host "PASS  run $s of 4: $($stageNames[$s])" -ForegroundColor Green
            $rows += "PASS  $s  $($stageNames[$s])"
            $passed = $s
        } else {
            $last = $info.steps | Select-Object -Last 1
            if (-not $last) { $last = "the plugin wrote nothing (it was not loaded, or no map started)" }
            Write-Host "FAIL  run $s of 4: $($stageNames[$s]). Game exit code $code. Last line from the plugin: $last" -ForegroundColor Red
            $rows += "FAIL  $s  $($stageNames[$s])  -  last line: $last"
            break
        }
    }
    Step "result of the staged check"
    $rows | ForEach-Object { Write-Host $_ }
    if ($passed -ge 2) {
        InstallPlugin $passed $stamp 0 0 | Out-Null
        Set-Content -Path $stageFile -Value "$passed$(if ($script:listInMain) { ' main' })"
        if ($passed -eq 4) { Write-Host "All four parts work. Run the script without -Diagnose to play with match data." -ForegroundColor Green }
        else { Write-Host "The plugin is left installed with the parts that work (stage ${passed}: $($stageNames[$passed])). Run the script without -Diagnose to play; it will use this stage." -ForegroundColor Yellow }
    } else {
        Step "undo the changes in the game folder"
        UninstallPlugin
        Set-Content -Path $stageFile -Value "0"
        Write-Host "The plugin cannot run on this game build yet, so it was removed again. The script now runs without it (companion and dashboard only) until -Diagnose passes." -ForegroundColor Yellow
    }
    Write-Host "Please send back everything printed above. The files are in $logs" -ForegroundColor Yellow
    StopGateway
    exit $(if ($passed -eq 4) { 0 } else { 20 + $passed })
}

# ---- the game -------------------------------------------------------------------------------
if ($plugin) {
    Step "start the telemetry bridge (receives the plugin's data on 127.0.0.1:$bridgePort)"
    StartBridge $logs
}
Write-Host ""
Write-Host "  DASHBOARD          $dashboardUrl" -ForegroundColor Green
Write-Host "  Studio (tenant id) demo" -ForegroundColor Green
Write-Host "  Dashboard key      demo-dashboard-key" -ForegroundColor Green
Write-Host ""
if (-not $NoBrowser) { Start-Process $dashboardUrl }

Step "start the game through the companion"
Note "The companion opens the session first, then starts $exeName. Leave this window open."
if ($plugin -and -not $Map) { Note "In the game: New Game, pick a map, Start. Add bots from the menu (or console: bot_add)." }
Note "After about 20 seconds in the game, open Sessions in the dashboard."
if ($TestAlertAfter -gt 0) { Note "A test alert appears $TestAlertAfter seconds after the session opens. Esc or a click closes it." }
if ($EndMatchOnDetect) { Note "-EndMatchOnDetect: if the session is flagged, the companion also closes the game it started." }
if ($ResetStartProfile) { Remove-Item -LiteralPath (StartProfilePath) -Force -ErrorAction SilentlyContinue }
$script:firstStart = -not (Test-Path -LiteralPath (StartProfilePath))
if ($script:firstStart) {
    Note "First recorded start of this game: whatever the game shows while it starts is taken to be the game build and is"
    Note "    not alerted on later. Run this once with no cheat present. -ResetStartProfile records it anew."
} else {
    Note "This start is compared with the first recorded start of this game ($(StartProfilePath))."
}
if ($AlertOnWallhackScore) {
    if ($plugin) { Note "-AlertOnWallhackScore: a strong information-leak score in two four-minute stretches of one match raises the alert. Opt-in, for your own server: it is a behaviour score, not proof. Play one map for 20 to 30 minutes." }
    else { Note "-AlertOnWallhackScore needs the plugin's match data, which is off in this run: it does nothing." }
}
if ($NoAutoBan) { Note "-NoAutoBan: automatic bans are off in this run." }
else { Note "Automatic bans are on: evidence that is certain bans this test player and this PC's device key (-NoAutoBan turns that off, -Unban lifts a ban)." }
if ($AlertOnIntegrity) { Note "-AlertOnIntegrity: the alert is also raised for what a modified but honest game build shows. Expect alerts on a clean game." }
$elevated = $false
try { $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
if (-not $elevated) { Note "This window is not elevated: a program that runs as administrator (Cheat Engine does) cannot be seen holding the game open." }
$extra = @()
if ($Windowed) {
    $extra += @("-window", "-noborder")
    Note "-Windowed: the game starts in a borderless window and remembers that. To go back to full screen, start it once with -full"
    Note "    (for example -GameArgs:`"-game cstrike -full`") or change it under Options > Video."
}
if ($plugin) { $extra += "-condebug" }
if ($Map) { $extra += @("+maxplayers", "12", "+map", $Map) }
$from = $(if ($plugin) { ConsoleLength } else { 0 })
$since = Get-Date
$exit = RunGame $logs $extra

$matchData = @()
if ($plugin) { $matchData = StopBridge }

Step "result"
CompanionVerdict $exit $exeName
$refused = BannedLine
if (-not ($refused -and $refused.AtStart)) {
    AlertVerdict
    IntegrityReport
    BanReport
}
if ($plugin) {
    $info = CollectGame $logs $since $from $stamp
    $status = $matchData | Where-Object { $_ -match 'STATUS' } | Select-Object -Last 1
    $result = $matchData | Where-Object { $_ -match 'RESULT' } | Select-Object -Last 1
    $noData = [bool]($matchData | Where-Object { $_ -match 'NO DATA' })
    if ($noData) {
        Write-Host "FAIL  no match data: the plugin sent nothing." -ForegroundColor Red
        if (-not $exit) { $exit = 21 }
    } elseif ($result -match 'sent=(\d+) acknowledged=(\d+) rejected=(\d+)' -and $Matches[1] -ne '0' -and $Matches[1] -eq $Matches[2] -and $Matches[3] -eq '0') {
        Write-Host "OK    match data reached the gateway ($($Matches[1]) batches)" -ForegroundColor Green
    } else {
        Write-Host "FAIL  match data was not fully delivered (see $script:bridgeOut)" -ForegroundColor Red
        if (-not $exit) { $exit = 22 }
    }
    if ($matchData | Where-Object { $_ -match 'SLOT bound' }) {
        Write-Host "OK    your player slot was tied to the companion's session" -ForegroundColor Green
    } elseif (-not $noData) {
        Write-Host "NOTE  no player slot was tied to the companion's session: the plugin reported no player on this PC" -ForegroundColor Yellow
    }
    if ($status) { Note ($status -replace '^\[[^\]]*\]\s*', '') }
    if (-not $noData) { LeakReport $matchData }
    PrintGameReport $info ($noData -or $exit -ne 0)
    if ($noData) {
        Write-Host "To find which part of the plugin fails, close the game and run:" -ForegroundColor Yellow
        Write-Host "    powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -GameDir `"$GameDir`" -Diagnose" -ForegroundColor Yellow
    }
}
OracleResultNote
Note "logs: $logs"

Write-Host ""
Write-Host "The dashboard is still running at $dashboardUrl (studio demo, key demo-dashboard-key)." -ForegroundColor Green
Read-Host "Press Enter to stop it" | Out-Null
StopGateway
exit $exit
