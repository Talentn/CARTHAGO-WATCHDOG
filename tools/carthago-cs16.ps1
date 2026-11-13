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
  7. when the game closes, keeps the dashboard up until Enter is pressed.

  What is changed in the game folder, and only there:
    - cstrike\addons\amxmodx\plugins\carthago_cs16.amxx           (added)
    - cstrike\addons\amxmodx\configs\plugins-carthago.ini         (added)
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
  powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -DashboardOnly
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
    # Install the plugin and stop, without starting anything.
    [switch]$InstallOnly,
    [switch]$DashboardOnly,
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
# The compiled plugin in the repo (client\cs16\plugin\carthago_cs16.sma, AMX Mod X 1.8.2 compiler).
$pluginSha256 = "5253cb147df55d93106e259605d7c35279bc581130f918acb12eb22326ecd1aa"

function Step($m) { Write-Host "`n=== $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" }
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

function InstallPlugin {
    $cs = J $script:GameDir "cstrike"
    $mmDll = J $cs "addons" "metamod" "dlls" "metamod.dll"
    $amx = J $cs "addons" "amxmodx"
    $amxDll = J $amx "dlls" "amxmodx_mm.dll"
    $modules = @("fakemeta_amxx.dll", "hamsandwich_amxx.dll", "sockets_amxx.dll")
    $prebuilt = J $root "client" "cs16" "plugin" "carthago_cs16.amxx"
    if (-not (Test-Path -LiteralPath $prebuilt)) { Die "missing $prebuilt" }
    if ((Get-FileHash $prebuilt -Algorithm SHA256).Hash -ine $pluginSha256) { Die "$prebuilt does not match the hash pinned in this script" }
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
        Note "found       Metamod and AMX Mod X with the fakemeta, hamsandwich and sockets modules"
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
        Note "unchanged   cstrike\liblist.gam already loads Metamod"
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
        Note "unchanged   Metamod already loads AMX Mod X"
    }

    CopyIn $prebuilt (J $amx "plugins" "carthago_cs16.amxx")
    WriteText (J $amx "configs" "plugins-carthago.ini") "; Carthago Watchdog telemetry (added by tools\carthago-cs16.ps1; remove with -Uninstall)`r`ncarthago_cs16.amxx`r`n"
    Note "installed   cstrike\addons\amxmodx\plugins\carthago_cs16.amxx"
    Note "undo with   powershell -ExecutionPolicy Bypass -File tools\carthago-cs16.ps1 -Uninstall"
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
    exit 0
}

# ---- find, build, install -------------------------------------------------------------------
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logs = J $Scratch "logs" $stamp
New-Item -ItemType Directory -Force $bin, $logs | Out-Null
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = J $Scratch "cargo-target" }
$companionExe = J $env:CARGO_TARGET_DIR "release" "carthago-cs16$exeSuffix"
$bridgeExe = J $env:CARGO_TARGET_DIR "release" "carthago-cs16-bridge$exeSuffix"

if (-not $DashboardOnly) {
    Step "find Counter-Strike 1.6"
    FindGame
    Set-Content -Path $lastGameFile -Value @($GameDir, $script:GameExePath)
}

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
if (-not $DashboardOnly -and -not $NoPlugin) {
    Step "install the server plugin into the game (reversible)"
    $plugin = InstallPlugin
}
if ($InstallOnly) { exit 0 }

if (-not (Test-Path -LiteralPath $gatewayExe)) { Die "missing $gatewayExe (run without -SkipBuild)" }
if (-not $DashboardOnly) {
    if (-not (Test-Path -LiteralPath $companionExe)) { Die "missing $companionExe (run without -SkipBuild)" }
    if ($plugin -and -not (Test-Path -LiteralPath $bridgeExe)) { Die "missing $bridgeExe (run without -SkipBuild)" }
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
# -auto-kick: nothing the gateway sees can end the session or close the game.
$gwArgs = @("-data", "`"$data`"", "-listen", "127.0.0.1:$gatewayPort", "-dashboard-listen", "127.0.0.1:$dashboardPort", "-tls-dev-cert")
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

$session = J $logs "session.json"
$bridgeStop = J $logs "bridge.stop"
$bridgeOut = J $logs "bridge.out"
if ($plugin) {
    Step "start the telemetry bridge (receives the plugin's data on 127.0.0.1:$bridgePort)"
    $brArgs = @("run", "--keys", "`"$keys`"", "--listen", "127.0.0.1:$bridgePort", "--ingest", "wss://127.0.0.1:$gatewayPort/v1/ingest",
        "--session-file", "`"$session`"", "--record", "`"$(J $logs 'plugin-stream.txt')`"", "--stop-file", "`"$bridgeStop`"", "--log", "`"$(J $logs 'bridge.log')`"")
    $script:bridge = Start-Process $bridgeExe -ArgumentList $brArgs -RedirectStandardOutput $bridgeOut `
        -RedirectStandardError (J $logs "bridge.err") -NoNewWindow -PassThru
    Start-Sleep -Milliseconds 700
    if ($script:bridge.HasExited) {
        Get-Content (J $logs "bridge.err") -ErrorAction SilentlyContinue | Select-Object -Last 5
        Die "the bridge did not start (is another copy of this script still running?)"
    }
}

Write-Host ""
Write-Host "  DASHBOARD          $dashboardUrl" -ForegroundColor Green
Write-Host "  Studio (tenant id) demo" -ForegroundColor Green
Write-Host "  Dashboard key      demo-dashboard-key" -ForegroundColor Green
Write-Host ""
if (-not $NoBrowser) { Start-Process $dashboardUrl }

# ---- the game -------------------------------------------------------------------------------
$exit = 0
if (-not $DashboardOnly) {
    Step "start the game through the companion"
    $exeName = Split-Path -Leaf $script:GameExePath
    Note "The companion opens the session first, then starts $exeName. Leave this window open."
    if ($plugin -and -not $Map) { Note "In the game: New Game, pick a map, Start. Add bots from the menu (or console: bot_add)." }
    Note "After about 20 seconds in the game, open Sessions in the dashboard."
    $compLog = J $logs "companion.log"
    $compArgs = @("--keys", $keys, "--gateway", "wss://127.0.0.1:$gatewayPort/v1/client", "--exe", $script:GameExePath,
        "--player", $Player, "--session-file", $session, "--log", $compLog)
    if ($NoTpm) { $compArgs += "--no-tpm" }
    if ($InputMonitor) { $compArgs += "--input-monitor" }
    $compArgs += "--"
    $compArgs += $GameArgs
    if ($Map) { $compArgs += @("+maxplayers", "12", "+map", $Map) }
    & $companionExe @compArgs
    $exit = $LASTEXITCODE

    $matchData = $null
    if ($plugin) {
        Set-Content -Path $bridgeStop -Value "stop"
        for ($i = 0; $i -lt 300 -and -not $script:bridge.HasExited; $i++) { Start-Sleep -Milliseconds 100 }
        StopProc $script:bridge
        $matchData = Get-Content $bridgeOut -ErrorAction SilentlyContinue
    }

    Step "result"
    switch ($exit) {
        0 { Write-Host "OK    the session stayed up while the game ran" -ForegroundColor Green }
        2 { Write-Host "FAIL  no session with the gateway; the game was not started (see $compLog)" -ForegroundColor Red }
        3 { Write-Host "FAIL  the session opened but $exeName could not be started (see $compLog)" -ForegroundColor Red }
        4 { Write-Host "FAIL  the session was lost and could not be re-established (see $compLog)" -ForegroundColor Red }
        5 { Write-Host "FAIL  $exeName ended within seconds and no game appeared; the game did not start (see $compLog)" -ForegroundColor Red }
        default { Write-Host "FAIL  the companion exited with code $exit (see $compLog)" -ForegroundColor Red }
    }
    if ($plugin) {
        $status = $matchData | Where-Object { $_ -match 'STATUS' } | Select-Object -Last 1
        $result = $matchData | Where-Object { $_ -match 'RESULT' } | Select-Object -Last 1
        if ($matchData | Where-Object { $_ -match 'NO DATA' }) {
            Write-Host "FAIL  no match data: the plugin sent nothing. Was a map started? In the game console, 'meta list' should show AMX Mod X and 'amxx plugins' should list carthago_cs16.amxx." -ForegroundColor Red
            if (-not $exit) { $exit = 21 }
        } elseif ($result -match 'sent=(\d+) acknowledged=(\d+) rejected=(\d+)' -and $Matches[1] -ne '0' -and $Matches[1] -eq $Matches[2] -and $Matches[3] -eq '0') {
            Write-Host "OK    match data reached the gateway ($($Matches[1]) batches)" -ForegroundColor Green
        } else {
            Write-Host "FAIL  match data was not fully delivered (see $bridgeOut)" -ForegroundColor Red
            if (-not $exit) { $exit = 22 }
        }
        if ($matchData | Where-Object { $_ -match 'SESSION bound' }) {
            Write-Host "OK    your player slot was tied to the companion's session" -ForegroundColor Green
        }
        if ($status) { Note ($status -replace '^\[[^\]]*\]\s*', '') }
    }
    Note "logs: $logs"
}

Write-Host ""
Write-Host "The dashboard is still running at $dashboardUrl (studio demo, key demo-dashboard-key)." -ForegroundColor Green
Read-Host "Press Enter to stop it" | Out-Null
StopGateway
exit $exit
