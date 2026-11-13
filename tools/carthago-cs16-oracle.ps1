<#
The Carthago Oracle part of tools\carthago-cs16.ps1. It is not run by itself: the CS 1.6
script loads it and calls the functions below, so everything about the Oracle is in this
one file. Windows PowerShell 5.1 syntax only.

What the CS 1.6 script does with the Oracle:
  - it starts the gateway with the Oracle whenever a trained bundle exists in the bundle
    folder: -OracleDir, else the CARTHAGO_ORACLE_DIR environment variable, else
    %LOCALAPPDATA%\Carthago\oracle-bundle;
  - with -Oracle it first trains a bundle into that folder if there is none (once, about
    8 minutes on a 4-core PC) and downloads the analyst's language model with
    tools\carthago-oracle-fetch.ps1 if it is not installed (once, about 1.2 GB, to
    %LOCALAPPDATA%\Carthago\oracle-runtime or CARTHAGO_ORACLE_RUNTIME_DIR);
  - -OracleNoModel trains without downloading: sessions are scored, no opinion is written;
  - -NoOracle starts the gateway without the Oracle even when a bundle exists.

The Oracle only writes to the dashboard. The alert screen is raised by the gateway's rules
(-client-notices) and is the same with the Oracle on or off.
#>

function OracleUserData {
    if ($env:LOCALAPPDATA) { return (J $env:LOCALAPPDATA "Carthago") }
    return $null
}
function OracleBundleDir {
    if ($OracleDir) { return $OracleDir }
    if ($env:CARTHAGO_ORACLE_DIR) { return $env:CARTHAGO_ORACLE_DIR }
    $base = OracleUserData
    if ($base) { return (J $base "oracle-bundle") }
    return (J $Scratch "oracle-bundle")
}
# Where the gateway looks for the language model. $null: not known here (not Windows).
function OracleRuntimeDir {
    if ($env:CARTHAGO_ORACLE_RUNTIME_DIR) { return $env:CARTHAGO_ORACLE_RUNTIME_DIR }
    $base = OracleUserData
    if ($base) { return (J $base "oracle-runtime") }
    return $null
}
function OracleHasBundle($dir) { Test-Path -LiteralPath (J $dir "manifest.json") -PathType Leaf }
# The analyst the gateway will use needs the downloaded model only when it is the local one.
function OracleWantsLocalModel {
    $kind = "$env:CARTHAGO_ORACLE_ANALYST"
    return ($kind -eq "" -or $kind -eq "auto" -or $kind -eq "local")
}
function OracleModelInstalled($bundleDir) {
    $dir = OracleRuntimeDir
    if (-not $dir -or -not (Test-Path -LiteralPath $dir -PathType Container)) { return $false }
    $file = $null
    try { $file = (Get-Content -LiteralPath (J $bundleDir "manifest.json") -Raw | ConvertFrom-Json).analyst.local_model.file } catch { }
    if (-not $file) { return $false }
    if (-not (Test-Path -LiteralPath (J $dir "models" $file) -PathType Leaf)) { return $false }
    return [bool](Get-ChildItem -LiteralPath $dir -Recurse -File -Filter "llama-server*" -ErrorAction SilentlyContinue | Select-Object -First 1)
}

function OracleTrain($dir) {
    $inRepo = ([IO.Path]::GetFullPath($dir).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar).StartsWith($root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
    if ($inRepo) { Die "the Oracle bundle folder '$dir' is inside the repository; a trained model must stay out of it (name another folder with -OracleDir)" }
    if ((Test-Path -LiteralPath $dir) -and @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue).Count) {
        Die "'$dir' exists and holds no Oracle bundle (no manifest.json); name another folder with -OracleDir, or empty it"
    }
    Step "Carthago Oracle: train the behaviour model (first use only; about 8 minutes on a 4-core PC)"
    $oracleExe = J $bin "carthago-oracle$exeSuffix"
    if (-not $SkipBuild) {
        if (-not (Get-Command go -ErrorAction SilentlyContinue)) { Die "'go' is not on PATH (it builds the Oracle's training tool)" }
        Push-Location (J $root "backend")
        go build -o $oracleExe ./cmd/carthago-oracle 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath (J $logs "build-oracle.log")
        $code = $LASTEXITCODE
        Pop-Location
        if ($code) { Die "go build carthago-oracle (see $(J $logs 'build-oracle.log'))" }
    }
    if (-not (Test-Path -LiteralPath $oracleExe)) { Die "missing $oracleExe (run without -SkipBuild)" }
    $parent = Split-Path -Parent $dir
    if ($parent) { New-Item -ItemType Directory -Force $parent | Out-Null }
    $tmp = "$dir.new"
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
    # The seed decides the model. It is drawn here, used once and not written anywhere, so
    # nobody can rebuild this model from the repository.
    $seed = $OracleSeed
    if (-not $seed) {
        $bytes = New-Object byte[] 8
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($bytes)
        $rng.Dispose()
        $seed = "$([BitConverter]::ToUInt64($bytes, 0))"
    }
    $trainArgs = @("train", "-seed", "$seed", "-out", "`"$tmp`"")
    if ($OracleMatches -gt 0) { $trainArgs += @("-matches", "$OracleMatches") }
    # The report describes the model, so it is kept beside the bundle and not with the
    # logs that are sent back for support.
    $report = "$dir-training-report.txt"
    $p = Start-Process $oracleExe -ArgumentList $trainArgs -RedirectStandardOutput $report `
        -RedirectStandardError (J $logs "oracle-train.err") -NoNewWindow -PassThru
    $null = $p.Handle
    $t0 = Get-Date
    $said = 0
    while (-not $p.HasExited) {
        Start-Sleep -Milliseconds 500
        $min = [int][Math]::Floor(((Get-Date) - $t0).TotalMinutes)
        if ($min -gt $said) { $said = $min; Note "still training ($min min)" }
    }
    $p.WaitForExit()
    if ($p.ExitCode -or -not (OracleHasBundle $tmp)) {
        Get-Content (J $logs "oracle-train.err") -ErrorAction SilentlyContinue | Select-Object -Last 5
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        Die "training the Oracle's behaviour model failed (see $(J $logs 'oracle-train.err'))"
    }
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Force }
    Move-Item -LiteralPath $tmp -Destination $dir
    Note "trained in $([int]((Get-Date) - $t0).TotalSeconds) s; the bundle is in $dir"
    Note "its evaluation is in $report (it describes your model: keep it to yourself)"
}

function OracleFetchModel {
    if ($exeSuffix -ne ".exe") {
        Write-Host "NOTE  the language model is not downloaded on this system; use tools/carthago-oracle-fetch.sh" -ForegroundColor Yellow
        return
    }
    Step "Carthago Oracle: download the analyst's language model (first use only; about 1.2 GB)"
    Note "It goes to $(OracleRuntimeDir), outside the repository. An interrupted download continues on the next run."
    $fetchArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (J $root "tools" "carthago-oracle-fetch.ps1"))
    if ($env:CARTHAGO_ORACLE_RUNTIME_DIR) { $fetchArgs += @("-Dir", $env:CARTHAGO_ORACLE_RUNTIME_DIR) }
    & (Get-Process -Id $PID).Path @fetchArgs | Out-Host
    if ($LASTEXITCODE) {
        Write-Host "NOTE  the language model could not be downloaded. The Oracle still scores sessions; it writes no opinions." -ForegroundColor Yellow
        Note "Run again with -Oracle to try the download again."
    }
}

# Decides whether the gateway starts with the Oracle, and prepares what -Oracle asks for.
# Call it once, after the builds and before the gateway is started.
function OraclePrepare {
    $script:oracleOn = $false
    $script:oracleDir = OracleBundleDir
    $script:oracleWhy = ""
    if ($Oracle -and $NoOracle) { Die "-Oracle and -NoOracle exclude each other" }
    if ($NoOracle) { $script:oracleWhy = "-NoOracle"; return }
    if (-not (OracleHasBundle $script:oracleDir)) {
        if (-not $Oracle) {
            $script:oracleWhy = "no trained bundle in $script:oracleDir; add -Oracle to train one and download the language model (once: about 8 minutes and 1.2 GB)"
            return
        }
        OracleTrain $script:oracleDir
    }
    $script:oracleOn = $true
    if ($Oracle -and -not $OracleNoModel -and (OracleWantsLocalModel) -and -not (OracleModelInstalled $script:oracleDir)) { OracleFetchModel }
}

# The gateway options. -oracle-dir is always given, so neither an environment variable
# nor a bundle left in the gateway's data folder switches the Oracle on behind -NoOracle.
function OracleGatewayArgs {
    $dir = $script:oracleDir
    if ($NoOracle) {
        $dir = J $Scratch "oracle-off"
        New-Item -ItemType Directory -Force $dir | Out-Null
    }
    return @("-oracle-dir", "`"$dir`"")
}

# One or two lines on what the started gateway says about the Oracle, from its log.
function OracleStatus($log) {
    $lines = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue | Where-Object { $_ -match 'Carthago Oracle' })
    $ready = $lines | Where-Object { $_ -match 'msg="Carthago Oracle ready"' } | Select-Object -First 1
    if (-not $ready) {
        if ($lines | Where-Object { $_ -match 'the bundle failed its checks' }) {
            Write-Host "NOTE  Carthago Oracle: off. The bundle in $script:oracleDir failed its checks (see $log)." -ForegroundColor Yellow
            Note "To train a new one, delete that folder and run with -Oracle."
        } else {
            Note "Carthago Oracle: off ($script:oracleWhy)"
        }
        return
    }
    $bundle = "?"
    $analyst = "off"
    if ($ready -match ' bundle=(\S+)') { $bundle = $Matches[1] }
    if ($ready -match ' analyst=(\S+)') { $analyst = $Matches[1] }
    Note "Carthago Oracle: on, bundle $bundle from $script:oracleDir"
    if ($analyst -eq "local") {
        Note "    analyst: the local language model; it reviews a flagged session after the game has closed"
    } elseif ($analyst -eq "off") {
        $reason = ""
        $offLine = $lines | Where-Object { $_ -match 'analyst off' } | Select-Object -First 1
        if ($offLine -match 'reason="((?:[^"\\]|\\.)*)"') { $reason = $Matches[1] -replace '\\\\', '\' }
        elseif ($offLine -match 'reason=(\S+)') { $reason = $Matches[1] }
        Note "    analyst: off. Sessions are scored; no opinion is written. $reason"
        if ((OracleWantsLocalModel) -and -not $OracleNoModel) { Note "    Run with -Oracle to download the language model (once, about 1.2 GB)." }
    } else {
        Note "    analyst: $analyst (CARTHAGO_ORACLE_ANALYST)"
    }
}

function OracleResultNote {
    if (-not $script:oracleOn) { return }
    Note "Carthago Oracle: this session's score is on its page in the dashboard (Sessions, then the session)."
    Note "    An opinion is written only for a session that the score or the rules flagged, after the game has closed."
    Note "    With the local model that takes a few minutes: leave this window open and reload the page."
}

# For -Uninstall: what of the Oracle is outside the scratch folder and is left alone.
function OracleKeptNote {
    $kept = @()
    foreach ($d in @((OracleBundleDir), (OracleRuntimeDir))) {
        if ($d -and (Test-Path -LiteralPath $d) -and -not ([IO.Path]::GetFullPath($d)).StartsWith([IO.Path]::GetFullPath($Scratch), [StringComparison]::OrdinalIgnoreCase)) { $kept += $d }
    }
    if ($kept.Count) { Note "The Carthago Oracle's own folders are not touched; delete them yourself to remove the model: $($kept -join ', ')" }
}
