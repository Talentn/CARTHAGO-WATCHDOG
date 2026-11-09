<#
.SYNOPSIS
  Phase 0 risk spike 1: TPM device key + AK enrollment + quote + WBCL, verified by go-attestation.
.DESCRIPTION
  Builds the Go verifier and the Rust client, starts the verifier on 127.0.0.1:8740 (exits after
  one report), runs the client, and leaves evidence in attest-out\ and attest-reports\.
  Run from a normal (non-elevated) PowerShell; nothing here needs administrator rights.
#>
param(
    [ValidateSet('auto', 'ek-certify', 'pcp', 'tbs-activate')]
    [string]$Activation = 'auto',
    [switch]$NoFetchEK
)
# Native tools write progress to stderr; failures are detected through exit codes instead.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null

Push-Location (Join-Path $root 'backend')
try { go build -o (Join-Path $bin 'attest-spike-verifier.exe') ./cmd/attest-spike; if ($LASTEXITCODE) { throw 'go build failed' } }
finally { Pop-Location }

Push-Location (Join-Path $root 'client')
try { cargo build --release -p attest-spike; if ($LASTEXITCODE) { throw 'cargo build failed' } }
finally { Pop-Location }
$target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'client\target' }
$client = Join-Path $target 'release\attest-spike.exe'

$verifierArgs = @('-once', '-out', ('"{0}"' -f (Join-Path $root 'attest-reports')))
if ($NoFetchEK) { $verifierArgs += '-fetch-ek=false' }
$verifier = Start-Process -FilePath (Join-Path $bin 'attest-spike-verifier.exe') -ArgumentList $verifierArgs -PassThru -NoNewWindow
try {
    Start-Sleep -Seconds 1
    & $client --out (Join-Path $root 'attest-out') --activation $Activation
    $code = $LASTEXITCODE
}
finally {
    if (-not $verifier.WaitForExit(5000)) { $verifier.Kill() }
}
exit $code
