<#
Fetches what the Carthago Oracle analyst runs on: the llama.cpp server (MIT) and one small
open-weights language model, both pinned and checked against SHA-256 hashes.

Nothing is installed system-wide, no setting is changed and nothing is put in the
repository: the files go to a per-user folder the gateway looks in by default,
  %LOCALAPPDATA%\Carthago\oracle-runtime
Without them the gateway still runs and scores sessions; the analyst stays off and the
gateway says so at startup.

Usage (Windows PowerShell 5.1 or later, no administrator rights):
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\carthago-oracle-fetch.ps1
  ... -Dir D:\somewhere\oracle-runtime     another folder (then pass it to the gateway)
  ... -RuntimeOnly                         the server only, when you bring your own model

Layout:
  DIR\llama-<tag>\llama-server.exe   the server and its libraries
  DIR\models\<model file>            the model weights
  DIR\THIRD-PARTY-NOTICES.txt        their licences
#>
param(
    [string]$Dir = (Join-Path $env:LOCALAPPDATA 'Carthago\oracle-runtime'),
    [switch]$RuntimeOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

# --- pinned versions (keep in step with carthago-oracle-fetch.sh and
# --- backend\cmd\carthago-oracle\localmodel.go) --------------------------------------
$LlamaTag     = 'b12360'
$LlamaFile    = 'llama-b12360-bin-win-cpu-x64.zip'
$LlamaSha256  = 'eae1726047e0eaa707b1302929d196c999b96c2f243b21aea6e93bcebacc4e17'
$LlamaUrl     = "https://github.com/ggml-org/llama.cpp/releases/download/$LlamaTag/$LlamaFile"
$ModelRepo     = 'Qwen/Qwen2.5-1.5B-Instruct-GGUF'
$ModelRevision = '91cad51170dc346986eccefdc2dd33a9da36ead9'
$ModelFile     = 'qwen2.5-1.5b-instruct-q4_k_m.gguf'
$ModelSha256   = '6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e'
$ModelLicence  = 'Apache-2.0'
$ModelUrl      = "https://huggingface.co/$ModelRepo/resolve/$ModelRevision/$ModelFile"
# --------------------------------------------------------------------------------------

function Fail([string]$Message) {
    Write-Host "carthago-oracle-fetch: $Message" -ForegroundColor Red
    exit 1
}

if (-not [Environment]::Is64BitOperatingSystem) { Fail 'a 64-bit Windows is required' }
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$root = Split-Path -Parent $PSScriptRoot
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$Dir = (Resolve-Path -LiteralPath $Dir).Path
if (($Dir.TrimEnd('\') + '\').StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    Fail "$Dir is inside the repository; model files must stay out of it"
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# Downloads Url to File unless it is already there with the right hash. A partial download
# is kept as File.part and resumed when curl.exe (part of Windows 10 and 11) is available.
function Fetch([string]$Url, [string]$File, [string]$Want) {
    $name = Split-Path -Leaf $File
    if ((Test-Path -LiteralPath $File) -and ((Get-Sha256 $File) -eq $Want)) {
        Write-Host "have $name"
        return
    }
    Write-Host "downloading $name"
    $part = "$File.part"
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (Test-Path -LiteralPath $curl) {
        & $curl -fL --retry 4 --retry-delay 4 -C - -o $part $Url
        if ($LASTEXITCODE -ne 0) { Fail "download failed: $Url" }
    } else {
        $client = New-Object System.Net.WebClient
        try { $client.DownloadFile($Url, $part) } catch { Fail "download failed: $Url ($($_.Exception.Message))" } finally { $client.Dispose() }
    }
    $got = Get-Sha256 $part
    if ($got -ne $Want) {
        Remove-Item -LiteralPath $part -Force
        Fail "$name has SHA-256 $got, expected $Want; nothing was installed"
    }
    Move-Item -LiteralPath $part -Destination $File -Force
}

$downloads = Join-Path $Dir 'downloads'
$models    = Join-Path $Dir 'models'
New-Item -ItemType Directory -Force -Path $downloads, $models | Out-Null

$archive = Join-Path $downloads $LlamaFile
Fetch $LlamaUrl $archive $LlamaSha256
$llama = Join-Path $Dir "llama-$LlamaTag"
if (-not (Get-ChildItem -LiteralPath $llama -Recurse -Filter 'llama-server.exe' -ErrorAction SilentlyContinue)) {
    $tmp = "$llama.tmp"
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
    Expand-Archive -LiteralPath $archive -DestinationPath $tmp
    if (-not (Get-ChildItem -LiteralPath $tmp -Recurse -Filter 'llama-server.exe')) { Fail 'the archive holds no llama-server.exe' }
    if (Test-Path -LiteralPath $llama) { Remove-Item -LiteralPath $llama -Recurse -Force }
    Move-Item -LiteralPath $tmp -Destination $llama
}
if (-not $RuntimeOnly) {
    Fetch $ModelUrl (Join-Path $models $ModelFile) $ModelSha256
}

$notice = @"
This folder holds third-party software fetched by tools\carthago-oracle-fetch.ps1.
Carthago did not write or train any of it.

llama.cpp $LlamaTag (the server in llama-$LlamaTag\)
  https://github.com/ggml-org/llama.cpp   MIT License

$ModelFile (in models\)
  https://huggingface.co/$ModelRepo at revision $ModelRevision
  Licence: $ModelLicence
See THIRD-PARTY-NOTICES.md in the Carthago repository for the full notices.
"@
Set-Content -LiteralPath (Join-Path $Dir 'THIRD-PARTY-NOTICES.txt') -Value $notice -Encoding ASCII

Write-Host ''
Write-Host "Carthago Oracle analyst runtime is ready in $Dir"
Write-Host "  llama.cpp $LlamaTag, model $ModelFile"
Write-Host "The gateway finds it there by default (or pass -oracle-runtime-dir `"$Dir`")."
