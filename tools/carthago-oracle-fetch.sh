#!/usr/bin/env bash
# Fetches what the Carthago Oracle analyst runs on: the llama.cpp server (MIT) and one
# small open-weights language model, both pinned and checked against SHA-256 hashes.
#
# Nothing is installed system-wide and nothing is put in the repository: the files go to a
# per-user directory the gateway looks in by default,
#   ${XDG_DATA_HOME:-~/.local/share}/carthago/oracle-runtime
# Without them the gateway still runs and scores sessions; the analyst stays off and the
# gateway says so at startup.
#
# Usage: tools/carthago-oracle-fetch.sh [--dir DIR] [--runtime-only]
# Needs curl, tar and sha256sum (or shasum). Linux x86-64; on other systems build llama.cpp
# at the pinned tag yourself and put llama-server and the model under DIR as laid out below.
#
#   DIR/llama-<tag>/llama-server     the server and its libraries
#   DIR/models/<model file>          the model weights
#   DIR/THIRD-PARTY-NOTICES.txt      their licences
set -euo pipefail

# --- pinned versions (keep in step with carthago-oracle-fetch.ps1 and
# --- backend/cmd/carthago-oracle/localmodel.go) --------------------------------------
LLAMA_TAG="b12360"
LLAMA_FILE="llama-b12360-bin-ubuntu-x64.tar.gz"
LLAMA_SHA256="b60dc211e4ba206bb04bbc9eb06294364c43d0aab8fc308c44a361477466ba4c"
LLAMA_URL="https://github.com/ggml-org/llama.cpp/releases/download/$LLAMA_TAG/$LLAMA_FILE"
MODEL_REPO="Qwen/Qwen2.5-1.5B-Instruct-GGUF"
MODEL_REVISION="91cad51170dc346986eccefdc2dd33a9da36ead9"
MODEL_FILE="qwen2.5-1.5b-instruct-q4_k_m.gguf"
MODEL_SHA256="6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e"
MODEL_LICENCE="Apache-2.0"
MODEL_URL="https://huggingface.co/$MODEL_REPO/resolve/$MODEL_REVISION/$MODEL_FILE"
# --------------------------------------------------------------------------------------

root="$(cd "$(dirname "$0")/.." && pwd)"
dir="${XDG_DATA_HOME:-$HOME/.local/share}/carthago/oracle-runtime"
runtime_only=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) dir="$2"; shift 2 ;;
    --runtime-only) runtime_only=1; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
fail() { echo "carthago-oracle-fetch: $*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] || fail "this script fetches the Linux x86-64 build only; see the header for other systems"
mkdir -p "$dir"
dir="$(cd "$dir" && pwd)"
case "$dir/" in
  "$root"/*) fail "$dir is inside the repository; model files must stay out of it" ;;
esac
command -v curl >/dev/null || fail "curl is required"
if command -v sha256sum >/dev/null; then sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null; then sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else fail "sha256sum or shasum is required"; fi

# fetch URL FILE SHA256: download to FILE unless it is already there with the right hash.
# A partial download is kept as FILE.part and resumed.
fetch() {
  local url="$1" file="$2" want="$3"
  if [[ -f "$file" && "$(sha "$file")" == "$want" ]]; then
    echo "have $(basename "$file")"
    return
  fi
  echo "downloading $(basename "$file")"
  curl -fL --retry 4 --retry-delay 4 -C - -o "$file.part" "$url" || fail "download failed: $url"
  local got; got="$(sha "$file.part")"
  if [[ "$got" != "$want" ]]; then
    rm -f "$file.part"
    fail "$(basename "$file") has SHA-256 $got, expected $want; nothing was installed"
  fi
  mv "$file.part" "$file"
}

mkdir -p "$dir/downloads" "$dir/models"
chmod 700 "$dir"
fetch "$LLAMA_URL" "$dir/downloads/$LLAMA_FILE" "$LLAMA_SHA256"
if [[ ! -x "$dir/llama-$LLAMA_TAG/llama-server" ]]; then
  rm -rf "$dir/llama-$LLAMA_TAG.tmp"
  mkdir -p "$dir/llama-$LLAMA_TAG.tmp"
  tar -xzf "$dir/downloads/$LLAMA_FILE" -C "$dir/llama-$LLAMA_TAG.tmp" --strip-components=1
  [[ -x "$dir/llama-$LLAMA_TAG.tmp/llama-server" ]] || fail "the archive holds no llama-server"
  rm -rf "$dir/llama-$LLAMA_TAG"
  mv "$dir/llama-$LLAMA_TAG.tmp" "$dir/llama-$LLAMA_TAG"
fi
if [[ "$runtime_only" == 0 ]]; then
  fetch "$MODEL_URL" "$dir/models/$MODEL_FILE" "$MODEL_SHA256"
fi

cat > "$dir/THIRD-PARTY-NOTICES.txt" <<NOTICE
This directory holds third-party software fetched by tools/carthago-oracle-fetch.sh.
Carthago did not write or train any of it.

llama.cpp $LLAMA_TAG (the server in llama-$LLAMA_TAG/)
  https://github.com/ggml-org/llama.cpp   MIT License; the text is in llama-$LLAMA_TAG/

$MODEL_FILE (in models/)
  https://huggingface.co/$MODEL_REPO at revision $MODEL_REVISION
  Licence: $MODEL_LICENCE
See THIRD-PARTY-NOTICES.md in the Carthago repository for the full notices.
NOTICE

echo
echo "Carthago Oracle analyst runtime is ready in $dir"
echo "  llama.cpp $LLAMA_TAG, model $MODEL_FILE"
echo "The gateway finds it there by default (or pass -oracle-runtime-dir \"$dir\")."
