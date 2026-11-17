#!/usr/bin/env bash
# The sample game check on Linux: the Windows build of the SDK and of the sample game
# (client/examples/sample-game) under Wine, against a gateway on this machine.
#
#   1. cross-builds carthago_sentinel.dll, carthago-sample-game.exe and the harmless marker
#      library for x86_64-pc-windows-gnu, and the gateway;
#   2. runs tools/carthago-sample.ps1 with pwsh when it is installed (the script Windows
#      runs, with the game started through Wine), otherwise the same three runs by hand:
#      honest, cheat (the game loads the marker, whose hash is on the list of known cheat
#      files), and the banned player again.
#
# Wine has no TPM and no signed driver list, so this checks trust level 0 and the
# "unavailable" driver list only. The TPM handshake and a real driver list need Windows.
#
# Needs: cargo with the x86_64-pc-windows-gnu target, mingw-w64 (x86_64), wine, go.
# Uses ports 8750 and 8751.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
run="$(mktemp -d -t carthago-sample.XXXXXX)"
export WINEDEBUG=-all
fail() { printf 'FAIL: %s\n' "$*"; echo "logs in $run"; exit 1; }
step() { printf '\n=== %s\n' "$*"; }

step "build the SDK, the sample game and the marker (x86_64-pc-windows-gnu) and the gateway"
(cd "$root/client" && cargo build -q -p carthago-sentinel -p carthago-sample-game -p carthago-sample-marker --target x86_64-pc-windows-gnu)
built="${CARGO_TARGET_DIR:-$root/client/target}/x86_64-pc-windows-gnu/debug"
mkdir -p "$run/target/release" "$run/scratch/bin"
cp "$built/carthago-sample-game.exe" "$built/carthago_sentinel.dll" "$built/carthago_sample_marker.dll" "$run/target/release/"
(cd "$root/backend" && go build -o "$run/scratch/bin/carthago-gateway" ./cmd/carthago-gateway)

# The script looks for release builds without ".exe" here: a wrapper starts the game
# through Wine, naming the marker by its Wine path.
cat >"$run/target/release/carthago-sample-game" <<WRAP
#!/bin/bash
args=()
while (( \$# )); do
  if [[ \$1 == --load ]]; then args+=(--load "Z:\$2"); shift 2; else args+=("\$1"); shift; fi
done
exec wine "$run/target/release/carthago-sample-game.exe" "\${args[@]}"
WRAP
chmod +x "$run/target/release/carthago-sample-game"

if command -v pwsh >/dev/null; then
  step "tools/carthago-sample.ps1 (pwsh, the game through Wine)"
  CARGO_TARGET_DIR="$run/target" pwsh -NoLogo -NoProfile -File "$root/tools/carthago-sample.ps1" \
    -Scratch "$run/scratch" -SkipBuild -NoWindow -NoWait </dev/null | tee "$run/script.log" || true
  grep -q '^RESULT: PASS, 6 of 6 checks, trust level 0' "$run/script.log" || fail "carthago-sample.ps1 did not pass"
  echo "ok   carthago-sample.ps1 passed"
  exit 0
fi

step "pwsh is not installed: the same three runs by hand"
gw="$run/scratch/bin/carthago-gateway"
data="$run/data"
"$gw" cheats add -data "$data" -tenant demo -file "$run/target/release/carthago_sample_marker.dll" -name "sample marker (harmless)"
"$gw" -data "$data" -tls-dev-cert -client-notices -hb-interval 2s -hb-timeout 15s >"$run/gateway.log" 2>&1 &
trap 'kill %1 2>/dev/null || true' EXIT
for _ in $(seq 50); do [[ -f "$data/public-keys.json" ]] && break; sleep 0.1; done
key="$(sed -n '/server_identity/,/}/s/.*"public_key": "\(.*\)".*/\1/p' "$data/public-keys.json")"
pin="$(sed -n '/tls_spki_sha256/,/]/s/^ *"\([0-9a-f]*\)".*/\1/p' "$data/public-keys.json" | paste -sd,)"
game() { "$run/target/release/carthago-sample-game" --server-key-hex "$key" --gateway-pin "$pin" --no-window "$@"; }

code=0; game --player sample-honest --secs 8 | tee "$run/honest.log" || code=$?
[[ $code == 0 ]] && grep -q '^TRUST LEVEL 0' "$run/honest.log" && grep -q '^MATCH FINISHED' "$run/honest.log" || fail "honest run (exit $code)"
"$gw" drivers show -data "$data" -tenant demo -player sample-honest | grep '^DRIVER LIST' || fail "no driver list record"
code=0; game --player sample-cheater --secs 40 --load "$run/target/release/carthago_sample_marker.dll" | tee "$run/cheat.log" || code=$?
[[ $code == 3 ]] && grep -q '^BANNED SCREEN shown, reference CW-' "$run/cheat.log" || fail "cheat run (exit $code)"
"$gw" bans list -data "$data" -tenant demo | grep -E 'player sample-cheater .*by automatic +rule known_cheat +active' || fail "no known_cheat ban"
code=0; game --player sample-cheater --secs 5 | tee "$run/again.log" || code=$?
[[ $code == 3 ]] && ! grep -q 'match started' "$run/again.log" || fail "the banned player was not refused (exit $code)"
echo "ok   honest, cheat and again passed"
