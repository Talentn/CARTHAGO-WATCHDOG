#!/usr/bin/env bash
# Checks the Carthago Oracle part of tools/carthago-cs16.ps1 on Linux, with PowerShell 7,
# Wine and the stand-in game of tools/carthago-cs16-check.sh. No real game, no download.
#
#   1. without a trained bundle the script starts the gateway without the Oracle and says
#      how to get it;
#   2. -Oracle trains a bundle on first use (here a small one, without the language model)
#      and starts the gateway with it; a second run starts at once with the same bundle;
#   3. a bundle that exists is used without the switch; -NoOracle switches it off, also
#      against CARTHAGO_ORACLE_DIR; -OracleDir and CARTHAGO_ORACLE_DIR name other folders,
#      also ones with a space in the name, and a bundle trained there has a seed of its
#      own that is written nowhere; -Uninstall leaves such a folder alone;
#   4. a real run through the companion under Wine with a debugger on the stand-in game:
#      the alert is the rules' debugger alert and nothing else, the game keeps running,
#      the session gets an Oracle score and, once the game has closed, an analyst opinion
#      (the built-in stand-in analyst), and a reviewer label can be set on it.
#
# Usage: tools/carthago-cs16-oracle-check.sh
# Needs pwsh, wine, i686-w64-mingw32-gcc, the x86_64-pc-windows-gnu Rust target, go, curl.
# Uses ports 8750 and 8751 (the script's own); takes about six minutes.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
for tool in pwsh wine i686-w64-mingw32-gcc go cargo curl; do
  command -v "$tool" >/dev/null || { echo "skip: $tool is not installed"; exit 0; }
done
run="$(mktemp -d -t carthago-cs16-oracle.XXXXXX)"
game="$run/drive/Counter-Strike WaRzOnE Edition"
scratch="$run/carthago-scratch"
dash="http://127.0.0.1:8751"
export WINEDEBUG=-all
unset LOCALAPPDATA CARTHAGO_ORACLE_DIR CARTHAGO_ORACLE_ANALYST CARTHAGO_ORACLE_REVIEW_LIVE
# No language model on this machine, wherever the gateway would look for one.
export CARTHAGO_ORACLE_RUNTIME_DIR="$run/no-runtime"
pids=()
if [[ -z "${DISPLAY:-}" ]] && command -v Xvfb >/dev/null; then
  Xvfb :97 -screen 0 1280x720x24 >/dev/null 2>&1 &
  pids+=($!)
  export DISPLAY=:97
  sleep 1
fi
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  pkill -f "$scratch/bin/carthago-gateway" 2>/dev/null || true
}
trap cleanup EXIT
step() { printf '\n=== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; echo "logs in $run"; exit 1; }

step "build: stand-in game (i686), gateway, carthago-oracle, companion (windows-gnu)"
mkdir -p "$game/cstrike/dlls" "$run/bin" "$scratch/bin" "$run/target/release"
i686-w64-mingw32-gcc -O1 -o "$game/cstrike.exe" "$root/client/cs16/fakegame/fake_hl.c"
i686-w64-mingw32-gcc -shared -o "$game/hw.dll" "$root/client/cs16/fakegame/fake_dll.c"
i686-w64-mingw32-gcc -shared -o "$game/cstrike/dlls/mp.dll" "$root/client/cs16/fakegame/fake_dll.c"
i686-w64-mingw32-gcc -O1 -o "$run/bin/fake_debugger.exe" "$root/client/cs16/fakegame/fake_debugger.c"
printf 'game "Counter-Strike"\r\ngamedll "dlls\\mp.dll"\r\n' >"$game/cstrike/liblist.gam"
(cd "$root/backend" && go build -o "$scratch/bin/carthago-gateway" ./cmd/carthago-gateway && go build -o "$scratch/bin/carthago-oracle" ./cmd/carthago-oracle)
(cd "$root/client" && cargo build -q -p carthago-cs16-companion --target x86_64-pc-windows-gnu)
companion="${CARGO_TARGET_DIR:-$root/client/target}/x86_64-pc-windows-gnu/debug/carthago-cs16.exe"
cat >"$run/target/release/carthago-cs16" <<WRAP
#!/bin/bash
args=()
while (( \$# )); do
  if [[ \$1 == --exe ]]; then args+=(--exe "Z:\$2"); shift 2; else args+=("\$1"); shift; fi
done
exec wine "$companion" "\${args[@]}"
WRAP
chmod +x "$run/target/release/carthago-cs16"
ps1() { CARGO_TARGET_DIR="$run/target" pwsh -NoLogo -NoProfile -File "$root/tools/carthago-cs16.ps1" -Scratch "$scratch" -SkipBuild -NoBrowser -NoTpm "$@"; }
# The newest gateway log of the script.
gwlog() { ls -t "$scratch"/logs/*/gateway.log | head -1; }
bundle="$scratch/oracle-bundle"
bundle_id() { sed -n 's/.*"bundle_id": *"\(cb-[0-9a-f]*\)".*/\1/p' "$1/manifest.json" | head -1; }

step "no bundle, no switch: the gateway runs without the Oracle and the script says how to get it"
ps1 -DashboardOnly </dev/null >"$run/a.log" 2>&1 || { cat "$run/a.log"; fail "the script failed without a bundle"; }
grep -F 'Carthago Oracle: off (no trained bundle in' "$run/a.log" | grep -qF 'add -Oracle' || { cat "$run/a.log"; fail "no hint about -Oracle"; }
grep -q 'msg="Carthago Oracle off: no bundle"' "$(gwlog)" || fail "the gateway did not report the Oracle as off"
[[ ! -e "$bundle" ]] || fail "a bundle folder was made without -Oracle"
echo "ok   Oracle off, with the hint; nothing was trained"

step "-Oracle and -NoOracle together are refused"
! ps1 -DashboardOnly -Oracle -NoOracle </dev/null >"$run/both.log" 2>&1 || fail "-Oracle -NoOracle was accepted"
grep -q 'exclude each other' "$run/both.log" || fail "no message for -Oracle -NoOracle"
echo "ok"

step "-Oracle, first use: trains a bundle (a small one here) and starts the gateway with it"
ps1 -DashboardOnly -Oracle -OracleNoModel -OracleMatches 40 </dev/null >"$run/b.log" 2>&1 || { cat "$run/b.log"; fail "-Oracle failed"; }
grep -E 'Carthago Oracle|trained in|analyst' "$run/b.log" || true
grep -q '=== Carthago Oracle: train the behaviour model' "$run/b.log" || fail "the first run did not train"
[[ -f "$bundle/manifest.json" && ! -e "$bundle.new" ]] || fail "no bundle in $bundle after training"
first=$(bundle_id "$bundle")
[[ -n "$first" ]] || fail "the bundle has no id"
grep -qF "Carthago Oracle: on, bundle $first from $bundle" "$run/b.log" || fail "the script does not report the Oracle as on with bundle $first"
grep -q "msg=\"Carthago Oracle ready\" bundle=$first " "$(gwlog)" || fail "the gateway did not load bundle $first"
grep -q 'analyst: off. Sessions are scored; no opinion is written.' "$run/b.log" || fail "the analyst is not reported as off"
! grep -q 'download' "$run/b.log" || fail "-OracleNoModel still talks about a download"
[[ -s "$bundle-training-report.txt" ]] || fail "no training report beside the bundle"
! ls "$scratch"/logs/*/ | grep -qi 'report' || fail "the training report is in the logs folder"
echo "ok   trained once, gateway started with bundle $first, analyst off"

step "-Oracle again: no training, the same bundle"
ps1 -DashboardOnly -Oracle -OracleNoModel </dev/null >"$run/c.log" 2>&1 || { cat "$run/c.log"; fail "the second -Oracle run failed"; }
! grep -q 'train the behaviour model' "$run/c.log" || fail "the second run trained again"
[[ "$(bundle_id "$bundle")" == "$first" ]] || fail "the bundle changed"
grep -qF "Carthago Oracle: on, bundle $first" "$run/c.log" || fail "the second run is not on"
echo "ok"

step "a bundle that exists is used without the switch; -NoOracle switches it off"
ps1 -DashboardOnly </dev/null >"$run/d.log" 2>&1 || { cat "$run/d.log"; fail "run without the switch"; }
grep -qF "Carthago Oracle: on, bundle $first" "$run/d.log" || { cat "$run/d.log"; fail "an existing bundle was not used"; }
grep -q 'Run with -Oracle to download the language model' "$run/d.log" || fail "no hint about the missing language model"
CARTHAGO_ORACLE_DIR="$bundle" ps1 -DashboardOnly -NoOracle </dev/null >"$run/e.log" 2>&1 || { cat "$run/e.log"; fail "-NoOracle"; }
grep -qF 'Carthago Oracle: off (-NoOracle)' "$run/e.log" || { cat "$run/e.log"; fail "-NoOracle is not reported"; }
grep -q 'msg="Carthago Oracle off: no bundle"' "$(gwlog)" && ! grep -q 'Carthago Oracle ready' "$(gwlog)" || fail "-NoOracle did not keep the gateway's Oracle off"
echo "ok"

step "-OracleDir with a space in its name: trained there, with a seed of its own; CARTHAGO_ORACLE_DIR names it later"
other="$run/else where/my bundle"
mkdir -p "$run/empty"
ps1 -DashboardOnly -Oracle -OracleNoModel -OracleMatches 40 -OracleDir "$other" </dev/null >"$run/f.log" 2>&1 || { cat "$run/f.log"; fail "-Oracle -OracleDir"; }
second=$(bundle_id "$other")
[[ -n "$second" && -s "$other-training-report.txt" ]] || { cat "$run/f.log"; fail "no bundle was trained in '$other'"; }
[[ "$second" != "$first" ]] || fail "two trainings gave the same bundle: the seed is not random"
grep -qF "Carthago Oracle: on, bundle $second from $other" "$run/f.log" || { cat "$run/f.log"; grep -i oracle "$(gwlog)"; fail "-OracleDir was not used"; }
[[ "$(bundle_id "$bundle")" == "$first" ]] || fail "training elsewhere changed the default bundle"
CARTHAGO_ORACLE_DIR="$other" ps1 -DashboardOnly </dev/null >"$run/g.log" 2>&1 || { cat "$run/g.log"; fail "CARTHAGO_ORACLE_DIR"; }
grep -qF "Carthago Oracle: on, bundle $second from $other" "$run/g.log" || { cat "$run/g.log"; fail "CARTHAGO_ORACLE_DIR was not used"; }
CARTHAGO_ORACLE_DIR="$run/empty" ps1 -DashboardOnly -OracleDir "$other" </dev/null >"$run/h.log" 2>&1 || { cat "$run/h.log"; fail "-OracleDir against CARTHAGO_ORACLE_DIR"; }
grep -qF "Carthago Oracle: on, bundle $second from $other" "$run/h.log" || { cat "$run/h.log"; fail "-OracleDir did not win over CARTHAGO_ORACLE_DIR"; }
CARTHAGO_ORACLE_DIR="$other" ps1 -Uninstall >"$run/uninstall.log" 2>&1 || { cat "$run/uninstall.log"; fail "-Uninstall"; }
grep -qF "$other" "$run/uninstall.log" && [[ -f "$other/manifest.json" ]] || { cat "$run/uninstall.log"; fail "-Uninstall did not leave the bundle folder alone, or did not say so"; }
if grep -rqE -- '-seed|seed=' "$scratch"/logs/ "$run"/[a-h].log; then fail "a training seed was written to the output or the logs"; fi
echo "ok   bundle $second"

step "a run through the companion with a debugger on the game: the rules' alert, an Oracle score, then an opinion"
mkfifo "$run/enter"
CARTHAGO_ORACLE_ANALYST=stub ps1 -GameDir "$game" -NoPlugin -AlertSecs 3 -GameArgs:"-game cstrike -secs 40" <"$run/enter" >"$run/game.log" 2>&1 &
ps_pid=$!
exec 3>"$run/enter"
for _ in $(seq 300); do grep -q 'GAME pid=' "$run/game.log" 2>/dev/null && break; sleep 0.1; done
game_pid=$(sed -n 's/.*GAME pid=\([0-9]*\) .*/\1/p' "$run/game.log" | head -1)
[[ -n "$game_pid" ]] || { cat "$run/game.log"; fail "the game did not start"; }
wine "$run/bin/fake_debugger.exe" "$game_pid" 25 >"$run/debugger.log" 2>&1 || { cat "$run/debugger.log"; fail "the stand-in debugger could not attach"; }
for _ in $(seq 600); do grep -q 'The dashboard is still running' "$run/game.log" && break; sleep 0.1; done
grep -q 'The dashboard is still running' "$run/game.log" || { cat "$run/game.log"; fail "the run did not reach its result"; }
grep -E '^(OK|FAIL|NOTE|ALERT)|Carthago Oracle|analyst' "$run/game.log"
grep -qF "Carthago Oracle: on, bundle $first" "$run/game.log" || fail "the game run is not with the Oracle"
grep -q 'analyst: stub (CARTHAGO_ORACLE_ANALYST)' "$run/game.log" || fail "the analyst from the environment is not reported"
[[ "$(grep -c '^ALERT' "$run/game.log")" == 1 ]] || fail "expected exactly one alert"
grep -q '^ALERT the session was flagged: A debugger is attached to the game. \[category debugger, severity high, notice [0-9a-f]\{32\}\]' "$run/game.log" || fail "the alert is not the rules' debugger alert"
secs=$(sed -n 's/.*GAME exited with code 0x0 after \([0-9]*\) s.*/\1/p' "$run/game.log")
[[ -n "$secs" && "$secs" -ge 39 ]] || fail "the game should have run its 40 s, ran ${secs:-?}"
grep -q "Carthago Oracle: this session's score is on its page" "$run/game.log" || fail "the result does not point at the Oracle's score"
log=$(gwlog)
[[ "$(grep -c 'msg="enforcement notice"' "$log")" == 1 ]] && grep -q 'msg="enforcement notice" .* category=debugger severity=high' "$log" \
  || fail "the gateway should have sent one notice, for the debugger"
grep -q 'msg="notice raised by" .* rule=debugger ' "$log" || fail "the notice was not raised by the debugger rule"
! grep -qi 'kick' "$log" || fail "the gateway kicked"
sid=$(sed -n 's/.*"session_id":"\([0-9a-f]*\)".*/\1/p' "$(dirname "$log")/session.json")
[[ -n "$sid" ]] || fail "no session id"
jar="$run/cookies"
curl -s -o /dev/null -c "$jar" -b "$jar" -H 'Sec-Fetch-Site: same-origin' -d 'tenant=demo&key=demo-dashboard-key' "$dash/login"
page() { curl -sf -b "$jar" "$dash/sessions/$sid"; }
p=$(page) || fail "the session page does not open with the demo login"
grep -qF '<h2>Carthago Oracle</h2>' <<<"$p" && grep -qF 'class="oscore"' <<<"$p" || fail "the session has no Oracle score"
deadline=$((SECONDS + 60))
until grep -qF 'class="lead olead"' <<<"$p"; do
  [[ $SECONDS -lt $deadline ]] || fail "no analyst opinion after the game had closed"
  sleep 2
  p=$(page)
done
echo "ok   one alert, raised by the debugger rule; the game ran on; the session has a score and an opinion"

step "the demo login labels the session; the label is audited"
grep -qF 'Your name' <<<"$p" || fail "the demo login is not asked for a name"
csrf=$(grep -o 'name="csrf" value="[0-9a-f]*"' <<<"$p" | head -1 | sed 's/.*value="//; s/"//')
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$jar" -H 'Sec-Fetch-Site: same-origin' -d "csrf=$csrf&label=cleared&reviewer=check&note=own+test" "$dash/sessions/$sid/label")
[[ "$code" == 303 ]] || fail "the label was refused ($code)"
grep -qF 'class="mark lbl-cleared">Cleared' <<<"$(page)" || fail "the label is not shown"
[[ "$(grep -c '^ALERT' "$run/game.log")" == 1 && "$(grep -c 'msg="enforcement notice"' "$log")" == 1 ]] || fail "the opinion or the label raised an alert"
if command -v python3 >/dev/null; then
  audit=$(python3 - "$scratch/gateway-data/gateway.db" "$sid" <<'PY'
import sqlite3, sys
c = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
for row in c.execute("SELECT actor, action, target, detail FROM dashboard_audit WHERE action LIKE 'label.%'"):
    print("|".join(row))
print("schema", c.execute("PRAGMA user_version").fetchone()[0], ",".join(str(r[0]) for r in c.execute("SELECT number FROM schema_migrations ORDER BY number")))
PY
)
  grep -qxF "demo|label.set|session $sid|cleared; player cs16-local-player; demo login, name given: check" <<<"$audit" || { echo "$audit"; fail "the label is not in the audit log as the demo login's"; }
  grep -qxF "schema 5 20,21" <<<"$audit" || { echo "$audit"; fail "unexpected schema state of the script's database"; }
  echo "ok   label stored, shown and audited as the demo login's; the database is at 0005 with 0020 and 0021"
else
  echo "ok   label stored and shown (python3 not installed: the audit entry was not read)"
fi

echo >&3
exec 3>&-
wait "$ps_pid" || { tail -5 "$run/game.log"; fail "the script ended with an error"; }

echo
echo "PASS (logs in $run)"
