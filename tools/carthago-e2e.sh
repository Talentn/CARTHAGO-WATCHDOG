#!/usr/bin/env bash
# Phase 1 end-to-end check on Linux: gateway + detection pipeline + dashboard, driven by
# synthetic traffic only (no game, no Windows, no TPM).
#
#   1. carthago-sim opens 8 client sessions through the real handshake and heartbeats synthetic
#      telemetry: clean, TPM-claimed, allowlisted overlay, mocked integrity findings, a fast
#      QPC, and mostly injected input;
#   2. gs-stub simulate streams a synthetic match for those sessions through the game-server
#      SDK, with anomaly profiles on three slots;
#   3. the script checks every expected rule fired, that clean and overlay-only players were
#      not flagged, and that the dashboard serves the result behind its login;
#   4. telemetry v2: carthago-sim writes two 30-minute matches on the carthago-yard test map
#      (a competitive shooter on slots 9-18, an extraction raid on slots 19-28), each with one
#      "informed" player whose behaviour the simulator derives from true enemy positions and
#      nine honest ones, including noisy honest play (prefiring common angles, tracking
#      footsteps, following team spots). gs-stub replays them through the SDK's v2 API, the
#      second by map reference only, and the script checks the information_leak rule flags
#      the informed slots, stays quiet on every honest one, never kicks, and that the
#      dashboard explains the flag.
#
# Usage: tools/carthago-e2e.sh [--skip-build]
# Uses ports 18750 (gateway) and 18751 (dashboard); takes about two minutes (the time-source
# rule needs a minute of samples).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
run="$(mktemp -d -t carthago-e2e.XXXXXX)"
bin="$run/bin"
mkdir -p "$bin"
gw_port=18750
dash_port=18751
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
step() { printf '\n=== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; echo "logs in $run"; exit 1; }

if [[ "${1:-}" != "--skip-build" ]]; then
  step "build carthago gateway, carthago-sim, gs-stub"
  (cd "$root/backend" && go build -o "$bin/carthago-gateway" ./cmd/carthago-gateway && go build -o "$bin/carthago-sim" ./cmd/carthago-sim)
  (cd "$root/client" && cargo build -q -p gs-stub)
fi
gs_stub="${CARGO_TARGET_DIR:-$root/client/target}/debug/gs-stub"
[[ -x "$bin/carthago-gateway" ]] || { (cd "$root/backend" && go build -o "$bin/carthago-gateway" ./cmd/carthago-gateway && go build -o "$bin/carthago-sim" ./cmd/carthago-sim); }

step "start gateway (SQLite in $run/data) with the dashboard"
"$bin/carthago-gateway" -data "$run/data" -listen "127.0.0.1:$gw_port" -dashboard-listen "127.0.0.1:$dash_port" \
  -hb-interval 2s -hb-timeout 15s >"$run/gateway.log" 2>&1 &
pids+=($!)
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$gw_port/healthz" >/dev/null && break; sleep 0.1; done
curl -sf "http://127.0.0.1:$gw_port/healthz" >/dev/null || fail "gateway did not start"

v2_shooter="legit,informed,prefire,sound,teamcall,legit,legit,prefire,sound,teamcall"
v2_extraction="informed,legit,sound,prefire,teamcall,legit,legit,sound,prefire,teamcall"
step "carthago-sim: telemetry v2 scenarios (shooter slots 9-18, extraction slots 19-28)"
"$bin/carthago-sim" -scenario-out "$run/shooter.scn" -mode shooter -roles "$v2_shooter" -first-slot 9 -match e2e-v2-shooter -seed 11
"$bin/carthago-sim" -scenario-out "$run/extraction.scn" -mode extraction -roles "$v2_extraction" -first-slot 19 -match e2e-v2-extraction -seed 12

step "carthago-sim: 28 sessions with synthetic telemetry (70 s)"
"$bin/carthago-sim" -gateway "ws://127.0.0.1:$gw_port/v1/client" -keys "$run/data/public-keys.json" \
  -profiles "clean,tpm,overlay,integrity,clock,input,clean,tpm,$v2_shooter,$v2_extraction" \
  -duration 70s -sessions-out "$run/sessions.txt" >"$run/sim.log" 2>&1 &
sim=$!
pids+=($sim)
for _ in $(seq 100); do [[ -s "$run/sessions.txt" ]] && break; sleep 0.1; done
[[ -s "$run/sessions.txt" ]] || fail "no sessions (see sim.log)"
cat "$run/sessions.txt"

step "gs-stub simulate: synthetic match with anomaly profiles on slots 2, 7 and 8"
"$gs_stub" simulate --ingest "ws://127.0.0.1:$gw_port/v1/ingest" --sessions "$run/sessions.txt" --match e2e-match \
  --seconds 180 --anomaly 2=snap+headshot --anomaly 7=fast --anomaly 8=cmdrate+regular | tee "$run/gs.log"

step "gs-stub simulate --scenario: telemetry v2 shooter match (uploads the map geometry)"
"$gs_stub" simulate --scenario "$run/shooter.scn" --ingest "ws://127.0.0.1:$gw_port/v1/ingest" --sessions "$run/sessions.txt" \
  >"$run/gs-shooter.log" 2>&1 || { cat "$run/gs-shooter.log"; fail "shooter replay was not acknowledged cleanly"; }
tail -1 "$run/gs-shooter.log"

step "gs-stub simulate --scenario: telemetry v2 extraction raid (map by reference only)"
"$gs_stub" simulate --scenario "$run/extraction.scn" --map-ref-only --ingest "ws://127.0.0.1:$gw_port/v1/ingest" --sessions "$run/sessions.txt" \
  >"$run/gs-extraction.log" 2>&1 || { cat "$run/gs-extraction.log"; fail "extraction replay was not acknowledged cleanly"; }
tail -1 "$run/gs-extraction.log"

step "wait for the simulated clients to finish"
wait "$sim" || fail "carthago-sim failed (see sim.log)"

step "check detections"
expect=(code_patch unbacked_exec injected_input time_source_divergence angle_snap headshot_rate time_to_damage command_rate macro_interval)
for r in "${expect[@]}"; do
  grep -q "rule=$r " "$run/gateway.log" || fail "rule $r did not fire"
  echo "ok   $r"
done
grep -q 'rule=overlay_window severity=info' "$run/gateway.log" || fail "allowlisted overlay was not recorded as info"
echo "ok   overlay_window recorded as info"

step "check the dashboard"
jar="$run/cookies"
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$dash_port/players")
[[ "$code" == 303 ]] || fail "dashboard served /players without a login ($code)"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$jar" -H 'Sec-Fetch-Site: same-origin' \
  -d 'tenant=demo&key=wrong' "http://127.0.0.1:$dash_port/login")
[[ "$code" == 401 ]] || fail "wrong dashboard key accepted ($code)"
curl -s -o /dev/null -c "$jar" -b "$jar" -H 'Sec-Fetch-Site: same-origin' -d 'tenant=demo&key=demo-dashboard-key' "http://127.0.0.1:$dash_port/login"
curl -sf -b "$jar" "http://127.0.0.1:$dash_port/players" >"$run/players.html" || fail "flagged players page"
curl -sf -b "$jar" "http://127.0.0.1:$dash_port/" | grep -q 'Carthago <b>Watchdog</b>' || fail "overview page"
player() { awk -v s="$1" '$1==s {print $3}' "$run/sessions.txt"; }
for s in 2 4 5 6 7 8; do
  grep -q "/players/$(player $s)" "$run/players.html" || fail "slot $s ($(player $s)) not flagged"
done
for s in 1 3; do
  ! grep -q "/players/$(player $s)" "$run/players.html" || fail "slot $s ($(player $s)) flagged without cause"
done
echo "ok   flagged: slots 2 4 5 6 7 8; not flagged: clean slot 1, overlay-only slot 3"

step "check telemetry v2 information-leak scoring"
session() { awk -v s="$1" '$1==s {print $2}' "$run/sessions.txt"; }
for s in 10 19; do
  grep -q "player=$(player $s) rule=information_leak " "$run/gateway.log" || fail "informed slot $s ($(player $s)) not flagged for information_leak"
  grep -q "/players/$(player $s)" "$run/players.html" || fail "informed slot $s not listed as flagged"
  page=$(curl -sf -b "$jar" "http://127.0.0.1:$dash_port/sessions/$(session $s)") || fail "session page for slot $s"
  for want in 'Gameplay (telemetry v2)' 'Information leak · slot' 'never triggers an automatic kick' 'class="rp-wall"' 'Moments'; do
    grep -qF "$want" <<<"$page" || fail "session page for informed slot $s lacks: $want"
  done
  echo "ok   informed slot $s flagged, explained on its session page"
done
for s in 9 11 12 13 14 15 16 17 18 20 21 22 23 24 25 26 27 28; do
  ! grep "msg=detection " "$run/gateway.log" | grep -q "player=$(player $s) " || fail "honest v2 slot $s ($(player $s)) has evidence: $(grep "msg=detection " "$run/gateway.log" | grep "player=$(player $s) " | head -1)"
  ! grep -q "/players/$(player $s)" "$run/players.html" || fail "honest v2 slot $s flagged"
  page=$(curl -sf -b "$jar" "http://127.0.0.1:$dash_port/sessions/$(session $s)") || fail "session page for slot $s"
  grep -qF 'clear · z' <<<"$page" || fail "honest v2 slot $s not scored as clear"
done
echo "ok   honest v2 slots 9 11-18 20-28 (legit, prefire, sound, teamcall) scored and clear"
! grep -q 'kick.*information_leak\|integrity_violation: information_leak' "$run/gateway.log" || fail "an information_leak flag kicked someone"
echo "ok   information_leak never kicks"

printf '\nPASS (logs in %s)\n' "$run"
