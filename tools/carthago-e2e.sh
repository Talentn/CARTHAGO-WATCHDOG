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
#      not flagged, and that the dashboard serves the result behind its login.
#
# Usage: tools/carthago-e2e.sh [--skip-build]
# Uses ports 18750 (gateway) and 18751 (dashboard); takes about 80 s (the time-source rule
# needs a minute of samples).
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
  (cd "$root/backend" && go build -o "$bin/carthago-gateway" ./cmd/gateway && go build -o "$bin/carthago-sim" ./cmd/carthago-sim)
  (cd "$root/client" && cargo build -q -p gs-stub)
fi
gs_stub="${CARGO_TARGET_DIR:-$root/client/target}/debug/gs-stub"
[[ -x "$bin/carthago-gateway" ]] || { (cd "$root/backend" && go build -o "$bin/carthago-gateway" ./cmd/gateway && go build -o "$bin/carthago-sim" ./cmd/carthago-sim); }

step "start gateway (SQLite in $run/data) with the dashboard"
"$bin/carthago-gateway" -data "$run/data" -listen "127.0.0.1:$gw_port" -dashboard-listen "127.0.0.1:$dash_port" \
  -hb-interval 2s -hb-timeout 15s >"$run/gateway.log" 2>&1 &
pids+=($!)
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$gw_port/healthz" >/dev/null && break; sleep 0.1; done
curl -sf "http://127.0.0.1:$gw_port/healthz" >/dev/null || fail "gateway did not start"

step "carthago-sim: 8 sessions with synthetic telemetry (70 s)"
"$bin/carthago-sim" -gateway "ws://127.0.0.1:$gw_port/v1/client" -keys "$run/data/public-keys.json" \
  -duration 70s -sessions-out "$run/sessions.txt" >"$run/sim.log" 2>&1 &
sim=$!
pids+=($sim)
for _ in $(seq 100); do [[ -s "$run/sessions.txt" ]] && break; sleep 0.1; done
[[ -s "$run/sessions.txt" ]] || fail "no sessions (see sim.log)"
cat "$run/sessions.txt"

step "gs-stub simulate: synthetic match with anomaly profiles on slots 2, 7 and 8"
"$gs_stub" simulate --ingest "ws://127.0.0.1:$gw_port/v1/ingest" --sessions "$run/sessions.txt" --match e2e-match \
  --seconds 180 --anomaly 2=snap+headshot --anomaly 7=fast --anomaly 8=cmdrate+regular | tee "$run/gs.log"

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

printf '\nPASS (logs in %s)\n' "$run"
