#!/usr/bin/env bash
# Carthago Oracle end-to-end check on Linux: a real gateway with the Oracle switched on,
# driven by synthetic traffic only (no game, no Windows, no TPM, no network).
#
#   1. carthago-oracle trains a small bundle on synthetic sessions into the gateway's data
#      directory (or uses the one given with --bundle);
#   2. the gateway starts with that bundle and the deterministic stub analyst;
#   3. carthago-sim opens 18 client sessions (clean, attested, overlay, tampered, fast clock,
#      injected input, and a ten-player shooter lobby with one informed player) and gs-stub
#      streams their matches;
#   4. the script checks that every session got a score, that flagged sessions got an analyst
#      opinion citing stored evidence once they had ended, that nobody was kicked, that a
#      reviewer label can be set only with the form's token and ends up in the export, and
#      that nothing the Oracle keeps secret (model, features, thresholds, prompts, case
#      files) is served by the dashboard, sent to a client or written to the default log.
#
# Usage: tools/carthago-oracle-check.sh [--skip-build] [--bundle DIR] [--local [RUNTIME_DIR]]
#   --local   use the local language model instead of the stub (fetch it first with
#             tools/carthago-oracle-fetch.sh); slower, and the verdicts are then the model's
# Uses ports 18760 (gateway) and 18761 (dashboard); takes about three minutes.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
run="$(mktemp -d -t carthago-oracle.XXXXXX)"
bin="$run/bin"
mkdir -p "$bin"
gw_port=18760
dash_port=18761
skip_build=0
bundle=""
analyst="stub"
runtime_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build) skip_build=1; shift ;;
    --bundle) bundle="$2"; shift 2 ;;
    --local) analyst="local"; shift; if [[ $# -gt 0 && "$1" != --* ]]; then runtime_dir="$1"; shift; fi ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
step() { printf '\n=== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; echo "logs in $run"; exit 1; }

step "build gateway, carthago-sim, carthago-oracle, gs-stub"
(cd "$root/backend" && go build -o "$bin/carthago-gateway" ./cmd/carthago-gateway && go build -o "$bin/carthago-sim" ./cmd/carthago-sim \
  && go build -o "$bin/carthago-oracle" ./cmd/carthago-oracle)
if [[ "$skip_build" == 0 ]]; then (cd "$root/client" && cargo build -q -p gs-stub); fi
gs_stub="${CARGO_TARGET_DIR:-$root/client/target}/debug/gs-stub"
[[ -x "$gs_stub" ]] || fail "gs-stub is not built (run without --skip-build)"

mkdir -p "$run/data"
if [[ -n "$bundle" ]]; then
  step "use the bundle in $bundle"
  cp -r "$bundle" "$run/data/oracle"
else
  step "train a small bundle on synthetic sessions (seed 7)"
  "$bin/carthago-oracle" train -matches 60 -min-seconds 300 -max-seconds 420 -seed 7 -out "$run/data/oracle" >"$run/train.log" 2>&1 || { tail -5 "$run/train.log"; fail "training failed"; }
  sed -n '1,2p;/^AUC/p' "$run/train.log"
fi
chmod 700 "$run/data/oracle"
"$bin/carthago-oracle" info -bundle "$run/data/oracle" >"$run/bundle.json" || fail "the bundle does not load"
bundle_id=$(sed -n 's/.*"bundle_id": "\(cb-[0-9a-f]*\)".*/\1/p' "$run/bundle.json" | head -1)
review=$(sed -n 's/.*"review": \([0-9.]*\).*/\1/p' "$run/bundle.json" | head -1)
[[ -n "$bundle_id" && -n "$review" ]] || fail "could not read the bundle"
echo "bundle $bundle_id"

step "start the gateway with the Oracle ($analyst analyst, review after a session has been silent for 10 s)"
extra=()
if [[ "$analyst" == "local" && -n "$runtime_dir" ]]; then extra+=(-oracle-runtime-dir "$runtime_dir"); fi
"$bin/carthago-gateway" -data "$run/data" -listen "127.0.0.1:$gw_port" -dashboard-listen "127.0.0.1:$dash_port" \
  -hb-interval 2s -hb-timeout 15s -oracle-analyst "$analyst" -oracle-ended-after 10s "${extra[@]}" >"$run/gateway.log" 2>&1 &
gw=$!
pids+=($gw)
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$gw_port/healthz" >/dev/null && break; sleep 0.1; done
curl -sf "http://127.0.0.1:$gw_port/healthz" >/dev/null || fail "gateway did not start"
grep -q "msg=\"Carthago Oracle ready\" bundle=$bundle_id .*analyst=$analyst" "$run/gateway.log" || { grep -i oracle "$run/gateway.log"; fail "no Oracle health line for bundle $bundle_id with the $analyst analyst"; }
grep "Carthago Oracle ready" "$run/gateway.log" | sed 's/^.*msg=/  /'

shooter="legit,informed,prefire,sound,teamcall,legit,legit,prefire,sound,teamcall"
"$bin/carthago-sim" -scenario-out "$run/shooter.scn" -mode shooter -roles "$shooter" -first-slot 9 -match check-shooter -seed 11

step "carthago-sim: 18 sessions with synthetic telemetry (70 s)"
"$bin/carthago-sim" -gateway "ws://127.0.0.1:$gw_port/v1/client" -keys "$run/data/public-keys.json" \
  -profiles "clean,tpm,overlay,integrity,clock,input,clean,tpm,$shooter" \
  -duration 70s -sessions-out "$run/sessions.txt" >"$run/sim.log" 2>&1 &
sim=$!
pids+=($sim)
for _ in $(seq 100); do [[ -s "$run/sessions.txt" ]] && break; sleep 0.1; done
[[ -s "$run/sessions.txt" ]] || fail "no sessions (see sim.log)"

step "gs-stub: a synthetic match with anomalies on slots 2, 7 and 8, and the shooter lobby"
"$gs_stub" simulate --ingest "ws://127.0.0.1:$gw_port/v1/ingest" --sessions "$run/sessions.txt" --match check-match \
  --seconds 180 --anomaly 2=snap+headshot --anomaly 7=fast --anomaly 8=cmdrate+regular >"$run/gs.log" 2>&1 || { cat "$run/gs.log"; fail "match replay failed"; }
"$gs_stub" simulate --scenario "$run/shooter.scn" --ingest "ws://127.0.0.1:$gw_port/v1/ingest" --sessions "$run/sessions.txt" \
  >"$run/gs-shooter.log" 2>&1 || { cat "$run/gs-shooter.log"; fail "shooter replay failed"; }

jar="$run/cookies"
curl -s -o /dev/null -c "$jar" -b "$jar" -H 'Sec-Fetch-Site: same-origin' -d 'tenant=demo&key=demo-dashboard-key' "http://127.0.0.1:$dash_port/login"
session() { awk -v s="$1" '$1==s {print $2}' "$run/sessions.txt"; }
player() { awk -v s="$1" '$1==s {print $3}' "$run/sessions.txt"; }
page() { curl -sf -b "$jar" "http://127.0.0.1:$dash_port/sessions/$(session "$1")"; }

step "while the sessions are live: scored, and no analyst opinion yet"
sleep 20
live=$(page 4) || fail "session page for slot 4"
grep -qF '<h2>Carthago Oracle</h2>' <<<"$live" || fail "no Oracle card on the session page"
grep -qF 'class="oscore"' <<<"$live" || fail "the tampered session (slot 4) has no score while live"
! grep -qF 'class="lead olead"' <<<"$live" || fail "the analyst reviewed a session that is still connected"
grep -qF 'The analyst reviews a session after it has ended.' <<<"$live" || fail "the live session does not say why it has no opinion yet"
echo "ok   slot 4 is scored while connected; its review waits for the session to end"

step "wait for the simulated clients to finish, then for the analyst"
wait "$sim" || fail "carthago-sim failed (see sim.log)"
deadline=$((SECONDS + 90))
[[ "$analyst" == "local" ]] && deadline=$((SECONDS + 900))
flagged=(2 4 5 7 8 10)
while :; do
  missing=""
  for s in "${flagged[@]}"; do
    p=$(page "$s") || fail "session page for slot $s"
    grep -qE 'class="lead olead"|No opinion:' <<<"$p" || missing="$missing $s"
  done
  [[ -z "$missing" ]] && break
  [[ $SECONDS -lt $deadline ]] || fail "no analyst opinion for slots$missing"
  sleep 3
done

step "check scores and opinions"
for s in $(awk '{print $1}' "$run/sessions.txt"); do
  p=$(page "$s") || fail "session page for slot $s"
  grep -qF 'class="oscore"' <<<"$p" || fail "slot $s has no Oracle score"
done
echo "ok   all $(wc -l <"$run/sessions.txt") sessions are scored"
for s in "${flagged[@]}"; do
  p=$(page "$s")
  grep -qF 'class="lead olead"' <<<"$p" || fail "slot $s: the analyst gave no opinion: $(grep -o 'No opinion:[^<]*' <<<"$p")"
  grep -qF 'It is advisory: it never kicks, bans or changes a player' <<<"$p" || fail "slot $s: the opinion is not marked as advisory"
  kind=$(grep -o 'class="lead olead">[^<]*' <<<"$p" | sed 's/.*>//')
  cites=$(grep -o 'href="/evidence/[0-9]*">E[0-9]*' <<<"$p" | wc -l)
  echo "ok   slot $s: $kind, $cites cited evidence rows"
done
if [[ "$analyst" == "stub" ]]; then
  p=$(page 4)
  grep -qF 'class="lead olead">Client tampering' <<<"$p" || fail "slot 4 (patched code): expected a client tampering opinion"
  ev=$(grep -o 'href="/evidence/[0-9]*">E1' <<<"$p" | head -1 | grep -o '[0-9]*' | head -1)
  [[ -n "$ev" ]] || fail "slot 4: the opinion cites no stored evidence"
  grep -qE 'code_patch|unbacked_exec' <<<"$(curl -sf -b "$jar" "http://127.0.0.1:$dash_port/evidence/$ev")" || fail "slot 4: the cited evidence row is not an integrity finding"
  echo "ok   slot 4: the cited id opens the stored integrity finding"
fi
for s in 1 3; do
  p=$(page "$s")
  ! grep -qF 'tier-review' <<<"$p" || fail "clean slot $s is in the review band"
  grep -qF 'Not sent to the analyst' <<<"$p" || fail "clean slot $s was sent to the analyst"
done
echo "ok   clean slot 1 and overlay-only slot 3: below review, not sent to the analyst"
grep -qF '<h2>Carthago Oracle</h2>' <<<"$(curl -sf -b "$jar" "http://127.0.0.1:$dash_port/players/$(player 4)")" || fail "player page lacks the Oracle section"
echo "ok   player page lists the Oracle's view of the player's sessions"

step "check the Oracle is advisory"
# The simulated clients hang up at the end, and the gateway closes a session that stops
# sending heartbeats with reason heartbeat_timeout. Any other reason would be a kick for
# cause, and the Oracle must never produce one.
kicks() { grep 'msg="session kicked"' "$run/gateway.log" | grep -v 'reason=heartbeat_timeout' || true; }
[[ -z "$(kicks)" ]] || fail "a session was kicked for cause: $(kicks | head -1)"
! grep -q 'msg="kick' "$run/gateway.log" || fail "the gateway sent a kick"
kill -0 "$gw" 2>/dev/null || fail "the gateway is not running"
echo "ok   six sessions flagged and reviewed; no session was kicked for cause"

step "reviewer label: form token required, stored, audited, exported"
sid=$(session 4)
p=$(page 4)
grep -qF 'Suggested: <b>Confirmed cheat</b> · Client tampering' <<<"$p" || fail "no suggested label for the session with critical integrity evidence"
csrf=$(grep -o 'name="csrf" value="[0-9a-f]*"' <<<"$p" | head -1 | sed 's/.*value="//; s/"//')
[[ -n "$csrf" ]] || fail "the label form has no token"
post() { curl -s -o /dev/null -w '%{http_code}' -b "$jar" "$@" "http://127.0.0.1:$dash_port/sessions/$sid/label"; }
[[ "$(post -H 'Sec-Fetch-Site: same-origin' -d 'label=cleared')" == 403 ]] || fail "a label was accepted without the form token"
[[ "$(post -H 'Sec-Fetch-Site: cross-site' -d "csrf=$csrf&label=cleared")" == 403 ]] || fail "a cross-site label was accepted"
[[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: same-origin' -d "csrf=$csrf&label=cleared" "http://127.0.0.1:$dash_port/sessions/$sid/label")" == 303 ]] || fail "a signed-out label request was not sent to the login page"
[[ "$(post -H 'Sec-Fetch-Site: same-origin' -d "csrf=$csrf&suggested=1&label=confirmed_cheat&cheat_type=client_tampering&reviewer=check")" == 303 ]] || fail "accepting the suggested label failed"
sid2=$(session 1)
csrf2=$(grep -o 'name="csrf" value="[0-9a-f]*"' <<<"$(page 1)" | head -1 | sed 's/.*value="//; s/"//')
[[ "$(curl -s -o /dev/null -w '%{http_code}' -b "$jar" -H 'Sec-Fetch-Site: same-origin' --data-urlencode "note=cheat off, own test" -d "csrf=$csrf2&label=cleared&reviewer=check" "http://127.0.0.1:$dash_port/sessions/$sid2/label")" == 303 ]] || fail "labelling the clean session failed"
p=$(page 4)
grep -qF 'class="mark lbl-confirmed_cheat">Confirmed cheat' <<<"$p" || fail "the label is not shown"
grep -qF 'Accepted suggestion' <<<"$p" || fail "the label's history is not shown"
[[ -z "$(kicks)" ]] || fail "a label kicked someone"
echo "ok   label needs the form token and a same-origin request; shown with its history; nobody kicked"
"$bin/carthago-oracle" export -data "$run/data" -tenant demo -out "$run/export" >"$run/export.log" 2>&1 || { cat "$run/export.log"; fail "export failed"; }
[[ "$(wc -l <"$run/export/behaviour.jsonl")" == 2 && "$(wc -l <"$run/export/analyst.jsonl")" == 2 ]] || fail "the export does not hold the two labelled sessions"
grep -q '"label":"confirmed_cheat","cheat_type":"client_tampering"' "$run/export/behaviour.jsonl" || fail "the confirmed label is not in the export"
grep -q '"label":"cleared"' "$run/export/behaviour.jsonl" || fail "the cleared label is not in the export"
for secret in "$(player 4)" "$(player 1)" "$sid" "$sid2" "own test" "check"; do
  ! grep -qF -- "$secret" "$run/export/behaviour.jsonl" "$run/export/analyst.jsonl" || fail "the export contains $secret"
done
echo "ok   export: 2 labelled sessions, pseudonymised, no reviewer text"
sed -n '1,3p' "$run/export.log"

step "check what stays secret"
secrets=("review analyst of Carthago Oracle" "Decide with these steps" "aim_snap_rate" "integrity_findings" "reaction_vs_lobby" '"case_schema"' '"thresholds"' "cited_evidence")
[[ ${#review} -ge 5 ]] && secrets+=("$review")
urls=(/ /sessions /players "/players?all=1" "/players/$(player 4)" "/sessions/$(session 4)" "/sessions/$(session 10)" "/sessions/$(session 1)" /static/app.css)
for u in "${urls[@]}"; do
  body=$(curl -sf -b "$jar" "http://127.0.0.1:$dash_port$u") || fail "GET $u"
  for sct in "${secrets[@]}"; do
    ! grep -qF -- "$sct" <<<"$body" || fail "the dashboard page $u contains: $sct"
  done
done
for u in /oracle /oracle/manifest.json /static/manifest.json /static/behaviour-model.json /static/prompts/system.txt /static/oracle/manifest.json \
  "/static/%2e%2e/oracle/manifest.json" "/sessions/$(session 4)/case" "/sessions/$(session 4)/features" /manifest.json /behaviour-model.json; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -b "$jar" "http://127.0.0.1:$dash_port$u")
  [[ "$code" != 200 ]] || fail "the dashboard serves $u"
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$gw_port$u")
  [[ "$code" != 200 ]] || fail "the client gateway serves $u"
done
echo "ok   no page shows prompts, feature names, thresholds or case files; no route serves the bundle"
for sct in "${secrets[@]}" "consistent with" "P-[0-9a-f]\{10\}"; do
  ! grep -q -- "$sct" "$run/gateway.log" || fail "the gateway log (default level) contains: $sct"
done
echo "ok   the gateway log names the bundle and model ids only"
! grep -qiE 'oracle|verdict|analyst|cob-|cb-[0-9a-f]{12}' "$run/sim.log" "$run/gs.log" "$run/gs-shooter.log" || fail "a client or game server saw something of the Oracle"
echo "ok   nothing of the Oracle reached a client or the game server"

echo
echo "PASS: Carthago Oracle end-to-end ($analyst analyst). Logs in $run"
