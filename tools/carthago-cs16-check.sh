#!/usr/bin/env bash
# Linux check of the Counter-Strike 1.6 kit, without the game, Windows or a TPM:
#
#   1. a 32-bit stand-in for the game (client/cs16/fakegame), in a folder laid out like the
#      WaRzOnE build (cstrike.exe and no hl.exe, next to programs that are not the game), is
#      started by the real companion
#      (carthago-cs16.exe, cross-compiled, under Wine) after a real handshake over pinned
#      TLS with a software device key;
#   2. the telemetry bridge receives a synthetic plugin stream over loopback UDP (one local
#      human, three bots, one of them machine-like) and delivers it to the gateway, with
#      the human's slot bound to the companion's session;
#   3. the script checks that the companion's findings arrive as info, that the machine-like
#      bot trips the aim rules and is labelled a bot, and that nobody is flagged;
#   4. the companion is started on a launcher instead: one that starts the game and exits,
#      one that stays, and one whose game never comes up. It must follow the first two to
#      the game process and report the third as a failure;
#   5. if pwsh is installed, tools/carthago-cs16.ps1 finds that folder by searching, takes
#      cstrike.exe as the game program, installs the plugin, and -Uninstall restores the
#      folder byte for byte;
#   6. its staged check (-Diagnose) is run against the stand-in game, which writes what the
#      plugin would write and can end at a chosen stage: the failing step must be named, the
#      working stage left installed, and a later run must use it. A player slot must be
#      reported as tied to the session only when match data says so;
#   7. the alert: a test notice, a debugger on the stand-in game, a flagged match, and
#      what the companion sees change in the started game. For the last the stand-in game
#      changes itself while it runs (loads a library from outside its folder, maps a
#      second image, rewrites an export of its own stand-in libraries, starts with a
#      renderer library in its folder): a clean start must stay silent, each change must
#      raise the alert under the right category, and what the build has always shown
#      must be held back unless -AlertOnIntegrity is given. Nothing is injected into any
#      process and no real game or system file is touched;
#   8. information-leak (wallhack) scoring: synthetic Counter-Strike matches on a map file
#      in the game's maps folder (carthago-sim -cs-stream, -cs-map) go through the bridge,
#      which reads the map's walls, to the gateway. An honest local player must stay
#      clean, one who acts on hidden enemies must be flagged for review without an alert,
#      and -AlertOnWallhackScore must turn that into an alert during the match. A map file
#      that changed since it was first seen, or that is not the map being played, must
#      switch the scoring off and say so.
#
# Needs: cargo with the x86_64-pc-windows-gnu target, mingw-w64 (i686 and x86_64), wine, go.
# Usage: tools/carthago-cs16-check.sh       (ports 28750, 28751 and UDP 27992; part 6 uses the
#        script's own 8750, 8751 and UDP 27991)
#        CARTHAGO_AMXXPC_DIR=<AMX Mod X scripting folder with a Linux amxxpc> also checks that
#        the script builds the plugin with the game's own compiler.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
run="$(mktemp -d -t carthago-cs16.XXXXXX)"
game="$run/drive/Counter-Strike WaRzOnE Edition"
gw_port=28750
dash_port=28751
udp_port=27992
export WINEDEBUG=-all
pids=()
# The alert is a window. Without a display Wine cannot open one, and only the alert's log
# lines are checked; with Xvfb installed the window itself is opened as well.
if [[ -z "${DISPLAY:-}" ]] && command -v Xvfb >/dev/null; then
  Xvfb :98 -screen 0 1280x720x24 >/dev/null 2>&1 &
  pids+=($!)
  export DISPLAY=:98
  sleep 1
fi
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
step() { printf '\n=== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; echo "logs in $run"; exit 1; }

step "build: stand-in game (i686), gateway, companion (windows-gnu), bridge"
mkdir -p "$game/cstrike/dlls" "$run/bin"
i686-w64-mingw32-gcc -O1 -o "$game/cstrike.exe" "$root/client/cs16/fakegame/fake_hl.c"
i686-w64-mingw32-gcc -shared -o "$game/hw.dll" "$root/client/cs16/fakegame/fake_dll.c"
i686-w64-mingw32-gcc -shared -o "$game/cstrike/dlls/mp.dll" "$root/client/cs16/fakegame/fake_dll.c"
i686-w64-mingw32-gcc -O1 -o "$game/launcher.exe" "$root/client/cs16/fakegame/fake_launcher.c"
i686-w64-mingw32-gcc -O1 -o "$run/bin/fake_debugger.exe" "$root/client/cs16/fakegame/fake_debugger.c"
# A library outside the game folder for the stand-in game to load late, and a stand-in for a
# renderer library that a case below puts into the game folder for the length of one run.
mkdir -p "$run/outside"
i686-w64-mingw32-gcc -shared -o "$run/outside/late.dll" "$root/client/cs16/fakegame/fake_dll.c"
i686-w64-mingw32-gcc -shared -o "$run/bin/opengl32.dll" "$root/client/cs16/fakegame/fake_dll.c"
i686-w64-mingw32-gcc -O1 -o "$run/bin/fake_holder.exe" "$root/client/cs16/fakegame/fake_holder.c" -lgdi32
# Programs that sit in the real folder and must never be taken for the game.
for other in crashpad_handler.exe hltv.exe unins000.exe; do echo "not the game" >"$game/$other"; done
printf 'game "Counter-Strike"\r\ngamedll "dlls\\mp.dll"\r\ngamedll_linux "dlls/cs_i386.so"\r\n' >"$game/cstrike/liblist.gam"
(cd "$root/backend" && go build -o "$run/bin/carthago-gateway" ./cmd/carthago-gateway && go build -o "$run/bin/carthago-sim" ./cmd/carthago-sim)
# The game's maps folder: the map the synthetic matches are played on, written as a map
# file, and a file that is not a map.
mkdir -p "$game/cstrike/maps"
"$run/bin/carthago-sim" -cs-map "$game/cstrike/maps/cs_carthago_yard.bsp"
echo "not a map" >"$game/cstrike/maps/de_broken.bsp"
(cd "$root/client" && cargo build -q -p carthago-cs16-companion --target x86_64-pc-windows-gnu && cargo build -q -p carthago-cs16-bridge)
target="${CARGO_TARGET_DIR:-$root/client/target}"
companion="$target/x86_64-pc-windows-gnu/debug/carthago-cs16.exe"
bridge="$target/debug/carthago-cs16-bridge"

step "start gateway (wss, self-signed, pinned) and dashboard"
"$run/bin/carthago-gateway" -data "$run/data" -listen "127.0.0.1:$gw_port" -dashboard-listen "127.0.0.1:$dash_port" \
  -hb-interval 3s -hb-timeout 20s -tls-dev-cert >"$run/gateway.log" 2>&1 &
pids+=($!)
for _ in $(seq 50); do curl -skf "https://127.0.0.1:$gw_port/healthz" >/dev/null && break; sleep 0.1; done
curl -skf "https://127.0.0.1:$gw_port/healthz" >/dev/null || fail "gateway did not start"

step "bridge: listen for the plugin stream"
"$bridge" synth --out "$run/synth.txt" --seconds 150 >/dev/null
"$bridge" run --keys "$run/data/public-keys.json" --listen "127.0.0.1:$udp_port" --ingest "wss://127.0.0.1:$gw_port/v1/ingest" \
  --session-file "$run/session.json" --record "$run/plugin-stream.txt" --stop-file "$run/bridge.stop" >"$run/bridge.log" 2>&1 &
bridge_pid=$!
pids+=($bridge_pid)

step "companion under Wine: handshake, start the stand-in cstrike.exe, watch it for 30 s"
(cd "$game" && wine "$companion" --keys "Z:$run/data/public-keys.json" --gateway "wss://127.0.0.1:$gw_port/v1/client" \
  --game-dir "Z:$game" --session-file "Z:$run/session.json" --no-tpm -- -game cstrike -secs 30 >"$run/companion.log" 2>&1) &
companion_pid=$!
for _ in $(seq 100); do [[ -s "$run/session.json" ]] && break; sleep 0.1; done
[[ -s "$run/session.json" ]] || { cat "$run/companion.log"; fail "the companion opened no session"; }

step "play the synthetic plugin stream over UDP (8x speed)"
"$bridge" send "$run/synth.txt" --to "127.0.0.1:$udp_port" --speed 8
wait "$companion_pid" || { cat "$run/companion.log"; fail "the companion exited with an error"; }
touch "$run/bridge.stop"
wait "$bridge_pid" || { cat "$run/bridge.log"; fail "the bridge did not deliver every batch"; }
grep -E 'SESSION|GAME|DONE' "$run/companion.log"
grep -E 'SLOT bound|RESULT' "$run/bridge.log"

step "check what the gateway recorded"
log="$run/gateway.log"
grep -q 'GAME pid=.* 32-bit watched with read-only access' "$run/companion.log" || fail "the game was not watched as a 32-bit process"
grep -q 'SLOT bound: slot 1 ' "$run/bridge.log" || fail "the local player's slot was not bound to the companion's session"
grep -q 'lost=0 .* bad_lines=0' "$run/bridge.log" || fail "the bridge lost or rejected plugin data"
grep -q 'starting .*cstrike\.exe"\? -game cstrike' "$run/companion.log" || fail "the companion did not start cstrike.exe"
for m in cstrike.exe hw.dll mp.dll; do
  grep -q "rule=module_signature severity=info summary=\"module $m (game folder): not signed\"" "$log" || fail "module $m not reported as unsigned, info"
done
echo "ok   modules of the game reported with their signature state, as info"
grep -q 'rule=external_exec_regions severity=info' "$log" || fail "executable memory summary missing"
echo "ok   unbacked executable memory summarised as info"
for r in angle_snap headshot_rate time_to_damage; do
  grep -q "player=bot:_BOT__Snap rule=$r " "$log" || fail "rule $r did not fire on the machine-like bot"
done
echo "ok   machine-like bot trips angle_snap, headshot_rate, time_to_damage"
if grep 'msg=detection ' "$log" | grep 'player=cs16-local-player ' | grep -v 'severity=info' | grep -v 'rule=scanner_stalled'; then
  fail "the human player has evidence above info"
fi
echo "ok   the human player has nothing above info"
! grep -q 'msg=detection .*player=bot:_BOT__\(Calm\|Mate\) ' "$log" || fail "an ordinary bot has evidence"
! grep -qi 'kick' "$log" || fail "something was kicked"
! grep -q 'ALERT' "$run/companion.log" || fail "an alert was raised although the gateway runs without -client-notices"
! grep -q 'msg="enforcement notice"' "$log" || fail "the gateway issued a notice without -client-notices"
echo "ok   no notice and no alert unless the gateway is started with -client-notices"

step "synthetic Counter-Strike matches through the bridge and the gateway's scorer (go test)"
(cd "$root/backend" && CARTHAGO_CS16_BRIDGE="$bridge" go test -count=1 -run 'TestCSMatchesThroughTheBridge' ./internal/knowledge/synth) || fail "the scorer's check through the bridge failed"
pin=$("$bridge" map-hash "$game/cstrike/maps/cs_carthago_yard.bsp" | tail -1)
[[ "$pin" =~ ^cs_carthago_yard\ [0-9a-f]{64}$ ]] || fail "map-hash printed no pin line: $pin"
pins=$("$bridge" map-pins --maps "$run/nowhere" --maps "$game/cstrike/maps")
grep -qxF "$pin" <<<"$pins" || fail "map-pins and map-hash disagree: $pins"
grep -q '^# de_broken: not usable: ' <<<"$pins" || fail "map-pins did not list the file that is not a map"
echo "ok   the map file's pin line is the same from map-hash and map-pins; a file that is not a map is skipped"

if [[ -n "${DISPLAY:-}" ]]; then
  step "companion --test-alert: the alert screen as a preview (3 s)"
  wine "$companion" --test-alert --alert-secs 3 >"$run/preview.log" 2>&1 || { cat "$run/preview.log"; fail "--test-alert failed"; }
  grep -q 'ALERT preview: closed' "$run/preview.log" || fail "--test-alert did not show and close the screen"
  echo "ok   the alert screen opens and closes by itself"
else
  echo "skip the alert window itself (no display; install Xvfb to check it)"
fi

# The companion started on a launcher. $1 names the case, the rest are game arguments.
launcher_case() {
  local name="$1" code=0
  shift
  (cd "$game" && wine "$companion" --keys "Z:$run/data/public-keys.json" --gateway "wss://127.0.0.1:$gw_port/v1/client" \
    --exe "Z:$game/launcher.exe" --player "cs16-launcher-$name" --no-tpm -- -game cstrike "$@" >"$run/companion-$name.log" 2>&1) || code=$?
  return "$code"
}
step "companion started on a launcher that starts the game and exits, then on one that stays"
for name in exits stays; do
  extra=()
  [[ $name == stays ]] && extra=(-launcher-stay)
  launcher_case "$name" -secs 12 "${extra[@]}" || { cat "$run/companion-$name.log"; fail "launcher that $name: the companion exited with an error"; }
  clog="$run/companion-$name.log"
  grep -E 'started by|GAME exited' "$clog"
  grep -q 'GAME pid=[0-9]* 32-bit (cstrike.exe, hw.dll loaded) was started by pid=[0-9]*; now watching it' "$clog" || fail "launcher that $name: the game process was not found"
  secs=$(sed -n 's/.*GAME exited with code 0x0 after \([0-9]*\) s.*/\1/p' "$clog")
  [[ -n "$secs" && "$secs" -ge 11 ]] || fail "launcher that $name: the watch ended after ${secs:-?} s, before the game did"
  grep -q "player=cs16-launcher-$name .*summary=\"module cstrike.exe (game folder): not signed\"" "$log" || fail "launcher that $name: the game's modules were not reported"
done
echo "ok   a launcher is followed to the game process, whether it exits or stays"

step "companion started on a launcher whose game never comes up (takes 20 s)"
code=0
launcher_case nothing -launcher-nothing || code=$?
grep -E 'looking for|no game process' "$run/companion-nothing.log" || true
[[ $code == 5 ]] || { cat "$run/companion-nothing.log"; fail "a launcher without a game should end with exit code 5, got $code"; }
echo "ok   a program that ends without a game process is reported as a failure, not as a finished game"

jar="$run/cookies"
curl -s -o /dev/null -c "$jar" -b "$jar" -H 'Sec-Fetch-Site: same-origin' -d 'tenant=demo&key=demo-dashboard-key' "http://127.0.0.1:$dash_port/login"
players=$(curl -sf -b "$jar" "http://127.0.0.1:$dash_port/players") || fail "flagged players page"
! grep -q '/players/bot:' <<<"$players" || fail "a bot is listed as a flagged player"
grep -q 'This is a bot slot' <(curl -sf -b "$jar" "http://127.0.0.1:$dash_port/players/bot:_BOT__Snap") || fail "bot page does not say it is a bot"
sid=$(grep -o '"session_id":"[0-9a-f]*"' "$run/session.json" | cut -d'"' -f4)
page=$(curl -sf -b "$jar" "http://127.0.0.1:$dash_port/sessions/$sid") || fail "session page"
for want in 'Gameplay (telemetry v2)' 'cs16-synth' 'module_signature'; do
  grep -qF "$want" <<<"$page" || fail "session page lacks: $want"
done
echo "ok   dashboard: bot labelled and not flagged; the session shows the match and the modules"

if command -v pwsh >/dev/null; then
  step "carthago-cs16.ps1: find the game by searching, install the plugin, then -Uninstall"
  mkdir -p "$game/cstrike/addons/metamod/dlls" "$game/cstrike/addons/amxmodx/dlls" "$game/cstrike/addons/amxmodx/modules"
  for f in addons/amxmodx/dlls/amxmodx_mm.dll addons/amxmodx/modules/fakemeta_amxx.dll \
           addons/amxmodx/modules/hamsandwich_amxx.dll addons/amxmodx/modules/sockets_amxx.dll; do
    echo stand-in >"$game/cstrike/$f"
  done
  # A loadable stand-in: with FAKE_CS16_ADDONS=1 the game has a server add-on in its process.
  i686-w64-mingw32-gcc -shared -o "$game/cstrike/addons/metamod/dlls/metamod.dll" "$root/client/cs16/fakegame/fake_dll.c"
  cp -a "$game" "$run/game.before"
  ps1() { pwsh -NoLogo -NoProfile -File "$root/tools/carthago-cs16.ps1" -Scratch "$run/carthago-scratch" "$@"; }
  ps1 -SearchRoot "$run/drive" -InstallOnly >"$run/install.log" 2>&1 || { cat "$run/install.log"; fail "install"; }
  grep -qF "game folder : $game" "$run/install.log" || { cat "$run/install.log"; fail "the search did not find the game folder"; }
  grep -q 'game program: cstrike\.exe ' "$run/install.log" || { cat "$run/install.log"; fail "the script did not choose cstrike.exe"; }
  echo "ok   the search finds the folder and takes cstrike.exe as the game program"
  for bad in crashpad_handler.exe hltv.exe unins000.exe; do
    ! ps1 -GameDir "$game" -GameExe "$bad" -NoPlugin -InstallOnly >"$run/gameexe.log" 2>&1 || fail "-GameExe $bad was accepted"
  done
  ps1 -GameDir "$game" -GameExe launcher.exe -NoPlugin -InstallOnly >"$run/gameexe.log" 2>&1 \
    && grep -q 'game program: launcher\.exe ' "$run/gameexe.log" || { cat "$run/gameexe.log"; fail "-GameExe launcher.exe was not accepted"; }
  echo "ok   -GameExe names another program; the crash reporter, hltv and the uninstaller are refused"
  amx="$game/cstrike/addons/amxmodx"
  grep -q '^gamedll "addons\\metamod\\dlls\\metamod.dll"' "$game/cstrike/liblist.gam" || fail "liblist.gam does not load Metamod"
  grep -q '^win32 addons\\amxmodx\\dlls\\amxmodx_mm.dll' "$game/cstrike/addons/metamod/plugins.ini" || fail "Metamod does not load AMX Mod X"
  cmp -s "$root/client/cs16/plugin/carthago_cs16_stage4.amxx" "$amx/plugins/carthago_cs16.amxx" || fail "plugin not installed"
  ps1 -GameDir "$game" -Stage 2 -InstallOnly >"$run/install2.log" 2>&1 || { cat "$run/install2.log"; fail "install of stage 2"; }
  cmp -s "$root/client/cs16/plugin/carthago_cs16_stage2.amxx" "$amx/plugins/carthago_cs16.amxx" || fail "-Stage 2 did not install the stage 2 plugin"
  ps1 -Uninstall >"$run/uninstall.log" 2>&1 || { cat "$run/uninstall.log"; fail "uninstall"; }
  diff -r "$run/game.before" "$game" || fail "the game folder differs after -Uninstall"
  echo "ok   install is reversible: the game folder is identical after -Uninstall"

  # The whole script, with the stand-in game writing what the plugin would write. The script
  # looks for release builds; point it at the debug builds made above (the companion through
  # Wine) and at the gateway built above.
  mkdir -p "$run/target/release" "$run/carthago-scratch/bin"
  # Wine takes Linux paths, but the companion compares the game's path with the paths of
  # its modules, which Wine reports as Z:\ paths: name the game program the same way.
  cat >"$run/target/release/carthago-cs16" <<WRAP
#!/bin/bash
args=()
while (( \$# )); do
  if [[ \$1 == --exe ]]; then args+=(--exe "Z:\$2"); shift 2; else args+=("\$1"); shift; fi
done
exec wine "$companion" "\${args[@]}"
WRAP
  chmod +x "$run/target/release/carthago-cs16"
  cp "$bridge" "$run/target/release/carthago-cs16-bridge"
  cp "$run/bin/carthago-gateway" "$run/carthago-scratch/bin/carthago-gateway"
  full() { CARGO_TARGET_DIR="$run/target" ps1 -GameDir "$game" -SkipBuild -NoBrowser -NoTpm "$@" </dev/null; }

  step "carthago-cs16.ps1 -Diagnose: a game that cannot even load the plugin (two short runs)"
  code=0
  FAKE_CS16_CRASH_STAGE=1 full -Diagnose -DiagnoseSecs 2 >"$run/diagnose1.log" 2>&1 || code=$?
  grep -E '^(PASS|FAIL|NOTE)|plugin cannot run' "$run/diagnose1.log" || true
  [[ $code == 20 ]] || { cat "$run/diagnose1.log"; fail "-Diagnose should end with 20 when stage 1 fails, got $code"; }
  grep -q 'trying once more with the plugin listed in configs.plugins.ini' "$run/diagnose1.log" || fail "-Diagnose did not retry with plugins.ini"
  diff -r "$run/game.before" "$game" || fail "a failed -Diagnose left changes in the game folder"
  [[ "$(cat "$run/carthago-scratch/plugin-stage.txt")" == 0 ]] || fail "the failed stage was not remembered"
  echo "ok   stage 1 fails: reported, the plugin is removed again, and later runs go without it"

  step "carthago-cs16.ps1 -Diagnose: a game that ends when user commands are hooked, and reads plugins.ini only"
  # With the game's own compiler in place (a wrapper around a Linux amxxpc, if one is given).
  if [[ -n "${CARTHAGO_AMXXPC_DIR:-}" && -x "$CARTHAGO_AMXXPC_DIR/amxxpc" ]]; then
    mkdir -p "$amx/scripting"
    cp -r "$CARTHAGO_AMXXPC_DIR/include" "$amx/scripting/include"
    printf '#!/bin/sh\ncd "%s" && exec ./amxxpc "$@"\n' "$CARTHAGO_AMXXPC_DIR" >"$amx/scripting/amxxpc.exe"
    chmod +x "$amx/scripting/amxxpc.exe"
    rm -rf "$run/game.before" && cp -a "$game" "$run/game.before"
  fi
  code=0
  FAKE_CS16_CRASH_STAGE=3 FAKE_CS16_IGNORE_EXTRA_INI=1 full -Diagnose -DiagnoseSecs 2 >"$run/diagnose3.log" 2>&1 || code=$?
  grep -E '^(PASS|FAIL|NOTE)|plugin  |left installed' "$run/diagnose3.log" || true
  [[ $code == 22 ]] || { cat "$run/diagnose3.log"; fail "-Diagnose should end with 22 when stage 3 fails, got $code"; }
  grep -q '^PASS  2 ' "$run/diagnose3.log" || fail "-Diagnose: stage 2 should pass"
  grep -q '^FAIL  3 .*last line: step 3 commands: hooking CmdStart' "$run/diagnose3.log" || fail "-Diagnose did not name the failing step"
  grep -q 'Exe build: ' "$run/diagnose3.log" || fail "-Diagnose did not print the version lines from the game console"
  [[ "$(cat "$run/carthago-scratch/plugin-stage.txt")" == "2 main" ]] || fail "the working stage was not remembered"
  grep -q '^carthago_cs16.amxx' "$amx/configs/plugins.ini" || fail "the plugin is not listed in plugins.ini"
  grep -q '^stage=2' "$amx/configs/carthago_cs16.ini" || fail "the working stage was not left installed"
  ls "$run"/carthago-scratch/logs/*/stage3/{plugin-steps.txt,console.log,companion.log} >/dev/null || fail "-Diagnose did not collect the logs of the failing run"
  if [[ -x "$amx/scripting/amxxpc.exe" ]]; then
    grep -q "built here with the game's own AMX Mod X compiler, stage 2" "$run/diagnose3.log" || { cat "$run/diagnose3.log"; fail "the game's compiler was not used"; }
    ! cmp -s "$root/client/cs16/plugin/carthago_cs16_stage2.amxx" "$amx/plugins/carthago_cs16.amxx" || fail "the locally built plugin was not installed"
    echo "ok   the plugin is built with the game's own compiler when it ships one"
  else
    cmp -s "$root/client/cs16/plugin/carthago_cs16_stage2.amxx" "$amx/plugins/carthago_cs16.amxx" || fail "the stage 2 plugin was not left installed"
    echo "skip building with the game's compiler (set CARTHAGO_AMXXPC_DIR to an AMX Mod X scripting folder with amxxpc)"
  fi
  echo "ok   stage 3 fails: the failing step is named and stage 2 is left installed"

  step "carthago-cs16.ps1: a run with the stage found above, first without and then with match data"
  code=0
  full -Map de_dust2 -GameArgs:"-game cstrike -secs 6" >"$run/full-nodata.log" 2>&1 || code=$?
  grep -E '^(OK|FAIL|NOTE)' "$run/full-nodata.log" || true
  [[ $code == 21 ]] || { cat "$run/full-nodata.log"; fail "a run without match data should end with 21, got $code"; }
  grep -q 'plugin stage 2 .*as found by the last -Diagnose run' "$run/full-nodata.log" || fail "the remembered stage was not used"
  ! grep -q 'your player slot was tied' "$run/full-nodata.log" || fail "a slot is reported as tied although the plugin sent nothing"
  grep -q 'maps: the walls of 1 maps were hashed and recorded in ' "$run/full-nodata.log" || fail "the first run with the plugin did not record the map files"
  grep -q 'load token=.* stage=2 ' "$run/full-nodata.log" || fail "the plugin's lines are missing from the result"
  "$bridge" synth --out "$run/synth-short.txt" --seconds 60 >/dev/null
  full -Map de_dust2 -GameArgs:"-game cstrike -secs 16" >"$run/full-data.log" 2>&1 &
  full_pid=$!
  for _ in $(seq 200); do grep -q 'GAME pid=' "$run/full-data.log" 2>/dev/null && break; sleep 0.1; done
  "$bridge" send "$run/synth-short.txt" --to 127.0.0.1:27991 --speed 12
  wait "$full_pid" || { cat "$run/full-data.log"; fail "a run with match data failed"; }
  grep -E '^(OK|FAIL|NOTE)' "$run/full-data.log"
  grep -q '^OK    match data reached the gateway' "$run/full-data.log" || fail "match data did not reach the gateway"
  grep -q "^OK    your player slot was tied to the companion's session" "$run/full-data.log" || fail "the player's slot was not tied to the session"
  echo "ok   the slot is reported as tied only when the plugin reported the player"
  for f in full-nodata full-data; do
    grep -q '^OK    no alert: the gateway did not flag this session' "$run/$f.log" || fail "$f: the result does not say that no alert was raised"
  done
  echo "ok   an ordinary run raises no alert, and the result says so"

  step "carthago-cs16.ps1 -NoPlugin -TestAlertAfter: a test notice over the running game, alert only"
  rm -rf "$run/game.mid" && cp -a "$game" "$run/game.mid"
  full -NoPlugin -TestAlertAfter 4 -AlertSecs 3 -GameArgs:"-game cstrike -secs 14" >"$run/full-testalert.log" 2>&1 || { cat "$run/full-testalert.log"; fail "the run with a test alert failed"; }
  grep -E '^(OK|FAIL|NOTE|ALERT)|ALERT|END MATCH' "$run/full-testalert.log"
  grep -q '^ALERT (test) Test of the alert screen. Nothing was detected.' "$run/full-testalert.log" || fail "the test alert is missing from the result"
  grep -q 'ALERT notice=[0-9a-f]\{32\} category=test severity=notice test=true' "$run/full-testalert.log" || fail "the companion did not log the test notice"
  secs=$(sed -n 's/.*GAME exited with code 0x0 after \([0-9]*\) s.*/\1/p' "$run/full-testalert.log")
  [[ -n "$secs" && "$secs" -ge 13 ]] || fail "alert only: the game should have run its 14 s, ran ${secs:-?}"
  ! grep -q 'END MATCH' "$run/full-testalert.log" || fail "the game was closed although -EndMatchOnDetect was not given"
  diff -r "$run/game.mid" "$game" || fail "-NoPlugin changed the game folder"
  echo "ok   test notice: alert raised, labelled as a test, the game left running"

  step "carthago-cs16.ps1 -NoPlugin: a debugger attached to the game raises a real alert, and the game keeps running"
  full -NoPlugin -AlertSecs 3 -GameArgs:"-game cstrike -secs 50" >"$run/full-debugger.log" 2>&1 &
  full_pid=$!
  for _ in $(seq 200); do grep -q 'GAME pid=' "$run/full-debugger.log" 2>/dev/null && break; sleep 0.1; done
  game_pid=$(sed -n 's/.*GAME pid=\([0-9]*\) .*/\1/p' "$run/full-debugger.log" | head -1)
  wine "$run/bin/fake_debugger.exe" "$game_pid" 35 >"$run/debugger.log" 2>&1 || { cat "$run/debugger.log"; fail "the stand-in debugger could not attach"; }
  wait "$full_pid" || { cat "$run/full-debugger.log"; fail "the run with a debugger failed"; }
  grep -E '^(OK|FAIL|NOTE|ALERT)' "$run/full-debugger.log"
  grep -q '^ALERT the session was flagged: A debugger is attached to the game. \[category debugger, severity high, notice [0-9a-f]\{32\}\]' "$run/full-debugger.log" \
    || { cat "$run/full-debugger.log"; fail "a debugger on the game raised no alert"; }
  secs=$(sed -n 's/.*GAME exited with code 0x0 after \([0-9]*\) s.*/\1/p' "$run/full-debugger.log")
  [[ -n "$secs" && "$secs" -ge 49 ]] || fail "alert only: the game should have run its 50 s, ran ${secs:-?}"
  echo "ok   debugger on the game: a real alert without the plugin, the game left running"

  step "carthago-cs16.ps1 -EndMatchOnDetect: the local player aims like a machine; the alert is real and the game is closed"
  "$bridge" synth --out "$run/synth-machine.txt" --seconds 150 --match cs16-flagged --local-is-machine >/dev/null
  FAKE_CS16_WINDOW=1 full -Map de_dust2 -EndMatchOnDetect -AlertSecs 3 -GameArgs:"-game cstrike -secs 90" >"$run/full-flagged.log" 2>&1 &
  full_pid=$!
  for _ in $(seq 200); do grep -q 'GAME pid=' "$run/full-flagged.log" 2>/dev/null && break; sleep 0.1; done
  "$bridge" send "$run/synth-machine.txt" --to 127.0.0.1:27991 --speed 12
  wait "$full_pid" || { cat "$run/full-flagged.log"; fail "the flagged run failed"; }
  grep -E '^(OK|FAIL|NOTE|ALERT)|END MATCH' "$run/full-flagged.log"
  grep -q '^ALERT the session was flagged: Aim assistance was detected in this match. \[category aim_assistance, severity high, notice [0-9a-f]\{32\}\]' "$run/full-flagged.log" \
    || { cat "$run/full-flagged.log"; fail "the machine-like local player raised no alert"; }
  secs=$(sed -n 's/.*GAME exited with code 0x0 after \([0-9]*\) s.*/\1/p' "$run/full-flagged.log")
  [[ -n "$secs" && "$secs" -lt 60 ]] || fail "-EndMatchOnDetect: the game should have been closed early, ran ${secs:-?} s"
  if [[ -n "${DISPLAY:-}" ]]; then
    grep -q 'END MATCH asked the game (pid=[0-9]*) to close (1 window)' "$run/full-flagged.log" || fail "the game's window was not asked to close"
    grep -q 'END MATCH the game closed' "$run/full-flagged.log" || fail "the game did not close when asked"
    echo "ok   flagged session: alert raised, the game asked to close, and it closed"
  else
    grep -Eq 'END MATCH (the game closed|the game did not close within 5 s; ended the process this companion started)' "$run/full-flagged.log" || fail "the game was not ended"
    echo "ok   flagged session: alert raised, the game ended"
  fi
  ! grep -qi 'kick' "$run"/carthago-scratch/logs/*/gateway.log || fail "the gateway kicked a session"

  if [[ -n "${DISPLAY:-}" ]]; then
    step "carthago-cs16.ps1 -EndMatchOnDetect: a game that ignores the request to close"
    FAKE_CS16_WINDOW=2 full -NoPlugin -TestAlertAfter 3 -EndMatchOnDetect -AlertSecs 2 -GameArgs:"-game cstrike -secs 60" >"$run/full-hung.log" 2>&1 || { cat "$run/full-hung.log"; fail "the run with a game that ignores the request failed"; }
    grep -E 'END MATCH' "$run/full-hung.log"
    grep -q 'END MATCH the game did not close within 5 s; ended the process this companion started' "$run/full-hung.log" || fail "a game that ignores the request was not ended"
    echo "ok   a game that does not close when asked is ended, and only because the companion started it"
  fi

  visibility_alert='^ALERT the session was flagged: A visibility cheat (wallhack) was detected on this game. \[category visibility, severity high,'
  # Information-leak scoring. $1 names the case, $2 the stream, the rest are options of
  # the script. The stream is a whole match played in well under a minute.
  leak() {
    local name="$1" stream="$2"
    shift 2
    full -Map cs_carthago_yard -AlertSecs 3 -GameArgs:"-game cstrike -secs 55" "$@" >"$run/leak-$name.log" 2>&1 &
    local pid=$!
    for _ in $(seq 200); do grep -q 'GAME pid=' "$run/leak-$name.log" 2>/dev/null && break; sleep 0.1; done
    "$bridge" send "$stream" --to 127.0.0.1:27991 --speed 30 >/dev/null
    wait "$pid" || { cat "$run/leak-$name.log"; fail "information-leak case $name: the run failed"; }
    grep -E '^(OK|FAIL|NOTE|ALERT|FLAG)|^ +(evidence|raised by) |four-minute stretches were|at the gateway' "$run/leak-$name.log" | cut -c1-250
    grep -q '^OK    match data reached the gateway' "$run/leak-$name.log" || fail "information-leak case $name: match data did not reach the gateway"
  }
  lhas() { grep -q -- "$2" "$run/leak-$1.log" || { cat "$run/leak-$1.log"; fail "information-leak case $1: missing: $2"; }; }
  lhasnt() { ! grep -q -- "$2" "$run/leak-$1.log" || { cat "$run/leak-$1.log"; fail "information-leak case $1: unexpected: $2"; }; }
  leak_log() { echo "$(ls -d "$run"/carthago-scratch/logs/*/ | tail -1)gateway.log"; }
  others="legit,prefire,sound,teamcall,legit,subtle,legit,sound,prefire"
  # The gateway takes a match id once, so every run gets a match of its own.
  "$run/bin/carthago-sim" -cs-stream "$run/cs-honest.txt" -roles "legit,$others" -match cs-honest -match-seconds 1200 -seed 13
  for id in review alert; do
    "$run/bin/carthago-sim" -cs-stream "$run/cs-$id.txt" -roles "informed,$others" -match "cs-$id" -match-seconds 1200 -seed 13
  done
  for id in changed wrongmap; do
    "$run/bin/carthago-sim" -cs-stream "$run/cs-$id.txt" -roles "informed,$others" -match "cs-$id" -match-seconds 150 -seed 13
  done

  step "information leak: an honest player on the map from the game's maps folder, with -AlertOnWallhackScore"
  leak honest "$run/cs-honest.txt" -AlertOnWallhackScore
  lhas honest 'maps: 1 recorded in '
  lhas honest '^OK    map cs_carthago_yard: walls read from .*cs_carthago_yard.bsp'
  lhas honest 'map cs_carthago_yard at the gateway: geometry [0-9a-f]\{64\}, the one recorded when this script first saw the map file, read by the game server from a map file with SHA-256 [0-9a-f]\{64\}'
  lhas honest 'MAP check for cs_carthago_yard: [0-9]* of [0-9]* player positions were inside walls (0\.[0-9]* %)$'
  lhas honest '^OK    information-leak score for you in match cs-honest: [-0-9.]*, not flagged (flag at 4\.5)'
  lhas honest '-AlertOnWallhackScore: 0 of [45] four-minute stretches were strong; the alert needs 2'
  lhas honest '^OK    no alert: the gateway did not flag this session'
  lhasnt honest 'information_leak_live'
  ! grep 'msg=detection ' "$(leak_log)" | grep 'player=cs16-local-player ' | grep -v 'severity=info' | grep -v 'rule=scanner_stalled' || fail "the honest player has evidence above info"
  grep -q 'msg="map pins loaded" .* maps=1 ' "$(leak_log)" || fail "the gateway was not given the map pins"
  echo "ok   honest play on a pinned map: scored, not flagged, no alert even with the opt-in"

  step "information leak: a player who acts on enemies behind walls is flagged for review, with no alert"
  leak review "$run/cs-review.txt"
  lhas review '^FLAG  information-leak score for you in match cs-review: [0-9.]*, flagged for review (flag at 4\.5)'
  lhas review '^OK    no alert: the gateway did not flag this session'
  lhas review 'The score raises no alert by default; -AlertOnWallhackScore lets it'
  lhasnt review 'information_leak_live'
  lhasnt review 'four-minute stretches were'
  grep -q 'msg=detection .*player=cs16-local-player rule=information_leak severity=\(medium\|high\) ' "$(leak_log)" || fail "no information_leak evidence for the local player"
  ! grep -q 'msg="enforcement notice"' "$(leak_log)" || fail "a review flag sent a notice"
  echo "ok   the review flag is evidence only: nothing is shown to the player"

  step "information leak: the same match with -AlertOnWallhackScore raises the alert during the match"
  leak alert "$run/cs-alert.txt" -AlertOnWallhackScore
  lhas alert "$visibility_alert"
  lhas alert 'raised by information_leak_live: Opt-in live wallhack rule: 2 of [0-9] windows of 240 s were strong'
  lhas alert 'A behaviour score, not proof'
  lhas alert '-AlertOnWallhackScore: [2-5] of [45] four-minute stretches were strong; the alert needs 2'
  lhas alert '^FLAG  information-leak score for you in match cs-alert'
  secs=$(sed -n 's/.*GAME exited with code 0x0 after \([0-9]*\) s.*/\1/p' "$run/leak-alert.log")
  [[ -n "$secs" && "$secs" -ge 54 ]] || fail "alert only: the game should have run its 55 s, ran ${secs:-?}"
  ! grep -qi 'kick' "$(leak_log)" || fail "the gateway kicked a session"
  echo "ok   with the opt-in, two strong stretches raise a visibility alert; the game is left running"

  step "information leak: a map file that changed since it was first seen, then one that is not the map being played"
  cp "$game/cstrike/maps/cs_carthago_yard.bsp" "$run/yard.bsp"
  cp "$root/client/cs16/bridge/tests/data/cs_fixture.bsp" "$game/cstrike/maps/cs_carthago_yard.bsp"
  leak changed "$run/cs-changed.txt" -AlertOnWallhackScore
  lhas changed '^NOTE  the file of map cs_carthago_yard is not the one recorded for this game folder'
  lhas changed '^NOTE  the gateway refused the walls of cs_carthago_yard: map pin: the geometry sent for cs_carthago_yard (hash [0-9a-f]*) is not the pinned one'
  lhasnt changed 'information-leak score for you'
  lhasnt changed 'no information-leak score yet'
  lhas changed '^OK    no alert: the gateway did not flag this session'
  leak wrongmap "$run/cs-wrongmap.txt" -AlertOnWallhackScore -ResetMapPins
  lhasnt wrongmap 'is not the one recorded for this game folder'
  lhas wrongmap '^NOTE  MAP check for cs_carthago_yard: .* the map file does not match the map being played'
  lhas wrongmap '^NOTE  information-leak scores withheld: the map file does not match where the players were'
  lhasnt wrongmap 'information-leak score for you'
  lhas wrongmap '^OK    no alert: the gateway did not flag this session'
  cp "$run/yard.bsp" "$game/cstrike/maps/cs_carthago_yard.bsp"
  rm "$run"/carthago-scratch/map-pins-*.txt
  echo "ok   a changed map file is refused by its pin; a map that does not fit the players' positions is not scored"

  # What the companion sees change in the started game. $1 names the case, variables for
  # the stand-in game follow up to "--", then options of the script. The picture of the
  # started game is taken early (-BaselineSecs 2) and the stand-in changes itself 22 s in.
  integ() {
    local name="$1" vars=()
    shift
    while [[ $1 != -- ]]; do vars+=("$1"); shift; done
    shift
    (
      for v in "${vars[@]}"; do export "$v"; done
      full -NoPlugin -AlertSecs 2 -BaselineSecs 2 "$@"
    ) >"$run/integ-$name.log" 2>&1 || { cat "$run/integ-$name.log"; fail "integrity case $name: the run failed"; }
    grep -E '^(OK|FAIL|NOTE|ALERT)|^ +(evidence|raised by) ' "$run/integ-$name.log" | cut -c1-230
  }
  has() { grep -q -- "$2" "$run/integ-$1.log" || { cat "$run/integ-$1.log"; fail "integrity case $1: missing: $2"; }; }
  hasnt() { ! grep -q -- "$2" "$run/integ-$1.log" || { cat "$run/integ-$1.log"; fail "integrity case $1: unexpected: $2"; }; }
  late='FAKE_CS16_LATE_AFTER=22'
  integrity_alert='^ALERT the session was flagged: The game.s code, memory or libraries were tampered with. \[category game_integrity, severity high,'

  step "integrity: a first start that is closed after a few seconds is continued by the next start"
  profile() { cat "$run"/carthago-scratch/start-profile-*.txt; }
  integ short -- -ResetStartProfile -GameArgs:"-game cstrike -secs 7"
  has short '^OK    no alert: the gateway did not flag this session'
  # Mapped code is looked for every ten seconds, so a game closed this early has usually
  # not shown it; the record says so and the next start still counts as a first one for it.
  profile | grep -q '^whole mapped' || has short 'the game was closed before the companion had looked at everything a clean start shows'
  integ continued -- -GameArgs:"-game cstrike -secs 25"
  has continued '^OK    no alert: the gateway did not flag this session'
  hasnt continued '^ \+evidence '
  profile | grep -q '^whole mapped' || fail "the second start did not complete the record of the first"
  profile | grep -q '^start mapped:' || fail "the image the stand-in maps at every start was not recorded"
  echo "ok   a start that was cut short alerts on nothing later: the next start completes the record"

  step "integrity: the first recorded start of a clean game, then a clean start with a hook that is taken out again"
  integ first -- -ResetStartProfile -GameArgs:"-game cstrike -secs 25"
  has first '^OK    no alert: the gateway did not flag this session'
  has first 'the first start of this game was recorded in '
  has first 'BASELINE taken [0-9]* s after pid=[0-9]* started, [0-9]* modules loaded (first recorded start). Engine modules the module scan has listed: hw.dll (of '
  hasnt first 'BASELINE was taken by the clock'
  # The stand-in maps an image itself at every start, as build 4554 does with its engine:
  # part of the build, named in the result, never alerted on by default.
  has first '^NOTE  no alert by default for: an image of 256 KB was mapped by hand'
  hasnt first '^ \+evidence '
  integ clean "$late" FAKE_CS16_LATE_REWRITE=hw.dll:restore -- -GameArgs:"-game cstrike -secs 45"
  has clean '^OK    no alert: the gateway did not flag this session'
  has clean 'This start is compared with the first recorded start of this game'
  hasnt clean '^ \+evidence '
  clean_log=$(ls -d "$run"/carthago-scratch/logs/*/ | tail -1)gateway.log
  grep -q 'rule=code_changed severity=info .*a jump into kernel32.dll, a Windows library' "$clean_log" || fail "the hook that was taken out again was not seen"
  [[ $(grep -c 'rule=code_changed' "$clean_log") == 1 ]] || fail "taking a hook out again was reported as a second change"
  ! grep 'msg=detection ' "$clean_log" | grep -v 'severity=info' | grep -v 'rule=scanner_stalled' || fail "a clean start has evidence above info"
  echo "ok   a clean start raises no alert and leaves nothing above info; a hook into a Windows library that is removed again is information"

  step "integrity: a library from outside the game folder loaded late, a second mapped image, and the engine hooked by that library"
  integ injected "$late" "FAKE_CS16_LATE_DLL=Z:$run/outside/late.dll" FAKE_CS16_LATE_IMAGE=1 FAKE_CS16_LATE_REWRITE=hw.dll:dll -- -GameArgs:"-game cstrike -secs 45"
  has injected "$integrity_alert"
  has injected 'evidence  foreign_module (high): module late.dll (outside the game folder): not signed; loaded [0-9]* s after the game started'
  has injected 'evidence  mapped_image (high): an image of 256 KB was mapped by hand at 0x[0-9a-f]*, outside the Windows loader (appeared after the game had finished starting)'
  has injected 'evidence  code_changed (high): code of hw.dll was rewritten at 0x[0-9a-f]* after the game had finished starting: a jump into late.dll, an unsigned file from outside the game folder, itself loaded after start'
  hasnt injected 'category visibility'
  secs=$(sed -n 's/.*GAME exited with code 0x0 after \([0-9]*\) s.*/\1/p' "$run/integ-injected.log")
  [[ -n "$secs" && "$secs" -ge 44 ]] || fail "alert only: the game should have run its 45 s, ran ${secs:-?}"
  echo "ok   late library, mapped image and hooked engine: a game-integrity alert without the plugin, each named in the result"

  step "integrity: engine code rewritten while a server add-on is loaded is held back by default"
  integ addons "$late" FAKE_CS16_ADDONS=1 FAKE_CS16_LATE_REWRITE=hw.dll:unbacked -- -GameArgs:"-game cstrike -secs 45"
  has addons '^OK    no alert: the gateway did not flag this session'
  has addons 'evidence  code_changed (high): code of hw.dll was rewritten at 0x[0-9a-f]* after the game had finished starting: a jump to 0x[0-9a-f]*, memory that no file backs'
  has addons '^NOTE  no alert by default for: code of hw.dll was rewritten'
  has addons 'why: server add-ons are loaded in this process'
  has addons '-AlertOnIntegrity raises the alert for these as well'
  echo "ok   engine hooked from unbacked memory beside server add-ons: evidence, a note, no alert"

  step "wallhack delivery: a renderer library dropped into the game folder"
  cp "$run/bin/opengl32.dll" "$game/opengl32.dll"
  integ proxy FAKE_CS16_OPENGL=1 WINEDLLOVERRIDES=opengl32=n,b -- -GameArgs:"-game cstrike -secs 30"
  has proxy "$visibility_alert"
  has proxy 'evidence  renderer_replaced (high): renderer library opengl32.dll is not the Windows one: an unsigned file of that name was loaded from outside the system directory (present at start, but not at the first recorded start of this game)'
  echo "ok   a renderer library that was not there at the first recorded start: a visibility alert"

  step "wallhack delivery: a build that has always shipped its own renderer library, and that library hooked while the game runs"
  integ shipped "$late" FAKE_CS16_OPENGL=1 WINEDLLOVERRIDES=opengl32=n,b FAKE_CS16_LATE_REWRITE=opengl32.dll:unbacked -- -AllowRendererLibrary -ResetStartProfile -GameArgs:"-game cstrike -secs 45"
  has shipped '^NOTE  no alert by default for: renderer library opengl32.dll is not the Windows one'
  has shipped 'opengl32.dll is not the Windows one: .* (present at start; this run is the first recorded start, so there is nothing to compare it with)'
  has shipped 'why: this run is the first recorded start of this game, so it has not been compared with anything'
  hasnt shipped 'as at the first recorded start'
  has shipped '^NOTE  an unsigned opengl32.dll sits in the game folder (.*opengl32.dll) and the game loaded it in place of the Windows renderer library'
  has shipped 'It is excused only because this is the first recorded run and -AllowRendererLibrary is given. Unless this game build ships that file, it is a wallhack'
  has shipped "$visibility_alert"
  has shipped 'evidence  code_changed (high): code of opengl32.dll was rewritten at 0x[0-9a-f]* after the game had finished starting: a jump to 0x[0-9a-f]*, memory that no file backs'
  hasnt shipped 'evidence  renderer_replaced'
  echo "ok   the build's own renderer library is held back; rewriting its code while the game runs is a visibility alert"

  step "wallhack delivery: -AlertOnIntegrity also alerts on what the build has always shipped"
  integ strict FAKE_CS16_OPENGL=1 WINEDLLOVERRIDES=opengl32=n,b -- -AllowRendererLibrary -AlertOnIntegrity -GameArgs:"-game cstrike -secs 30"
  has strict "$visibility_alert"
  has strict '-AlertOnIntegrity: the alert is also raised for what a modified but honest game build shows'
  hasnt strict '^NOTE  no alert by default'
  has strict 'raised by renderer_replaced: renderer library opengl32.dll is not the Windows one.*(present at start, as at the first recorded start)'
  hasnt strict 'It is excused only because this is the first recorded run'
  grep -q -- '-client-notices-strict' "$root/tools/carthago-cs16.ps1" || fail "the script does not pass the opt-in to the gateway"
  echo "ok   with the opt-in, the build's own renderer library raises the alert"

  step "wallhack delivery: without -AllowRendererLibrary an unsigned renderer library alerts in every run, recorded or not"
  integ recorded FAKE_CS16_OPENGL=1 WINEDLLOVERRIDES=opengl32=n,b -- -GameArgs:"-game cstrike -secs 30"
  has recorded "$visibility_alert"
  has recorded 'evidence  renderer_replaced (high): renderer library opengl32.dll is not the Windows one: .* (present at start, as at the first recorded start)'
  hasnt recorded '^NOTE  no alert by default for: renderer library'
  integ firstrun FAKE_CS16_OPENGL=1 WINEDLLOVERRIDES=opengl32=n,b -- -ResetStartProfile -GameArgs:"-game cstrike -secs 30"
  has firstrun "$visibility_alert"
  has firstrun 'evidence  renderer_replaced (high): renderer library opengl32.dll is not the Windows one: .* (present at start; this run is the first recorded start, so there is nothing to compare it with)'
  hasnt firstrun '^NOTE  no alert by default for: renderer library'
  hasnt firstrun 'It is excused only because'
  echo "ok   an unsigned renderer library raises the visibility alert by default, in the first recorded run and when the record lists it"
  rm "$game/opengl32.dll"
  ! grep -qi 'kick' "$run"/carthago-scratch/logs/*/gateway.log || fail "the gateway kicked a session"

  ps1 -Uninstall >"$run/uninstall2.log" 2>&1 || { cat "$run/uninstall2.log"; fail "uninstall after the staged check"; }
  diff -r "$run/game.before" "$game" || fail "the game folder differs after the staged check and -Uninstall"
  echo "ok   after -Diagnose and two runs, -Uninstall leaves the game folder identical"
else
  echo "skip the PowerShell checks (pwsh not installed)"
fi

printf '\nPASS (logs in %s)\n' "$run"
