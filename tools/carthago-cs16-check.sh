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
#      folder byte for byte.
#
# Needs: cargo with the x86_64-pc-windows-gnu target, mingw-w64 (i686 and x86_64), wine, go.
# Usage: tools/carthago-cs16-check.sh       (ports 28750, 28751 and UDP 27992)
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
run="$(mktemp -d -t carthago-cs16.XXXXXX)"
game="$run/drive/Counter-Strike WaRzOnE Edition"
gw_port=28750
dash_port=28751
udp_port=27992
export WINEDEBUG=-all
pids=()
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
# Programs that sit in the real folder and must never be taken for the game.
for other in crashpad_handler.exe hltv.exe unins000.exe; do echo "not the game" >"$game/$other"; done
printf 'game "Counter-Strike"\r\ngamedll "dlls\\mp.dll"\r\ngamedll_linux "dlls/cs_i386.so"\r\n' >"$game/cstrike/liblist.gam"
(cd "$root/backend" && go build -o "$run/bin/carthago-gateway" ./cmd/carthago-gateway)
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
grep -E 'SESSION bound|RESULT' "$run/bridge.log"

step "check what the gateway recorded"
log="$run/gateway.log"
grep -q 'GAME pid=.* 32-bit watched with read-only access' "$run/companion.log" || fail "the game was not watched as a 32-bit process"
grep -q 'SESSION bound' "$run/bridge.log" || fail "the local player's slot was not bound to the companion's session"
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
  for f in addons/metamod/dlls/metamod.dll addons/amxmodx/dlls/amxmodx_mm.dll addons/amxmodx/modules/fakemeta_amxx.dll \
           addons/amxmodx/modules/hamsandwich_amxx.dll addons/amxmodx/modules/sockets_amxx.dll; do
    echo stand-in >"$game/cstrike/$f"
  done
  cp -a "$game" "$run/game.before"
  pwsh -NoLogo -NoProfile -File "$root/tools/carthago-cs16.ps1" -SearchRoot "$run/drive" -Scratch "$run/carthago-scratch" -InstallOnly >"$run/install.log" 2>&1 || { cat "$run/install.log"; fail "install"; }
  grep -qF "game folder : $game" "$run/install.log" || { cat "$run/install.log"; fail "the search did not find the game folder"; }
  grep -q 'game program: cstrike\.exe ' "$run/install.log" || { cat "$run/install.log"; fail "the script did not choose cstrike.exe"; }
  echo "ok   the search finds the folder and takes cstrike.exe as the game program"
  for bad in crashpad_handler.exe hltv.exe unins000.exe; do
    ! pwsh -NoLogo -NoProfile -File "$root/tools/carthago-cs16.ps1" -GameDir "$game" -GameExe "$bad" -Scratch "$run/carthago-scratch" -NoPlugin -InstallOnly >"$run/gameexe.log" 2>&1 \
      || fail "-GameExe $bad was accepted"
  done
  pwsh -NoLogo -NoProfile -File "$root/tools/carthago-cs16.ps1" -GameDir "$game" -GameExe launcher.exe -Scratch "$run/carthago-scratch" -NoPlugin -InstallOnly >"$run/gameexe.log" 2>&1 \
    && grep -q 'game program: launcher\.exe ' "$run/gameexe.log" || { cat "$run/gameexe.log"; fail "-GameExe launcher.exe was not accepted"; }
  echo "ok   -GameExe names another program; the crash reporter, hltv and the uninstaller are refused"
  grep -q '^gamedll "addons\\metamod\\dlls\\metamod.dll"' "$game/cstrike/liblist.gam" || fail "liblist.gam does not load Metamod"
  grep -q '^win32 addons\\amxmodx\\dlls\\amxmodx_mm.dll' "$game/cstrike/addons/metamod/plugins.ini" || fail "Metamod does not load AMX Mod X"
  cmp -s "$root/client/cs16/plugin/carthago_cs16.amxx" "$game/cstrike/addons/amxmodx/plugins/carthago_cs16.amxx" || fail "plugin not installed"
  pwsh -NoLogo -NoProfile -File "$root/tools/carthago-cs16.ps1" -Scratch "$run/carthago-scratch" -Uninstall >"$run/uninstall.log" 2>&1 || { cat "$run/uninstall.log"; fail "uninstall"; }
  diff -r "$run/game.before" "$game" || fail "the game folder differs after -Uninstall"
  echo "ok   install is reversible: the game folder is identical after -Uninstall"
else
  echo "skip the PowerShell install check (pwsh not installed)"
fi

printf '\nPASS (logs in %s)\n' "$run"
