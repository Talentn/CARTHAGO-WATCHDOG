/*
 * Carthago Watchdog: match telemetry for Counter-Strike 1.6 (AMX Mod X 1.8 or newer).
 *
 * Runs on the game server (a listen server or a local HLDS) and reports what the server
 * already knows about every player and bot to a bridge on the same machine, as UDP text
 * datagrams to 127.0.0.1. It reads game state only: it changes no entity, blocks no call
 * and sends nothing to clients. Every hook returns "ignored".
 *
 * Built to be safe on an AMX Mod X and engine build it has never met:
 *   - nothing is hooked while the map loads. The parts are switched on one at a time, a
 *     second apart, after the map is up;
 *   - every step is written to addons/amxmodx/logs/carthago_cs16.log before it is taken and
 *     after it worked, so the last line names the step a crash happened in;
 *   - it uses the engine and game function tables only (fakemeta) and core natives. It
 *     does not use hamsandwich: virtual function offsets differ between game builds;
 *   - an old AMX Mod X, a missing module or a missing native turns it off with a log line.
 *
 * STAGE (compile-time, default 4) limits what is built in, and which modules are needed:
 *   1  loads and reports versions, nothing else         (no module)
 *   2  + UDP socket, players and positions each tick    (fakemeta, sockets)
 *   3  + user commands, line of sight                   (fakemeta, sockets)
 *   4  + shots and hits                                 (fakemeta, sockets)
 *
 * Cvars (read once, when the parts are switched on):
 *   carthago_on      1      0 turns the plugin off
 *   carthago_port    27991  bridge UDP port on 127.0.0.1
 *   carthago_rate    32     samples per second (the telemetry tick rate), 16..100
 *   carthago_traces  24     line-of-sight traces per sample, at most
 *
 * addons/amxmodx/configs/carthago_cs16.ini (optional, written by tools\carthago-cs16.ps1):
 *   token=<text>     copied into the log, so a run can find its own lines
 *   selftest=<secs>  after the parts are on, run this long, write the counters to the log
 *                    and close the game (server command "quit"). For the staged check.
 *   bots=<n>         with selftest: ask the game for this many bots (bot_quota)
 *
 * Datagram: "D <seq> <tick>" then lines, all for that tick.
 *   H <match> <map> <rate> <maxplayers> <dedicated>
 *   P <slot> <flags> <team> <name>          flags: 1 bot, 2 hltv, 4 local (same machine)
 *   X <slot>                                left the server
 *   T <slot> <yaw*100> <pitch*100> <eye x y z> <vel x y z> <flags>   flags: 1 on ground, 2 ducking
 *   C <slot> <commands> <msec>              user commands and their simulated time since the last C
 *   G <slot> <client ms>                    trigger press of a semi-automatic weapon
 *   S <slot> <weapon> <target|-1> <hitgroup> <kill> <distance>
 *   V <a> <b> <0|1>                         line of sight between two opponents changed
 *   E                                       map is ending
 * Angles are the engine's (pitch positive looking down), distances are in game units.
 */

#include <amxmodx>

#if !defined STAGE
	#define STAGE 4
#endif

#if STAGE >= 2
	#include <fakemeta>
	#include <sockets>
#endif

#define PLUGIN  "Carthago Watchdog telemetry"
#define VERSION "0.2"
#define AUTHOR  "Carthago"

#define LOGFILE     "carthago_cs16.log"
#define BUF_SIZE    1400
#define BUF_LIMIT   1200
#define INFO_EVERY  64
#define CMD_EVERY   16

#define FLAG_BOT    1
#define FLAG_HLTV   2
#define FLAG_LOCAL  4

#define STEP_SOCKET   1
#define STEP_FRAMES   2
#define STEP_COMMANDS 3
#define STEP_SIGHT    4
#define STEP_SHOTS    5
#define STEP_DONE     6

new g_cvOn, g_cvPort, g_cvRate, g_cvTraces
new bool:g_off, g_missing[96]
new g_token[40], g_selftest, g_bots
new g_maxplayers
new g_match[48], g_map[32]
new g_nFrames, g_nDatagrams, g_nCommands, g_nTraces, g_nShots, g_nHits

new bool:g_in[33], g_flags[33]

#if STAGE >= 2
new bool:g_on
new g_sock, g_rate
new g_seq, g_tick, g_lastTick
new g_buf[BUF_SIZE], g_len
new g_team[33], bool:g_sent[33]
#endif

#if STAGE < 2
	#pragma unused g_cvOn, g_cvPort, g_cvRate
#endif
#if STAGE < 3
	#pragma unused g_cvTraces
#endif

#if STAGE >= 3
new bool:g_sight, g_traces
new g_cmds[33], g_msec[33], g_clientMs[33], g_buttons[33]
new bool:g_los[33][33]
new g_pairA, g_pairB

// Pistols, bolt-action and semi-automatic rifles, shotguns: one shot per trigger press.
const SEMI_AUTO = (1<<CSW_P228)|(1<<CSW_SCOUT)|(1<<CSW_XM1014)|(1<<CSW_ELITE)|(1<<CSW_FIVESEVEN)|(1<<CSW_SG550)
	|(1<<CSW_USP)|(1<<CSW_GLOCK18)|(1<<CSW_AWP)|(1<<CSW_M3)|(1<<CSW_G3SG1)|(1<<CSW_DEAGLE)
#endif

#if STAGE >= 4
// Everything that fires bullets: not the knife, the grenades or the bomb.
const NOT_GUNS = (1<<CSW_KNIFE)|(1<<CSW_HEGRENADE)|(1<<CSW_SMOKEGRENADE)|(1<<CSW_FLASHBANG)|(1<<CSW_C4)|(1<<0)|(1<<2)|(1<<31)
new const g_weaponName[][] = {
	"none", "p228", "none", "scout", "hegrenade", "xm1014", "c4", "mac10", "aug", "smokegrenade", "elite",
	"fiveseven", "ump45", "sg550", "galil", "famas", "usp", "glock18", "awp", "mp5n", "m249", "m3", "m4a1",
	"tmp", "g3sg1", "flashbang", "deagle", "sg552", "ak47", "knife", "p90"
}
// Damage each player had taken when last looked at; a rise during a shot is that shot's hit.
new Float:g_seenDmg[33]
#endif

// ---- the step log -------------------------------------------------------------------------

mark(const fmt[], any:...)
{
	new text[220]
	vformat(text, charsmax(text), fmt, 2)
	log_to_file(LOGFILE, "%s", text)
	server_print("[Carthago] %s", text)
}

// ---- load: nothing here touches the engine ------------------------------------------------

public plugin_natives()
{
	set_module_filter("module_filter")
	set_native_filter("native_filter")
}

// A module this plugin was built to use is not loaded: load anyway and stay off.
public module_filter(const library[])
{
	if (strlen(g_missing) + strlen(library) + 2 < charsmax(g_missing))
		format(g_missing, charsmax(g_missing), "%s%s%s", g_missing, g_missing[0] ? ", " : "", library)
	return PLUGIN_HANDLED
}

public native_filter(const name[], index, trap)
{
	if (!g_off) {
		g_off = true
		if (!g_missing[0])
			copy(g_missing, charsmax(g_missing), name)
	}
	return PLUGIN_HANDLED
}

read_config()
{
	new dir[96], path[128], text[96], len, line
	get_localinfo("amxx_configsdir", dir, charsmax(dir))
	if (!dir[0])
		copy(dir, charsmax(dir), "addons/amxmodx/configs")
	formatex(path, charsmax(path), "%s/carthago_cs16.ini", dir)
	if (!file_exists(path))
		return
	while ((line = read_file(path, line, text, charsmax(text), len)) != 0) {
		trim(text)
		if (equal(text, "token=", 6))
			copy(g_token, charsmax(g_token), text[6])
		else if (equal(text, "selftest=", 9))
			g_selftest = clamp(str_to_num(text[9]), 0, 600)
		else if (equal(text, "bots=", 5))
			g_bots = clamp(str_to_num(text[5]), 0, 16)
	}
}

public plugin_init()
{
	register_plugin(PLUGIN, VERSION, AUTHOR)
	g_cvOn = register_cvar("carthago_on", "1")
	g_cvPort = register_cvar("carthago_port", "27991")
	g_cvRate = register_cvar("carthago_rate", "32")
	g_cvTraces = register_cvar("carthago_traces", "24")
	read_config()

	g_maxplayers = get_maxplayers()
	get_mapname(g_map, charsmax(g_map))
	formatex(g_match, charsmax(g_match), "cs16-%s-%d", g_map, get_systime())

	new amxx[32], metamod[48], engine[64], mod[32]
	get_amxx_verstring(amxx, charsmax(amxx))
	get_cvar_string("metamod_version", metamod, charsmax(metamod))
	get_cvar_string("sv_version", engine, charsmax(engine))
	get_modname(mod, charsmax(mod))
	mark("load token=%s plugin=%s stage=%d amxx=%s built_with=%s metamod=%s engine=%s mod=%s map=%s maxplayers=%d dedicated=%d selftest=%d",
		g_token[0] ? g_token : "-", VERSION, STAGE, amxx, AMXX_VERSION_STR, metamod[0] ? metamod : "?", engine[0] ? engine : "?",
		mod, g_map, g_maxplayers, is_dedicated_server(), g_selftest)

	// "1.8.2", "1.9.0.5294": everything this plugin uses exists from 1.8 on.
	new major = str_to_num(amxx), minor, dot = contain(amxx, ".")
	if (dot != -1)
		minor = str_to_num(amxx[dot + 1])
	if (major < 1 || (major == 1 && minor < 8)) {
		mark("off: AMX Mod X %s is older than 1.8", amxx)
		g_off = true
	} else if (g_missing[0] || g_off) {
		mark("off: not available in this AMX Mod X: %s (are the fakemeta and sockets modules enabled in configs/modules.ini?)", g_missing)
		g_off = true
	} else if (!equal(mod, "cstrike")) {
		mark("off: the game is %s, not cstrike", mod)
		g_off = true
	}
	if (g_token[0])
		set_task(1.5, "task_report")
	if (g_off) {
		// A staged check still has to end: there is nothing to wait for.
		if (g_selftest)
			set_task(8.0, "task_selftest_end")
		return
	}
	set_task(3.0, "task_step", STEP_SOCKET)
}

// Version and module lists into the console (and its log, when the game runs with -condebug).
public task_report()
{
	server_cmd("version")
	server_cmd("meta list")
	server_cmd("amxx modules")
	server_cmd("amxx plugins")
}

// Switches the parts on one at a time. The line before a step and the line after it bracket
// whatever that step does to the game.
public task_step(step)
{
	if (g_off)
		return
	switch (step) {
#if STAGE >= 2
		case STEP_SOCKET: {
			if (!get_pcvar_num(g_cvOn)) {
				mark("off: carthago_on is 0")
				g_off = true
				return
			}
			g_rate = clamp(get_pcvar_num(g_cvRate), 16, 100)
			new port = get_pcvar_num(g_cvPort), err
			mark("step 1 socket: opening UDP 127.0.0.1:%d", port)
			g_sock = socket_open("127.0.0.1", port, SOCKET_UDP, err)
			if (g_sock <= 0 || err) {
				mark("off: could not open the UDP socket (error %d)", err)
				g_sock = 0
				g_off = true
				return
			}
			mark("step 1 socket: ok")
		}
		case STEP_FRAMES: {
			mark("step 2 positions: hooking StartFrame, %d samples/s, match %s", g_rate, g_match)
			g_on = true
			register_forward(FM_StartFrame, "fw_StartFrame")
			mark("step 2 positions: ok")
		}
#endif
#if STAGE >= 3
		case STEP_COMMANDS: {
			mark("step 3 commands: hooking CmdStart")
			register_forward(FM_CmdStart, "fw_CmdStart")
			mark("step 3 commands: ok")
		}
		case STEP_SIGHT: {
			g_traces = clamp(get_pcvar_num(g_cvTraces), 0, 256)
			mark("step 4 sight: world traces on, at most %d per sample", g_traces)
			g_pairA = 1
			g_pairB = 2
			g_sight = true
		}
#endif
#if STAGE >= 4
		case STEP_SHOTS: {
			mark("step 5 shots: hooking PlaybackEvent and PlayerPreThink")
			register_forward(FM_PlayerPreThink, "fw_PlayerPreThink_Post", 1)
			register_forward(FM_PlaybackEvent, "fw_PlaybackEvent")
			mark("step 5 shots: ok")
		}
#endif
		default: {
			mark("all parts of stage %d are on", STAGE)
			if (g_selftest) {
				if (g_bots && STAGE >= 2) {
					mark("selftest: asking the game for %d bots (bot_quota)", g_bots)
					server_cmd("bot_join_after_player 0")
					server_cmd("bot_quota %d", g_bots)
				}
				set_task(float(g_selftest), "task_selftest_end")
			}
			return
		}
	}
	new next = step + 1
	if ((STAGE < 2) || (STAGE < 3 && next >= STEP_COMMANDS) || (STAGE < 4 && next >= STEP_SHOTS))
		next = STEP_DONE
	set_task(1.0, "task_step", next)
}

counters(text[], len)
{
	new players, bots
	for (new id = 1; id <= g_maxplayers; id++) {
		if (g_in[id]) {
			if (g_flags[id] & FLAG_BOT)
				bots++
			else
				players++
		}
	}
	formatex(text, len, "frames=%d datagrams=%d commands=%d traces=%d shots=%d hits=%d players=%d bots=%d",
		g_nFrames, g_nDatagrams, g_nCommands, g_nTraces, g_nShots, g_nHits, players, bots)
}

public task_selftest_end()
{
	new text[160]
	counters(text, charsmax(text))
	if (g_off)
		mark("selftest ended: the plugin is off; %s", text)
	else
		mark("selftest passed: stage %d ran %d s; %s", STAGE, g_selftest, text)
	mark("selftest: closing the game")
	server_cmd("quit")
}

public plugin_end()
{
	new text[160]
	counters(text, charsmax(text))
	mark("unload: the map ended or the game closed; %s", text)
#if STAGE >= 2
	if (g_on) {
		put("E^n")
		flush()
		g_on = false
	}
	if (g_sock > 0) {
		socket_close(g_sock)
		g_sock = 0
	}
#endif
}

// ---- players ------------------------------------------------------------------------------

public client_putinserver(id)
{
	if (id < 1 || id > 32)
		return
	g_in[id] = true
	g_flags[id] = 0
	if (is_user_bot(id))
		g_flags[id] |= FLAG_BOT
	if (is_user_hltv(id))
		g_flags[id] |= FLAG_HLTV
	new ip[32]
	get_user_ip(id, ip, charsmax(ip), 1)
	if (!(g_flags[id] & FLAG_BOT) && (equal(ip, "loopback") || equal(ip, "127.", 4)))
		g_flags[id] |= FLAG_LOCAL
#if STAGE >= 2
	g_sent[id] = false
#endif
#if STAGE >= 3
	g_cmds[id] = 0
	g_msec[id] = 0
	g_clientMs[id] = 0
	g_buttons[id] = 0
#endif
#if STAGE >= 4
	g_seenDmg[id] = 0.0
#endif
}

public client_disconnect(id)
{
	if (id < 1 || id > 32 || !g_in[id])
		return
	g_in[id] = false
#if STAGE >= 2
	if (g_on) {
		new line[16]
		put(line, formatex(line, charsmax(line), "X %d^n", id))
	}
#endif
}

// ---- stage 2: positions -------------------------------------------------------------------

#if STAGE >= 2
public fw_StartFrame()
{
	if (!g_on)
		return FMRES_IGNORED
	new tick = floatround(get_gametime() * float(g_rate), floatround_floor) + 1
	if (tick != g_lastTick) {
		g_lastTick = tick
		g_tick = tick
		if (!g_nFrames)
			mark("first sample: begin")
		sample()
		if (!g_nFrames++)
			mark("first sample: ok")
	}
	flush()
	return FMRES_IGNORED
}

sample()
{
	new line[128]
	new bool:info = (g_tick % INFO_EVERY) == 0
	if (info || g_seq == 0)
		put(line, formatex(line, charsmax(line), "H %s %s %d %d %d^n", g_match, g_map, g_rate, g_maxplayers, is_dedicated_server()))

	new Float:ang[3], Float:org[3], Float:ofs[3], Float:vel[3], name[32]
	for (new id = 1; id <= g_maxplayers; id++) {
		if (!g_in[id] || !is_user_connected(id))
			continue
		new team = get_user_team(id)
		if (info || !g_sent[id] || team != g_team[id]) {
			g_sent[id] = true
			g_team[id] = team
			get_user_name(id, name, charsmax(name))
			put(line, formatex(line, charsmax(line), "P %d %d %d %s^n", id, g_flags[id], team, name))
		}
#if STAGE >= 3
		if ((g_tick % CMD_EVERY) == 0 && g_cmds[id] > 0) {
			put(line, formatex(line, charsmax(line), "C %d %d %d^n", id, g_cmds[id], g_msec[id]))
			g_cmds[id] = 0
			g_msec[id] = 0
		}
#endif
		if (!is_user_alive(id) || (g_flags[id] & FLAG_HLTV))
			continue
		pev(id, pev_v_angle, ang)
		pev(id, pev_origin, org)
		pev(id, pev_view_ofs, ofs)
		pev(id, pev_velocity, vel)
		new fl = pev(id, pev_flags)
		put(line, formatex(line, charsmax(line), "T %d %d %d %d %d %d %d %d %d %d^n", id,
			floatround(ang[1] * 100.0), floatround(ang[0] * 100.0),
			floatround(org[0] + ofs[0]), floatround(org[1] + ofs[1]), floatround(org[2] + ofs[2]),
			floatround(vel[0]), floatround(vel[1]), floatround(vel[2]),
			((fl & FL_ONGROUND) ? 1 : 0) | ((fl & FL_DUCKING) ? 2 : 0)))
	}
#if STAGE >= 3
	if (g_sight)
		sight()
#endif
}

put(const line[], len = -1)
{
	if (len < 0)
		len = strlen(line)
	if (g_len + len > BUF_LIMIT)
		flush()
	if (!g_len)
		g_len = formatex(g_buf, charsmax(g_buf), "D %d %d^n", g_seq++, g_tick)
	g_len += copy(g_buf[g_len], charsmax(g_buf) - g_len, line)
}

flush()
{
	if (g_len && g_sock > 0) {
		if (!g_nDatagrams)
			mark("first datagram: sending %d bytes", g_len)
		socket_send(g_sock, g_buf, g_len)
		if (!g_nDatagrams++)
			mark("first datagram: ok")
	}
	g_len = 0
}
#endif

// ---- stage 3: user commands and line of sight ---------------------------------------------

#if STAGE >= 3
public fw_CmdStart(id, uc)
{
	if (!g_on || id < 1 || id > g_maxplayers || !g_in[id])
		return FMRES_IGNORED
	if (!g_nCommands)
		mark("first user command: begin (player %d)", id)
	new msec = get_uc(uc, UC_Msec)
	g_cmds[id]++
	g_msec[id] += msec
	g_clientMs[id] += msec
	new buttons = get_uc(uc, UC_Buttons)
	if ((buttons & IN_ATTACK) && !(g_buttons[id] & IN_ATTACK) && is_user_alive(id)) {
		new weapon = get_user_weapon(id)
		if (weapon > 0 && weapon < 32 && (SEMI_AUTO & (1<<weapon))) {
			new line[32]
			put(line, formatex(line, charsmax(line), "G %d %d^n", id, g_clientMs[id]))
		}
	}
	g_buttons[id] = buttons
	if (!g_nCommands++)
		mark("first user command: ok")
	return FMRES_IGNORED
}

bool:opponents(a, b)
{
	if (!g_in[a] || !g_in[b] || !is_user_alive(a) || !is_user_alive(b))
		return false
	new ta = get_user_team(a), tb = get_user_team(b)
	return (ta == 1 && tb == 2) || (ta == 2 && tb == 1)
}

bool:clear_line(const Float:from[3], const Float:to[3], skip)
{
	new Float:fraction
	if (!g_nTraces)
		mark("first sight trace: begin")
	engfunc(EngFunc_TraceLine, from, to, IGNORE_MONSTERS | IGNORE_GLASS, skip, 0)
	get_tr2(0, TR_flFraction, fraction)
	if (!g_nTraces++)
		mark("first sight trace: ok")
	return fraction >= 1.0
}

// Walks the opponent pairs round-robin, a bounded number of world traces per sample, and
// reports a pair only when its line of sight changes. A pair is in sight when either eye
// sees the other's eyes or body centre through the world (players and glass ignored).
sight()
{
	if (g_maxplayers < 2)
		return
	new line[24], traces, pairs = g_maxplayers * (g_maxplayers - 1) / 2
	new Float:eyeA[3], Float:eyeB[3], Float:orgA[3], Float:orgB[3], Float:ofs[3]
	for (new n = 0; n < pairs && traces < g_traces; n++) {
		new a = g_pairA, b = g_pairB
		if (++g_pairB > g_maxplayers) {
			if (++g_pairA >= g_maxplayers)
				g_pairA = 1
			g_pairB = g_pairA + 1
		}
		new bool:seen = false
		if (opponents(a, b)) {
			pev(a, pev_origin, orgA)
			pev(a, pev_view_ofs, ofs)
			eyeA[0] = orgA[0] + ofs[0]
			eyeA[1] = orgA[1] + ofs[1]
			eyeA[2] = orgA[2] + ofs[2]
			pev(b, pev_origin, orgB)
			pev(b, pev_view_ofs, ofs)
			eyeB[0] = orgB[0] + ofs[0]
			eyeB[1] = orgB[1] + ofs[1]
			eyeB[2] = orgB[2] + ofs[2]
			traces++
			seen = clear_line(eyeA, eyeB, a)
			if (!seen) {
				traces++
				seen = clear_line(eyeA, orgB, a)
			}
			if (!seen) {
				traces++
				seen = clear_line(eyeB, orgA, b)
			}
		}
		if (seen != g_los[a][b]) {
			g_los[a][b] = seen
			put(line, formatex(line, charsmax(line), "V %d %d %d^n", a, b, seen ? 1 : 0))
		}
	}
}
#endif

// ---- stage 4: shots and hits --------------------------------------------------------------

#if STAGE >= 4
// The game clears a player's pending damage in its own PreThink; after it, whatever is
// left is the baseline the next shot is compared with.
public fw_PlayerPreThink_Post(id)
{
	if (g_on && id >= 1 && id <= g_maxplayers)
		pev(id, pev_dmg_take, g_seenDmg[id])
	return FMRES_IGNORED
}

// A weapon plays its fire event right after its bullets were traced and their damage was
// applied, so at this point the victim (if any) already carries the damage, the game has
// recorded who inflicted it, and AMX Mod X has recorded the hit group of the shooter's
// trace. All three are read, nothing is changed.
public fw_PlaybackEvent(flags, invoker)
{
	if (!g_on || invoker < 1 || invoker > g_maxplayers || !g_in[invoker] || !is_user_alive(invoker))
		return FMRES_IGNORED
	new weapon = get_user_weapon(invoker)
	if (weapon < 1 || weapon > 30 || (NOT_GUNS & (1<<weapon)))
		return FMRES_IGNORED
	if (!g_nShots)
		mark("first shot: begin (player %d, %s)", invoker, g_weaponName[weapon])

	new victim, group, Float:dmg, inflictorWeapon, body
	new team = get_user_team(invoker)
	for (new v = 1; v <= g_maxplayers; v++) {
		if (v == invoker || !g_in[v] || !is_user_connected(v))
			continue
		pev(v, pev_dmg_take, dmg)
		if (dmg <= g_seenDmg[v] + 0.01)
			continue
		g_seenDmg[v] = dmg
		if (victim || get_user_team(v) == team)
			continue
		if (get_user_attacker(v, inflictorWeapon, body) != invoker)
			continue
		// The first opponent a shot damages is its result; pellets and wall-bangs beyond it are not.
		victim = v
		group = body
	}

	new line[96]
	if (victim) {
		new Float:a[3], Float:b[3]
		pev(invoker, pev_origin, a)
		pev(victim, pev_origin, b)
		put(line, formatex(line, charsmax(line), "S %d %s %d %d %d %d^n", invoker, g_weaponName[weapon], victim, group,
			is_user_alive(victim) ? 0 : 1, floatround(get_distance_f(a, b))))
		if (!g_nHits++)
			mark("first hit: ok (player %d hit player %d, hit group %d)", invoker, victim, group)
	} else {
		put(line, formatex(line, charsmax(line), "S %d %s -1 0 0 0^n", invoker, g_weaponName[weapon]))
	}
	if (!g_nShots++)
		mark("first shot: ok")
	return FMRES_IGNORED
}
#endif
