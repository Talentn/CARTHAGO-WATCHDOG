/*
 * Carthago Watchdog: match telemetry for Counter-Strike 1.6 (AMX Mod X 1.8.2 or newer).
 *
 * Runs on the game server (a listen server or a local HLDS) and reports what the server
 * already knows about every player and bot to a bridge on the same machine, as UDP text
 * datagrams to 127.0.0.1. It reads game state only: it changes no entity, blocks no call
 * and sends nothing to clients. Every hook returns "ignored".
 *
 * Needs the fakemeta, hamsandwich and sockets modules (loaded automatically).
 *
 * Cvars (read once, a second after the map starts):
 *   carthago_on      1      0 turns the plugin off
 *   carthago_port    27991  bridge UDP port on 127.0.0.1
 *   carthago_rate    32     samples per second (the telemetry tick rate), 16..100
 *   carthago_traces  24     line-of-sight traces per sample, at most
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
#include <fakemeta>
#include <hamsandwich>
#include <sockets>

#define PLUGIN  "Carthago Watchdog telemetry"
#define VERSION "0.1"
#define AUTHOR  "Carthago"

#define MAX_EVENTS  256
#define BUF_SIZE    1400
#define BUF_LIMIT   1200
#define INFO_EVERY  64
#define CMD_EVERY   16

#define FLAG_BOT    1
#define FLAG_HLTV   2
#define FLAG_LOCAL  4

// Pistols, bolt-action and semi-automatic rifles, shotguns: one shot per trigger press.
const SEMI_AUTO = (1<<CSW_P228)|(1<<CSW_SCOUT)|(1<<CSW_XM1014)|(1<<CSW_ELITE)|(1<<CSW_FIVESEVEN)|(1<<CSW_SG550)
	|(1<<CSW_USP)|(1<<CSW_GLOCK18)|(1<<CSW_AWP)|(1<<CSW_M3)|(1<<CSW_G3SG1)|(1<<CSW_DEAGLE)

new g_cvOn, g_cvPort, g_cvRate, g_cvTraces
new bool:g_on
new g_sock, g_rate, g_traces, g_maxplayers
new g_seq, g_tick, g_lastTick
new g_buf[BUF_SIZE], g_len
new g_match[48], g_map[32]

new g_evName[MAX_EVENTS][16]

new bool:g_in[33], g_flags[33], g_team[33], bool:g_sent[33]
new g_cmds[33], g_msec[33], g_clientMs[33], g_buttons[33]

// Shots and hits of the frame in progress, written out when the next frame starts.
new g_shots[33], g_shotEv[33], g_hitVictim[33], g_hitGroup[33], Float:g_hitDist[33]

new bool:g_los[33][33]
new g_pairA, g_pairB
new bool:g_botHam

public plugin_precache()
{
	register_forward(FM_PrecacheEvent, "fw_PrecacheEvent_Post", 1)
}

public plugin_init()
{
	register_plugin(PLUGIN, VERSION, AUTHOR)
	g_cvOn = register_cvar("carthago_on", "1")
	g_cvPort = register_cvar("carthago_port", "27991")
	g_cvRate = register_cvar("carthago_rate", "32")
	g_cvTraces = register_cvar("carthago_traces", "24")

	g_maxplayers = get_maxplayers()
	get_mapname(g_map, charsmax(g_map))
	formatex(g_match, charsmax(g_match), "cs16-%s-%d", g_map, get_systime())
	g_pairA = 1
	g_pairB = 2

	register_forward(FM_StartFrame, "fw_StartFrame")
	register_forward(FM_CmdStart, "fw_CmdStart")
	register_forward(FM_PlaybackEvent, "fw_PlaybackEvent")
	RegisterHam(Ham_TraceAttack, "player", "fw_TraceAttack")

	set_task(1.0, "task_open")
}

public task_open()
{
	if (!get_pcvar_num(g_cvOn))
		return
	g_rate = clamp(get_pcvar_num(g_cvRate), 16, 100)
	g_traces = clamp(get_pcvar_num(g_cvTraces), 0, 256)
	new err
	g_sock = socket_open("127.0.0.1", get_pcvar_num(g_cvPort), SOCKET_UDP, err)
	if (g_sock <= 0 || err) {
		log_amx("Carthago: could not open a UDP socket to 127.0.0.1:%d (error %d); telemetry is off", get_pcvar_num(g_cvPort), err)
		g_sock = 0
		return
	}
	g_on = true
	log_amx("Carthago: telemetry on, match %s, %d samples/s, 127.0.0.1:%d", g_match, g_rate, get_pcvar_num(g_cvPort))
}

public plugin_end()
{
	if (g_on) {
		put("E^n")
		flush()
		socket_close(g_sock)
		g_on = false
	}
}

public fw_PrecacheEvent_Post(type, const name[])
{
	new idx = get_orig_retval()
	if (idx <= 0 || idx >= MAX_EVENTS || !equal(name, "events/", 7))
		return FMRES_IGNORED
	// Weapon fire events only: the knife, grenades and map events are not shots.
	if (contain(name, "knife") != -1 || contain(name, "create") != -1 || contain(name, "decal") != -1 || contain(name, "vehicle") != -1)
		return FMRES_IGNORED
	copy(g_evName[idx], charsmax(g_evName[]), name[7])
	new dot = contain(g_evName[idx], ".")
	if (dot != -1)
		g_evName[idx][dot] = 0
	return FMRES_IGNORED
}

public client_putinserver(id)
{
	g_in[id] = true
	g_sent[id] = false
	g_flags[id] = 0
	g_cmds[id] = 0
	g_msec[id] = 0
	g_clientMs[id] = 0
	g_buttons[id] = 0
	g_shots[id] = 0
	g_hitVictim[id] = 0
	if (is_user_bot(id)) {
		g_flags[id] |= FLAG_BOT
		// Bots are a different entity class from human players, so the "player" hook above
		// does not cover them; hook the class of the first bot once it has spawned.
		if (!g_botHam)
			set_task(0.5, "task_bot_ham", id)
	}
	if (is_user_hltv(id))
		g_flags[id] |= FLAG_HLTV
	new ip[32]
	get_user_ip(id, ip, charsmax(ip), 1)
	if (!(g_flags[id] & FLAG_BOT) && (equal(ip, "loopback") || equal(ip, "127.", 4)))
		g_flags[id] |= FLAG_LOCAL
}

public task_bot_ham(id)
{
	if (g_botHam || !g_in[id] || !is_user_bot(id) || !pev_valid(id))
		return
	RegisterHamFromEntity(Ham_TraceAttack, id, "fw_TraceAttack")
	g_botHam = true
}

public client_disconnect(id)
{
	if (!g_in[id])
		return
	g_in[id] = false
	if (g_on) {
		new line[16]
		put(line, formatex(line, charsmax(line), "X %d^n", id))
	}
}

public fw_CmdStart(id, uc)
{
	if (!g_on || id < 1 || id > g_maxplayers || !g_in[id])
		return FMRES_IGNORED
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
	return FMRES_IGNORED
}

public fw_PlaybackEvent(flags, invoker, ev)
{
	if (!g_on || ev <= 0 || ev >= MAX_EVENTS || !g_evName[ev][0] || invoker < 1 || invoker > g_maxplayers)
		return FMRES_IGNORED
	g_shots[invoker]++
	g_shotEv[invoker] = ev
	return FMRES_IGNORED
}

public fw_TraceAttack(victim, attacker, Float:damage, Float:direction[3], tr, bits)
{
	if (!g_on || attacker < 1 || attacker > g_maxplayers || victim < 1 || victim > g_maxplayers || attacker == victim)
		return HAM_IGNORED
	// The first opponent a shot touches is its result; later pellets and wall-bangs are not.
	if (g_hitVictim[attacker] || get_user_team(attacker) == get_user_team(victim))
		return HAM_IGNORED
	new Float:a[3], Float:v[3]
	pev(attacker, pev_origin, a)
	pev(victim, pev_origin, v)
	g_hitVictim[attacker] = victim
	g_hitGroup[attacker] = get_tr2(tr, TR_iHitgroup)
	g_hitDist[attacker] = get_distance_f(a, v)
	return HAM_IGNORED
}

public fw_StartFrame()
{
	if (!g_on)
		return FMRES_IGNORED
	flush_shots()
	new tick = floatround(get_gametime() * float(g_rate), floatround_floor) + 1
	if (tick != g_lastTick) {
		g_lastTick = tick
		g_tick = tick
		sample()
	}
	flush()
	return FMRES_IGNORED
}

flush_shots()
{
	new line[96]
	for (new id = 1; id <= g_maxplayers; id++) {
		if (g_shots[id] > 0) {
			new victim = g_hitVictim[id]
			new kill = (victim && !is_user_alive(victim)) ? 1 : 0
			put(line, formatex(line, charsmax(line), "S %d %s %d %d %d %d^n", id, g_evName[g_shotEv[id]],
				victim ? victim : -1, victim ? g_hitGroup[id] : 0, kill, victim ? floatround(g_hitDist[id]) : 0))
			// A burst inside one server frame: the remaining rounds are counted as misses.
			for (new n = 1; n < g_shots[id] && n < 4; n++)
				put(line, formatex(line, charsmax(line), "S %d %s -1 0 0 0^n", id, g_evName[g_shotEv[id]]))
		}
		g_shots[id] = 0
		g_hitVictim[id] = 0
	}
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
		if ((g_tick % CMD_EVERY) == 0 && g_cmds[id] > 0) {
			put(line, formatex(line, charsmax(line), "C %d %d %d^n", id, g_cmds[id], g_msec[id]))
			g_cmds[id] = 0
			g_msec[id] = 0
		}
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
	sight()
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
	engfunc(EngFunc_TraceLine, from, to, IGNORE_MONSTERS | IGNORE_GLASS, skip, 0)
	get_tr2(0, TR_flFraction, fraction)
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
	if (g_len && g_sock > 0)
		socket_send(g_sock, g_buf, g_len)
	g_len = 0
}
