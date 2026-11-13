// Package train builds the Oracle's behaviour model from synthetic telemetry and measures
// it. Nothing here runs in the gateway.
//
// The data comes from the same simulator the information-leak scorer is calibrated on
// (knowledge/synth), with behaviour profiles laid over it, and from synthetic client
// heartbeats. Every simulated match is pushed through the real pipeline with an in-memory
// store, so the features a model is trained on are computed by exactly the code that
// computes them in production.
//
// What that buys is a model that is internally consistent and reproducible. What it does
// not buy is knowledge of real players: every distribution in this file (how often an
// honest player flicks, how regular a human trigger rhythm is, which trust levels cheaters
// have) is an assumption written down by hand. The evaluation therefore says how well the
// model separates these profiles, not how it performs on a live population.
package train

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math"
	"runtime"
	"sort"
	"sync"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/knowledge/synth"
	"carthago/backend/internal/oracle"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/store"
)

// Profiles a synthetic session can have. Honest ones differ in how they play (the
// simulator's roles) and in what their PC looks like; the rest are cheating.
const (
	Honest      = "honest"
	AimBlatant  = "aim_blatant"
	AimSubtle   = "aim_subtle"
	Trigger     = "trigger"
	Info        = "info"
	InfoSubtle  = "info_subtle"
	Speed       = "speed"
	SpeedSubtle = "speed_subtle"
	Macro       = "macro"
	MacroSubtle = "macro_subtle"
	Tamper      = "tamper"
	Clock       = "clock"
	Mixed       = "mixed"
)

// CheatProfiles in the order reports list them.
var CheatProfiles = []string{AimBlatant, AimSubtle, Trigger, Info, InfoSubtle, Speed, SpeedSubtle, Macro, MacroSubtle, Tamper, Clock, Mixed}

// Truth is the analyst verdict a profile should get, for scoring verdicts.
var Truth = map[string]string{
	Honest: "none", AimBlatant: "aim_assistance", AimSubtle: "aim_assistance", Trigger: "aim_assistance",
	Info: "wallhack_information", InfoSubtle: "wallhack_information", Speed: "speed_manipulation", SpeedSubtle: "speed_manipulation",
	Macro: "input_automation", MacroSubtle: "input_automation", Tamper: "client_tampering", Clock: "speed_manipulation", Mixed: "mixed",
}

type Options struct {
	Matches int
	// MinSeconds and MaxSeconds bound a match's length; each match draws its own.
	MinSeconds, MaxSeconds int
	Seed                   uint64
	Workers                int
	// KeepEvidence keeps each row's stored evidence, for building analyst cases.
	KeepEvidence bool
	Progress     func(done, total int)
}

func (o *Options) defaults() {
	if o.Matches <= 0 {
		o.Matches = 320
	}
	if o.MinSeconds <= 0 {
		o.MinSeconds = 480
	}
	if o.MaxSeconds < o.MinSeconds {
		o.MaxSeconds = max(o.MinSeconds, 1200)
	}
	if o.Workers <= 0 {
		o.Workers = runtime.GOMAXPROCS(0)
	}
}

// Row is one synthetic session.
type Row struct {
	Match    int
	Profile  string
	Cheating bool
	// InMatch is false for a session that only sent heartbeats.
	InMatch bool
	Vector  oracle.Vector
	// RuleFlag is what the rules alone say: the session has evidence of medium severity
	// or above. Risk is the session's evidence risk as the dashboard computes it.
	RuleFlag bool
	Risk     float64
	Session  store.Session
	Evidence []store.Evidence
}

// Tenant is the tenant id synthetic sessions are recorded under.
const Tenant = "synthetic"

// rng is splitmix64: small, fast and identical on every platform.
type rng struct{ s uint64 }

func (r *rng) next() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ z>>30) * 0xbf58476d1ce4e5b9
	z = (z ^ z>>27) * 0x94d049bb133111eb
	return z ^ z>>31
}
func (r *rng) unit() float64                { return float64(r.next()>>11) / (1 << 53) }
func (r *rng) between(a, b float64) float64 { return a + (b-a)*r.unit() }
func (r *rng) intn(n int) int               { return int(r.next() % uint64(n)) }
func (r *rng) chance(p float64) bool        { return r.unit() < p }
func (r *rng) normal() float64 {
	return math.Sqrt(-2*math.Log(1-r.unit())) * math.Cos(2*math.Pi*r.unit())
}
func (r *rng) poisson(mean float64) int {
	if mean <= 0 {
		return 0
	}
	if mean > 30 {
		return max(0, int(math.Round(mean+math.Sqrt(mean)*r.normal())))
	}
	l, k, p := math.Exp(-mean), 0, 1.0
	for {
		p *= r.unit()
		if p <= l {
			return k
		}
		k++
	}
}
func (r *rng) pick(weights []float64) int {
	total := 0.0
	for _, w := range weights {
		total += w
	}
	x := r.unit() * total
	for i, w := range weights {
		if x -= w; x < 0 {
			return i
		}
	}
	return len(weights) - 1
}

// play is how a session behaves in a match.
type play struct {
	role       synth.Role
	snapsPerMn float64 // snap-and-lock movements per minute
	headshot   float64 // chance a hit is a headshot
	fastShare  float64 // share of first hits moved close to the moment the target appeared
	fastMs     [2]float64
	cmdFactor  float64 // commands per tick
	cmdJitter  float64
	presses    bool // sends semi-automatic trigger presses
	pressCV    float64
	pressMs    float64
}

// client is what a session's scanner reports.
type client struct {
	findings  []*pb.Finding
	injected  float64 // share of mouse events that were injected
	qpc       float64 // QPC rate against the kernel interrupt time
	machine   float64 // the whole machine's clock rate against the gateway's
	mitFailed uint64
	stuckJob  bool
}

type person struct {
	profile string
	inMatch bool
	mmr     int32
	trust   uint32
	play    play
	client  client
	sess    store.Session
	slot    uint32
}

var honestRoles = []synth.Role{synth.RoleLegit, synth.RoleLegit, synth.RoleLegit, synth.RoleLegit, synth.RolePrefire, synth.RoleSound, synth.RoleTeamCall}

// Shares of cheating profiles among cheaters, in CheatProfiles order.
var cheatWeights = []float64{1, 1.4, 1, 1, 1.4, 0.7, 0.8, 0.7, 0.8, 1, 0.6, 1}

func finding(code pb.FindingCode, job string, a, b uint64, detail string) *pb.Finding {
	return &pb.Finding{Job: job, Code: uint32(code), A: a, B: b, Detail: detail}
}

func expectedHeadshot(mmr int32) float64 {
	return math.Max(0.08, math.Min(0.45, 0.18+0.12*float64(mmr-1500)/1000))
}

func clamp(x, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, x)) }

// honestPlay draws an honest player's habits.
func honestPlay(r *rng, mmr int32) play {
	p := play{role: honestRoles[r.intn(len(honestRoles))], cmdFactor: 1, cmdJitter: 0.003}
	// Most players never move 35 degrees in one tick and then stop dead; a few with a
	// high sensitivity do it now and then.
	switch x := r.unit(); {
	case x < 0.85:
	case x < 0.98:
		p.snapsPerMn = r.between(0.005, 0.06)
	default:
		p.snapsPerMn = r.between(0.06, 0.2)
	}
	p.headshot = clamp(expectedHeadshot(mmr)+0.035*r.normal(), 0.03, 0.6)
	// Packet loss and client frame drops only ever lose commands.
	p.cmdFactor = 1 - math.Abs(0.004*r.normal())
	if r.chance(0.65) {
		p.presses, p.pressMs = true, r.between(110, 420)
		p.pressCV = r.between(0.16, 0.6)
		if r.chance(0.04) {
			p.pressCV = r.between(0.06, 0.16) // a very even hand
		}
	}
	return p
}

// tamperFindings are what the scanner reports about an injected or patched client.
func tamperFindings(r *rng, n int) []*pb.Finding {
	kinds := []func() *pb.Finding{
		func() *pb.Finding {
			return finding(pb.FindingCode_FINDING_CODE_UNBACKED_EXEC, "memory_region_walk", 0x1f00000+uint64(r.intn(4096))<<12,
				0x4000|uint64(pb.UnbackedFlags_UNBACKED_FLAGS_PRIVATE|pb.UnbackedFlags_UNBACKED_FLAGS_WRITABLE|pb.UnbackedFlags_UNBACKED_FLAGS_PE_SIGNATURE|pb.UnbackedFlags_UNBACKED_FLAGS_MZ_HEADER)<<48, "")
		},
		func() *pb.Finding {
			return finding(pb.FindingCode_FINDING_CODE_UNBACKED_EXEC, "memory_region_walk", 0x2a00000+uint64(r.intn(4096))<<12,
				0x2000|uint64(pb.UnbackedFlags_UNBACKED_FLAGS_PRIVATE|pb.UnbackedFlags_UNBACKED_FLAGS_MZ_HEADER)<<48, "")
		},
		func() *pb.Finding {
			return finding(pb.FindingCode_FINDING_CODE_IMAGE_NOT_IN_LOADER, "module_inventory", 0x7ff500000000+uint64(r.intn(256))<<16, 0, "module.dll")
		},
		func() *pb.Finding {
			return finding(pb.FindingCode_FINDING_CODE_THREAD_START_UNBACKED, "thread_starts", 0x1f10000+uint64(r.intn(256))<<12, 0, "")
		},
		func() *pb.Finding {
			return finding(pb.FindingCode_FINDING_CODE_API_HOOK, "api_hooks", uint64(r.intn(1<<20)), uint64(pb.WatchedApi_WATCHED_API_NTDLL_NT_QUERY_VIRTUAL_MEMORY), "")
		},
		func() *pb.Finding {
			return finding(pb.FindingCode_FINDING_CODE_CODE_PATCH, "text_integrity", 0x7ffb20001000+uint64(r.intn(4096))<<4, 0, "d3d9.dll>?")
		},
		func() *pb.Finding {
			return finding(pb.FindingCode_FINDING_CODE_MODULE_NOT_IMAGE, "module_inventory", 0x7ff510000000+uint64(r.intn(256))<<16, 0, "module.dll")
		},
		func() *pb.Finding {
			return finding(pb.FindingCode_FINDING_CODE_DEBUGGER, "debugger", uint64(pb.DebugSignal_DEBUG_SIGNAL_DEBUG_OBJECT), 0, "")
		},
	}
	var out []*pb.Finding
	for range n {
		out = append(out, kinds[r.intn(len(kinds))]())
	}
	return out
}

// honestClient draws what an honest player's PC reports: mostly nothing, often overlays
// and tools the allowlist knows, sometimes ones it does not.
func honestClient(r *rng) client {
	c := client{qpc: 1, machine: 1, injected: r.between(0, 0.01)}
	env := func() *pb.Finding {
		switch r.intn(6) {
		case 0:
			return finding(pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE, "external_handles", uint64(1000+r.intn(9000)), 0x1410, "tool.exe")
		case 1:
			return finding(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, "overlay_windows", uint64(1000+r.intn(9000)), 0x80020, "tool.exe")
		case 2:
			return finding(pb.FindingCode_FINDING_CODE_VULNERABLE_DRIVER, "drivers", 0, 0, "driver.sys")
		case 3:
			return finding(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE, "module_signatures", 0,
				uint64(pb.ModuleSignature_MODULE_SIGNATURE_NONE)|uint64(pb.ModulePathClass_MODULE_PATH_CLASS_OTHER)<<8, "module.dll")
		case 4:
			return finding(pb.FindingCode_FINDING_CODE_DEBUGGER, "debugger", uint64(pb.DebugSignal_DEBUG_SIGNAL_PEB_BEING_DEBUGGED), 0, "")
		}
		return finding(pb.FindingCode_FINDING_CODE_UNBACKED_EXEC, "memory_region_walk", 0x3c00000+uint64(r.intn(4096))<<12, 0x1000|uint64(pb.UnbackedFlags_UNBACKED_FLAGS_PRIVATE)<<48, "")
	}
	switch x := r.unit(); {
	case x < 0.5:
	case x < 0.72:
		c.findings = append(c.findings,
			finding(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, "overlay_windows", 4120, 0x80020, "steam.exe"),
			finding(pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE, "external_handles", 5032, 0x1410, "discordhook64.dll"))
		if r.chance(0.3) {
			c.findings = append(c.findings, finding(pb.FindingCode_FINDING_CODE_CODE_PATCH, "text_integrity", 0x7ffb20001a40, 0, "d3d9.dll>gameoverlayrenderer.dll"))
		}
	default:
		for range 1 + r.intn(3) {
			c.findings = append(c.findings, env())
		}
		if r.chance(0.25) {
			c.injected = r.between(0.55, 1) // an input remapper or remote play
		}
		if r.chance(0.2) {
			c.mitFailed = 1 << uint(r.intn(3))
		}
		c.stuckJob = r.chance(0.08)
	}
	// Rare, and the reason integrity evidence alone does not settle a case: a capture or
	// overlay tool the allowlist has never heard of patches a graphics DLL, or a signed
	// file was updated in place.
	if r.chance(0.006) {
		c.findings = append(c.findings, finding(pb.FindingCode_FINDING_CODE_CODE_PATCH, "text_integrity", 0x7ffb20002000+uint64(r.intn(4096))<<4, 0, "d3d9.dll>?"))
	}
	if r.chance(0.01) {
		c.findings = append(c.findings, finding(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE, "module_signatures", 0,
			uint64(pb.ModuleSignature_MODULE_SIGNATURE_BAD_DIGEST)|uint64(pb.ModulePathClass_MODULE_PATH_CLASS_GAME_DIR)<<8, "module.dll"))
	}
	return c
}

// cheatClient lays what a cheat's footprint adds over an ordinary PC. Many cheats leave
// none the scanner sees: those sessions look clean and only the gameplay gives them away.
func cheatClient(r *rng, visible float64) client {
	c := honestClient(r)
	switch x := r.unit(); {
	case x < visible:
		c.findings = append(c.findings, tamperFindings(r, 1+r.intn(3))...)
	case x < visible+0.25:
		// An external tool: a handle to the game and, for ESP, a window over it.
		c.findings = append(c.findings, finding(pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE, "external_handles", uint64(1000+r.intn(9000)), 0x1fffff, "tool.exe"))
		if r.chance(0.5) {
			c.findings = append(c.findings, finding(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, "overlay_windows", uint64(1000+r.intn(9000)), 0x80020, "tool.exe"))
		}
	}
	return c
}

var (
	honestTrust = []float64{0.20, 0.10, 0.35, 0.35}
	cheatTrust  = []float64{0.35, 0.15, 0.30, 0.20}
)

// draw makes one synthetic session of the given profile.
func draw(r *rng, profile string, inMatch bool) person {
	p := person{profile: profile, inMatch: inMatch, mmr: int32(clamp(1500+300*r.normal(), 800, 2600))}
	p.play = honestPlay(r, p.mmr)
	if profile == Honest {
		p.trust, p.client = uint32(r.pick(honestTrust)), honestClient(r)
		return p
	}
	p.trust = uint32(r.pick(cheatTrust))
	exp := expectedHeadshot(p.mmr)
	aimSubtle := func() {
		p.play.snapsPerMn = r.between(0, 0.45)
		p.play.headshot = clamp(exp+r.between(0.10, 0.30), 0, 0.9)
		p.play.fastShare, p.play.fastMs = r.between(0.25, 0.55), [2]float64{90, 170}
	}
	speed := func(lo, hi float64) { p.play.cmdFactor = r.between(lo, hi) }
	macro := func(lo, hi float64) {
		p.play.presses, p.play.pressCV, p.play.pressMs = true, r.between(lo, hi), r.between(60, 160)
	}
	visible := 0.3
	switch profile {
	case AimBlatant:
		p.play.snapsPerMn = r.between(1.2, 6)
		p.play.headshot = r.between(0.55, 0.92)
		p.play.fastShare, p.play.fastMs = r.between(0.5, 0.9), [2]float64{15, 100}
	case AimSubtle:
		aimSubtle()
	case Trigger:
		p.play.headshot = clamp(p.play.headshot+r.between(0, 0.08), 0, 0.9)
		p.play.fastShare, p.play.fastMs = r.between(0.6, 0.95), [2]float64{10, 70}
	case Info:
		p.play.role = synth.RoleInformed
	case InfoSubtle:
		p.play.role = synth.RoleSubtle
	case Speed:
		speed(1.10, 1.6)
	case SpeedSubtle:
		speed(1.025, 1.085)
	case Macro:
		macro(0.002, 0.018)
	case MacroSubtle:
		macro(0.02, 0.07)
	case Tamper:
		visible = 1
	case Clock:
		visible = 0.1
	case Mixed:
		p.play.role = synth.RoleSubtle
		if r.chance(0.5) {
			p.play.role = synth.RoleInformed
		}
		aimSubtle()
		if r.chance(0.3) {
			speed(1.03, 1.2)
		}
		visible = 0.45
	}
	p.client = cheatClient(r, visible)
	switch profile {
	case Macro, MacroSubtle:
		if r.chance(0.6) {
			p.client.injected = r.between(0.3, 0.98) // the macro's own input
		}
	case Clock:
		if r.chance(0.7) {
			p.client.qpc = r.between(1.04, 1.5)
		} else {
			p.client.machine = r.between(1.04, 1.3)
		}
		if r.chance(0.5) {
			speed(1.0, 1.3)
		}
	}
	return p
}

// overlay rewrites one slot's telemetry in a simulated match to follow p's habits. The
// simulator's players all aim, shoot and send commands the same idealised way; this is
// where honest players get their noise and cheating ones their tells.
func overlay(r *rng, batches []*pb.GameplayBatch, slot uint32, p play, seconds int) {
	const rate = 64
	var hits []*pb.ShotEvent
	open := map[int32]uint32{} // target -> tick it became visible; 0 = taken
	for _, b := range batches {
		// Same order as the analyzer: by tick, visibility first.
		type ev struct {
			tick uint32
			vis  *pb.VisibilityEvent
			shot *pb.ShotEvent
		}
		var evs []ev
		for _, v := range b.Visibility {
			if v.ObserverSlot == slot {
				evs = append(evs, ev{v.Tick, v, nil})
			}
		}
		for _, s := range b.Shots {
			if s.Slot == slot {
				evs = append(evs, ev{s.Tick, nil, s})
			}
		}
		sort.SliceStable(evs, func(i, j int) bool {
			if evs[i].tick != evs[j].tick {
				return evs[i].tick < evs[j].tick
			}
			return evs[i].vis != nil && evs[j].vis == nil
		})
		for _, e := range evs {
			if v := e.vis; v != nil {
				if !v.Visible {
					delete(open, int32(v.TargetSlot))
				} else if _, ok := open[int32(v.TargetSlot)]; !ok {
					open[int32(v.TargetSlot)] = v.Tick
				}
				continue
			}
			s := e.shot
			if !s.Hit {
				continue
			}
			s.Headshot = r.chance(p.headshot)
			hits = append(hits, s)
			if since, ok := open[s.TargetSlot]; ok && since != 0 && s.Tick >= since {
				open[s.TargetSlot] = 0
				if r.chance(p.fastShare) {
					if t := since + uint32(r.between(p.fastMs[0], p.fastMs[1])*rate/1000); t < s.Tick {
						s.Tick = t
					}
				}
			}
		}
		for _, c := range b.Commands {
			if c.Slot == slot {
				c.Commands = uint32(math.Round(float64(c.Commands) * p.cmdFactor * (1 + p.cmdJitter*r.normal())))
			}
		}
	}

	// Snap-and-lock movements: the view is somewhere else for a moment and is back on its
	// real course within one tick. Laid in just before a hit where there is one, so an aim
	// cheat's snaps sit where they would. The window is short, so what the player's view
	// says about hidden enemies (the information-leak scorer's input) is unchanged.
	if n := r.poisson(p.snapsPerMn * float64(seconds) / 60); n > 0 {
		tracks := map[uint32]*pb.AimTrack{} // by first tick
		var firsts []uint32
		for _, b := range batches {
			for _, a := range b.Aim {
				if a.Slot == slot && len(a.Yaw) >= 40 {
					tracks[a.FirstTick] = a
					firsts = append(firsts, a.FirstTick)
				}
			}
		}
		step := func(a *pb.AimTrack, i int) float64 {
			dy := math.Mod(float64(a.Yaw[i]-a.Yaw[i-1])+540, 360) - 180
			return math.Hypot(dy, float64(a.Pitch[i]-a.Pitch[i-1]))
		}
		place := func(a *pb.AimTrack, i int) bool {
			k := 8 + r.intn(10)
			if i-k < 1 || i+1 >= len(a.Yaw) || step(a, i+1) >= 1.2 {
				return false
			}
			for j := i - k; j <= i; j++ {
				if step(a, j) > 6 {
					return false // already turning hard: leave it
				}
			}
			off := r.between(46, 110)
			if r.chance(0.5) {
				off = -off
			}
			for j := i - k; j < i; j++ {
				f := math.Min(1, float64(j-(i-k)+1)/float64(k/2))
				a.Yaw[j] = float32(math.Mod(float64(a.Yaw[j])+off*f+720, 360))
			}
			return true
		}
		placed := 0
		for _, h := range hits {
			if placed >= n {
				break
			}
			if len(hits) > n && !r.chance(float64(n)/float64(len(hits))*1.5) {
				continue
			}
			for _, f := range firsts {
				if a := tracks[f]; h.Tick > f && int(h.Tick-f) < len(a.Yaw) {
					if place(a, int(h.Tick-f)) {
						placed++
					}
					break
				}
			}
		}
		for try := 0; placed < n && try < 40*n && len(firsts) > 0; try++ {
			a := tracks[firsts[r.intn(len(firsts))]]
			if place(a, 20+r.intn(len(a.Yaw)-22)) {
				placed++
			}
		}
	}

	// Semi-automatic trigger presses, in bursts, stamped in microseconds.
	if p.presses {
		var us []uint64
		t := 5e6 * r.unit()
		end := float64(seconds) * 1e6
		for t < end && len(us) < 480 {
			t += r.between(4e6, 40e6)
			for range 3 + r.intn(10) {
				iv := p.pressMs * 1000 * (1 + p.pressCV*r.normal())
				t += math.Max(iv, 20e3)
				if t >= end {
					break
				}
				us = append(us, uint64(t)+1_000_000)
			}
		}
		i := 0
		for bi, b := range batches {
			var chunk []uint64
			for i < len(us) && (us[i] < uint64(bi+1)*1_000_000+1_000_000 || bi == len(batches)-1) {
				chunk = append(chunk, us[i])
				i++
			}
			if len(chunk) > 0 {
				b.Triggers = append(b.Triggers, &pb.TriggerPresses{Slot: slot, ClientTimeUs: chunk})
			}
		}
	}
}

// heartbeat is the session's n-th heartbeat, elapsed after it began.
func (c *client) heartbeat(n int, elapsed time.Duration) *pb.Heartbeat {
	const boot = 3 * time.Hour
	local := boot + time.Duration(float64(elapsed)*c.machine)
	hb := &pb.Heartbeat{
		Time: &pb.TimeSample{QpcNs: uint64(boot + time.Duration(float64(elapsed)*c.machine*c.qpc)), TickCountMs: uint64(local.Milliseconds()), InterruptTime_100Ns: uint64(local / 100)},
		Sched: &pb.SchedSummary{WorkerCpuNs: uint64(float64(elapsed) * 0.0035), Slices: uint64(elapsed / (100 * time.Millisecond)), SliceCpuMaxNs: 410_000,
			Frames: uint64(elapsed / (7 * time.Millisecond)), InputThreadCpuNs: uint64(float64(elapsed) * 0.0002)},
	}
	for i, j := range []string{"module_inventory", "memory_region_walk", "text_integrity", "api_hooks"} {
		hb.Coverage = append(hb.Coverage, &pb.JobCoverage{Job: j, RunsCompleted: uint64(elapsed/time.Second) / uint64(2+i)})
	}
	if c.stuckJob {
		hb.Sched.JobsQuarantined = 1
		hb.Coverage = append(hb.Coverage, &pb.JobCoverage{Job: "drivers", Quarantined: true})
	}
	events := uint64(elapsed / (8 * time.Millisecond))
	hb.Input = &pb.InputStats{MouseEvents: events, Injected: uint64(float64(events) * c.injected), FocusedMs: uint64(elapsed.Milliseconds())}
	if n == 0 {
		hb.Findings = append(hb.Findings, finding(pb.FindingCode_FINDING_CODE_MITIGATIONS, "mitigations", 7&^c.mitFailed, c.mitFailed, ""))
	}
	if n == 1 {
		hb.Findings = append(hb.Findings, c.findings...)
	}
	return hb
}

type collector struct {
	mu      sync.Mutex
	players []pipeline.MatchPlayer
}

func (c *collector) MatchFinished(_, _ string, players []pipeline.MatchPlayer, _ time.Time) {
	c.mu.Lock()
	c.players = append(c.players, players...)
	c.mu.Unlock()
}
func (c *collector) SessionActivity(store.Session, bool, time.Time) {}

// simulate runs match idx and returns its sessions.
func simulate(idx int, opt Options) ([]Row, error) {
	r := &rng{s: opt.Seed*0x9e3779b97f4a7c15 + uint64(idx)*0xd1342543de82ef95 + 1}
	seconds := opt.MinSeconds + r.intn(opt.MaxSeconds-opt.MinSeconds+1)
	mode := pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER
	if r.chance(0.3) {
		mode = pb.GameMode_GAME_MODE_EXTRACTION
	}
	var people []person
	for i := range 12 {
		inMatch := i < 10
		profile := Honest
		if r.chance(0.3) {
			profile = CheatProfiles[r.pick(cheatWeights)]
			if !inMatch {
				// A session that never joins a match can only show what its client shows.
				profile = []string{Tamper, Tamper, Clock}[r.intn(3)]
			}
		}
		p := draw(r, profile, inMatch)
		var id [16]byte
		for j := range id {
			id[j] = byte(r.next())
		}
		p.slot = uint32(i + 1)
		at := time.Unix(1_800_000_000, 0).UTC()
		p.sess = store.Session{SessionID: hex.EncodeToString(id[:]), TenantID: Tenant, PlayerHash: fmt.Sprintf("syn-%d-%d", idx, i),
			DeviceID: fmt.Sprintf("dev-%d-%d", idx, i), TrustLevel: p.trust, State: store.SessionActive, CreatedAt: at, ExpiresAt: at.Add(24 * time.Hour), LastHeartbeat: at}
		people = append(people, p)
	}

	ctx := context.Background()
	st := store.NewMemory()
	for i := range people {
		if err := st.PutSession(ctx, &people[i].sess); err != nil {
			return nil, err
		}
	}
	start := time.Unix(1_800_000_000, 0).UTC()
	now := start
	col := &collector{}
	pl := pipeline.New(pipeline.Config{Observer: col, Now: func() time.Time { return now }}, st, st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer pl.Close()

	// Heartbeats every 15 s for the length of the match (and a few minutes for sessions
	// that play none), on a clock the simulation owns.
	total := time.Duration(seconds) * time.Second
	for n := 0; time.Duration(n)*15*time.Second <= total; n++ {
		elapsed := time.Duration(n) * 15 * time.Second
		now = start.Add(elapsed)
		for i := range people {
			pl.Heartbeat(people[i].sess, people[i].client.heartbeat(n, elapsed))
		}
	}

	players := synth.DefaultPlayers(mode, 1, nil)
	for i := range players {
		p := &people[i]
		players[i].Role, players[i].SessionID, players[i].PlayerHash, players[i].MMR = p.play.role, p.sess.SessionID, p.sess.PlayerHash, p.mmr
	}
	spec := synth.Spec{MatchID: fmt.Sprintf("syn-%d", idx), Mode: mode, TickRate: 64, Seconds: seconds, Seed: r.next() | 1, Players: players, Decoys: true}
	batches := synth.Batches(spec)
	for i := range players {
		overlay(r, batches, players[i].Slot, people[i].play, seconds)
	}
	for _, b := range batches {
		if _, _, err := pl.Gameplay(ctx, Tenant, b); err != nil {
			return nil, fmt.Errorf("match %d: %w", idx, err)
		}
	}
	pl.Close()

	bySession := map[string]*pipeline.MatchPlayer{}
	for i := range col.players {
		bySession[col.players[i].Session.SessionID] = &col.players[i]
	}
	rows := make([]Row, 0, len(people))
	for i := range people {
		p := &people[i]
		ev, err := st.ListEvidence(ctx, Tenant, store.EvidenceFilter{SessionID: p.sess.SessionID, Limit: 500})
		if err != nil {
			return nil, err
		}
		tel, _ := st.GetTelemetry(ctx, Tenant, p.sess.SessionID)
		row := Row{Match: idx, Profile: p.profile, Cheating: p.profile != Honest, InMatch: p.inMatch, Vector: oracle.Missing(), Session: p.sess}
		if mp := bySession[p.sess.SessionID]; mp != nil {
			oracle.GameplayFeatures(&row.Vector, mp)
		} else if p.inMatch {
			return nil, fmt.Errorf("match %d: slot %d was not reported", idx, p.slot)
		}
		oracle.ClientFeatures(&row.Vector, p.sess.TrustLevel, ev, tel)
		for _, e := range ev {
			if e.Severity >= int(analyzer.SeverityMedium) {
				row.RuleFlag = true
			}
			if e.Severity > 0 && e.Severity < len(store.RiskWeight) {
				row.Risk += store.RiskWeight[e.Severity] * e.Score
			}
		}
		if opt.KeepEvidence {
			sort.Slice(ev, func(a, b int) bool { return ev[a].ID < ev[b].ID })
			row.Evidence = ev
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// Generate simulates opt.Matches matches and returns their sessions in match order. The
// result depends on the options only, not on the number of workers.
func Generate(opt Options) ([]Row, error) {
	opt.defaults()
	out := make([][]Row, opt.Matches)
	errs := make([]error, opt.Matches)
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for range opt.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				out[i], errs[i] = simulate(i, opt)
				if opt.Progress != nil {
					mu.Lock()
					done++
					opt.Progress(done, opt.Matches)
					mu.Unlock()
				}
			}
		}()
	}
	for i := range opt.Matches {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	var rows []Row
	for i := range out {
		if errs[i] != nil {
			return nil, errs[i]
		}
		rows = append(rows, out[i]...)
	}
	return rows, nil
}
