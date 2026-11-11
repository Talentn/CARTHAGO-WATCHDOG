package analyzer

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"

	pb "carthago/backend/gen/carthago/v1"
)

func rules(evs []Evidence) map[string]Evidence {
	m := map[string]Evidence{}
	for _, e := range evs {
		m[e.Rule] = e
	}
	return m
}

func TestStats(t *testing.T) {
	x := []float64{1, 2, 3, 4, 100}
	if median(x) != 3 {
		t.Fatalf("median %v", median(x))
	}
	if got := mad(x); math.Abs(got-1.4826) > 1e-9 {
		t.Fatalf("mad %v: the outlier must not widen it", got)
	}
	if z := robustZ(100, x); z < 60 {
		t.Fatalf("robustZ %v", z)
	}
	if z := binomialZ(50, 100, 0.5); z != 0 {
		t.Fatalf("binomialZ at expectation %v", z)
	}
	if z := binomialZ(80, 100, 0.5); math.Abs(z-6) > 1e-9 {
		t.Fatalf("binomialZ %v", z)
	}
}

func TestClassifyFinding(t *testing.T) {
	c := Defaults()
	cases := []struct {
		code      pb.FindingCode
		a, b      uint64
		detail    string
		rule      string
		sev       Severity
		integrity bool
	}{
		{pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, 1, 0, "GameOverlayRenderer64.dll", "overlay_window", SeverityInfo, false},
		{pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, 1, 0, "steam.exe", "overlay_window", SeverityInfo, false},
		{pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, 1, 0, "esp-box.exe", "overlay_window", SeverityLow, false},
		{pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE, 1, 0x38, "discordhook64.dll", "external_handle", SeverityInfo, false},
		{pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE, 1, 0x38, "cheatengine-x86_64.exe", "external_handle", SeverityMedium, true},
		{pb.FindingCode_FINDING_CODE_UNBACKED_EXEC, 0x1000, 0x1000 | uint64(pb.UnbackedFlags_UNBACKED_FLAGS_WRITABLE|pb.UnbackedFlags_UNBACKED_FLAGS_PE_SIGNATURE)<<48, "", "unbacked_exec", SeverityCritical, true},
		{pb.FindingCode_FINDING_CODE_UNBACKED_EXEC, 0x1000, 0x1000, "", "unbacked_exec", SeverityHigh, true},
		{pb.FindingCode_FINDING_CODE_CODE_PATCH, 0, 0, "d3d11.dll>evil.dll", "code_patch", SeverityCritical, true},
		{pb.FindingCode_FINDING_CODE_DEBUGGER, uint64(pb.DebugSignal_DEBUG_SIGNAL_PEB_BEING_DEBUGGED), 0, "", "debugger", SeverityLow, false},
		{pb.FindingCode_FINDING_CODE_DEBUGGER, uint64(pb.DebugSignal_DEBUG_SIGNAL_KERNEL_DEBUGGER), 0, "", "debugger", SeverityHigh, true},
	}
	for _, tc := range cases {
		e, ok := c.ClassifyFinding(uint32(tc.code), tc.a, tc.b, tc.detail)
		if !ok || e.Rule != tc.rule || e.Severity != tc.sev || e.Integrity != tc.integrity {
			t.Errorf("%v %q: got %+v ok=%v", tc.code, tc.detail, e, ok)
		}
	}
	for _, code := range []pb.FindingCode{pb.FindingCode_FINDING_CODE_MODULE_LOADED, pb.FindingCode_FINDING_CODE_MITIGATIONS} {
		if _, ok := c.ClassifyFinding(uint32(code), 0, 0, "x.dll"); ok {
			t.Errorf("%v must not produce standalone evidence", code)
		}
	}
}

// human aim: smooth turns with noise, occasional fast flicks that decelerate over a few ticks.
func humanAim(rng *rand.Rand, n int) ([]float32, []float32) {
	yaw, pitch := make([]float32, n), make([]float32, n)
	y, p, v := 90.0, 0.0, 0.0
	for i := range n {
		if rng.IntN(60) == 0 {
			v = (rng.Float64()*2 - 1) * 45 // flick
		}
		v *= 0.6 // decelerates, overshoots via noise
		y += v + rng.NormFloat64()*0.8
		p += rng.NormFloat64() * 0.3
		yaw[i], pitch[i] = float32(math.Mod(y+360, 360)), float32(p)
	}
	return yaw, pitch
}

// aimbot: snaps straight onto a target in one tick, then holds it dead still.
func botAim(n int) ([]float32, []float32) {
	yaw, pitch := make([]float32, n), make([]float32, n)
	y := 10.0
	for i := range n {
		if i%40 == 0 {
			y = math.Mod(y+70, 360)
		}
		yaw[i], pitch[i] = float32(y), 2
	}
	return yaw, pitch
}

func TestAngleSnap(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	m := NewMatch(Defaults())
	hy, hp := humanAim(rng, 4000)
	by, bp := botAim(4000)
	m.Add(&pb.GameplayBatch{TickRate: 64, Aim: []*pb.AimTrack{{Slot: 1, Yaw: hy, Pitch: hp}, {Slot: 2, Yaw: by, Pitch: bp}}})
	got := m.Evaluate()
	if _, ok := rules(got[1])["angle_snap"]; ok {
		t.Errorf("human flagged for angle snaps (%d locks)", m.Players[1].SnapLocks)
	}
	if _, ok := rules(got[2])["angle_snap"]; !ok {
		t.Errorf("aimbot not flagged (%d locks)", m.Players[2].SnapLocks)
	}
}

func TestAngleSnapAcrossBatchesAndWrap(t *testing.T) {
	m := NewMatch(Defaults())
	// 359 -> 1 is a 2° turn, not a 358° snap.
	for i := range 20 {
		y := float32(359)
		if i%2 == 1 {
			y = 1
		}
		m.Add(&pb.GameplayBatch{Aim: []*pb.AimTrack{{Slot: 1, FirstTick: uint32(i), Yaw: []float32{y}, Pitch: []float32{0}}}})
	}
	if m.Players[1].SnapLocks != 0 {
		t.Fatalf("yaw wrap counted as snaps: %d", m.Players[1].SnapLocks)
	}
	// A snap at the end of one batch locked at the start of the next still counts.
	m.Add(&pb.GameplayBatch{Aim: []*pb.AimTrack{{Slot: 2, FirstTick: 100, Yaw: []float32{0, 80}, Pitch: []float32{0, 0}}}})
	m.Add(&pb.GameplayBatch{Aim: []*pb.AimTrack{{Slot: 2, FirstTick: 102, Yaw: []float32{80.2}, Pitch: []float32{0}}}})
	if m.Players[2].SnapLocks != 1 {
		t.Fatalf("snap across a batch boundary: %d", m.Players[2].SnapLocks)
	}
	// A gap in ticks breaks continuity.
	m.Add(&pb.GameplayBatch{Aim: []*pb.AimTrack{{Slot: 3, FirstTick: 0, Yaw: []float32{0, 80}, Pitch: []float32{0, 0}}}})
	m.Add(&pb.GameplayBatch{Aim: []*pb.AimTrack{{Slot: 3, FirstTick: 10, Yaw: []float32{80}, Pitch: []float32{0}}}})
	if m.Players[3].SnapLocks != 0 {
		t.Fatalf("snap across a tick gap: %d", m.Players[3].SnapLocks)
	}
}

func shots(slot uint32, hits, headshots int) []*pb.ShotEvent {
	out := make([]*pb.ShotEvent, hits)
	for i := range hits {
		out[i] = &pb.ShotEvent{Slot: slot, Tick: uint32(i), TargetSlot: -1, Hit: true, Headshot: i < headshots}
	}
	return out
}

func TestHeadshotRateAgainstMMR(t *testing.T) {
	m := NewMatch(Defaults())
	m.Add(&pb.GameplayBatch{
		Players: []*pb.MatchPlayer{{Slot: 1, Mmr: 1500}, {Slot: 2, Mmr: 1500}, {Slot: 3, Mmr: 3000}},
		Shots:   append(append(shots(1, 120, 24), shots(2, 120, 80)...), shots(3, 120, 46)...),
	})
	got := m.Evaluate()
	if _, ok := rules(got[1])["headshot_rate"]; ok {
		t.Error("20% headshots at MMR 1500 flagged")
	}
	if _, ok := rules(got[2])["headshot_rate"]; !ok {
		t.Error("67% headshots at MMR 1500 not flagged")
	}
	// 38% is far above the MMR-1500 baseline but normal at the top of the ladder.
	if _, ok := rules(got[3])["headshot_rate"]; ok {
		t.Error("38% headshots at MMR 3000 flagged")
	}
}

func TestTimeToDamage(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	m := NewMatch(Defaults())
	var vis []*pb.VisibilityEvent
	var sh []*pb.ShotEvent
	tick := uint32(1000)
	for round := range 20 {
		for obs := uint32(1); obs <= 5; obs++ {
			target := obs%5 + 1
			reactTicks := uint32(13 + rng.IntN(10)) // ~200-340 ms at 64 Hz
			if obs == 5 {
				reactTicks = uint32(rng.IntN(2)) // triggerbot: 0-15 ms
			}
			vis = append(vis, &pb.VisibilityEvent{ObserverSlot: obs, TargetSlot: target, Tick: tick, Visible: true})
			sh = append(sh, &pb.ShotEvent{Slot: obs, Tick: tick + reactTicks, TargetSlot: int32(target), Hit: true})
			// a follow-up hit in the same exposure is tracking, not a second reaction
			sh = append(sh, &pb.ShotEvent{Slot: obs, Tick: tick + reactTicks + 5, TargetSlot: int32(target), Hit: true})
			vis = append(vis, &pb.VisibilityEvent{ObserverSlot: obs, TargetSlot: target, Tick: tick + 60, Visible: false})
		}
		tick += 100
		_ = round
	}
	m.Add(&pb.GameplayBatch{TickRate: 64, Visibility: vis, Shots: sh})
	if n := len(m.Players[1].TTDms); n != 20 {
		t.Fatalf("one reaction sample per exposure: got %d", n)
	}
	got := m.Evaluate()
	for slot := uint32(1); slot <= 4; slot++ {
		if _, ok := rules(got[slot])["time_to_damage"]; ok {
			t.Errorf("human slot %d flagged (median %.0f ms)", slot, median(m.Players[slot].TTDms))
		}
	}
	if _, ok := rules(got[5])["time_to_damage"]; !ok {
		t.Errorf("triggerbot not flagged (median %.0f ms)", median(m.Players[5].TTDms))
	}
}

func TestCommandRate(t *testing.T) {
	m := NewMatch(Defaults())
	var cw []*pb.CommandWindow
	for w := range uint32(10) {
		cw = append(cw, &pb.CommandWindow{Slot: 1, TickFrom: w * 64, TickTo: (w + 1) * 64, Commands: 64 + w%3}) // jitter
		cw = append(cw, &pb.CommandWindow{Slot: 2, TickFrom: w * 64, TickTo: (w + 1) * 64, Commands: 80})       // 1.25x
	}
	// a single catch-up burst after packet loss averages out
	cw = append(cw, &pb.CommandWindow{Slot: 1, TickFrom: 640, TickTo: 704, Commands: 90})
	m.Add(&pb.GameplayBatch{TickRate: 64, Commands: cw})
	got := m.Evaluate()
	if _, ok := rules(got[1])["command_rate"]; ok {
		t.Errorf("honest client flagged: %d cmds / %d ticks", m.Players[1].Cmds, m.Players[1].CmdTicks)
	}
	if _, ok := rules(got[2])["command_rate"]; !ok {
		t.Error("1.25x speedhack not flagged")
	}
}

func TestMacroInterval(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	var human, macro []uint64
	th, tm := uint64(0), uint64(0)
	for range 40 {
		th += uint64(110_000 + rng.NormFloat64()*15_000)
		tm += uint64(100_000 + rng.IntN(500)) // ±0.25 ms jitter from the OS
		human, macro = append(human, th), append(macro, tm)
	}
	m := NewMatch(Defaults())
	m.Add(&pb.GameplayBatch{Triggers: []*pb.TriggerPresses{{Slot: 1, ClientTimeUs: human}, {Slot: 2, ClientTimeUs: macro}}})
	got := m.Evaluate()
	if _, ok := rules(got[1])["macro_interval"]; ok {
		t.Error("human clicking flagged")
	}
	if _, ok := rules(got[2])["macro_interval"]; !ok {
		t.Error("macro not flagged")
	}
}

func hbAt(qpc, tick, intr time.Duration) *pb.Heartbeat {
	return &pb.Heartbeat{Time: &pb.TimeSample{QpcNs: uint64(qpc), TickCountMs: uint64(tick / time.Millisecond), InterruptTime_100Ns: uint64(intr / 100)}}
}

func TestTimeSourceDivergence(t *testing.T) {
	c := Defaults()
	t0 := time.Unix(1_700_000_000, 0)
	boot := 5 * time.Hour

	var honest, hooked ClientState
	var got []Evidence
	for i := range 9 {
		el := time.Duration(i) * 15 * time.Second
		jitter := time.Duration(i%3) * 40 * time.Millisecond // network delay on the server side
		at := t0.Add(el + jitter)
		if e := c.Heartbeat(&honest, hbAt(boot+el, boot+el, boot+el), at); len(e) > 0 {
			t.Fatalf("honest clocks flagged at %s: %+v", el, e)
		}
		got = append(got, c.Heartbeat(&hooked, hbAt(boot+el*13/10, boot+el, boot+el), at)...)
	}
	if e, ok := rules(got)["time_source_divergence"]; !ok || !e.Integrity {
		t.Fatalf("1.3x QPC not flagged: %+v", got)
	}

	// Every client clock accelerated together: only the server comparison sees it.
	var vm ClientState
	got = nil
	for i := range 30 {
		el := time.Duration(i) * 15 * time.Second
		fast := el * 11 / 10
		got = append(got, c.Heartbeat(&vm, hbAt(boot+fast, boot+fast, boot+fast), t0.Add(el))...)
	}
	r := rules(got)
	if _, ok := r["clock_drift"]; !ok {
		t.Fatalf("whole-machine 1.1x not flagged: %+v", got)
	}
	if _, ok := r["time_source_divergence"]; ok {
		t.Fatal("consistent client clocks reported as a hooked source")
	}

	// A client restart (QPC goes backwards) re-baselines instead of reporting.
	if e := c.Heartbeat(&vm, hbAt(time.Second, time.Second, time.Second), t0.Add(time.Hour)); len(e) != 0 {
		t.Fatalf("restart flagged: %+v", e)
	}
}

// One disturbed window must never be enough: this rule can lead to an automatic kick.
func TestClockRulesNeedTwoWindows(t *testing.T) {
	c := Defaults()
	t0 := time.Unix(1_700_000_000, 0)
	boot := 5 * time.Hour
	run := func(name string, n int, sample func(i int, el time.Duration) (*pb.Heartbeat, time.Time)) {
		t.Helper()
		var st ClientState
		for i := range n {
			hb, at := sample(i, time.Duration(i)*10*time.Second)
			if e := c.Heartbeat(&st, hb, at); len(e) != 0 {
				t.Fatalf("%s: flagged at heartbeat %d: %+v", name, i, e)
			}
		}
	}
	// QPC steps 5 s ahead of the interrupt time once (the clocks resynchronising after a
	// suspend): one window is off, the next ones are not.
	run("single QPC step", 40, func(i int, el time.Duration) (*pb.Heartbeat, time.Time) {
		step := time.Duration(0)
		if i >= 7 {
			step = 5 * time.Second
		}
		return hbAt(boot+el+step, boot+el, boot+el), t0.Add(el)
	})
	// GetTickCount going backwards (a 32-bit counter wrapping) used to underflow into a ratio
	// of trillions and a critical integrity finding.
	run("tick count wrap", 40, func(i int, el time.Duration) (*pb.Heartbeat, time.Time) {
		tick := boot + el
		if i >= 9 {
			tick = el - 90*time.Second
		}
		return hbAt(boot+el, tick, boot+el), t0.Add(el)
	})
	// A failed read of the interrupt time (reported as 0) must not become the baseline.
	run("missing interrupt time", 40, func(i int, el time.Duration) (*pb.Heartbeat, time.Time) {
		if i == 0 || i == 11 {
			return hbAt(boot+el, boot+el, 0), t0.Add(el)
		}
		return hbAt(boot+el, boot+el, boot+el), t0.Add(el)
	})
	// One heartbeat held up for 12 s by the network: the window that ends with it looks slow
	// and the one after looks fast, which is not a clock running at a different rate.
	run("late heartbeat", 120, func(i int, el time.Duration) (*pb.Heartbeat, time.Time) {
		at := t0.Add(el)
		if i == 18 || i == 36 {
			at = at.Add(12 * time.Second)
		}
		return hbAt(boot+el, boot+el, boot+el), at
	})

	// A sustained 4% QPC speed-up is still reported, at the second window.
	var st ClientState
	var at []int
	for i := range 10 {
		el := time.Duration(i) * 10 * time.Second
		if e := c.Heartbeat(&st, hbAt(boot+el*104/100, boot+el, boot+el), t0.Add(el)); len(e) != 0 {
			at = append(at, i)
		}
	}
	if len(at) == 0 || at[0] != 6 {
		t.Fatalf("sustained speed-up: reported at heartbeats %v, want first at 6 (60 s)", at)
	}
}

func TestScannerStallAndInput(t *testing.T) {
	c := Defaults()
	var st ClientState
	now := time.Unix(0, 0)
	var got []Evidence
	for i := range 6 {
		cpu := uint64(1_000_000)
		if i == 0 {
			cpu = 500_000
		}
		at := now.Add(time.Duration(i) * 15 * time.Second)
		got = append(got, c.Heartbeat(&st, &pb.Heartbeat{Activity: 0, Sched: &pb.SchedSummary{WorkerCpuNs: cpu, Frames: uint64(1000 * (i + 1))}}, at)...)
	}
	if n := len(got); n != 1 || got[0].Rule != "scanner_stalled" {
		t.Fatalf("stall: %+v", got)
	}
	// Heartbeats every half second: four of them fit between two runs of a 4 s scan job.
	var quick ClientState
	for i := range 12 {
		cpu := uint64(1_000_000 * (1 + i/8))
		at := now.Add(time.Duration(i) * 500 * time.Millisecond)
		if e := c.Heartbeat(&quick, &pb.Heartbeat{Activity: 0, Sched: &pb.SchedSummary{WorkerCpuNs: cpu, Frames: uint64(100 * (i + 1))}}, at); len(e) != 0 {
			t.Fatalf("idle gap between scan periods flagged at heartbeat %d: %+v", i, e)
		}
	}
	// Loading screens legitimately starve the worker.
	var menu ClientState
	for i := range 6 {
		if e := c.Heartbeat(&menu, &pb.Heartbeat{Activity: 2, Sched: &pb.SchedSummary{WorkerCpuNs: 7, Frames: uint64(10 * (i + 1))}}, now); len(e) != 0 {
			t.Fatalf("loading stall flagged: %+v", e)
		}
	}

	in := c.Heartbeat(&ClientState{}, &pb.Heartbeat{Input: &pb.InputStats{MouseEvents: 5000, Injected: 4900}}, now)
	if _, ok := rules(in)["injected_input"]; !ok {
		t.Fatal("injected input not flagged")
	}
	if e := c.Heartbeat(&ClientState{}, &pb.Heartbeat{Input: &pb.InputStats{MouseEvents: 5000, Injected: 30}}, now); len(e) != 0 {
		t.Fatalf("occasional injected events flagged: %+v", e)
	}
}
