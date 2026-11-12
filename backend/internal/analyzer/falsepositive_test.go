package analyzer

import (
	"math"
	"math/rand/v2"
	"strings"
	"testing"

	pb "carthago/backend/gen/carthago/v1"
)

func flagged(m *Match, slot uint32, rule string) bool {
	_, ok := rules(m.Evaluate()[slot])[rule]
	return ok
}

// A quick flick that stops on target covers 40° in one tick of a 20 Hz server; at 64 Hz the
// same hand movement is spread over three ticks. The threshold is an angular speed.
func TestAngleSnapScalesWithTickRate(t *testing.T) {
	flicks := func() ([]float32, []float32) {
		var yaw, pitch []float32
		y := float32(10)
		for range 8 {
			y += 40
			for range 30 {
				yaw, pitch = append(yaw, y), append(pitch, 0)
			}
		}
		return yaw, pitch
	}
	y, p := flicks()
	slow := NewMatch(Defaults())
	slow.Add(&pb.GameplayBatch{TickRate: 20, Aim: []*pb.AimTrack{{Slot: 1, Yaw: y, Pitch: p}}})
	if flagged(slow, 1, "angle_snap") {
		t.Fatalf("800°/s flicks flagged at 20 Hz (%d locks)", slow.Players[1].SnapLocks)
	}
	fast := NewMatch(Defaults())
	fast.Add(&pb.GameplayBatch{TickRate: 64, Aim: []*pb.AimTrack{{Slot: 1, Yaw: y, Pitch: p}}})
	if !flagged(fast, 1, "angle_snap") {
		t.Fatal("2560°/s snaps not flagged at 64 Hz")
	}
	// 128 Hz keeps the per-tick threshold: scaling it down would flag ordinary flicks.
	if got := Defaults().SnapDeg * math.Max(1, refTickRate/128.0); got != Defaults().SnapDeg {
		t.Fatalf("threshold at 128 Hz: %v", got)
	}
}

func TestHeadshotTestIsExactAndNeedsAMargin(t *testing.T) {
	m := NewMatch(Defaults())
	m.Add(&pb.GameplayBatch{
		// MMR 500 has an 8% baseline. 10 of 40 is z=4.0 by the normal approximation, but the
		// exact chance is 1 in 1000, far more often than the 1 in 4300 the threshold stands for.
		Players: []*pb.MatchPlayer{{Slot: 1, Mmr: 500}, {Slot: 2, Mmr: 1500}, {Slot: 3, Mmr: 500}},
		// 24% over 2000 hits against an 18% baseline is hugely "significant" and means only
		// that the baseline is a little off for this player.
		Shots: append(append(shots(1, 40, 10), shots(2, 2000, 480)...), shots(3, 40, 22)...),
	})
	if z := binomialZ(10, 40, 0.08); z <= Defaults().HeadshotZ {
		t.Fatalf("fixture: z=%v no longer above the threshold", z)
	}
	if tail := binomialTail(10, 40, 0.08); tail < 9e-4 || tail > 1e-3 {
		t.Fatalf("exact tail %v, want about 9.7e-4", tail)
	}
	if flagged(m, 1, "headshot_rate") {
		t.Error("10/40 at an 8% baseline flagged")
	}
	if flagged(m, 2, "headshot_rate") {
		t.Error("24% over 2000 hits at an 18% baseline flagged")
	}
	if !flagged(m, 3, "headshot_rate") {
		t.Error("55% at an 8% baseline not flagged")
	}
}

func TestBinomialTail(t *testing.T) {
	for _, tc := range []struct {
		k, n int
		p    float64
		want float64
	}{
		{0, 10, 0.3, 1}, {11, 10, 0.3, 0}, {1, 1, 0.25, 0.25}, {5, 10, 0.5, 0.623046875}, {10, 10, 0.5, 1.0 / 1024},
		{3, 5, 0, 0}, {3, 5, 1, 1},
	} {
		if got := binomialTail(tc.k, tc.n, tc.p); math.Abs(got-tc.want) > 1e-12 {
			t.Errorf("binomialTail(%d, %d, %v) = %v, want %v", tc.k, tc.n, tc.p, got, tc.want)
		}
	}
	if got := normalTail(3.5); math.Abs(got-2.326e-4) > 1e-6 {
		t.Errorf("normalTail(3.5) = %v", got)
	}
}

// A client that freezes for a second and then delivers the commands it buffered has not run
// fast. The SDK reports no window for the silent second, so only the burst used to be counted.
func TestCommandRateCountsStalledTicks(t *testing.T) {
	m := NewMatch(Defaults())
	var cw []*pb.CommandWindow
	for w := range uint32(30) {
		if w%2 == 0 {
			continue // slot 1 sent nothing in this window: no record
		}
		cw = append(cw, &pb.CommandWindow{Slot: 1, TickFrom: w * 64, TickTo: (w + 1) * 64, Commands: 128})
	}
	for w := range uint32(30) {
		cw = append(cw, &pb.CommandWindow{Slot: 2, TickFrom: w * 64, TickTo: (w + 1) * 64, Commands: 80})
	}
	// Slot 3 left for a minute and came back: an absence is not a stall, and is not counted.
	cw = append(cw, &pb.CommandWindow{Slot: 3, TickFrom: 0, TickTo: 640, Commands: 640})
	cw = append(cw, &pb.CommandWindow{Slot: 3, TickFrom: 640 + 3840, TickTo: 640 + 3840 + 640, Commands: 640})
	// A window resent after a reconnect is not counted twice.
	cw = append(cw, &pb.CommandWindow{Slot: 3, TickFrom: 640 + 3840, TickTo: 640 + 3840 + 640, Commands: 640})
	m.Add(&pb.GameplayBatch{TickRate: 64, Commands: cw})
	if p := m.Players[1]; flagged(m, 1, "command_rate") {
		t.Errorf("lagging client flagged: %d commands / %d ticks", p.Cmds, p.CmdTicks)
	}
	if !flagged(m, 2, "command_rate") {
		t.Error("1.25x speedhack not flagged")
	}
	if p := m.Players[3]; p.CmdTicks != 1280 || p.Cmds != 1280 {
		t.Errorf("absence or resend miscounted: %d commands / %d ticks", p.Cmds, p.CmdTicks)
	}

	// Four seconds of data is not enough to tell a burst from a rate.
	short := NewMatch(Defaults())
	short.Add(&pb.GameplayBatch{TickRate: 64, Commands: []*pb.CommandWindow{{Slot: 1, TickFrom: 0, TickTo: 256, Commands: 300}}})
	if flagged(short, 1, "command_rate") {
		t.Error("flagged on 256 ticks")
	}
}

// Press times stamped with the server tick (15.625 ms steps): a steady human rhythm lands on
// the same number of ticks every time and has "zero" variation.
func TestMacroRuleNeedsFineTimestamps(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	const tick = 15625
	var quantised, perfect []uint64
	th, tp := uint64(tick*100), uint64(5_000_000)
	for burst := range 12 {
		for range 4 {
			th += 6 * tick
			tp += 100_000
			quantised, perfect = append(quantised, th), append(perfect, tp)
		}
		th += uint64(100+burst) * tick
		tp += 1_500_000 + uint64(rng.IntN(900_000))
	}
	m := NewMatch(Defaults())
	m.Add(&pb.GameplayBatch{Triggers: []*pb.TriggerPresses{{Slot: 1, ClientTimeUs: quantised}, {Slot: 2, ClientTimeUs: perfect}}})
	if flagged(m, 1, "macro_interval") {
		t.Error("tick-stamped presses flagged as a macro")
	}
	// Microsecond stamps with exactly equal intervals: the pauses between bursts show the
	// clock is fine-grained, so the regularity is real.
	if !flagged(m, 2, "macro_interval") {
		t.Error("perfectly regular macro not flagged")
	}

	// Eight presses are one or two bursts: too few to judge.
	few := NewMatch(Defaults())
	few.Add(&pb.GameplayBatch{Triggers: []*pb.TriggerPresses{{Slot: 1, ClientTimeUs: perfect[:9]}}})
	if flagged(few, 1, "macro_interval") {
		t.Error("flagged on 9 presses")
	}
}

func TestTimeToDamageGuards(t *testing.T) {
	// lobby builds exposures for `humans` ordinary players (slots 1..humans) and one player
	// under test (slot 9) whose shots are produced by fn.
	lobby := func(humans int, fn func(tick uint32) []*pb.ShotEvent) *Match {
		rng := rand.New(rand.NewPCG(11, 12))
		var vis []*pb.VisibilityEvent
		var sh []*pb.ShotEvent
		tick := uint32(1000)
		for range 20 {
			for obs := uint32(1); obs <= uint32(humans); obs++ {
				vis = append(vis, &pb.VisibilityEvent{ObserverSlot: obs, TargetSlot: 9, Tick: tick, Visible: true},
					&pb.VisibilityEvent{ObserverSlot: obs, TargetSlot: 9, Tick: tick + 60, Visible: false})
				sh = append(sh, &pb.ShotEvent{Slot: obs, Tick: tick + uint32(13+rng.IntN(10)), TargetSlot: 9, Hit: true})
			}
			vis = append(vis, &pb.VisibilityEvent{ObserverSlot: 9, TargetSlot: 1, Tick: tick, Visible: true},
				&pb.VisibilityEvent{ObserverSlot: 9, TargetSlot: 1, Tick: tick + 60, Visible: false})
			sh = append(sh, fn(tick)...)
			tick += 200
		}
		m := NewMatch(Defaults())
		m.Add(&pb.GameplayBatch{TickRate: 64, Visibility: vis, Shots: sh})
		return m
	}
	instant := func(tick uint32) []*pb.ShotEvent {
		return []*pb.ShotEvent{{Slot: 9, Tick: tick, TargetSlot: 1, Hit: true}}
	}
	if m := lobby(4, instant); !flagged(m, 9, "time_to_damage") {
		t.Fatalf("fixture: 0 ms reactions against four humans not flagged (%d samples)", len(m.Players[9].TTDms))
	}
	// Suppressing fire: already shooting at the doorway when the target walks into it.
	spray := func(tick uint32) []*pb.ShotEvent {
		return []*pb.ShotEvent{
			{Slot: 9, Tick: tick - 12, TargetSlot: -1}, {Slot: 9, Tick: tick - 6, TargetSlot: -1},
			{Slot: 9, Tick: tick, TargetSlot: 1, Hit: true},
		}
	}
	if m := lobby(4, spray); len(m.Players[9].TTDms) != 0 || flagged(m, 9, "time_to_damage") {
		t.Errorf("pre-firing counted as reaction: %v", m.Players[9].TTDms)
	}
	// One other player is not a lobby to be compared with.
	if m := lobby(2, instant); flagged(m, 9, "time_to_damage") {
		t.Error("flagged against two other players")
	}

	// A hit stamped before the exposure opened (events of two batches out of order) used to
	// be subtracted as unsigned ticks: a reaction time of 2^32 ticks.
	m := NewMatch(Defaults())
	m.Add(&pb.GameplayBatch{TickRate: 64, Visibility: []*pb.VisibilityEvent{{ObserverSlot: 1, TargetSlot: 2, Tick: 500, Visible: true}}})
	m.Add(&pb.GameplayBatch{TickRate: 64, Shots: []*pb.ShotEvent{{Slot: 1, Tick: 490, TargetSlot: 2, Hit: true}}})
	if got := m.Players[1].TTDms; len(got) != 0 {
		t.Errorf("out-of-order hit produced reaction samples %v", got)
	}
}

func TestMatchMemoryIsBounded(t *testing.T) {
	bad := []*pb.GameplayBatch{
		{Players: []*pb.MatchPlayer{{Slot: MaxSlots}}},
		{Players: []*pb.MatchPlayer{{Slot: 1, PlayerHash: strings.Repeat("a", 129)}}},
		{Players: []*pb.MatchPlayer{{Slot: 1, PlayerHash: "a b"}}},
		{Players: []*pb.MatchPlayer{{Slot: 1, PlayerHash: "<script>\x00"}}},
		{Aim: []*pb.AimTrack{{Slot: 1 << 30}}},
		{Aim: []*pb.AimTrack{{Slot: 1, Yaw: []float32{1, 2}, Pitch: []float32{1}}}},
		{Shots: []*pb.ShotEvent{{Slot: 1, TargetSlot: MaxSlots}}},
		{Shots: []*pb.ShotEvent{{Slot: 1, TargetSlot: -2}}},
		{Visibility: []*pb.VisibilityEvent{{ObserverSlot: 1, TargetSlot: 70000}}},
		{Commands: []*pb.CommandWindow{{Slot: 1, TickFrom: 10, TickTo: 5}}},
		{Triggers: []*pb.TriggerPresses{{Slot: 4096}}},
		{TickRate: 100000},
	}
	for i, b := range bad {
		if err := CheckBatch(b); err == nil {
			t.Errorf("bad batch %d accepted", i)
		}
	}
	ok := &pb.GameplayBatch{TickRate: 128, Players: []*pb.MatchPlayer{{Slot: 255, SessionId: "ab12", PlayerHash: "p-1"}, {Slot: 0}},
		Shots: []*pb.ShotEvent{{Slot: 0, TargetSlot: -1}}}
	if err := CheckBatch(ok); err != nil {
		t.Fatalf("valid batch refused: %v", err)
	}

	// Even unchecked input cannot grow the match: out-of-range slots are ignored, and the
	// reaction samples of one player are capped.
	m := NewMatch(Defaults())
	var vis []*pb.VisibilityEvent
	var sh []*pb.ShotEvent
	for i := range uint32(5000) {
		vis = append(vis, &pb.VisibilityEvent{ObserverSlot: 1 << 20, TargetSlot: i, Tick: i, Visible: true},
			&pb.VisibilityEvent{ObserverSlot: 1, TargetSlot: 2, Tick: 100 * i, Visible: true},
			&pb.VisibilityEvent{ObserverSlot: 1, TargetSlot: 2, Tick: 100*i + 50, Visible: false})
		sh = append(sh, &pb.ShotEvent{Slot: 1, Tick: 100*i + 13, TargetSlot: 2, Hit: true}, &pb.ShotEvent{Slot: 1<<20 + i, Tick: i, Hit: true})
	}
	m.Add(&pb.GameplayBatch{TickRate: 64, Visibility: vis, Shots: sh,
		Aim:      []*pb.AimTrack{{Slot: 1 << 21, Yaw: []float32{1}, Pitch: []float32{1}}},
		Commands: []*pb.CommandWindow{{Slot: 1 << 22, TickTo: 9}}, Triggers: []*pb.TriggerPresses{{Slot: 1 << 23, ClientTimeUs: []uint64{1}}}})
	if len(m.Players) != 1 || len(m.visible) > 1 {
		t.Fatalf("match grew to %d players and %d open exposures", len(m.Players), len(m.visible))
	}
	if n := len(m.Players[1].TTDms); n != maxTTDSamples {
		t.Fatalf("reaction samples: %d, want the cap %d", n, maxTTDSamples)
	}
}
