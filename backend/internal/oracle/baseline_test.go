package oracle

import (
	"fmt"
	"math"
	"testing"
	"time"
)

// studio is n sessions of ordinary play, one per player: snap rates between 0 and 0.2 per
// minute, reaction times between 200 and 300 ms.
func studio(n int, at time.Time) []BaselineSample {
	out := make([]BaselineSample, n)
	for i := range out {
		v := Missing()
		v[FAimSnapRate] = float64(i%21) / 100
		v[FReactionMs] = 200 + float64(i%101)
		out[i] = BaselineSample{PlayerHash: fmt.Sprintf("p%d", i), Vector: v, At: at}
	}
	return out
}

func session(snaps, reaction float64) Vector {
	v := Missing()
	v[FAimSnapRate], v[FReactionMs] = snaps, reaction
	return v
}

func TestBaselineOnlyWatchesUntilItHasEnoughSessions(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	b := LearnBaseline(studio(BaselineMinSessions-1, now))
	if b.Ready || b.Sessions != BaselineMinSessions-1 {
		t.Fatalf("ready %v after %d sessions", b.Ready, b.Sessions)
	}
	if _, _, ok := b.Distance(session(50, 20)); ok {
		t.Fatal("a baseline that is still learning scored a session")
	}
	if got := b.Players(studio(10, now), now); got != nil {
		t.Fatalf("a baseline that is still learning scored players: %v", got)
	}
	if b = LearnBaseline(studio(BaselineMinSessions, now)); !b.Ready {
		t.Fatal("not ready at the minimum")
	}
}

func TestBaselineDistance(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	b := LearnBaseline(studio(400, now))
	if d, sigs, ok := b.Distance(session(0.1, 250)); !ok || d != 0 || len(sigs) != 0 {
		t.Fatalf("ordinary session: distance %v, signals %v, ok %v", d, sigs, ok)
	}
	// Better than the studio is not outside: fewer snaps, slower reactions.
	if d, _, _ := b.Distance(session(0, 900)); d != 0 {
		t.Fatalf("a slow, calm session has distance %v", d)
	}
	d, sigs, _ := b.Distance(session(6, 250))
	if BaselineBand(d) != BaselineFar || len(sigs) != 1 || sigs[0].Key != "aim_snap_rate" {
		t.Fatalf("many snaps: distance %v (%s), signals %v", d, BaselineBand(d), sigs)
	}
	// A signal where lower is the suspicious side.
	d, sigs, _ = b.Distance(session(0.1, 60))
	if BaselineBand(d) == BaselineNormal || len(sigs) != 1 || sigs[0].Key != "reaction_time" {
		t.Fatalf("fast reactions: distance %v, signals %v", d, sigs)
	}
	// One signal cannot add more than the cap, and a session without gameplay is not judged.
	if d, _, _ := b.Distance(session(1e9, 250)); d != baselineCap {
		t.Fatalf("capped distance %v", d)
	}
	if _, _, ok := b.Distance(Missing()); ok {
		t.Fatal("a session without gameplay was judged")
	}
	if s := BaselineScore(baselineFar); math.Abs(s-0.5) > 1e-9 {
		t.Fatalf("score at the far line %v", s)
	}
}

// One account that plays all day, far outside, does not become the studio's normal.
func TestBaselineIsNotMovedByOnePlayer(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	samples := studio(300, now)
	for i := 0; i < 250; i++ {
		samples = append(samples, BaselineSample{PlayerHash: "grinder", Vector: session(6, 60), At: now})
	}
	b := LearnBaseline(samples)
	if d, _, _ := b.Distance(session(6, 60)); BaselineBand(d) != BaselineFar {
		t.Fatalf("the grinder's play became normal: distance %v", d)
	}
	if d, _, _ := b.Distance(session(0.1, 250)); d != 0 {
		t.Fatalf("an ordinary session moved outside: %v", d)
	}
}

func TestPlayerScoreCombinesSessionsInTheWindow(t *testing.T) {
	if got := PlayerDistance([]float64{8}); got != 4 {
		t.Fatalf("one session at 8: %v", got)
	}
	if got := PlayerDistance([]float64{8, 8, 8, 8, 8}); math.Abs(got-8*5.0/6) > 1e-9 {
		t.Fatalf("five sessions at 8: %v", got)
	}
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	samples := studio(400, now)
	b := LearnBaseline(samples)
	for i := 0; i < 4; i++ {
		samples = append(samples, BaselineSample{PlayerHash: "repeat", Vector: session(6, 250), At: now.Add(-time.Duration(i) * 24 * time.Hour)})
	}
	samples = append(samples,
		BaselineSample{PlayerHash: "once", Vector: session(6, 250), At: now},
		BaselineSample{PlayerHash: "once", Vector: session(0.1, 250), At: now},
		BaselineSample{PlayerHash: "once", Vector: session(0.1, 250), At: now},
		BaselineSample{PlayerHash: "old", Vector: session(6, 250), At: now.Add(-BaselineWindow - time.Hour)})
	players := b.Players(samples, now)
	repeat, once := players["repeat"], players["once"]
	if repeat.Sessions != 4 || repeat.Outside != 4 || repeat.Band != BaselineFar || len(repeat.Signals) != 1 {
		t.Fatalf("repeat: %+v", repeat)
	}
	if once.Sessions != 3 || once.Outside != 1 || once.Distance >= repeat.Distance {
		t.Fatalf("once: %+v, repeat: %+v", once, repeat)
	}
	if _, ok := players["old"]; ok {
		t.Fatal("a session older than the window counted")
	}
	if p := players["p7"]; p.Band != BaselineNormal || p.Score != 0 {
		t.Fatalf("an ordinary player: %+v", p)
	}
}
