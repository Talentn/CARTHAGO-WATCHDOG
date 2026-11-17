package oracle

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"

	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/pipeline"
)

// studio is n sessions of ordinary play, one per player: snap rates between 0 and 0.2 per
// minute, reaction times between 200 and 300 ms.
func studio(n int, at time.Time) []BaselineSample {
	out := make([]BaselineSample, n)
	for i := range out {
		v := session(float64(i%21)/100, 200+float64(i%101))
		v[BFireTiming] = float64(i%16) / 100
		out[i] = BaselineSample{PlayerHash: fmt.Sprintf("p%d", i), Vector: v, At: at}
	}
	return out
}

func session(snaps, reaction float64) BaselineVector {
	v := BaselineOf(Missing(), math.NaN())
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
	if _, _, ok := b.Distance(BaselineOf(Missing(), math.NaN())); ok {
		t.Fatal("a session without gameplay was judged")
	}
	if s := BaselineScore(baselineFar); s != 1 {
		t.Fatalf("score at the far line %v", s)
	}
}

// The fire timing is the baseline's own signal: it travels in the stored feature vector
// beside the model's features and is read back from there.
func TestBaselineFireTiming(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	b := LearnBaseline(studio(400, now))
	bot := session(0.1, 250)
	bot[BFireTiming] = 0.8
	d, sigs, _ := b.Distance(bot)
	if BaselineBand(d) == BaselineNormal || len(sigs) != 1 || sigs[0].Key != "fire_timing" {
		t.Fatalf("a trigger bot's fire timing: distance %v, signals %v", d, sigs)
	}
	if d, _, _ := b.Distance(session(0.1, 250)); d != 0 {
		t.Fatalf("a session without crosshair events has distance %v", d)
	}

	v := Missing()
	v[FAimSnapRate], v[FTrustLevel] = 0.1, 3
	stored, _ := json.Marshal(v)
	got, err := ParseBaselineVector(WithFireTiming(string(stored), 0.8))
	if err != nil || got[BFireTiming] != 0.8 || got[FAimSnapRate] != 0.1 || !math.IsNaN(got[FReactionMs]) {
		t.Fatalf("read back %v, %v", got, err)
	}
	if got := WithFireTiming(string(stored), math.NaN()); got != string(stored) {
		t.Fatalf("an unknown fire timing changed the stored vector: %s", got)
	}
	// The model's own vector reads the same row and does not see the extra signal.
	var back Vector
	if err := json.Unmarshal([]byte(WithFireTiming(string(stored), 0.8)), &back); err != nil || back[FAimSnapRate] != 0.1 || back[FTrustLevel] != 3 {
		t.Fatalf("the model's vector from the same row: %v, %v", back, err)
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
	for _, c := range []struct {
		name     string
		sessions []float64
		want     float64
		band     string
	}{
		{"no session", nil, 0, BaselineNormal},
		// One extraordinary match, however extreme, is not enough.
		{"one lucky match", []float64{30, 0, 0, 0, 0, 0}, 8.0 / 3, BaselineNormal},
		{"one lucky match and nothing else", []float64{30}, 8.0 / 3, BaselineNormal},
		// A quiet cheater: outside in three of ten sessions, ordinary in the rest. A mean
		// over all ten would be 1.2.
		{"now and then", []float64{0, 4, 0, 0, 5, 0, 0, 3, 0, 0}, 4, BaselineOutside},
		{"twice outside", []float64{0, 5, 0, 4.5}, 9.5 / 3, BaselineOutside},
		{"twice far outside", []float64{9, 0, 12}, 16.0 / 3, BaselineOutside},
		{"always far outside", []float64{9, 20, 12, 8}, 8, BaselineFar},
	} {
		got := PlayerDistance(c.sessions)
		if math.Abs(got-c.want) > 1e-9 || BaselineBand(got) != c.band {
			t.Errorf("%s: distance %v (%s), want %v (%s)", c.name, got, BaselineBand(got), c.want, c.band)
		}
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
	if repeat.Sessions != 4 || repeat.Outside != 4 || repeat.Band != BaselineFar || repeat.Score != 1 || len(repeat.Signals) != 1 {
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

// The engine stores the fire timing of the session's worst match in the score row.
func TestEngineStoresFireTiming(t *testing.T) {
	h := newHarness(t, false, nil)
	ctx := context.Background()
	bot, few := h.session("s-bot", "p-bot", 2), h.session("s-few", "p-few", 2)
	stats := cheaterStats()
	stats.FireDelays, stats.FireTimed = 30, 0.7
	short := analyzer.PlayerSummary{TickRate: 64, AimSamples: 64 * 600, FireDelays: minFireDelays - 1, FireTimed: 1}
	h.eng.MatchFinished("studio", "m1", []pipeline.MatchPlayer{{Session: bot, Slot: 1, Stats: stats}, {Session: few, Slot: 2, Stats: short}}, h.clock())
	h.flush()
	fire := func(session string) float64 {
		t.Helper()
		row, err := h.st.GetOracleScore(ctx, "studio", session)
		if err != nil {
			t.Fatal(err)
		}
		v, err := ParseBaselineVector(row.Features)
		if err != nil {
			t.Fatal(err)
		}
		return v[BFireTiming]
	}
	if got := fire("s-bot"); got != 0.7 {
		t.Fatalf("stored fire timing %v, want 0.7", got)
	}
	if got := fire("s-few"); !math.IsNaN(got) {
		t.Fatalf("fire timing from too few delays: %v", got)
	}
	// A cleaner later match does not replace it, and a rescore on new client activity keeps it.
	h.eng.MatchFinished("studio", "m2", []pipeline.MatchPlayer{{Session: bot, Slot: 1, Stats: analyzer.PlayerSummary{TickRate: 64, AimSamples: 64 * 600, FireDelays: 30, FireTimed: 0.1}}}, h.clock())
	h.eng.SessionActivity(bot, true, h.clock())
	h.flush()
	if got := fire("s-bot"); got != 0.7 {
		t.Fatalf("fire timing after a cleaner match and a rescore: %v, want 0.7", got)
	}
}
