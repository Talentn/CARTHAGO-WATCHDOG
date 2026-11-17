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
	"carthago/backend/internal/store"
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
	v := BaselineOf(Missing(), NoOwnSignals())
	v[FAimSnapRate], v[FReactionMs] = snaps, reaction
	return v
}

// A studio with too few sessions of its own is measured against the starting baseline,
// which is wide: it calls only play far from any person's outside normal.
func TestStartingBaselineUntilAStudioHasEnoughSessions(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	few := studio(BaselineMinSessions-1, now)
	b := LearnBaseline(few)
	if !b.Starting || !b.Ready || b.Sessions != BaselineMinSessions-1 {
		t.Fatalf("starting %v, ready %v after %d sessions", b.Starting, b.Ready, b.Sessions)
	}
	for i := range few {
		if d, _, ok := b.Distance(few[i].Vector); !ok || d != 0 {
			t.Fatalf("ordinary session %d against the starting baseline: distance %v, ok %v", i, d, ok)
		}
	}
	if d, sigs, _ := b.Distance(session(6, 20)); BaselineBand(d) != BaselineFar || len(sigs) != 2 {
		t.Fatalf("a blatant session against the starting baseline: distance %v, signals %v", d, sigs)
	}
	// Good and not impossible: a few snaps, quick reactions.
	if d, _, _ := b.Distance(session(0.9, 140)); BaselineBand(d) != BaselineNormal {
		t.Fatalf("a good player against the starting baseline: distance %v", d)
	}
	// The sight signals depend on the game's maps and have no starting value.
	sight := session(0.1, 250)
	sight[BHiddenAim], sight[BPreAim] = 1, 1
	if d, _, _ := b.Distance(sight); d != 0 {
		t.Fatalf("the starting baseline judged the sight signals: %v", d)
	}
	for i := 0; i < 3; i++ {
		few = append(few, BaselineSample{PlayerHash: "odd", Vector: session(6, 20), At: now})
	}
	if p := b.Players(few, now)["odd"]; p.Band != BaselineFar {
		t.Fatalf("the starting baseline did not score a player: %+v", p)
	}
	if b = LearnBaseline(studio(BaselineMinSessions, now)); b.Starting || !b.Ready {
		t.Fatal("at the minimum the studio's own baseline must take over")
	}
}

// Cheaters play in every studio. The baseline learns from the sessions that lie together
// and leaves the far ones out, so that cheating does not become normal.
func TestBaselineLearnsFromTheCleanMajority(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	samples := studio(400, now)
	clean := LearnBaseline(samples)
	for i := 0; i < 100; i++ { // a fifth of the studio
		samples = append(samples, BaselineSample{PlayerHash: fmt.Sprintf("c%d", i), Vector: session(2+float64(i%5), 250), At: now})
	}
	b := LearnBaseline(samples)
	if b.LeftOut != 100 || b.Sessions != 500 {
		t.Fatalf("left out %d of %d sessions, want the 100 cheating ones", b.LeftOut, b.Sessions)
	}
	if b.edge != clean.edge || b.spread != clean.spread {
		t.Fatalf("the cheating sessions moved the baseline: edges %v, without them %v", b.edge, clean.edge)
	}
	if d, _, _ := b.Distance(session(2, 250)); BaselineBand(d) == BaselineNormal {
		t.Fatalf("the cheaters' play became normal: distance %v", d)
	}
	// The honest tail is not cut: without cheaters nothing is left out.
	if clean.LeftOut != 0 {
		t.Fatalf("%d ordinary sessions were left out", clean.LeftOut)
	}
}

// Sessions with a certain finding and sessions of banned players are scored and never
// learned from, however many there are.
func TestBaselineNeverLearnsFromExcludedSessions(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	samples := studio(300, now)
	clean := LearnBaseline(samples)
	for i := 0; i < 600; i++ {
		samples = append(samples, BaselineSample{PlayerHash: fmt.Sprintf("banned%d", i), Vector: session(0.5, 120), At: now, Excluded: true})
	}
	b := LearnBaseline(samples)
	if b.Sessions != 300 || b.edge != clean.edge || b.spread != clean.spread {
		t.Fatalf("excluded sessions were learned from: %d sessions, edges %v, without them %v", b.Sessions, b.edge, clean.edge)
	}
	if p := b.Players(samples, now)["banned7"]; p.Sessions != 1 || p.Distance == 0 {
		t.Fatalf("an excluded session was not scored: %+v", p)
	}
	// Too few sessions left after the exclusion: the starting baseline, not a baseline
	// learned from the excluded ones.
	for i := range samples[:150] {
		samples[i].Excluded = true
	}
	if b = LearnBaseline(samples); !b.Starting || b.Sessions != 150 {
		t.Fatalf("starting %v with %d sessions to learn from", b.Starting, b.Sessions)
	}

	ev := []store.Evidence{{Rule: "angle_snap", Severity: 4}, {Rule: "code_patch", Severity: 4, Integrity: true}}
	if CertainFinding(ev) {
		t.Fatal("suspicious findings count as certain")
	}
	if !CertainFinding(append(ev, store.Evidence{Rule: analyzer.RuleKnownCheat, Severity: int(analyzer.SeverityCritical), Integrity: true})) {
		t.Fatal("a known cheat file is not a certain finding")
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
	if _, _, ok := b.Distance(BaselineOf(Missing(), NoOwnSignals())); ok {
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
	own := NoOwnSignals()
	own[BFireTiming-NumGameplay], own[BPreAim-NumGameplay] = 0.8, 0.25
	got, certain, err := ParseBaseline(WithBaseline(string(stored), own, true))
	if err != nil || !certain || got[BFireTiming] != 0.8 || got[BPreAim] != 0.25 || !math.IsNaN(got[BHiddenAim]) || got[FAimSnapRate] != 0.1 || !math.IsNaN(got[FReactionMs]) {
		t.Fatalf("read back %v, certain %v, %v", got, certain, err)
	}
	if got, certain, _ := ParseBaseline(WithBaseline(string(stored), NoOwnSignals(), false)); certain || got.Own() == own || got[FAimSnapRate] != 0.1 {
		t.Fatalf("a session without own signals: %v, certain %v", got, certain)
	}
	// The model's own vector reads the same row and does not see the extra keys.
	var back Vector
	if err := json.Unmarshal([]byte(WithBaseline(string(stored), own, true)), &back); err != nil || back[FAimSnapRate] != 0.1 || back[FTrustLevel] != 3 {
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

// The engine stores the baseline's own signals of the session's worst match in the score
// row, and marks a session that carries a certain finding.
func TestEngineStoresFireTiming(t *testing.T) {
	h := newHarness(t, false, nil)
	ctx := context.Background()
	bot, few := h.session("s-bot", "p-bot", 2), h.session("s-few", "p-few", 2)
	stats := cheaterStats()
	stats.FireDelays, stats.FireTimed = 30, 0.7
	stats.HiddenSamples, stats.HiddenTracked, stats.Appearances, stats.PreAimed = 1000, 50, minAppearances-1, 5
	short := analyzer.PlayerSummary{TickRate: 64, AimSamples: 64 * 600, FireDelays: minFireDelays - 1, FireTimed: 1}
	h.eng.MatchFinished("studio", "m1", []pipeline.MatchPlayer{{Session: bot, Slot: 1, Stats: stats}, {Session: few, Slot: 2, Stats: short}}, h.clock())
	h.flush()
	fire := func(session string) float64 {
		t.Helper()
		row, err := h.st.GetOracleScore(ctx, "studio", session)
		if err != nil {
			t.Fatal(err)
		}
		v, _, err := ParseBaseline(row.Features)
		if err != nil {
			t.Fatal(err)
		}
		return v[BFireTiming]
	}
	row, _ := h.st.GetOracleScore(ctx, "studio", "s-bot")
	if v, certain, _ := ParseBaseline(row.Features); certain || v[BHiddenAim] != 0.05 || !math.IsNaN(v[BPreAim]) {
		t.Fatalf("stored sight signals %v and %v, certain %v", v[BHiddenAim], v[BPreAim], certain)
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
	// A certain finding marks the session: the baseline will not learn from it.
	if err := h.st.AddEvidence(ctx, []store.Evidence{{TenantID: "studio", PlayerHash: "p-bot", SessionID: "s-bot", Source: store.SourceClient,
		Rule: analyzer.RuleKnownCheat, Severity: int(analyzer.SeverityCritical), Score: 1, Integrity: true, ObservedAt: h.clock()}}); err != nil {
		t.Fatal(err)
	}
	h.eng.SessionActivity(bot, true, h.clock())
	h.flush()
	row, _ = h.st.GetOracleScore(ctx, "studio", "s-bot")
	if v, certain, _ := ParseBaseline(row.Features); !certain || v[BFireTiming] != 0.7 {
		t.Fatalf("after a certain finding: certain %v, fire timing %v", certain, v[BFireTiming])
	}
}
