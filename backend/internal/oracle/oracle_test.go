package oracle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/oracle/analyst"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/store"
)

// testModel is a small hand-written model: snaps, leak and integrity raise the score,
// trust lowers it, everything else is flat.
func testModel() *Model {
	m := &Model{Kind: ModelKind, FormatVersion: 1, FeatureVersion: FeatureVersion, Bias: -3}
	for f := range NumFeatures {
		s := Shape{Key: Features[f].Key, Cuts: []float64{}, Values: []float64{0}}
		switch f {
		case FAimSnapRate:
			s.Cuts, s.Values = []float64{0.2, 1}, []float64{0, 1.5, 5}
		case FLeakRatio:
			s.Cuts, s.Values, s.Missing = []float64{0.7, 1}, []float64{-0.2, 1, 4}, 0.1
		case FIntegritySeverity:
			s.Cuts, s.Values = []float64{3, 4}, []float64{0, 3, 6}
		case FTrustLevel:
			s.Cuts, s.Values, s.Baseline = []float64{2}, []float64{0.4, -0.4}, -0.1
		}
		m.Shapes = append(m.Shapes, s)
	}
	return m
}

func modelBytes(t *testing.T, m *Model) []byte {
	t.Helper()
	b, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestModelScoreAndContributions(t *testing.T) {
	m := testModel()
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	v := Missing()
	v[FTrustLevel] = 3
	s, c := m.Score(v)
	// bias -3, leak missing +0.1, trust -0.4
	if want := 1 / (1 + math.Exp(3.3)); math.Abs(s-want) > 1e-12 {
		t.Fatalf("score %v, want %v", s, want)
	}
	if math.Abs(c[FTrustLevel]-(-0.3)) > 1e-12 || math.Abs(c[FLeakRatio]-0.1) > 1e-12 || c[FAimSnapRate] != 0 {
		t.Fatalf("contributions %v", c)
	}
	// A cut belongs to the upper side: a value equal to it gets the higher step.
	v[FAimSnapRate], v[FLeakRatio], v[FIntegritySeverity] = 1, 0.7, 2
	s2, c2 := m.Score(v)
	if c2[FAimSnapRate] != 5 || c2[FLeakRatio] != 1 || c2[FIntegritySeverity] != 0 || s2 <= s {
		t.Fatalf("contributions %v", c2)
	}
	top := TopSignals(c2, 2)
	if len(top) != 2 || top[0].Key != "aim_snap_rate" || top[0].Effect != 5 || top[1].Key != "information_leak" || top[0].Label == "" {
		t.Fatalf("top signals %+v", top)
	}
	// More of a suspicious signal never lowers the score.
	for f := range NumFeatures {
		if Features[f].Direction == 0 {
			t.Fatalf("feature %s has no direction", Features[f].Key)
		}
		prev := math.Inf(-1)
		for x := -2.0; x <= 6; x += 0.05 {
			w := v
			w[f] = x
			if Features[f].Direction < 0 {
				w[f] = -x
			}
			s, _ := m.Score(w)
			if s < prev-1e-12 {
				t.Fatalf("feature %s: score falls from %v to %v at %v", Features[f].Key, prev, s, x)
			}
			prev = s
		}
	}
}

func TestModelValidation(t *testing.T) {
	bad := map[string]func(*Model){
		"kind":            func(m *Model) { m.Kind = "x" },
		"feature version": func(m *Model) { m.FeatureVersion = FeatureVersion + 1 },
		"curve count":     func(m *Model) { m.Shapes = m.Shapes[:3] },
		"key order":       func(m *Model) { m.Shapes[0].Key, m.Shapes[1].Key = m.Shapes[1].Key, m.Shapes[0].Key },
		"values length":   func(m *Model) { m.Shapes[FAimSnapRate].Values = []float64{0, 1} },
		"unsorted cuts":   func(m *Model) { m.Shapes[FAimSnapRate].Cuts = []float64{1, 0.2} },
		"against direction": func(m *Model) {
			m.Shapes[FAimSnapRate].Values = []float64{0, 2, 1} // more snaps, lower score
		},
		"trust rising": func(m *Model) { m.Shapes[FTrustLevel].Values = []float64{-0.4, 0.4} },
		"nan":          func(m *Model) { m.Bias = math.NaN() },
	}
	for name, edit := range bad {
		m := testModel()
		edit(m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	data := modelBytes(t, testModel())
	m, id, err := ParseModel(data)
	if err != nil || !strings.HasPrefix(id, "cob-") || len(id) != 16 || m.Bias != -3 {
		t.Fatalf("%v %q", err, id)
	}
	if _, id2, _ := ParseModel(append(data, ' ')); id2 == id {
		t.Error("the id must name the exact bytes")
	}
	if _, _, err := ParseModel([]byte("{")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestVectorJSON(t *testing.T) {
	v := Missing()
	v[FAimSnapRate], v[FTrustLevel] = 1.5, 2
	b, err := json.Marshal(v)
	if err != nil || string(b) != `{"aim_snap_rate":1.5,"trust_level":2}` {
		t.Fatalf("%s %v", b, err)
	}
	var w Vector
	if err := json.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	for i := range v {
		if v[i] != w[i] && !(math.IsNaN(v[i]) && math.IsNaN(w[i])) {
			t.Fatalf("round trip: %v != %v", v, w)
		}
	}
}

func TestFeatures(t *testing.T) {
	p := pipeline.MatchPlayer{Stats: analyzer.PlayerSummary{TickRate: 64, AimSamples: 64 * 120, SnapLocks: 3, Hits: 50, HeadshotZ: 2.5,
		Reactions: 9, ReactionMedianMs: 210, LobbyOK: true, ReactionZ: -1.2, CmdTicks: 6400, Cmds: 6464, TriggerOK: true, TriggerPresses: 30, TriggerCV: 0.3},
		Leak: pipeline.KnowledgeScore{Scored: true, Score: 6, Threshold: 4}, Decoy: pipeline.KnowledgeScore{Scored: true, Score: 1, Threshold: 4}}
	v := Missing()
	GameplayFeatures(&v, &p)
	want := map[int]float64{FAimSnapRate: 1.5, FHeadshotZ: 2.5, FReactionMs: 210, FReactionLobbyZ: -1.2, FCommandRatio: 1.01, FTriggerCV: 0.3, FLeakRatio: 1.5, FDecoyRatio: 0.25}
	for f, x := range want {
		if math.Abs(v[f]-x) > 1e-9 {
			t.Errorf("%s = %v, want %v", Features[f].Key, v[f], x)
		}
	}
	// Too little data leaves a value unknown rather than guessing.
	thin := pipeline.MatchPlayer{Stats: analyzer.PlayerSummary{TickRate: 64, AimSamples: 64 * 10, SnapLocks: 2, Hits: 3, HeadshotZ: 9, Reactions: 2, ReactionMedianMs: 50, CmdTicks: 100, Cmds: 200, TriggerPresses: 5}}
	v = Missing()
	GameplayFeatures(&v, &thin)
	for f := range NumGameplay {
		if !math.IsNaN(v[f]) {
			t.Errorf("%s = %v from too little data", Features[f].Key, v[f])
		}
	}

	ev := []store.Evidence{
		{Source: store.SourceClient, Rule: "code_patch", Severity: 3, Score: 0.9, Integrity: true},
		{Source: store.SourceClient, Rule: "unbacked_exec", Severity: 4, Score: 0.9, Integrity: true},
		{Source: store.SourceClient, Rule: "time_source_divergence", Severity: 4, Score: 0.8, Integrity: true},
		{Source: store.SourceClient, Rule: "overlay_window", Severity: 1, Score: 0.35},
		{Source: store.SourceClient, Rule: "overlay_window", Severity: 0, Score: 0.1},
		{Source: store.SourceClient, Rule: "scan_quarantined", Severity: 1, Score: 0.3},
		{Source: store.SourceClient, Rule: "injected_input", Severity: 1, Score: 0.9},
		{Source: store.SourceGameplay, Rule: "angle_snap", Severity: 3, Score: 0.9}, // carried by the match features
	}
	v = Missing()
	ClientFeatures(&v, 7, ev, &store.Telemetry{MouseEvents: 1000, InjectedEvents: 800, MitigationsFailed: 0b101})
	want = map[int]float64{FIntegrityRisk: 6*0.9 + 10*0.9 + 10*0.8, FIntegritySeverity: 4, FClockEvidence: 1, FInjectedRatio: 0.8, FClientFindings: 0.35, FScannerGaps: 3, FTrustLevel: 3}
	for f, x := range want {
		if math.Abs(v[f]-x) > 1e-9 {
			t.Errorf("%s = %v, want %v", Features[f].Key, v[f], x)
		}
	}
	v = Missing()
	ClientFeatures(&v, 0, nil, nil)
	if v[FIntegrityRisk] != 0 || v[FScannerGaps] != 0 || !math.IsNaN(v[FInjectedRatio]) || v[FTrustLevel] != 0 {
		t.Errorf("clean client: %v", v)
	}
}

func writeTestBundle(t *testing.T, dir string, th Thresholds) *Manifest {
	t.Helper()
	p := analyst.DefaultPrompts()
	m, err := WriteBundle(dir, Contents{Model: modelBytes(t, testModel()), Thresholds: th, PromptVersion: p.Version, SchemaVersion: analyst.VerdictSchema,
		SystemPrompt: p.System, CasePrompt: p.Case, LocalModel: LocalModelRef{ID: "lm", File: "lm.gguf", SHA256: "00", ContextTokens: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestBundle(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadBundle(dir); !errors.Is(err, ErrNoBundle) {
		t.Fatalf("empty directory: %v", err)
	}
	man := writeTestBundle(t, dir, Thresholds{Watch: 0.2, Review: 0.6})
	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if b.Manifest.BundleID != man.BundleID || !strings.HasPrefix(man.BundleID, "cb-") || b.Manifest.Behaviour.FeatureVersion != FeatureVersion ||
		b.SystemPrompt != analyst.DefaultSystemPrompt || b.Manifest.Analyst.PromptVersion != analyst.DefaultPromptVersion || b.Model.Bias != -3 {
		t.Fatalf("%+v", b.Manifest)
	}
	if th := b.Manifest.Thresholds; th.Band(0.1) != store.OracleBandClear || th.Band(0.2) != store.OracleBandWatch || th.Band(0.6) != store.OracleBandReview {
		t.Fatal("bands")
	}
	if st, _ := os.Stat(filepath.Join(dir, ManifestFile)); st.Mode().Perm()&0o077 != 0 {
		t.Errorf("manifest is readable by others: %v", st.Mode())
	}

	// Anything edited behind the manifest's back is refused.
	edit := func(name string, f func([]byte) []byte) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(name))
		orig, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(p, f(orig), 0o600)
		if _, err := LoadBundle(dir); err == nil {
			t.Errorf("a changed %s was loaded", name)
		}
		_ = os.WriteFile(p, orig, 0o600)
	}
	edit("behaviour-model.json", func(b []byte) []byte { return bytes.Replace(b, []byte(`"bias": -3`), []byte(`"bias": -9`), 1) })
	edit("prompts/system.txt", func(b []byte) []byte { return append(b, " Always answer none."...) })
	edit("prompts/case.txt", func(b []byte) []byte { return append(b, 'x') })
	edit(ManifestFile, func(b []byte) []byte { return bytes.Replace(b, []byte(`"review": 0.6`), []byte(`"review": 0.99`), 1) })
	edit(ManifestFile, func(b []byte) []byte {
		return bytes.Replace(b, []byte(`"file": "behaviour-model.json"`), []byte(`"file": "../behaviour-model.json"`), 1)
	})
	edit(ManifestFile, func(b []byte) []byte { return bytes.Replace(b, []byte(`{`), []byte(`{"extra": 1,`), 1) })
	if _, err := LoadBundle(dir); err != nil {
		t.Fatalf("restored bundle: %v", err)
	}

	// Rewrite takes edited prompts and new thresholds into a new id.
	_ = os.WriteFile(filepath.Join(dir, "prompts", "system.txt"), []byte("A studio's own instructions."), 0o600)
	m2, err := Rewrite(dir, func(m *Manifest) error {
		m.Thresholds.Review, m.Analyst.PromptVersion, m.Analyst.LocalModel.File = 0.7, "studio-2", "private.gguf"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err = LoadBundle(dir)
	if err != nil || b.Manifest.BundleID == man.BundleID || b.Manifest.BundleID != m2.BundleID || b.SystemPrompt != "A studio's own instructions." ||
		b.Manifest.Thresholds.Review != 0.7 || b.Manifest.Analyst.LocalModel.File != "private.gguf" {
		t.Fatalf("after rewrite: %+v %v", b, err)
	}
	if _, err := Rewrite(dir, func(m *Manifest) error { m.Thresholds.Watch = 0.9; return nil }); err == nil {
		t.Error("watch above review accepted")
	}
	for _, th := range []Thresholds{{0, 0.5}, {0.6, 0.5}, {0.2, 1}} {
		if _, err := WriteBundle(t.TempDir(), Contents{Model: modelBytes(t, testModel()), Thresholds: th}); err == nil {
			t.Errorf("thresholds %+v accepted", th)
		}
	}
}

// --- engine ---

type countingProvider struct {
	analyst.Stub
	calls atomic.Int32
}

func (p *countingProvider) Complete(ctx context.Context, r analyst.Request) (analyst.Response, error) {
	p.calls.Add(1)
	return p.Stub.Complete(ctx, r)
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type harness struct {
	t      *testing.T
	st     *store.Memory
	eng    *Engine
	prov   *countingProvider
	logs   *syncBuffer
	cancel context.CancelFunc
	done   chan struct{}
	now    time.Time // the clock's value when the harness was made, plus what tests advanced it by
	start  time.Time
	mu     sync.Mutex
}

// clock runs in real time from a fixed date, and can be advanced.
func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now.Add(time.Since(h.start))
}
func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func newHarness(t *testing.T, withAnalyst bool, edit func(*Config)) *harness {
	t.Helper()
	dir := t.TempDir()
	writeTestBundle(t, dir, Thresholds{Watch: 0.2, Review: 0.6})
	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, st: store.NewMemory(), logs: &syncBuffer{}, now: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC), start: time.Now(), done: make(chan struct{})}
	cfg := Config{Bundle: b, PseudonymKey: []byte("0123456789abcdef0123456789abcdef"), Settle: 20 * time.Millisecond, ReviewLive: true, Now: h.clock}
	if withAnalyst {
		h.prov = &countingProvider{}
		cfg.Analyst, err = analyst.New(analyst.Config{Provider: h.prov, Prompts: analyst.Prompts{Version: b.Manifest.Analyst.PromptVersion, System: b.SystemPrompt, Case: b.CasePrompt}, Usage: h.st})
		if err != nil {
			t.Fatal(err)
		}
	}
	if edit != nil {
		edit(&cfg)
	}
	// The log is captured at the default level: what an operator's log file would hold.
	h.eng, err = New(cfg, h.st, slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		h.eng.Run(ctx)
		close(h.done)
	}()
	t.Cleanup(func() {
		cancel()
		<-h.done
	})
	return h
}

func (h *harness) flush() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h.eng.Flush(ctx)
	if ctx.Err() != nil {
		h.t.Fatal("the engine did not settle")
	}
}

func (h *harness) session(id, player string, trust uint32) store.Session {
	h.t.Helper()
	s := store.Session{SessionID: id, TenantID: "studio", PlayerHash: player, TrustLevel: trust, State: store.SessionActive, CreatedAt: h.clock(), LastHeartbeat: h.clock()}
	if err := h.st.PutSession(context.Background(), &s); err != nil {
		h.t.Fatal(err)
	}
	return s
}

func cheaterStats() analyzer.PlayerSummary {
	return analyzer.PlayerSummary{TickRate: 64, AimSamples: 64 * 600, SnapLocks: 30, Hits: 60, HeadshotZ: 6, Reactions: 20, ReactionMedianMs: 90}
}

func TestEngineScoresAndReviews(t *testing.T) {
	h := newHarness(t, true, nil)
	ctx := context.Background()
	cheat, honest := h.session("s-cheat", "p-cheat", 0), h.session("s-honest", "p-honest", 3)
	if err := h.st.AddEvidence(ctx, []store.Evidence{{TenantID: "studio", PlayerHash: "p-cheat", SessionID: "s-cheat", MatchID: "m1", Source: store.SourceGameplay,
		Rule: "angle_snap", Severity: 3, Score: 0.9, Summary: "30 snap-and-lock aim movements", ObservedAt: h.clock()}}); err != nil {
		t.Fatal(err)
	}
	before, _ := h.st.ListEvidence(ctx, "studio", store.EvidenceFilter{Limit: 100})

	h.eng.MatchFinished("studio", "m1", []pipeline.MatchPlayer{
		{Session: cheat, Slot: 1, Stats: cheaterStats(), Leak: pipeline.KnowledgeScore{Scored: true, Score: 6, Threshold: 4}},
		{Session: honest, Slot: 2, Stats: analyzer.PlayerSummary{TickRate: 64, AimSamples: 64 * 600}, Leak: pipeline.KnowledgeScore{Scored: true, Score: 0.4, Threshold: 4}},
	}, h.clock())
	h.flush()

	sc, err := h.st.GetOracleScore(ctx, "studio", "s-cheat")
	if err != nil || sc.Band != store.OracleBandReview || sc.Score < 0.9 || sc.MatchID != "m1" || sc.PlayerHash != "p-cheat" || !strings.HasPrefix(sc.ModelID, "cob-") {
		t.Fatalf("cheater score: %+v %v", sc, err)
	}
	var sigs []Signal
	if err := json.Unmarshal([]byte(sc.Signals), &sigs); err != nil || len(sigs) < 2 || sigs[0].Key != "aim_snap_rate" || sigs[0].Effect <= 0 {
		t.Fatalf("signals: %s", sc.Signals)
	}
	hs, err := h.st.GetOracleScore(ctx, "studio", "s-honest")
	if err != nil || hs.Band != store.OracleBandClear || hs.Score > 0.1 {
		t.Fatalf("honest score: %+v %v", hs, err)
	}

	v, err := h.st.GetOracleVerdict(ctx, "studio", "s-cheat")
	if err != nil || v.Status != store.OracleVerdictOK || v.CheatType != analyst.TypeAim || v.Provider != "stub" || v.PromptVersion != analyst.DefaultPromptVersion || v.CaseHash == "" {
		t.Fatalf("verdict: %+v %v", v, err)
	}
	var cited []CitedEvidence
	if err := json.Unmarshal([]byte(v.Cited), &cited); err != nil || len(cited) != 1 || cited[0].ID != "E1" || cited[0].Rule != "angle_snap" || len(cited[0].Evidence) != 1 || cited[0].Evidence[0] != before[0].ID {
		t.Fatalf("cited: %s", v.Cited)
	}
	if strings.Contains(v.CaseFile, "p-cheat") || strings.Contains(v.CaseFile, "s-cheat") || strings.Contains(v.CaseFile, "snap-and-lock") || strings.Contains(v.CaseFile, `"m1"`) {
		t.Errorf("the stored case file is not pseudonymised: %s", v.CaseFile)
	}
	if _, err := h.st.GetOracleVerdict(ctx, "studio", "s-honest"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an unflagged session was sent to the analyst: %v", err)
	}

	// Advisory: the engine added no evidence, so no risk changed and nothing could kick.
	after, _ := h.st.ListEvidence(ctx, "studio", store.EvidenceFilter{Limit: 100})
	if len(after) != len(before) {
		t.Fatalf("the engine wrote evidence: %d rows before, %d after", len(before), len(after))
	}

	// The same case is not judged twice; a changed case is.
	calls := h.prov.calls.Load()
	h.advance(2 * time.Minute)
	h.eng.SessionActivity(cheat, false, h.clock())
	h.flush()
	if h.prov.calls.Load() != calls {
		t.Fatalf("the cached verdict was not used: %d calls, then %d", calls, h.prov.calls.Load())
	}
	_ = h.st.AddEvidence(ctx, []store.Evidence{{TenantID: "studio", PlayerHash: "p-cheat", SessionID: "s-cheat", Source: store.SourceClient,
		Rule: "code_patch", Severity: 3, Score: 0.9, Integrity: true, ObservedAt: h.clock()}})
	h.eng.SessionActivity(cheat, true, h.clock())
	h.flush()
	v2, _ := h.st.GetOracleVerdict(ctx, "studio", "s-cheat")
	if h.prov.calls.Load() != calls+1 || v2.CaseHash == v.CaseHash || v2.CheatType != analyst.TypeMixed {
		t.Fatalf("new evidence must make a new case: %d calls, %+v", h.prov.calls.Load(), v2)
	}

	// A weaker later match does not replace the session's worst one.
	h.eng.MatchFinished("studio", "m2", []pipeline.MatchPlayer{{Session: cheat, Slot: 1, Stats: analyzer.PlayerSummary{TickRate: 64, AimSamples: 64 * 600}}}, h.clock())
	h.flush()
	if sc, _ := h.st.GetOracleScore(ctx, "studio", "s-cheat"); sc.MatchID != "m1" || sc.Band != store.OracleBandReview {
		t.Fatalf("score after a clean match: %+v", sc)
	}

	// Nothing at the default log level, and nothing of the bundle in any of it.
	if out := h.logs.String(); out != "" {
		t.Errorf("the engine logged at the default level:\n%s", out)
	}
}

func TestEngineClientOnlySession(t *testing.T) {
	h := newHarness(t, true, nil)
	ctx := context.Background()
	s := h.session("s-tamper", "p-tamper", 2)
	_ = h.st.AddEvidence(ctx, []store.Evidence{{TenantID: "studio", PlayerHash: "p-tamper", SessionID: "s-tamper", Source: store.SourceClient,
		Rule: "unbacked_exec", Severity: 4, Score: 0.9, Integrity: true, ObservedAt: h.clock()}})
	h.eng.SessionActivity(s, true, h.clock())
	h.flush()
	sc, err := h.st.GetOracleScore(ctx, "studio", "s-tamper")
	if err != nil || sc.MatchID != "" || sc.Band != store.OracleBandReview {
		t.Fatalf("a session with integrity evidence and no match must still be scored: %+v %v", sc, err)
	}
	v, err := h.st.GetOracleVerdict(ctx, "studio", "s-tamper")
	if err != nil || v.CheatType != analyst.TypeTampering || v.Action != analyst.ActionPriority {
		t.Fatalf("verdict: %+v %v", v, err)
	}
	// Heartbeats without news rescore at most once per Rescore interval.
	first := sc.UpdatedAt
	h.advance(10 * time.Second)
	h.eng.SessionActivity(s, false, h.clock())
	h.flush()
	if sc, _ := h.st.GetOracleScore(ctx, "studio", "s-tamper"); !sc.UpdatedAt.Equal(first) {
		t.Error("rescored on a heartbeat without news inside the interval")
	}
}

func TestEngineDefersReviewUntilSessionEnds(t *testing.T) {
	h := newHarness(t, true, func(c *Config) { c.ReviewLive, c.EndedAfter = false, time.Minute })
	ctx := context.Background()
	s := h.session("s1", "p1", 1)
	_ = h.st.AddEvidence(ctx, []store.Evidence{{TenantID: "studio", PlayerHash: "p1", SessionID: "s1", Source: store.SourceGameplay, Rule: "angle_snap", Severity: 3, Score: 0.9, ObservedAt: h.clock()}})
	h.eng.MatchFinished("studio", "m1", []pipeline.MatchPlayer{{Session: s, Slot: 1, Stats: cheaterStats()}}, h.clock())
	time.Sleep(300 * time.Millisecond)
	if sc, err := h.st.GetOracleScore(ctx, "studio", "s1"); err != nil || sc.Band != store.OracleBandReview {
		t.Fatalf("scoring is live: %+v %v", sc, err)
	}
	if h.prov.calls.Load() != 0 {
		t.Fatal("the analyst ran while the session was still connected")
	}
	// The gateway closes the session: the case is reviewed.
	s.State = store.SessionClosed
	_ = h.st.PutSession(ctx, &s)
	h.advance(20 * time.Second)
	h.flush()
	if v, err := h.st.GetOracleVerdict(ctx, "studio", "s1"); err != nil || v.Status != store.OracleVerdictOK || h.prov.calls.Load() != 1 {
		t.Fatalf("after the session ended: %+v %v", v, err)
	}

	// A session that just goes silent counts as ended after EndedAfter.
	s2 := h.session("s2", "p2", 1)
	_ = h.st.AddEvidence(ctx, []store.Evidence{{TenantID: "studio", PlayerHash: "p2", SessionID: "s2", Source: store.SourceClient, Rule: "code_patch", Severity: 3, Score: 0.9, Integrity: true, ObservedAt: h.clock()}})
	h.eng.SessionActivity(s2, true, h.clock())
	time.Sleep(200 * time.Millisecond)
	if h.prov.calls.Load() != 1 {
		t.Fatal("reviewed a live session")
	}
	h.advance(2 * time.Minute)
	h.flush()
	if h.prov.calls.Load() != 2 {
		t.Fatal("a silent session was never reviewed")
	}
}

func TestEngineWithoutAnalystStillScores(t *testing.T) {
	h := newHarness(t, false, nil)
	s := h.session("s1", "p1", 0)
	h.eng.MatchFinished("studio", "m1", []pipeline.MatchPlayer{{Session: s, Slot: 1, Stats: cheaterStats()}}, h.clock())
	h.flush()
	if sc, err := h.st.GetOracleScore(context.Background(), "studio", "s1"); err != nil || sc.Band != store.OracleBandReview {
		t.Fatalf("%+v %v", sc, err)
	}
	if _, err := h.st.GetOracleVerdict(context.Background(), "studio", "s1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a verdict without an analyst")
	}
	if st := h.eng.Status(); st.Analyst != "off" || st.BundleID == "" || st.ModelID == "" || st.FeatureVersion != FeatureVersion {
		t.Fatalf("status: %+v", st)
	}
}

// The pipeline calls the engine on its worker: the calls must return at once even when
// nothing is draining the queue.
func TestObserverNeverBlocks(t *testing.T) {
	dir := t.TempDir()
	writeTestBundle(t, dir, Thresholds{Watch: 0.2, Review: 0.6})
	b, _ := LoadBundle(dir)
	logs := &syncBuffer{}
	eng, err := New(Config{Bundle: b, PseudonymKey: []byte("0123456789abcdef"), QueueSize: 4}, store.NewMemory(), slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for range 1000 { // Run was never started
		eng.SessionActivity(store.Session{SessionID: "s", TenantID: "t"}, true, start)
		eng.MatchFinished("t", "m", nil, start)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("2000 observer calls took %v with a full queue", d)
	}
	if eng.dropped.Load() != 1996 || strings.Count(logs.String(), "behind") != 1 {
		t.Fatalf("dropped %d, log:\n%s", eng.dropped.Load(), logs.String())
	}
	if _, err := New(Config{Bundle: b, PseudonymKey: []byte("short")}, store.NewMemory(), slog.Default()); err == nil {
		t.Error("a short pseudonym key was accepted")
	}
}
