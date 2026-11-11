package pipeline

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/knowledge/synth"
	"carthago/backend/internal/store"
)

func leakMatch(id string, seconds int) synth.Spec {
	mode := pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER
	roles := []synth.Role{synth.RoleLegit, synth.RoleInformed, synth.RolePrefire, synth.RoleSound, synth.RoleTeamCall,
		synth.RoleLegit, synth.RoleLegit, synth.RolePrefire, synth.RoleSound, synth.RoleTeamCall}
	ps := synth.DefaultPlayers(mode, 1, roles)
	for i := range ps {
		ps[i].SessionID = "sess-" + ps[i].PlayerHash
	}
	return synth.Spec{MatchID: id, Mode: mode, TickRate: 64, Seconds: seconds, Seed: 11, Players: ps}
}

func feed(t *testing.T, p *Pipeline, tenant string, bs []*pb.GameplayBatch) []string {
	t.Helper()
	var warnings []string
	for _, b := range bs {
		ok, w, err := p.Gameplay(context.Background(), tenant, b)
		if err != nil || !ok {
			t.Fatalf("batch %d: %v %v", b.BatchSeq, ok, err)
		}
		if w != "" {
			warnings = append(warnings, w)
		}
	}
	return warnings
}

func TestInformationLeakIsFlagOnly(t *testing.T) {
	// Auto-kick on, at the lowest severity: only integrity evidence may ever kick, and an
	// information-leak flag is never integrity evidence.
	p, st, k := newTest(t, Config{AutoKick: true, AutoKickSeverity: analyzer.SeverityInfo})
	spec := leakMatch("leak-1", 1800)
	for _, ps := range spec.Players {
		session(st, ps.SessionID, "t1", ps.PlayerHash)
	}
	bs := synth.Batches(spec)
	if w := feed(t, p, "t1", bs); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}

	ctx := context.Background()
	evs, _ := st.ListEvidence(ctx, "t1", store.EvidenceFilter{Limit: 1000})
	var leaks []store.Evidence
	for _, e := range evs {
		if e.Rule == RuleInformationLeak {
			leaks = append(leaks, e)
		}
	}
	if len(leaks) != 1 {
		t.Fatalf("want one information_leak (the informed slot), got %d: %+v", len(leaks), leaks)
	}
	e := leaks[0]
	if e.SessionID != "sess-synth-2-informed" || e.Integrity || e.Severity < int(analyzer.SeverityMedium) || e.Source != store.SourceGameplay {
		t.Fatalf("evidence: %+v", e)
	}
	var raw struct {
		Slot     uint32 `json:"slot"`
		Policy   string `json:"policy"`
		Moments  []any  `json:"moments"`
		Replay   any    `json:"replay"`
		Segment  string `json:"segment"`
		Features []struct {
			Name   string `json:"name"`
			Scored bool   `json:"scored"`
		} `json:"features"`
	}
	if err := json.Unmarshal([]byte(e.Raw), &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Slot != 2 || len(raw.Moments) == 0 || raw.Replay == nil || raw.Segment != "competitive_shooter/mouse_keyboard" ||
		!strings.Contains(raw.Policy, "never triggers an automatic kick") || len(raw.Features) != 4 {
		t.Fatalf("explanation: %+v", raw)
	}
	for _, ps := range spec.Players {
		if r := k.reason(ps.SessionID); r != "" {
			t.Fatalf("%s kicked: %s", ps.SessionID, r)
		}
	}

	sums, _ := st.ListGameplaySummaries(ctx, "t1", store.GameplayFilter{MatchID: "leak-1"})
	if len(sums) != 10 {
		t.Fatalf("summaries: %d", len(sums))
	}
	for _, s := range sums {
		if !s.LeakScored || s.MapID != "carthago-yard" || s.SchemaVersion != 2 || s.MotionSamples == 0 || s.Batches == 0 || s.Mode != "competitive_shooter" {
			t.Fatalf("summary: %+v", s)
		}
		if s.LeakFlagged != (s.Slot == 2) {
			t.Fatalf("slot %d flagged=%v score %.2f", s.Slot, s.LeakFlagged, s.LeakScore)
		}
		if s.SessionID != "sess-"+s.PlayerHash {
			t.Fatalf("summary session: %+v", s)
		}
	}
	raws, _ := st.ListGameplayBatches(ctx, "t1", "leak-1", 0)
	if len(raws) != len(bs) {
		t.Fatalf("raw batches %d of %d", len(raws), len(bs))
	}
	var back pb.GameplayBatch
	if err := proto.Unmarshal(raws[0].Data, &back); err != nil || back.MapGeometry == nil {
		t.Fatalf("raw batch: %v", err)
	}
	if _, err := st.GetMap(ctx, "t1", "carthago-yard", 1); err != nil {
		t.Fatalf("map not stored: %v", err)
	}
}

func TestMapReferenceAndConflicts(t *testing.T) {
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p1 := New(Config{}, st, st, nil, log)
	feed(t, p1, "t1", synth.Batches(leakMatch("m-upload", 20)))
	p1.Close()

	// A fresh gateway process resolves a MapRef from the store, without the geometry.
	p2 := New(Config{}, st, st, nil, log)
	t.Cleanup(p2.Close)
	bs := synth.Batches(leakMatch("m-ref", 20))
	bs[0].MapGeometry = nil
	if w := feed(t, p2, "t1", bs); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	sums, _ := st.ListGameplaySummaries(context.Background(), "t1", store.GameplayFilter{MatchID: "m-ref"})
	if len(sums) == 0 || !sums[0].LeakScored {
		t.Fatalf("match on a referenced map not scored: %+v", sums)
	}

	// Another tenant never sees t1's map.
	bs = synth.Batches(leakMatch("m-other", 20))
	bs[0].MapGeometry = nil
	w := feed(t, p2, "t2", bs)
	if len(w) != 1 || !strings.Contains(w[0], "unknown") {
		t.Fatalf("other tenant: %v", w)
	}

	// Same version, different geometry: refused once, the match still ingests.
	bs = synth.Batches(leakMatch("m-conflict", 20))
	bs[0].MapGeometry.Occluders = bs[0].MapGeometry.Occluders[1:]
	w = feed(t, p2, "t1", bs)
	if len(w) != 1 || !strings.Contains(w[0], "bump the version") {
		t.Fatalf("conflict: %v", w)
	}

	// Invalid geometry is refused with a reason; v1 rules keep running.
	bs = synth.Batches(leakMatch("m-bad", 20))
	bs[0].MapGeometry.Version = 2
	bs[0].MapGeometry.Occluders[0].XyCm = []int32{0, 0, 100, 0}
	bs[0].Map.Version = 2
	w = feed(t, p2, "t1", bs)
	if len(w) != 1 || !strings.Contains(w[0], "map geometry refused") {
		t.Fatalf("invalid: %v", w)
	}
}

func TestV1BatchesSkipV2(t *testing.T) {
	p, st, _ := newTest(t, Config{})
	if ok, w, err := p.Gameplay(context.Background(), "t1", cheaterBatch(1, nil, true)); !ok || w != "" || err != nil {
		t.Fatalf("v1 batch: %v %q %v", ok, w, err)
	}
	flush(p)
	if sums, _ := st.ListGameplaySummaries(context.Background(), "t1", store.GameplayFilter{}); len(sums) != 0 {
		t.Fatalf("v1 batch produced v2 summaries: %+v", sums)
	}
}
