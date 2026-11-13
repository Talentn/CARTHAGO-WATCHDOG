package pipeline

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/knowledge"
	"carthago/backend/internal/knowledge/bsptree"
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

func noticeList(n *notices) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for id, list := range n.got {
		for _, x := range list {
			out = append(out, id+" "+noticeCategoryName(x.category)+" "+strings.ToLower(strings.TrimPrefix(x.severity.String(), "ENFORCEMENT_SEVERITY_")))
		}
	}
	sort.Strings(out)
	return out
}

func leakRules(t *testing.T, st *store.Memory, tenant, match string) map[string][]store.Evidence {
	t.Helper()
	evs, _ := st.ListEvidence(context.Background(), tenant, store.EvidenceFilter{Limit: 1000})
	out := map[string][]store.Evidence{}
	for _, e := range evs {
		if e.MatchID == match && strings.HasPrefix(e.Rule, RuleInformationLeak) {
			out[e.Rule] = append(out[e.Rule], e)
		}
	}
	return out
}

func TestMapPins(t *testing.T) {
	hash, _, err := knowledge.GeometryHash(synth.YardGeometry())
	if err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("ab", 32)

	// The pinned geometry: scored, and the evidence says the map was pinned.
	p, st, _ := newTest(t, Config{MapPins: map[string]string{synth.YardID: strings.ToUpper(hash)}, MapPinsRequired: true})
	if w := feed(t, p, "t1", synth.Batches(leakMatch("pin-ok", 1800))); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	leaks := leakRules(t, st, "t1", "pin-ok")[RuleInformationLeak]
	if len(leaks) != 1 || !strings.Contains(leaks[0].Raw, "pinned by the operator") || !strings.Contains(leaks[0].Raw, hash) {
		t.Fatalf("pinned map: %+v", leaks)
	}

	// Another geometry under a pinned name: refused, nothing scored, nothing stored.
	p, st, _ = newTest(t, Config{MapPins: map[string]string{synth.YardID: other}})
	w := feed(t, p, "t1", synth.Batches(leakMatch("pin-wrong", 1800)))
	if len(w) != 1 || !strings.Contains(w[0], "is not the pinned one") {
		t.Fatalf("wrong geometry: %v", w)
	}
	if len(leakRules(t, st, "t1", "pin-wrong")) != 0 {
		t.Fatal("a match on a refused map was scored")
	}
	if _, err := st.GetMap(context.Background(), "t1", synth.YardID, 1); err == nil {
		t.Fatal("a refused geometry was stored")
	}
	sums, _ := st.ListGameplaySummaries(context.Background(), "t1", store.GameplayFilter{MatchID: "pin-wrong"})
	if len(sums) != 10 || sums[0].LeakScored || sums[0].MotionSamples == 0 {
		t.Fatalf("the match itself must still be taken in: %+v", sums)
	}

	// A geometry stored before the pin existed does not get round it.
	st2 := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p1 := New(Config{}, st2, st2, nil, log)
	feed(t, p1, "t1", synth.Batches(leakMatch("pin-before", 20)))
	p1.Close()
	p2 := New(Config{MapPins: map[string]string{synth.YardID: other}}, st2, st2, nil, log)
	t.Cleanup(p2.Close)
	bs := synth.Batches(leakMatch("pin-after", 1800))
	bs[0].MapGeometry = nil
	w = feed(t, p2, "t1", bs)
	if len(w) != 1 || !strings.Contains(w[0], "is not the pinned one") || len(leakRules(t, st2, "t1", "pin-after")) != 0 {
		t.Fatalf("stored geometry against a later pin: %v", w)
	}

	// Pins required and the map not listed: refused. Not required: used, marked as not pinned.
	p, st, _ = newTest(t, Config{MapPins: map[string]string{"de_other": other}, MapPinsRequired: true})
	w = feed(t, p, "t1", synth.Batches(leakMatch("pin-missing", 1800)))
	if len(w) != 1 || !strings.Contains(w[0], "has no pinned geometry") || len(leakRules(t, st, "t1", "pin-missing")) != 0 {
		t.Fatalf("unlisted map with pins required: %v", w)
	}
	p, st, _ = newTest(t, Config{MapPins: map[string]string{"de_other": other}})
	if w := feed(t, p, "t1", synth.Batches(leakMatch("pin-none", 1800))); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	leaks = leakRules(t, st, "t1", "pin-none")[RuleInformationLeak]
	if len(leaks) != 1 || !strings.Contains(leaks[0].Raw, "not pinned: taken as the game server sent it") {
		t.Fatalf("unpinned map: %+v", leaks)
	}
}

// A geometry whose walls contain the players is not the map being played: no score.
func TestMapThatDoesNotMatchTheMatch(t *testing.T) {
	// One solid slab over the whole yard, from below the floor to above the eyes.
	tree, err := bsptree.Build([]bsptree.Brush{bsptree.Box(-10, -10, -1, 70, 50, 3)})
	if err != nil {
		t.Fatal(err)
	}
	p, st, _ := newTest(t, Config{})
	bs := synth.Batches(leakMatch("wrong-map", 1800))
	bs[0].MapGeometry = &pb.MapGeometry{MapId: "de_wrong", Version: 7, Solid: tree.Proto(100)}
	for _, b := range bs {
		b.Map = &pb.MapRef{MapId: "de_wrong", Version: 7}
	}
	w := feed(t, p, "t1", bs)
	if len(w) != 1 || !strings.Contains(w[0], "does not match the match") || !strings.Contains(w[0], "inside its walls") {
		t.Fatalf("warnings: %v", w)
	}
	if got := leakRules(t, st, "t1", "wrong-map"); len(got) != 0 {
		t.Fatalf("scored on a map that does not match: %+v", got)
	}
	sums, _ := st.ListGameplaySummaries(context.Background(), "t1", store.GameplayFilter{MatchID: "wrong-map"})
	if len(sums) != 10 || sums[0].LeakScored {
		t.Fatalf("summaries: %+v", sums)
	}
}

func TestLiveLeakRuleIsOptIn(t *testing.T) {
	spec := leakMatch("live-1", 1800)
	bs := synth.Batches(spec)
	run := func(cfg Config) (map[string][]store.Evidence, *notices, *kicks) {
		p, st, k := newTest(t, cfg)
		n := &notices{}
		p.SetNotifier(n)
		for _, ps := range spec.Players {
			session(st, ps.SessionID, "t1", ps.PlayerHash)
		}
		if w := feed(t, p, "t1", bs); len(w) != 0 {
			t.Fatalf("warnings: %v", w)
		}
		return leakRules(t, st, "t1", "live-1"), n, k
	}

	// Off (the default): the review flag at the end of the match and nothing else, even
	// with notices on.
	got, n, _ := run(Config{Notices: true, NoticesOptIn: true})
	if len(got[RuleInformationLeak]) != 1 || len(got[RuleInformationLeakLive]) != 0 || len(noticeList(n)) != 0 {
		t.Fatalf("default: %d review flags, %d live, notices %v", len(got[RuleInformationLeak]), len(got[RuleInformationLeakLive]), noticeList(n))
	}

	// On: the informed slot, once, during the match; its session is told; nobody is kicked.
	alert := knowledge.DefaultAlert()
	got, n, k := run(Config{Notices: true, LeakAlert: &alert, AutoKick: true, AutoKickSeverity: analyzer.SeverityInfo})
	live := got[RuleInformationLeakLive]
	if len(live) != 1 || live[0].SessionID != "sess-synth-2-informed" || live[0].Integrity || !strings.Contains(live[0].Summary, "Opt-in live wallhack rule") ||
		!strings.Contains(live[0].Summary, "not proof") {
		t.Fatalf("live evidence: %+v", live)
	}
	if len(got[RuleInformationLeak]) != 1 {
		t.Fatalf("the review flag must not change: %+v", got[RuleInformationLeak])
	}
	want := []string{"sess-synth-2-informed visibility high"}
	if l := noticeList(n); len(l) != 1 || l[0] != want[0] {
		t.Fatalf("notices: %v", l)
	}
	for _, ps := range spec.Players {
		if r := k.reason(ps.SessionID); r != "" {
			t.Fatalf("%s kicked: %s", ps.SessionID, r)
		}
	}

	// On without notices: evidence only.
	got, n, _ = run(Config{LeakAlert: &alert})
	if len(got[RuleInformationLeakLive]) != 1 || len(noticeList(n)) != 0 {
		t.Fatalf("no notices configured: %d live, notices %v", len(got[RuleInformationLeakLive]), noticeList(n))
	}

	// A slot without a verified session is never told.
	p, st, _ := newTest(t, Config{Notices: true, LeakAlert: &alert})
	n = &notices{}
	p.SetNotifier(n)
	unbound := leakMatch("live-2", 1800)
	for i := range unbound.Players {
		unbound.Players[i].SessionID = ""
	}
	feed(t, p, "t1", synth.Batches(unbound))
	if got := leakRules(t, st, "t1", "live-2"); len(got[RuleInformationLeakLive]) != 1 || got[RuleInformationLeakLive][0].SessionID != "" || len(noticeList(n)) != 0 {
		t.Fatalf("unbound slot: %+v, notices %v", got[RuleInformationLeakLive], noticeList(n))
	}
}
