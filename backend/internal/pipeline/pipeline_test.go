package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/store"
)

type kicks struct {
	mu  sync.Mutex
	got map[string]string
}

func (k *kicks) Kick(id, reason string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.got == nil {
		k.got = map[string]string{}
	}
	k.got[id] = reason
}

func (k *kicks) reason(id string) string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.got[id]
}

func newTest(t *testing.T, cfg Config) (*Pipeline, *store.Memory, *kicks) {
	st := store.NewMemory()
	k := &kicks{}
	p := New(cfg, st, st, k, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(p.Close)
	return p, st, k
}

// flush waits until everything queued so far has been processed.
func flush(p *Pipeline) {
	done := make(chan struct{})
	for !p.enqueue(func() { close(done) }) {
		time.Sleep(time.Millisecond)
	}
	<-done
}

func session(st *store.Memory, id, tenant, player string) store.Session {
	s := store.Session{SessionID: id, TenantID: tenant, PlayerHash: player, State: store.SessionActive, CreatedAt: time.Now()}
	_ = st.PutSession(context.Background(), &s)
	return s
}

func finding(code pb.FindingCode, a, b uint64, detail string) *pb.Finding {
	return &pb.Finding{Job: "test", Code: uint32(code), A: a, B: b, Detail: detail}
}

func TestHeartbeatEvidenceAndTelemetry(t *testing.T) {
	p, st, k := newTest(t, Config{})
	s := session(st, "s1", "t1", "alice")
	hb := &pb.Heartbeat{
		Sched: &pb.SchedSummary{WorkerCpuNs: 5e6, Slices: 40, SliceOverruns: 1},
		Findings: []*pb.Finding{
			finding(pb.FindingCode_FINDING_CODE_MITIGATIONS, 3, 0, ""),
			finding(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, 42, 0x80020, "steam.exe"),
			finding(pb.FindingCode_FINDING_CODE_MODULE_LOADED, 0x7ff0000, 1, "game_plugin.dll"),
			finding(pb.FindingCode_FINDING_CODE_CODE_PATCH, 0x7ff1000, 0x1000, "d3d11.dll>?"),
		},
		Coverage: []*pb.JobCoverage{{Job: "api_hooks", RunsCompleted: 3}},
	}
	p.Heartbeat(s, hb)
	p.Heartbeat(s, hb) // the same findings again: deduped per session
	flush(p)

	evs, _ := st.ListEvidence(context.Background(), "t1", store.EvidenceFilter{})
	if len(evs) != 2 {
		t.Fatalf("want overlay (info) + code_patch, got %+v", evs)
	}
	bySev := map[string]store.Evidence{}
	for _, e := range evs {
		bySev[e.Rule] = e
	}
	if e := bySev["code_patch"]; e.Severity != 3 || !e.Integrity || e.PlayerHash != "alice" || e.Raw == "" {
		t.Fatalf("code_patch evidence: %+v", e)
	}
	if e := bySev["overlay_window"]; e.Severity != 0 {
		t.Fatalf("allowlisted overlay must be info: %+v", e)
	}
	if k.reason("s1") != "" {
		t.Fatal("auto-kick is off by default")
	}
	tel, err := st.GetTelemetry(context.Background(), "t1", "s1")
	if err != nil || tel.MitigationsApplied != 3 || tel.FindingsTotal != 8 || tel.SliceOverruns != 1 || tel.Coverage == "" {
		t.Fatalf("telemetry: %+v %v", tel, err)
	}
}

func TestAutoKickOnlyOnIntegrity(t *testing.T) {
	p, st, k := newTest(t, Config{AutoKick: true})
	a := session(st, "a", "t1", "alice")
	b := session(st, "b", "t1", "bob")
	p.Heartbeat(a, &pb.Heartbeat{Findings: []*pb.Finding{finding(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, 1, 0, "unknown.exe")}})
	// A graphics hook is what overlays do, and one through a relay page cannot be attributed.
	p.Heartbeat(a, &pb.Heartbeat{Findings: []*pb.Finding{finding(pb.FindingCode_FINDING_CODE_CODE_PATCH, 1, 2, "dxgi.dll>?")}})
	mapped := uint64(pb.UnbackedFlags_UNBACKED_FLAGS_WRITABLE|pb.UnbackedFlags_UNBACKED_FLAGS_PE_SIGNATURE) << 48
	p.Heartbeat(b, &pb.Heartbeat{Findings: []*pb.Finding{finding(pb.FindingCode_FINDING_CODE_UNBACKED_EXEC, 1, 0x2000|mapped, "")}})
	flush(p)
	if r := k.reason("a"); r != "" {
		t.Fatalf("overlay or graphics hook kicked: %q", r)
	}
	if r := k.reason("b"); r != "integrity_violation: unbacked_exec" {
		t.Fatalf("manually mapped image not kicked: %q", r)
	}
}

func cheaterBatch(seq uint64, players []*pb.MatchPlayer, over bool) *pb.GameplayBatch {
	var cw []*pb.CommandWindow
	for w := range uint32(5) {
		from := uint32(seq)*1000 + w*64
		cw = append(cw, &pb.CommandWindow{Slot: 1, TickFrom: from, TickTo: from + 64, Commands: 64})
		cw = append(cw, &pb.CommandWindow{Slot: 2, TickFrom: from, TickTo: from + 64, Commands: 85})
	}
	return &pb.GameplayBatch{MatchId: "m1", BatchSeq: seq, TickRate: 64, Players: players, Commands: cw, MatchOver: over}
}

func TestGameplayIdempotentAndTenantChecked(t *testing.T) {
	p, st, _ := newTest(t, Config{})
	session(st, "sess-honest", "t1", "honest")
	session(st, "sess-cheat", "t1", "cheater")
	session(st, "sess-foreign", "t2", "victim")
	ctx := context.Background()
	players := []*pb.MatchPlayer{{Slot: 1, SessionId: "sess-honest", PlayerHash: "spoofed"}, {Slot: 2, SessionId: "sess-cheat"}}

	ok, _, err := p.Gameplay(ctx, "t1", cheaterBatch(1, players, false))
	if err != nil || !ok {
		t.Fatalf("batch 1: %v %v", ok, err)
	}
	if ok, _, err := p.Gameplay(ctx, "t1", cheaterBatch(1, players, false)); err != nil || ok {
		t.Fatalf("retried batch 1 must be acked as duplicate: %v %v", ok, err)
	}
	if ok, _, _ := p.Gameplay(ctx, "t1", cheaterBatch(2, nil, true)); !ok {
		t.Fatal("batch 2")
	}
	evs, _ := st.ListEvidence(ctx, "t1", store.EvidenceFilter{})
	if len(evs) != 1 || evs[0].Rule != "command_rate" || evs[0].PlayerHash != "cheater" || evs[0].SessionID != "sess-cheat" || evs[0].MatchID != "m1" {
		t.Fatalf("evidence: %+v", evs)
	}

	// A t1 game server naming a t2 session: the link is dropped.
	foreign := []*pb.MatchPlayer{{Slot: 2, SessionId: "sess-foreign", PlayerHash: "p2"}}
	b := cheaterBatch(1, foreign, true)
	b.MatchId = "m2"
	if ok, _, err := p.Gameplay(ctx, "t1", b); !ok || err != nil {
		t.Fatalf("m2: %v %v", ok, err)
	}
	evs, _ = st.ListEvidence(ctx, "t1", store.EvidenceFilter{})
	for _, e := range evs {
		if e.MatchID == "m2" && (e.SessionID != "" || e.PlayerHash != "p2") {
			t.Fatalf("foreign session linked: %+v", e)
		}
	}
	if x, _ := st.ListEvidence(ctx, "t2", store.EvidenceFilter{}); len(x) != 0 {
		t.Fatalf("evidence leaked into t2: %+v", x)
	}
	if _, _, err := p.Gameplay(ctx, "t1", &pb.GameplayBatch{}); err == nil {
		t.Fatal("empty match id accepted")
	}
}

func TestBackpressure(t *testing.T) {
	p, st, _ := newTest(t, Config{QueueSize: 2})
	s := session(st, "s1", "t1", "alice")
	block := make(chan struct{})
	started := make(chan struct{})
	p.enqueue(func() { close(started); <-block })
	<-started
	p.enqueue(func() {})
	p.enqueue(func() {})
	p.Heartbeat(s, &pb.Heartbeat{})
	if p.Dropped() != 1 {
		t.Fatalf("dropped %d", p.Dropped())
	}
	if _, _, err := p.Gameplay(context.Background(), "t1", cheaterBatch(1, nil, false)); !errors.Is(err, ErrBusy) {
		t.Fatalf("full queue: %v", err)
	}
	close(block)
	flush(p)
	if ok, _, err := p.Gameplay(context.Background(), "t1", cheaterBatch(1, nil, false)); !ok || err != nil {
		t.Fatalf("retry after busy must be accepted: %v %v", ok, err)
	}
}

// A client that sprays distinct findings, whatever their severity, gets a bounded number of
// evidence rows and one note saying so.
func TestEvidencePerSessionIsCapped(t *testing.T) {
	p, st, _ := newTest(t, Config{})
	s := session(st, "s1", "t1", "alice")
	for i := 0; i < maxSeenPerSession+500; i += 100 {
		hb := &pb.Heartbeat{}
		for j := range 100 {
			hb.Findings = append(hb.Findings, finding(pb.FindingCode_FINDING_CODE_THREAD_START_UNBACKED, uint64(0x1000*(i+j+1)), 7, ""))
		}
		p.Heartbeat(s, hb)
	}
	flush(p)
	evs, _ := st.ListEvidence(context.Background(), "t1", store.EvidenceFilter{SessionID: "s1", Limit: 1000})
	total, _ := st.Overview(context.Background(), "t1", time.Time{}, time.Time{})
	floods := 0
	for _, e := range evs {
		if e.Rule == "evidence_flood" {
			floods++
			if e.Integrity || e.Severity != 1 {
				t.Fatalf("flood note must be low and not integrity evidence: %+v", e)
			}
		}
	}
	if total.Evidence != maxSeenPerSession+1 || floods != 1 {
		t.Fatalf("%d evidence rows with %d flood notes, want %d and 1", total.Evidence, floods, maxSeenPerSession+1)
	}

	// Informational findings are recorded once per rule and module, not once per address.
	b := session(st, "s2", "t1", "bob")
	hb := &pb.Heartbeat{}
	for j := range 60 {
		hb.Findings = append(hb.Findings, finding(pb.FindingCode_FINDING_CODE_UNBACKED_EXEC, uint64(0x10000*(j+1)), 0x1000, ""))
		hb.Findings = append(hb.Findings, finding(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, uint64(j), 0, "steam.exe"))
	}
	p.Heartbeat(b, hb)
	flush(p)
	if evs, _ := st.ListEvidence(context.Background(), "t1", store.EvidenceFilter{SessionID: "s2", Limit: 1000}); len(evs) != 2 {
		t.Fatalf("want one row per informational rule, got %d", len(evs))
	}
}

// Behavioural evidence is statistical: it must never kick, even with auto-kick on and the
// severity threshold at its lowest.
func TestGameplayEvidenceNeverKicks(t *testing.T) {
	p, st, k := newTest(t, Config{AutoKick: true, AutoKickSeverity: 1})
	session(st, "sess-cheat", "t1", "cheater")
	ctx := context.Background()
	players := []*pb.MatchPlayer{{Slot: 2, SessionId: "sess-cheat"}}
	for seq := uint64(1); seq <= 3; seq++ {
		if ok, _, err := p.Gameplay(ctx, "t1", cheaterBatch(seq, players, seq == 3)); !ok || err != nil {
			t.Fatalf("batch %d: %v %v", seq, ok, err)
		}
	}
	flush(p)
	evs, _ := st.ListEvidence(ctx, "t1", store.EvidenceFilter{SessionID: "sess-cheat"})
	if len(evs) == 0 {
		t.Fatal("fixture: the speedhack batches produced no evidence")
	}
	for _, e := range evs {
		if e.Integrity || e.Source != store.SourceGameplay {
			t.Fatalf("gameplay evidence marked as integrity evidence: %+v", e)
		}
	}
	if r := k.reason("sess-cheat"); r != "" {
		t.Fatalf("behavioural evidence kicked the session: %q", r)
	}
}

func TestOpenMatchesPerTenantAreBounded(t *testing.T) {
	p, _, _ := newTest(t, Config{MaxMatchesPerTenant: 2})
	ctx := context.Background()
	batch := func(match string, seq uint64, over bool) *pb.GameplayBatch {
		return &pb.GameplayBatch{MatchId: match, BatchSeq: seq, TickRate: 64, MatchOver: over}
	}
	for _, m := range []string{"a", "b"} {
		if ok, _, err := p.Gameplay(ctx, "t1", batch(m, 1, false)); !ok || err != nil {
			t.Fatalf("match %s: %v %v", m, ok, err)
		}
	}
	if ok, _, err := p.Gameplay(ctx, "t1", batch("c", 1, false)); ok || err == nil || errors.Is(err, ErrBusy) {
		t.Fatalf("third open match: accepted=%v err=%v", ok, err)
	}
	// Another tenant has its own budget, and an open match keeps receiving batches.
	if ok, _, err := p.Gameplay(ctx, "t2", batch("c", 1, false)); !ok || err != nil {
		t.Fatalf("other tenant: %v %v", ok, err)
	}
	if ok, _, err := p.Gameplay(ctx, "t1", batch("a", 2, true)); !ok || err != nil {
		t.Fatalf("match a batch 2: %v %v", ok, err)
	}
	// The refused batch did not advance its match: the same sequence number is accepted once
	// there is room.
	if ok, _, err := p.Gameplay(ctx, "t1", batch("c", 1, false)); !ok || err != nil {
		t.Fatalf("match c after a ended: %v %v", ok, err)
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  []byte
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b = append(l.b, p...)
	return len(p), nil
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return string(l.b)
}

// Losing analysis to a full queue must show up in the log, not only in a counter nobody reads.
func TestDroppedHeartbeatsAreLogged(t *testing.T) {
	st := store.NewMemory()
	var buf lockedBuf
	p := New(Config{QueueSize: 1}, st, st, nil, slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(p.Close)
	s := session(st, "s1", "t1", "alice")
	block, started := make(chan struct{}), make(chan struct{})
	p.enqueue(func() { close(started); <-block })
	<-started
	p.enqueue(func() {})
	p.Heartbeat(s, &pb.Heartbeat{})
	p.Heartbeat(s, &pb.Heartbeat{})
	close(block)
	flush(p)
	p.enqueue(p.prune)
	flush(p)
	if out := buf.String(); !strings.Contains(out, "heartbeat analyses dropped") || !strings.Contains(out, "since_last_report=2") {
		t.Fatalf("no report of 2 dropped analyses in the log: %q", out)
	}
	p.enqueue(p.prune)
	flush(p)
	if n := strings.Count(buf.String(), "heartbeat analyses dropped"); n != 1 {
		t.Fatalf("reported %d times without new drops", n)
	}
}
