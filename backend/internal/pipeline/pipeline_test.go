package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
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
	if e := bySev["code_patch"]; e.Severity != 4 || !e.Integrity || e.PlayerHash != "alice" || e.Raw == "" {
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
	p.Heartbeat(b, &pb.Heartbeat{Findings: []*pb.Finding{finding(pb.FindingCode_FINDING_CODE_CODE_PATCH, 1, 2, "dxgi.dll>x")}})
	flush(p)
	if r := k.reason("a"); r != "" {
		t.Fatalf("overlay kicked: %q", r)
	}
	if r := k.reason("b"); r != "integrity_violation: code_patch" {
		t.Fatalf("code patch not kicked: %q", r)
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

// A bot slot's gameplay evidence is labelled; a slot with a verified session is a person
// even when the game server calls it a bot.
func TestBotSlotsAreLabelledUnlessSessionBound(t *testing.T) {
	p, st, _ := newTest(t, Config{})
	session(st, "sess-human", "t1", "human")
	ctx := context.Background()
	players := []*pb.MatchPlayer{
		{Slot: 1, SessionId: "sess-human", Bot: true},
		{Slot: 2, PlayerHash: "bot:Hawk", Bot: true},
	}
	b := cheaterBatch(1, players, true)
	for _, c := range b.Commands {
		c.Commands = 85
	}
	if ok, _, err := p.Gameplay(ctx, "t1", b); !ok || err != nil {
		t.Fatalf("batch: %v %v", ok, err)
	}
	evs, _ := st.ListEvidence(ctx, "t1", store.EvidenceFilter{})
	if len(evs) != 2 {
		t.Fatalf("evidence: %+v", evs)
	}
	for _, e := range evs {
		switch e.PlayerHash {
		case "human":
			if e.Bot || e.SessionID != "sess-human" {
				t.Fatalf("session-bound slot treated as a bot: %+v", e)
			}
		case "bot:Hawk":
			if !e.Bot || e.SessionID != "" {
				t.Fatalf("bot slot not labelled: %+v", e)
			}
		default:
			t.Fatalf("unexpected evidence: %+v", e)
		}
	}
	rows, _ := st.ListPlayers(ctx, "t1", store.PlayerFilter{FlaggedOnly: true})
	if len(rows) != 1 || rows[0].PlayerHash != "human" {
		t.Fatalf("flagged: %+v", rows)
	}
}
