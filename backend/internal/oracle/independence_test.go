package oracle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/oracle/analyst"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/store"
)

// told records what the pipeline asks the gateway to do to a client: the notice behind
// the "detected" screen, and a kick.
type told struct {
	mu      sync.Mutex
	notices []string
	kicks   []string
}

func (r *told) Notice(id string, c pb.EnforcementCategory, s pb.EnforcementSeverity) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notices = append(r.notices, fmt.Sprintf("%s %s %s", id, c, s))
	return true
}

func (r *told) Kick(id, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kicks = append(r.kicks, id+" "+reason)
}

func (r *told) all() (notices, kicks []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.notices...), append([]string(nil), r.kicks...)
}

// The client notice and the Oracle are two separate paths out of the pipeline. A notice
// comes from the rules' own short list of evidence and nothing else. The Oracle is handed
// values and takes nothing back, so whatever it concludes, the player's screen and the
// session are the same as without it.
//
// The Oracle here is as eager as it can be: its thresholds put every session in the
// review band and the analyst reviews live. The pipeline is as eager as it can be too:
// notices on, also for evidence that needs the studio's opt-in, and kicks on.
func TestOracleNeverRaisesTheClientNotice(t *testing.T) {
	ctx := context.Background()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	type result struct {
		notices, kicks []string
		evidence       []string
		states         map[string]string
		st             *store.Memory
	}
	run := func(withOracle bool) result {
		st := store.NewMemory()
		rec := &told{}
		cfg := pipeline.Config{Notices: true, NoticesOptIn: true, AutoKick: true}
		var eng *Engine
		var prov *countingProvider
		if withOracle {
			dir := t.TempDir()
			writeTestBundle(t, dir, Thresholds{Watch: 0.001, Review: 0.002})
			b, err := LoadBundle(dir)
			if err != nil {
				t.Fatal(err)
			}
			prov = &countingProvider{}
			an, err := analyst.New(analyst.Config{Provider: prov, Prompts: analyst.Prompts{Version: b.Manifest.Analyst.PromptVersion, System: b.SystemPrompt, Case: b.CasePrompt}, Usage: st})
			if err != nil {
				t.Fatal(err)
			}
			eng, err = New(Config{Bundle: b, Analyst: an, PseudonymKey: []byte("0123456789abcdef0123456789abcdef"), Settle: 10 * time.Millisecond, ReviewLive: true}, st, quiet)
			if err != nil {
				t.Fatal(err)
			}
			engCtx, cancel := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() {
				eng.Run(engCtx)
				close(done)
			}()
			defer func() {
				cancel()
				<-done
			}()
			cfg.Observer = eng
		}
		p := pipeline.New(cfg, st, st, rec, quiet)
		p.SetNotifier(rec)

		sessions := map[string]store.Session{}
		for _, id := range []string{"clean", "patched"} {
			s := store.Session{SessionID: id, TenantID: "studio", PlayerHash: "p-" + id, State: store.SessionActive, CreatedAt: time.Now(), LastHeartbeat: time.Now()}
			if err := st.PutSession(ctx, &s); err != nil {
				t.Fatal(err)
			}
			sessions[id] = s
		}
		// An ordinary player: heartbeats with nothing in them.
		p.Heartbeat(sessions["clean"], &pb.Heartbeat{})
		p.Heartbeat(sessions["clean"], &pb.Heartbeat{})
		// A player whose game code was patched: the one kind of evidence here that is on
		// the rules' notice list.
		p.Heartbeat(sessions["patched"], &pb.Heartbeat{Findings: []*pb.Finding{{Job: "test", Code: uint32(pb.FindingCode_FINDING_CODE_CODE_PATCH), A: 1, B: 2, Detail: "hw.dll>x"}}})
		p.Close() // drains the queue
		if eng != nil {
			fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			eng.Flush(fctx)
			if fctx.Err() != nil {
				t.Fatal("the engine did not settle")
			}
			cancel()
			// The Oracle did conclude something about the ordinary player, and an analyst
			// was asked: there was every occasion to tell the client.
			sc, err := st.GetOracleScore(ctx, "studio", "clean")
			if err != nil || sc.Band != store.OracleBandReview {
				t.Fatalf("the test needs the Oracle to flag the clean session: %+v %v", sc, err)
			}
			if v, err := st.GetOracleVerdict(ctx, "studio", "clean"); err != nil || v.Status != store.OracleVerdictOK || prov.calls.Load() < 2 {
				t.Fatalf("the test needs an analyst opinion on the clean session: %+v %v (%d calls)", v, err, prov.calls.Load())
			}
		} else if _, err := st.GetOracleScore(ctx, "studio", "clean"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a score without the Oracle: %v", err)
		}
		res := result{states: map[string]string{}, st: st}
		res.notices, res.kicks = rec.all()
		evs, _ := st.ListEvidence(ctx, "studio", store.EvidenceFilter{Limit: 100})
		for _, e := range evs {
			res.evidence = append(res.evidence, fmt.Sprintf("%s %s %d %s", e.SessionID, e.Rule, e.Severity, e.Source))
		}
		for id := range sessions {
			s, _ := st.GetSession(ctx, id)
			res.states[id] = fmt.Sprintf("%v %q", s.State, s.KickReason)
		}
		return res
	}

	with, without := run(true), run(false)
	want := []string{"patched ENFORCEMENT_CATEGORY_GAME_INTEGRITY ENFORCEMENT_SEVERITY_HIGH"}
	if !reflect.DeepEqual(without.notices, want) {
		t.Fatalf("the rules alone: notices %v, want %v", without.notices, want)
	}
	if !reflect.DeepEqual(with.notices, without.notices) {
		t.Errorf("notices with the Oracle %v, without %v", with.notices, without.notices)
	}
	if !reflect.DeepEqual(with.kicks, without.kicks) {
		t.Errorf("kicks with the Oracle %v, without %v", with.kicks, without.kicks)
	}
	if !reflect.DeepEqual(with.evidence, without.evidence) {
		t.Errorf("evidence with the Oracle %v, without %v", with.evidence, without.evidence)
	}
	if !reflect.DeepEqual(with.states, without.states) {
		t.Errorf("sessions with the Oracle %v, without %v", with.states, without.states)
	}
}

// The Oracle has no way to reach a client: the only thing the pipeline accepts from it is
// the two calls of pipeline.Observer, which return nothing, and the engine's store is
// limited to reading evidence and sessions and writing the Oracle's own tables (scores,
// opinions, usage, reviewer labels).
func TestOracleHasNoWayToTheClient(t *testing.T) {
	obs := reflect.TypeOf((*pipeline.Observer)(nil)).Elem()
	for i := range obs.NumMethod() {
		if m := obs.Method(i); m.Type.NumOut() != 0 {
			t.Errorf("pipeline.Observer.%s returns a value to the pipeline", m.Name)
		}
	}
	eng := reflect.TypeOf(&Engine{})
	for _, iface := range []reflect.Type{reflect.TypeOf((*pipeline.Notifier)(nil)).Elem(), reflect.TypeOf((*pipeline.Kicker)(nil)).Elem()} {
		if eng.Implements(iface) {
			t.Errorf("the engine implements %s", iface)
		}
	}
	st := reflect.TypeOf((*Store)(nil)).Elem()
	reads := map[string]bool{"ListEvidence": true, "GetTelemetry": true, "GetSession": true}
	for i := range st.NumMethod() {
		name := st.Method(i).Name
		if !reads[name] && !strings.Contains(name, "Oracle") && !strings.Contains(name, "Label") {
			t.Errorf("the engine's store can %s; it may read evidence and sessions and write only the Oracle's own tables", name)
		}
	}
}
