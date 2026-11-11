package dashboard

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge/synth"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/store"
)

func TestInformationLeakExplanation(t *testing.T) {
	f := newFixture(t)
	st := f.srv.st.(*store.Memory)
	ctx := context.Background()
	s := store.Session{SessionID: "cccc3333", TenantID: "demo", PlayerHash: "mallory", DeviceID: "d3", TrustLevel: 2, State: store.SessionActive, CreatedAt: f.now, LastHeartbeat: f.now}
	if err := st.PutSession(ctx, &s); err != nil {
		t.Fatal(err)
	}
	mode := pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER
	ps := synth.DefaultPlayers(mode, 1, []synth.Role{synth.RoleLegit, synth.RoleInformed, synth.RolePrefire, synth.RoleSound})
	ps[1].SessionID = "cccc3333"
	spec := synth.Spec{MatchID: "dash-match", Mode: mode, TickRate: 64, Seconds: 1800, Seed: 11, Players: ps}

	p := pipeline.New(pipeline.Config{}, st, st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, b := range synth.Batches(spec) {
		if ok, _, err := p.Gameplay(ctx, "demo", b); !ok || err != nil {
			t.Fatalf("batch %d: %v %v", b.BatchSeq, ok, err)
		}
	}
	p.Close()
	evs, _ := st.ListEvidence(ctx, "demo", store.EvidenceFilter{SessionID: "cccc3333"})
	if len(evs) != 1 || evs[0].Rule != pipeline.RuleInformationLeak {
		t.Fatalf("evidence: %+v", evs)
	}

	c := f.login(t, "demo", "demo-key")
	w := f.do("GET", "/evidence/"+strconv.FormatInt(evs[0].ID, 10), c, nil, nil)
	if w.Code != 200 {
		t.Fatalf("evidence page: %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"Why this player was flagged", "never triggers an automatic kick", "hidden_aim", "competitive_shooter/mouse_keyboard",
		"<svg class=\"replay\"", "<polygon class=\"rp-wall\"", "rp-target", "Moments", "Knowledge model", "0.1% of honest player-matches"} {
		if !strings.Contains(body, want) {
			t.Errorf("evidence page lacks %q", want)
		}
	}
	if strings.Contains(body, "style=") || strings.Contains(body, "<script") {
		t.Error("page needs inline style or script, which the CSP blocks")
	}

	w = f.do("GET", "/sessions/cccc3333", c, nil, nil)
	body = w.Body.String()
	for _, want := range []string{"Gameplay (telemetry v2)", "dash-match", "carthago-yard v1", "flagged · z", "Information leak · slot 2", "<svg class=\"replay\""} {
		if !strings.Contains(body, want) {
			t.Errorf("session page lacks %q", want)
		}
	}

	// The other tenant sees none of it.
	rc := f.login(t, "rival", "rival-key")
	if w := f.do("GET", "/evidence/"+strconv.FormatInt(evs[0].ID, 10), rc, nil, nil); w.Code != 404 {
		t.Errorf("rival reads the evidence: %d", w.Code)
	}
}
