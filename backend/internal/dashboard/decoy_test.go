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

func TestDecoyReactionExplanation(t *testing.T) {
	f := newFixture(t)
	st := f.srv.st.(*store.Memory)
	ctx := context.Background()
	s := store.Session{SessionID: "dddd4444", TenantID: "demo", PlayerHash: "mallory", DeviceID: "d4", TrustLevel: 2, State: store.SessionActive, CreatedAt: f.now, LastHeartbeat: f.now}
	if err := st.PutSession(ctx, &s); err != nil {
		t.Fatal(err)
	}
	mode := pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER
	ps := synth.DefaultPlayers(mode, 1, []synth.Role{synth.RoleLegit, synth.RoleInformed, synth.RolePrefire, synth.RoleSound, synth.RoleTeamCall,
		synth.RoleLegit, synth.RoleLegit, synth.RolePrefire, synth.RoleSound, synth.RoleTeamCall})
	ps[1].SessionID = "dddd4444"
	spec := synth.Spec{MatchID: "dash-decoys", Mode: mode, TickRate: 64, Seconds: 1800, Seed: 11, Players: ps, Decoys: true}

	p := pipeline.New(pipeline.Config{}, st, st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, b := range synth.Batches(spec) {
		if ok, _, err := p.Gameplay(ctx, "demo", b); !ok || err != nil {
			t.Fatalf("batch %d: %v %v", b.BatchSeq, ok, err)
		}
	}
	p.Close()
	evs, _ := st.ListEvidence(ctx, "demo", store.EvidenceFilter{SessionID: "dddd4444"})
	var decoy *store.Evidence
	for i := range evs {
		if evs[i].Rule == pipeline.RuleDecoyReaction {
			decoy = &evs[i]
		}
	}
	if decoy == nil {
		t.Fatalf("no decoy_reaction evidence: %+v", evs)
	}

	c := f.login(t, "demo", "demo-key")
	w := f.do("GET", "/evidence/"+strconv.FormatInt(decoy.ID, 10), c, nil, nil)
	if w.Code != 200 {
		t.Fatalf("evidence page: %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"Why this player was flagged", "never triggers an automatic kick", "decoy_aim", "sent only to this player",
		"<polyline class=\"rp-decoy\"", "<polygon class=\"rp-wall\"", "Moments", "different decoys"} {
		if !strings.Contains(body, want) {
			t.Errorf("evidence page lacks %q", want)
		}
	}
	if strings.Contains(body, "Raw finding") || strings.Contains(body, "style=") || strings.Contains(body, "<script") {
		t.Error("decoy evidence fell back to raw JSON, or needs inline style or script")
	}

	w = f.do("GET", "/sessions/dddd4444", c, nil, nil)
	body = w.Body.String()
	for _, want := range []string{"Information leak · slot 2", "Decoy reaction · slot 2", "rp-decoy"} {
		if !strings.Contains(body, want) {
			t.Errorf("session page lacks %q", want)
		}
	}
	if i, j := strings.Index(body, "Information leak · slot 2"), strings.Index(body, "Decoy reaction · slot 2"); i < 0 || j < i {
		t.Error("decoy card should follow the leak card")
	}
}
