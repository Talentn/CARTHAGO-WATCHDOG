package dashboard

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
	"carthago/backend/internal/toxicity"
)

func TestBehaviourOnPlayerAndMatchPages(t *testing.T) {
	f := newFixture(t)
	st := f.srv.st.(*store.Memory)
	ctx := context.Background()
	if err := st.PutMatchReplay(ctx, &store.MatchReplay{TenantID: "demo", MatchID: "m1", StartedAt: f.now, UpdatedAt: f.now, DurationMs: 480_000,
		Data: emptyRecording(t), Players: []store.ReplayPlayer{{Slot: 4, PlayerHash: "walid"}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddToxicityFindings(ctx, []store.ToxicityFinding{
		{TenantID: "demo", PlayerHash: "walid", MatchID: "m1", Slot: 4, Kind: toxicity.KindTeamKill, Count: 2, MatchMs: 218_000, Summary: "Killed 2 teammates in this match (limit 2)", ObservedAt: f.now.Add(-time.Hour)},
		{TenantID: "demo", PlayerHash: "walid", MatchID: "m1", Slot: 4, Kind: toxicity.KindLeftEarly, Count: 31, MatchMs: 330_000, Summary: "Left at 05:30 with 31% of the match still to play (limit 25%)", ObservedAt: f.now.Add(-time.Hour)},
		{TenantID: "demo", PlayerHash: "walid", MatchID: "gone", Slot: 2, Kind: toxicity.KindTeamKill, Count: 3, MatchMs: 61_000, Summary: "Killed 3 teammates in this match (limit 2)", ObservedAt: f.now.Add(-48 * time.Hour)},
		{TenantID: "demo", PlayerHash: "walid", MatchID: "old", Slot: 2, Kind: toxicity.KindAFK, Count: 120, MatchMs: 5000, Summary: "idle more than a month ago", ObservedAt: f.now.Add(-31 * 24 * time.Hour)},
		{TenantID: "rival", PlayerHash: "walid", MatchID: "m1", Slot: 4, Kind: toxicity.KindFeeding, Count: 14, MatchMs: 9000, Summary: "the rival studio's finding", ObservedAt: f.now},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetToxicityLimits(ctx, "demo", toxicity.Limits{TeamKills: 2, LeftEarlyPercent: 25}.Encode(), f.now); err != nil {
		t.Fatal(err)
	}

	c := f.login(t, "demo", "demo-key")
	// A player known only for behaviour still has a page.
	w := f.do("GET", "/players/walid", c, nil, nil)
	if w.Code != 200 {
		t.Fatalf("player page: %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		`id="behaviour"`, "last 30 days", "advisory",
		`<li><b class="mono">2</b> Team kills</li>`, `<li><b class="mono">1</b> Left early</li>`, `<li class="muted"><b class="mono">0</b> Feeding</li>`,
		"Killed 2 teammates in this match (limit 2)", "Killed 3 teammates",
		`href="/matches/m1?player=walid&amp;t=218000"`, `href="/matches/m1?player=walid&amp;t=330000"`, "05:30",
		"It never counts toward risk, a ban or the shadow pool",
		"team damage off, team kills from 2, idle off, left early with more than 25% to play, feeding off",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("player page lacks %q", want)
		}
	}
	for _, not := range []string{"idle more than a month ago", "the rival studio", `href="/matches/gone`} {
		if strings.Contains(body, not) {
			t.Errorf("player page shows %q", not)
		}
	}
	// Behaviour is not risk: the player is clear and has no evidence.
	if !strings.Contains(body, "No evidence") || !strings.Contains(body, `class="tier tier-clear"`) || !strings.Contains(body, "<span>Risk</span><b>0.0</b>") {
		t.Error("behaviour changed the player's standing")
	}
	rows, err := st.ListPlayers(ctx, "demo", store.PlayerFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.PlayerHash == "walid" {
			t.Errorf("behaviour put the player on the risk list: %+v", r)
		}
	}
	if b := f.do("GET", "/players/alice", c, nil, nil).Body.String(); strings.Contains(b, `id="behaviour"`) {
		t.Error("a player without behaviour findings has the card")
	}

	// The match page marks them on the timeline, apart from findings.
	w = f.do("GET", "/matches/m1?player=walid", c, nil, nil)
	body = w.Body.String()
	for _, want := range []string{
		`data-kind="behaviour"`, `data-level="low"`, `data-t="218000"`, `data-t="330000"`, "team_kill", "left_early",
		"Left at 05:30 with 31% of the match still to play", `href="/players/walid#behaviour"`,
	} {
		if w.Code != 200 || !strings.Contains(body, want) {
			t.Errorf("match page (%d) lacks %q", w.Code, want)
		}
	}
	if strings.Contains(body, "Killed 3 teammates") || strings.Contains(body, `class="kpi warn"`) {
		t.Error("the match page shows another match's finding or raises behaviour as a warning")
	}

	// Another studio sees its own finding only; a read-only user may look.
	rival := f.login(t, "rival", "rival-key")
	if b := f.do("GET", "/players/walid", rival, nil, nil).Body.String(); !strings.Contains(b, "the rival studio&#39;s finding") || strings.Contains(b, "Killed 2 teammates") {
		t.Error("the rival studio's player page")
	}
	if w := f.do("GET", "/matches/m1", rival, nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("rival opens the match: %d", w.Code)
	}
	f.addUser(t, "demo", "vera", store.RoleReadOnly, goodPW)
	if w := f.get(f.signIn(t, "demo", "vera", goodPW), "/players/walid"); w.Code != 200 || !strings.Contains(w.Body.String(), `id="behaviour"`) {
		t.Errorf("a read-only user opens the player: %d", w.Code)
	}
}
