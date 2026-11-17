package dashboard

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/oracle"
	"carthago/backend/internal/store"
)

// baselineFixture is a studio of n ordinary players with one scored session each, plus
// "odd", who has five sessions far outside what the others do and no rule evidence, and
// "ruled", whom the rules flagged and whose play is ordinary.
func baselineFixture(t *testing.T, n int) *fixture {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	add := func(session, player, features string) {
		st.PutSession(ctx, &store.Session{SessionID: session, TenantID: "demo", PlayerHash: player, DeviceID: "d-" + player, TrustLevel: 3,
			State: store.SessionClosed, CreatedAt: now.Add(-time.Hour), LastHeartbeat: now.Add(-10 * time.Minute)})
		st.PutOracleScore(ctx, &store.OracleScore{TenantID: "demo", SessionID: session, PlayerHash: player, MatchID: "m", ModelID: "cob-0123456789ab",
			FeatureVersion: 1, Score: 0.03, Band: store.OracleBandClear, Signals: `[]`, Features: features, UpdatedAt: now.Add(-5 * time.Minute)})
	}
	for i := 0; i < n; i++ {
		add(fmt.Sprintf("sess%04d", i), fmt.Sprintf("player%04d", i), fmt.Sprintf(`{"aim_snap_rate":%.2f,"reaction_time":%d}`, float64(i%21)/100, 200+i%101))
	}
	for i := 0; i < 5; i++ {
		add(fmt.Sprintf("oddsess%d", i), "odd", `{"aim_snap_rate":7.3131,"reaction_time":250}`)
	}
	add("ruledsess", "ruled", `{"aim_snap_rate":0.05,"reaction_time":250}`)
	st.AddEvidence(ctx, []store.Evidence{{TenantID: "demo", PlayerHash: "ruled", SessionID: "ruledsess", Source: store.SourceClient, Rule: "code_patch",
		Severity: 4, Score: 0.9, Integrity: true, Summary: ".text patched", ObservedAt: now}})
	srv, err := New(Config{Keys: map[string]string{"demo": "demo-key"}, Now: func() time.Time { return now }, Oracle: testOracle}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ConfigureAuth(AuthConfig{Loopback: true}); err != nil {
		t.Fatal(err)
	}
	return &fixture{srv: srv, h: srv.Handler(), now: now}
}

func TestBaselineOrdersTheReviewQueue(t *testing.T) {
	f := baselineFixture(t, 300)
	c := f.login(t, "demo", "demo-key")
	w := f.do("GET", "/players", c, nil, nil)
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("players: %d %s", w.Code, body)
	}
	odd, ruled := strings.Index(body, `href="/players/odd"`), strings.Index(body, `href="/players/ruled"`)
	if odd < 0 || ruled < 0 || odd > ruled {
		t.Fatalf("odd at %d, ruled at %d: a player far outside normal with no rule evidence must be listed, and first", odd, ruled)
	}
	for _, want := range []string{"Against own players", `<span class="tier tier-review"`, "far outside", "stands out in: Aim snaps",
		`<span class="tier tier-clear"`, "never kicks or bans"} {
		if !strings.Contains(body, want) {
			t.Errorf("players page lacks %q", want)
		}
	}
	if strings.Contains(body, "player0001") {
		t.Error("an ordinary player without rule evidence is on the flagged list")
	}

	w = f.do("GET", "/players/odd", c, nil, nil)
	body = w.Body.String()
	for _, want := range []string{"Against this studio's own players", "far outside", "5 in the last 30 days, 5 of them outside normal", "Aim snaps", "advisory"} {
		if !strings.Contains(body, want) {
			t.Errorf("player page lacks %q", want)
		}
	}
	// The pages name signals. They show no value of a session and nothing of the baseline's edges.
	if strings.Contains(body, "7.31") {
		t.Error("the player page shows a feature value")
	}
	if body = f.do("GET", "/players/player0001", c, nil, nil).Body.String(); !strings.Contains(body, `<span class="tier tier-clear">normal</span>`) {
		t.Error("an ordinary player's page does not say normal")
	}
}

// A studio with too few sessions is measured against the starting baseline, and the
// pages say so.
func TestStartingBaselineForANewStudio(t *testing.T) {
	f := baselineFixture(t, 50)
	c := f.login(t, "demo", "demo-key")
	body := f.do("GET", "/players", c, nil, nil).Body.String()
	if !strings.Contains(body, "Starting baseline: this studio has 56 of the 200 sessions") || !strings.Contains(body, `href="/players/odd"`) || !strings.Contains(body, "far outside") {
		t.Errorf("a new studio's flagged list must use the starting baseline and say so")
	}
	if strings.Contains(body, "player0001") {
		t.Error("the starting baseline put an ordinary player on the flagged list")
	}
	body = f.do("GET", "/players/odd", c, nil, nil).Body.String()
	if !strings.Contains(body, "starting baseline · 56 of 200 own sessions so far") || !strings.Contains(body, "Player score") {
		t.Errorf("a new studio's player page must show the score and name the starting baseline")
	}
}

// A banned player's sessions do not feed the baseline: with most of the studio's
// sessions banned and far out, an ordinary player stays normal and the banned stay far.
func TestBannedPlayersDoNotFeedTheBaseline(t *testing.T) {
	f := baselineFixture(t, 300)
	ctx := context.Background()
	st := f.srv.st.(*store.Memory)
	for i := 0; i < 100; i++ {
		player := fmt.Sprintf("banned%03d", i)
		for j := 0; j < 5; j++ {
			st.PutOracleScore(ctx, &store.OracleScore{TenantID: "demo", SessionID: fmt.Sprintf("b%03d-%d", i, j), PlayerHash: player, MatchID: "m", ModelID: "cob-0123456789ab",
				FeatureVersion: 1, Score: 0.03, Band: store.OracleBandClear, Signals: `[]`, Features: `{"aim_snap_rate":3,"reaction_time":250}`, UpdatedAt: f.now.Add(-5 * time.Minute)})
		}
		if err := st.AddBan(ctx, &store.Ban{TenantID: "demo", PlayerHash: player, Reason: "test", BannedBy: "admin", BannedAt: f.now, EffectiveAt: f.now}); err != nil {
			t.Fatal(err)
		}
	}
	tb, err := f.srv.tenantBaseline(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if tb.base.Sessions != 306 {
		t.Fatalf("the baseline learned from %d sessions, want the 306 of players who are not banned", tb.base.Sessions)
	}
	if p := tb.players["banned007"]; p.Band == oracle.BaselineNormal {
		t.Fatalf("a banned player's play became normal: %+v", p)
	}
	if p := tb.players["player0007"]; p.Band != oracle.BaselineNormal {
		t.Fatalf("an ordinary player: %+v", p)
	}
}
