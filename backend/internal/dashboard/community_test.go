package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/review"
	"carthago/backend/internal/store"
)

func TestCommunityReviewPages(t *testing.T) {
	f := newFixture(t)
	st := f.srv.st.(*store.Memory)
	ctx := context.Background()
	players := []store.ReplayPlayer{{Slot: 1, PlayerHash: "alice"}, {Slot: 2, PlayerHash: "bob"}, {Slot: 3, PlayerHash: "carol"}}
	for _, m := range []struct{ tenant, id string }{{"demo", "m1"}, {"demo", "m2"}, {"rival", "m1"}} {
		if err := st.PutMatchReplay(ctx, &store.MatchReplay{TenantID: m.tenant, MatchID: m.id, StartedAt: f.now, UpdatedAt: f.now, DurationMs: 4000, Data: wallRecording(t, ""), Players: players}); err != nil {
			t.Fatal(err)
		}
	}
	// bob is flagged by the Oracle in m1, for both studios.
	for _, tenant := range []string{"demo", "rival"} {
		if err := st.PutOracleScore(ctx, &store.OracleScore{TenantID: tenant, SessionID: "bbbb2222", PlayerHash: "bob", MatchID: "m1", Band: store.OracleBandReview, Score: 0.9, UpdatedAt: f.now}); err != nil {
			t.Fatal(err)
		}
	}
	f.addUser(t, "demo", "vera", store.RoleReadOnly, goodPW)
	f.addUser(t, "demo", "rita", store.RoleReviewer, goodPW)
	f.addUser(t, "demo", "ada", store.RoleAdmin, goodPW)
	f.addUser(t, "rival", "eve", store.RoleAdmin, goodPW)
	vera, rita, ada, eve := f.signIn(t, "demo", "vera", goodPW), f.signIn(t, "demo", "rita", goodPW), f.signIn(t, "demo", "ada", goodPW), f.signIn(t, "rival", "eve", goodPW)

	if w := f.do("GET", "/community", nil, nil, nil); w.Code == http.StatusOK {
		t.Fatal("the community page without signing in")
	}
	// Off by default: the page says so and nothing became a case.
	body := f.get(rita, "/community").Body.String()
	if !strings.Contains(body, "<b>Off</b>") || !strings.Contains(body, "No decided cases") || strings.Contains(body, `action="/community/settings"`) {
		t.Fatalf("the page with the feature off: %s", body)
	}
	// Turning it on is the admin's.
	on := []string{"enabled", "1", "quorum", "3", "agreement", "60", "report_weight", "1.5"}
	for name, c := range map[string]*http.Cookie{"read-only": vera, "reviewer": rita} {
		if w := f.post(c, "/community/settings", on...); w.Code != http.StatusForbidden {
			t.Fatalf("a %s user changes the settings: %d", name, w.Code)
		}
	}
	if w := f.do("POST", "/community/settings", ada, map[string][]string{"enabled": {"1"}, "quorum": {"3"}, "agreement": {"60"}, "report_weight": {"1.5"}}, sameOriginHdr); w.Code == http.StatusSeeOther {
		t.Fatal("the settings were saved without the form token")
	}
	for _, bad := range [][]string{{"enabled", "1", "quorum", "2", "agreement", "60", "report_weight", "1"}, {"enabled", "1", "quorum", "5", "agreement", "40", "report_weight", "1"}, {"enabled", "1", "quorum", "x", "agreement", "60", "report_weight", "1"}} {
		if w := f.post(ada, "/community/settings", bad...); w.Code != http.StatusBadRequest {
			t.Fatalf("settings %v: %d", bad, w.Code)
		}
	}
	if set, _ := st.ReviewSettings(ctx, "demo"); set.Enabled {
		t.Fatal("a refused change turned the feature on")
	}
	if w := f.post(ada, "/community/settings", on...); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/community?ok=settings" {
		t.Fatalf("settings: %d %q", w.Code, w.Header().Get("Location"))
	}
	if set, _ := st.ReviewSettings(ctx, "demo"); set != (store.ReviewSettings{Enabled: true, Quorum: 3, Agreement: 0.6, ReportWeight: 1.5}) {
		t.Fatalf("settings stored: %+v", set)
	}
	f.wantAudit(t, "demo", "community.settings", "ada", "community review on, 3 verdicts close a case, 60% agreement")
	if set, _ := st.ReviewSettings(ctx, "rival"); set.Enabled {
		t.Fatal("the other studio's feature was turned on")
	}

	// A calibration case needs the reviewer role and a recorded match with the player.
	if w := f.post(vera, "/community/calibration", "match", "m2", "suspect", "carol", "expected", "insufficient"); w.Code != http.StatusForbidden {
		t.Fatalf("a read-only user adds a calibration case: %d", w.Code)
	}
	for _, bad := range [][]string{{"match", "m9", "suspect", "carol", "expected", "insufficient"}, {"match", "m2", "suspect", "nobody", "expected", "insufficient"}, {"match", "m2", "suspect", "carol", "expected", "guilty"}} {
		if w := f.post(rita, "/community/calibration", bad...); w.Code != http.StatusBadRequest {
			t.Fatalf("calibration %v: %d", bad, w.Code)
		}
	}
	if w := f.post(rita, "/community/calibration", "match", "m2", "suspect", "carol", "expected", "insufficient"); w.Code != http.StatusSeeOther {
		t.Fatalf("calibration: %d", w.Code)
	}
	f.wantAudit(t, "demo", "community.calibration", "rita", "carol in match m2, known answer insufficient")

	// Opening the page makes the case of what is flagged; three players decide it.
	body = f.get(rita, "/community?tab=open").Body.String()
	for _, want := range []string{"<b>On</b>", `class="on">Open <span class="mono">1</span>`, `href="/players/bob"`, "Oracle review flag", `href="/matches/m1?player=bob"`, "waiting for verdicts", `Calibration <span class="mono">1</span>`} {
		if !strings.Contains(body, want) {
			t.Errorf("open cases lack %q", want)
		}
	}
	svc := review.New(st, review.Config{Key: []byte("the gateway's review key"), Now: func() time.Time { return f.now }})
	vote := func(reviewer, verdict string) {
		t.Helper()
		for i := 0; i < 3; i++ {
			l, err := svc.Assign(ctx, "demo", reviewer)
			if errors.Is(err, review.ErrNothing) && verdict == "" {
				return
			}
			if err != nil {
				t.Fatalf("assign %s: %v", reviewer, err)
			}
			v := verdict
			if l.Assignment.Calibration {
				v = review.VerdictInsufficient
				if reviewer == "careless" {
					v = review.VerdictAim
				}
			}
			if err := svc.Vote(ctx, strings.TrimPrefix(l.Path, "/review/"), v); err != nil {
				t.Fatal(err)
			}
			if !l.Assignment.Calibration {
				return
			}
		}
	}
	vote("rev1", review.VerdictWalls)
	vote("rev2", review.VerdictWalls)
	vote("rev3", review.VerdictInsufficient)
	vote("careless", "") // one wrong calibration answer; the next would be a calibration case too, and none is left
	cases, _ := st.ListReviewCases(ctx, "demo", store.ReviewCaseFilter{State: store.ReviewDecided})
	if len(cases) != 1 {
		t.Fatalf("decided cases: %+v", cases)
	}
	id := strconv.FormatInt(cases[0].ID, 10)
	evBefore, _ := st.ListEvidence(ctx, "demo", store.EvidenceFilter{Limit: 100})
	bansBefore, _ := st.ListBans(ctx, "demo", 100)
	labelsBefore, _ := st.ListSessionLabels(ctx, "demo", store.OracleFilter{Limit: 100})

	body = f.get(rita, "/community").Body.String()
	for _, want := range []string{`class="on">Decided <span class="mono">1</span>`, "Cheating: sees through walls", "67% weighted agreement", `sees through walls <span class="mono">2</span> · not enough <span class="mono">1</span>`,
		`<span class="mono">3</span> <small class="muted">of 3</small>`, `action="/community/cases/` + id + `/decide"`, `value="confirmed"`, `value="dismissed"`, "It never bans"} {
		if !strings.Contains(body, want) {
			t.Errorf("decided cases lack %q", want)
		}
	}
	for _, not := range []string{"rev1", "rev2", `action="/community/settings"`} {
		if strings.Contains(body, not) {
			t.Errorf("the cases page for a reviewer shows %q", not)
		}
	}
	if b := f.get(vera, "/community").Body.String(); strings.Contains(b, `action="/community/cases/`) || !strings.Contains(b, "need the reviewer role") {
		t.Error("the cases page for a read-only user")
	}
	if b := f.get(ada, "/community").Body.String(); !strings.Contains(b, `action="/community/settings"`) {
		t.Error("the cases page for an admin lacks the settings")
	}
	// The other studio has its own page: off, and none of this.
	if b := f.get(eve, "/community").Body.String(); !strings.Contains(b, "<b>Off</b>") || strings.Contains(b, "sees through walls <span") {
		t.Error("the other studio's cases page")
	}
	if b := f.get(eve, "/community/reviewers").Body.String(); strings.Contains(b, "rev1") || !strings.Contains(b, "No reviewers yet") {
		t.Error("the other studio's reviewers page")
	}

	// Confirming needs the reviewer role and the form token; another studio cannot.
	path := "/community/cases/" + id + "/decide"
	if w := f.post(vera, path, "decision", "confirmed"); w.Code != http.StatusForbidden {
		t.Fatalf("a read-only user confirms: %d", w.Code)
	}
	if w := f.post(eve, path, "decision", "confirmed"); w.Code != http.StatusNotFound {
		t.Fatalf("another studio confirms: %d", w.Code)
	}
	if w := f.do("POST", path, rita, map[string][]string{"decision": {"confirmed"}}, sameOriginHdr); w.Code == http.StatusSeeOther {
		t.Fatal("a case was confirmed without the form token")
	}
	if w := f.post(rita, path, "decision", "banned"); w.Code != http.StatusBadRequest {
		t.Fatalf("a made-up decision: %d", w.Code)
	}
	if c, _ := st.GetReviewCase(ctx, "demo", cases[0].ID); c.Decision != "" {
		t.Fatalf("a refused decision went through: %+v", c)
	}
	if w := f.post(rita, path, "decision", "confirmed"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/community?ok=confirmed" {
		t.Fatalf("confirm: %d %q", w.Code, w.Header().Get("Location"))
	}
	if c, _ := st.GetReviewCase(ctx, "demo", cases[0].ID); c.Decision != store.ReviewConfirmed || c.DecidedBy != "rita" || !c.DecidedAt.Equal(f.now) {
		t.Fatalf("after confirming: %+v", c)
	}
	f.wantAudit(t, "demo", "community.confirmed", "rita", "bob in match m1, the players' answer: cheating (67% agreement)")
	if w := f.post(rita, path, "decision", "dismissed"); w.Code != http.StatusSeeOther {
		t.Fatalf("changing the decision: %d", w.Code)
	}
	if body = f.get(rita, "/community").Body.String(); !strings.Contains(body, "Dismissed<br>") || !strings.Contains(body, "by rita") {
		t.Error("the decided case does not show the decision")
	}

	// Confirming and dismissing are records: no ban, no evidence, no label for the Oracle.
	evAfter, _ := st.ListEvidence(ctx, "demo", store.EvidenceFilter{Limit: 100})
	bansAfter, _ := st.ListBans(ctx, "demo", 100)
	labelsAfter, _ := st.ListSessionLabels(ctx, "demo", store.OracleFilter{Limit: 100})
	if fmt.Sprint(evAfter, bansAfter, labelsAfter) != fmt.Sprint(evBefore, bansBefore, labelsBefore) {
		t.Fatal("a community decision changed evidence, bans or labels")
	}
	if shadow, _ := st.ListShadowBans(ctx, "demo"); len(shadow) != 0 {
		t.Fatalf("a community decision pooled a player: %+v", shadow)
	}

	// The reviewers page: after the dismissal rev3, who said not enough, was right.
	body = f.get(vera, "/community/reviewers").Body.String()
	for _, want := range []string{`href="/players/rev1"`, `href="/players/rev3"`, `href="/players/careless"`, "First correct verdict", "0.50", "1 of 1", "0 of 1", "GET /v1/review/standing"} {
		if !strings.Contains(body, want) {
			t.Errorf("reviewers page lacks %q", want)
		}
	}
	if b := f.get(rita, "/community?tab=calibration").Body.String(); !strings.Contains(b, "Not enough evidence") || !strings.Contains(b, `<span class="mono">3</span> correct · <span class="mono">1</span> wrong`) || !strings.Contains(b, `action="/community/calibration"`) {
		t.Errorf("the calibration tab: %s", b)
	}
}
