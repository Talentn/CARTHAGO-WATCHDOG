package dashboard

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

func TestReportsQueue(t *testing.T) {
	f := newFixture(t)
	st := f.srv.st.(*store.Memory)
	ctx := context.Background()
	add := func(tenant, reporter, reported, match string, ms int64, reason, note string, age time.Duration) int64 {
		t.Helper()
		r := &store.PlayerReport{TenantID: tenant, Reporter: reporter, Reported: reported, MatchID: match, MatchMs: ms, Reason: reason, Note: note, CreatedAt: f.now.Add(-age)}
		if added, err := st.AddPlayerReport(ctx, r); err != nil || !added {
			t.Fatalf("add: %v %v", added, err)
		}
		return r.ID
	}
	if err := st.PutMatchReplay(ctx, &store.MatchReplay{TenantID: "demo", MatchID: "m1", StartedAt: f.now, UpdatedAt: f.now, DurationMs: 900_000,
		Data: emptyRecording(t), Players: []store.ReplayPlayer{{Slot: 1, PlayerHash: "bob", SessionID: "bbbb2222"}}}); err != nil {
		t.Fatal(err)
	}
	// carol was banned, which confirms dave's earlier report about her.
	if err := st.AddBan(ctx, &store.Ban{TenantID: "demo", Ref: "CW-TEST-0001", PlayerHash: "carol", BannedBy: "ada", BannedAt: f.now, EffectiveAt: f.now}); err != nil {
		t.Fatal(err)
	}
	add("demo", "dave", "carol", "m0", -1, "cheating", "", 5*24*time.Hour)
	aboutBob := add("demo", "dave", "bob", "m1", 645_000, "cheating", `aimed through the wall <script>alert(1)</script>`, time.Hour)
	add("demo", "erin", "bob", "m1", 650_000, "griefing", "", 30*time.Minute)
	aboutAlice := add("demo", "erin", "alice", "unrecorded", 12_000, "toxic_behaviour", "blocked the door", 10*time.Minute)
	add("demo", "erin", "bob", "long-ago", -1, "other", "more than a month old", 40*24*time.Hour)
	secret := add("rival", "zoe", "rival-player", "m1", 1000, "cheating", "the rival studio's report", time.Minute)

	if w := f.do("GET", "/reports", nil, nil, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("signed out: %d", w.Code)
	}
	c := f.login(t, "demo", "demo-key")
	w := f.do("GET", "/reports", c, nil, nil)
	if w.Code != 200 {
		t.Fatalf("queue: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		`class="on">Open <span class="mono">5</span>`, `>Reviewed <span class="mono">0</span>`,
		`href="/players/bob"`, "Cheating", "Griefing", "Toxic behaviour",
		"aimed through the wall &lt;script&gt;alert(1)&lt;/script&gt;", "blocked the door",
		// Each report links to the replay at the reported moment, when the match was recorded.
		`href="/matches/m1?player=bob&amp;t=645000"`, `Replay at <span class="mono">10:45</span>`, "not recorded",
		// dave's weight: one confirmed report, none dismissed. erin has no outcome yet.
		`<span class="mono">0.67</span>`, "1 of 1 confirmed", `<span class="mono">0.50</span>`, "0 of 0 confirmed",
		// bob's last 30 days: two reports from two reporters; the one from 40 days ago is not counted.
		`<a href="/reports?player=bob">2 in 30 days</a> from 2 reporters`,
		`action="/reports/` + strconv.FormatInt(aboutBob, 10) + `/state"`, `value="dismissed"`, `value="reviewed"`,
		"It never bans",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("queue lacks %q", want)
		}
	}
	for _, not := range []string{"the rival studio", "<script>alert", `href="/matches/unrecorded`, `value="open"`} {
		if strings.Contains(body, not) {
			t.Errorf("queue shows %q", not)
		}
	}
	if b := f.do("GET", "/reports?player=alice", c, nil, nil).Body.String(); !strings.Contains(b, "blocked the door") || strings.Contains(b, "aimed through the wall") {
		t.Error("the queue of one player")
	}

	// The player page and the players list count the reports.
	page := f.do("GET", "/players/bob", c, nil, nil).Body.String()
	for _, want := range []string{`id="reports"`, `<li><b class="mono">2</b> reports</li>`, `<li><b class="mono">2</b> different reporters</li>`,
		`href="/matches/m1?player=bob&amp;t=645000"`, `href="/reports?player=bob"`, "0.67"} {
		if !strings.Contains(page, want) {
			t.Errorf("player page lacks %q", want)
		}
	}
	if strings.Contains(page, "more than a month old") {
		t.Error("the player page lists a report from before the 30 days")
	}
	list := f.do("GET", "/players?all=1", c, nil, nil).Body.String()
	if !strings.Contains(list, `<a href="/reports?player=bob" title="2 in 30 days from 2 reporters">2 <small class="muted">/ 2</small></a>`) {
		t.Error("players list lacks bob's report count")
	}
	// A player known only from a report still has a page.
	if w := f.do("GET", "/players/carol", c, nil, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `id="reports"`) {
		t.Errorf("the page of a player known only from a report: %d", w.Code)
	}

	// Reports are advice: bob's risk and evidence are what they were without them.
	evBefore, _ := st.ListEvidence(ctx, "demo", store.EvidenceFilter{Limit: 100})
	bansBefore, _ := st.ListBans(ctx, "demo", 100)

	// Setting a state needs the reviewer role and the form token, and is audited.
	f.addUser(t, "demo", "vera", store.RoleReadOnly, goodPW)
	f.addUser(t, "demo", "rita", store.RoleReviewer, goodPW)
	vera := f.signIn(t, "demo", "vera", goodPW)
	path := "/reports/" + strconv.FormatInt(aboutBob, 10) + "/state"
	if w := f.post(vera, path, "state", "dismissed"); w.Code != http.StatusForbidden {
		t.Fatalf("a read-only user dismisses: %d", w.Code)
	}
	if b := f.get(vera, "/reports").Body.String(); !strings.Contains(b, "aimed through the wall") || strings.Contains(b, `action="/reports/`) || !strings.Contains(b, "They need the reviewer role") {
		t.Error("the queue for a read-only user")
	}
	rita := f.signIn(t, "demo", "rita", goodPW)
	if w := f.do("POST", path, rita, map[string][]string{"state": {"dismissed"}}, sameOriginHdr); w.Code == http.StatusSeeOther {
		t.Fatal("a state was set without the form token")
	}
	if w := f.post(rita, path, "state", "banned"); w.Code != http.StatusNotFound {
		t.Fatalf("a made-up state: %d", w.Code)
	}
	if r, _ := st.GetPlayerReport(ctx, "demo", aboutBob); r.State != store.ReportOpen {
		t.Fatalf("a refused change went through: %+v", r)
	}
	if w := f.post(rita, path, "state", "dismissed"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/reports?state=open&saved=1" {
		t.Fatalf("dismiss: %d %q", w.Code, w.Header().Get("Location"))
	}
	if r, _ := st.GetPlayerReport(ctx, "demo", aboutBob); r.State != store.ReportDismissed || r.DecidedBy != "rita" || !r.DecidedAt.Equal(f.now) {
		t.Fatalf("after the dismissal: %+v", r)
	}
	f.wantAudit(t, "demo", "report.dismiss", "rita", "about bob, by dave, reason cheating, match m1")
	for _, e := range f.auditLog(t, "demo") {
		if strings.Contains(e.Detail+e.Target, "aimed through the wall") {
			t.Error("the note, a player's own words, is in the audit log")
		}
	}
	if w := f.post(rita, "/reports/"+strconv.FormatInt(aboutAlice, 10)+"/state", "state", "reviewed"); w.Code != http.StatusSeeOther {
		t.Fatalf("review: %d", w.Code)
	}
	f.wantAudit(t, "demo", "report.review", "rita", "about alice")
	body = f.get(rita, "/reports?state=dismissed").Body.String()
	for _, want := range []string{`class="on">Dismissed <span class="mono">1</span>`, "aimed through the wall", "dismissed by rita", `value="open"`,
		// The dismissal counts against dave, and bob's 30 days no longer count it.
		`<span class="mono">0.50</span>`, "1 of 2 confirmed", `>1 in 30 days</a> from 1 reporter<`} {
		if !strings.Contains(body, want) {
			t.Errorf("dismissed tab lacks %q", want)
		}
	}
	if w := f.post(rita, path, "state", "open"); w.Code != http.StatusSeeOther {
		t.Fatalf("reopen: %d", w.Code)
	}
	f.wantAudit(t, "demo", "report.reopen", "rita", "about bob")

	evAfter, _ := st.ListEvidence(ctx, "demo", store.EvidenceFilter{Limit: 100})
	bansAfter, _ := st.ListBans(ctx, "demo", 100)
	if len(evAfter) != len(evBefore) || len(bansAfter) != len(bansBefore) {
		t.Error("reviewing a report changed evidence or bans")
	}

	// Another studio neither sees nor changes these reports.
	rival := f.login(t, "rival", "rival-key")
	if b := f.do("GET", "/reports", rival, nil, nil).Body.String(); !strings.Contains(b, "the rival studio&#39;s report") || strings.Contains(b, "blocked the door") {
		t.Error("the rival's queue")
	}
	if w := f.post(rival, path, "state", "dismissed"); w.Code != http.StatusNotFound {
		t.Fatalf("the rival dismisses demo's report: %d", w.Code)
	}
	if w := f.post(rita, "/reports/"+strconv.FormatInt(secret, 10)+"/state", "state", "dismissed"); w.Code != http.StatusNotFound {
		t.Fatalf("demo dismisses the rival's report: %d", w.Code)
	}
	if r, _ := st.GetPlayerReport(ctx, "demo", aboutBob); r.State != store.ReportOpen {
		t.Fatalf("the rival changed the report: %+v", r)
	}
	if r, _ := st.GetPlayerReport(ctx, "rival", secret); r.State != store.ReportOpen {
		t.Fatalf("demo changed the rival's report: %+v", r)
	}
}
