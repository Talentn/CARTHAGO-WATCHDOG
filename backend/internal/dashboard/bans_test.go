package dashboard

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

// Banning and lifting need the reviewer role, the delay needs the admin role, a read-only
// account sees everything and can do nothing, and each step is in the audit log under the
// account that took it.
func TestBansByRole(t *testing.T) {
	f := newOracleFixture(t, testOracle)
	ctx := context.Background()
	f.addUser(t, "demo", "ada", store.RoleAdmin, goodPW)
	f.addUser(t, "demo", "rev", store.RoleReviewer, goodPW)
	f.addUser(t, "demo", "ron", store.RoleReadOnly, goodPW)
	f.addUser(t, "rival", "rex", store.RoleAdmin, goodPW)
	ada, rev, ron, rex := f.signIn(t, "demo", "ada", goodPW), f.signIn(t, "demo", "rev", goodPW), f.signIn(t, "demo", "ron", goodPW), f.signIn(t, "rival", "rex", goodPW)
	const banForm, liftForm = `action="/sessions/bbbb2222/ban"`, `/lift"`

	// Read-only: the card and the page are there, the forms are not, the routes refuse.
	body := f.get(ron, "/sessions/bbbb2222").Body.String()
	if !strings.Contains(body, "<h2>Ban</h2>") || !strings.Contains(body, "Not banned") || !strings.Contains(body, "Banning a player needs the reviewer role") || strings.Contains(body, banForm) {
		t.Error("read-only session page: the ban card is missing or offers the form")
	}
	if w := f.post(ron, "/sessions/bbbb2222/ban", "reason", "x"); w.Code != http.StatusForbidden {
		t.Fatalf("read-only ban: %d, want 403", w.Code)
	}
	if list, _ := f.st.ListBans(ctx, "demo", 0); len(list) != 0 {
		t.Fatalf("a read-only account banned: %+v", list)
	}
	f.wantAudit(t, "demo", "access.denied", "ron", "/sessions/bbbb2222/ban")
	// Another studio cannot ban this studio's session.
	if w := f.post(rex, "/sessions/bbbb2222/ban"); w.Code != http.StatusNotFound {
		t.Fatalf("ban across studios: %d, want 404", w.Code)
	}
	// Without the form's token the request is refused whatever the role.
	if w := f.do("POST", "/sessions/bbbb2222/ban", rev, nil, sameOriginHdr); w.Code != http.StatusForbidden {
		t.Fatalf("ban without a CSRF token: %d, want 403", w.Code)
	}

	// Reviewer bans from the session page.
	if body := f.get(rev, "/sessions/bbbb2222").Body.String(); !strings.Contains(body, banForm) || !strings.Contains(body, "Ban player") {
		t.Error("reviewer session page lacks the ban form")
	}
	w := f.post(rev, "/sessions/bbbb2222/ban", "reason", "wallhack, confirmed on video", "category", "wallhack_information")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/sessions/bbbb2222?banned=1#ban" {
		t.Fatalf("reviewer ban: %d %q", w.Code, w.Header().Get("Location"))
	}
	list, _ := f.st.ListBans(ctx, "demo", 0)
	if len(list) != 1 || list[0].BannedBy != "rev" || list[0].PlayerHash != "bob" || list[0].SessionID != "bbbb2222" || list[0].Rule != "wallhack_information" ||
		list[0].Reason != "wallhack, confirmed on video" || !list[0].Active(f.now) {
		t.Fatalf("ban: %+v", list)
	}
	b := list[0]
	if sess, _ := f.st.GetSession(ctx, "bbbb2222"); b.DeviceID != sess.DeviceID {
		t.Fatalf("the ban names device %q, the session %q", b.DeviceID, sess.DeviceID)
	}
	f.wantAudit(t, "demo", "ban.add", "rev", "session bbbb2222")
	f.wantAudit(t, "demo", "ban.add", "rev", "ban "+b.Ref+"; player bob")
	if w := f.post(rev, "/sessions/bbbb2222/ban", "category", "no_such_thing"); w.Code != http.StatusBadRequest {
		t.Errorf("unknown category: %d", w.Code)
	}
	// A second click does not make a second ban.
	f.post(ada, "/sessions/bbbb2222/ban")
	if list, _ := f.st.ListBans(ctx, "demo", 0); len(list) != 1 {
		t.Fatalf("banned twice: %+v", list)
	}
	body = f.get(rev, "/sessions/bbbb2222").Body.String()
	if !strings.Contains(body, b.Ref) || !strings.Contains(body, ">Banned</span>") || strings.Contains(body, banForm) {
		t.Error("session page of a banned player: no reference, or the form is still offered")
	}

	// The Bans page: everybody of the studio reads it, a reviewer can lift, only an admin
	// sets the delay, and the other studio sees none of it.
	body = f.get(ron, "/bans").Body.String()
	for _, want := range []string{b.Ref, "wallhack, confirmed on video", "wallhack_information", ">Active</span>", "1 active", "<b>0 min</b>", "Lifting a ban needs the reviewer role", `href="/bans" class="on"`} {
		if !strings.Contains(body, want) {
			t.Errorf("read-only Bans page lacks %q", want)
		}
	}
	if strings.Contains(body, liftForm) || strings.Contains(body, `action="/bans/delay"`) {
		t.Error("read-only Bans page offers an action")
	}
	if body := f.get(rex, "/bans").Body.String(); strings.Contains(body, b.Ref) || !strings.Contains(body, "Nobody is banned") {
		t.Error("the other studio sees this studio's ban")
	}
	if body := f.get(rev, "/bans").Body.String(); !strings.Contains(body, liftForm) || strings.Contains(body, `action="/bans/delay"`) {
		t.Error("reviewer Bans page: no lift form, or the delay form is offered")
	}
	lift := "/bans/" + regexp.MustCompile(`action="/bans/(\d+)/lift"`).FindStringSubmatch(f.get(rev, "/bans").Body.String())[1] + "/lift"
	if w := f.post(ron, lift, "note", "x"); w.Code != http.StatusForbidden {
		t.Fatalf("read-only lift: %d, want 403", w.Code)
	}
	if w := f.post(rex, lift); w.Code != http.StatusNotFound {
		t.Fatalf("lift across studios: %d, want 404", w.Code)
	}
	if w := f.post(rev, "/bans/delay", "minutes", "5"); w.Code != http.StatusForbidden {
		t.Fatalf("reviewer sets the delay: %d, want 403", w.Code)
	}
	if got, _ := f.st.StandingBan(ctx, "demo", "bob", ""); got == nil || got.ID != b.ID {
		t.Fatalf("a refused lift lifted the ban: %+v", got)
	}

	if w := f.post(ada, "/bans/delay", "minutes", "45"); w.Code != http.StatusSeeOther {
		t.Fatalf("admin sets the delay: %d", w.Code)
	}
	if d, _ := f.st.BanDelay(ctx, "demo"); d != 45*time.Minute {
		t.Fatalf("delay %v", d)
	}
	f.wantAudit(t, "demo", "ban.delay", "ada", "delay set to 45 minutes")
	if w := f.post(ada, "/bans/delay", "minutes", "-1"); w.Code != http.StatusBadRequest {
		t.Errorf("negative delay: %d", w.Code)
	}
	if body := f.get(ada, "/bans").Body.String(); !strings.Contains(body, "<b>45 min</b>") || !strings.Contains(body, `action="/bans/delay"`) {
		t.Error("admin Bans page lacks the delay or its form")
	}

	if w := f.post(rev, lift, "note", "appeal accepted"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/bans?lifted=1" {
		t.Fatalf("reviewer lift: %d %q", w.Code, w.Header().Get("Location"))
	}
	list, _ = f.st.ListBans(ctx, "demo", 0)
	if len(list) != 1 || !list[0].Lifted() || list[0].LiftedBy != "rev" || list[0].LiftNote != "appeal accepted" {
		t.Fatalf("after the lift: %+v", list)
	}
	f.wantAudit(t, "demo", "ban.lift", "rev", "ban "+b.Ref)
	f.wantAudit(t, "demo", "ban.lift", "rev", "player bob; note: appeal accepted")
	if w := f.post(rev, lift); w.Code != http.StatusNotFound {
		t.Errorf("lifting a lifted ban: %d", w.Code)
	}
	body = f.get(ron, "/bans").Body.String()
	for _, want := range []string{">Lifted</span>", "appeal accepted", "0 active", "1 lifted"} {
		if !strings.Contains(body, want) {
			t.Errorf("Bans page after the lift lacks %q", want)
		}
	}
	if body := f.get(rev, "/sessions/bbbb2222").Body.String(); !strings.Contains(body, "Not banned") || !strings.Contains(body, banForm) {
		t.Error("after the lift the session page does not offer the ban again")
	}
	if body := f.get(ada, "/audit?show=changes").Body.String(); !strings.Contains(body, "ban.add") || !strings.Contains(body, "ban.lift") || !strings.Contains(body, "ban.delay") {
		t.Error("the audit page's changes tab lacks the bans")
	}
	for _, e := range f.auditLog(t, "demo") {
		if strings.HasPrefix(e.Action, "ban.") && e.ActorID == 0 {
			t.Errorf("an account's ban is audited without the account: %+v", e)
		}
	}
}

// A pending automatic ban is listed as pending, and a reviewer can lift it or make it
// immediate from the session page.
func TestPendingBanOnTheBansPage(t *testing.T) {
	f := newOracleFixture(t, testOracle)
	ctx := context.Background()
	f.addUser(t, "demo", "rev", store.RoleReviewer, goodPW)
	rev := f.signIn(t, "demo", "rev", goodPW)
	if err := f.st.AddBan(ctx, &store.Ban{TenantID: "demo", Ref: "CW-TEST-PEND", PlayerHash: "bob", Rule: "renderer_replaced", SessionID: "bbbb2222",
		BannedBy: store.BanAutomatic, BannedAt: f.now, EffectiveAt: f.now.Add(20 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	body := f.get(rev, "/bans").Body.String()
	for _, want := range []string{"CW-TEST-PEND", ">Pending</span>", "1 pending", "0 active", "automatic", "renderer_replaced", `/lift"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Bans page lacks %q", want)
		}
	}
	body = f.get(rev, "/sessions/bbbb2222").Body.String()
	if !strings.Contains(body, ">Pending</span>") || !strings.Contains(body, `action="/sessions/bbbb2222/ban"`) {
		t.Error("session page of a player with a pending ban: no pending state, or no way to ban now")
	}
}
