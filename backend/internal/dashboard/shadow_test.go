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

// The Shadow pool page: everybody of the studio reads it, Ban now and Release need the
// reviewer role, the period is an admin's, another studio sees and reaches nothing, and
// every action is in the audit log.
func TestShadowPoolPageByRole(t *testing.T) {
	f := newOracleFixture(t, testOracle)
	ctx := context.Background()
	f.addUser(t, "demo", "ada", store.RoleAdmin, goodPW)
	f.addUser(t, "demo", "rev", store.RoleReviewer, goodPW)
	f.addUser(t, "demo", "ron", store.RoleReadOnly, goodPW)
	f.addUser(t, "rival", "rex", store.RoleAdmin, goodPW)
	ada, rev, ron, rex := f.signIn(t, "demo", "ada", goodPW), f.signIn(t, "demo", "rev", goodPW), f.signIn(t, "demo", "ron", goodPW), f.signIn(t, "rival", "rex", goodPW)

	// Off by default.
	body := f.get(ron, "/shadow").Body.String()
	for _, want := range []string{"Nobody is in the pool", "period off", "banned at once", "needs the admin role"} {
		if !strings.Contains(body, want) {
			t.Errorf("page with the period off lacks %q", want)
		}
	}
	if strings.Contains(body, `action="/shadow/period"`) {
		t.Error("read-only page offers the period form")
	}
	if w := f.post(rev, "/shadow/period", "amount", "2", "unit", "days"); w.Code != http.StatusForbidden {
		t.Errorf("reviewer sets the period: %d, want 403", w.Code)
	}
	if w := f.do("POST", "/shadow/period", ada, nil, sameOriginHdr); w.Code != http.StatusForbidden {
		t.Errorf("period without a CSRF token: %d, want 403", w.Code)
	}
	for _, bad := range [][]string{{"amount", "-1", "unit", "hours"}, {"amount", "x", "unit", "hours"}, {"amount", "2161", "unit", "hours"}, {"amount", "91", "unit", "days"}, {"amount", "2", "unit", "weeks"}, {"amount", "2"}} {
		if w := f.post(ada, "/shadow/period", bad...); w.Code != http.StatusBadRequest {
			t.Errorf("period %v: %d, want 400", bad, w.Code)
		}
	}
	if w := f.post(ada, "/shadow/period", "amount", "36", "unit", "hours"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/shadow?saved=1" {
		t.Fatalf("admin sets the period: %d", w.Code)
	}
	if d, _ := f.st.ShadowPeriod(ctx, "demo"); d != 36*time.Hour {
		t.Fatalf("period %v", d)
	}
	f.wantAudit(t, "demo", "shadow.period", "ada", "shadow pool")
	if w := f.post(ada, "/shadow/period", "amount", "2", "unit", "days"); w.Code != http.StatusSeeOther {
		t.Fatalf("admin sets the period in days: %d", w.Code)
	}
	if body := f.get(ada, "/shadow?saved=1").Body.String(); !strings.Contains(body, "period 2 days") || !strings.Contains(body, `<option value="days" selected>`) || !strings.Contains(body, `value="2"`) || !strings.Contains(body, "Period saved") {
		t.Error("the page does not show the period that was set")
	}
	if d, _ := f.st.ShadowPeriod(ctx, "rival"); d != 0 {
		t.Fatalf("another studio's period %v", d)
	}

	// bob was caught an hour ago in session bbbb2222 and has started one more since;
	// carol connected from bob's PC ten minutes ago.
	end := f.now.Add(47 * time.Hour)
	caught := &store.Ban{TenantID: "demo", Ref: "CW-POOL-BOB1", PlayerHash: "bob", DeviceID: "d2", Rule: "renderer_replaced", SessionID: "bbbb2222", Reason: "an unsigned renderer",
		BannedBy: store.BanAutomatic, BannedAt: f.now.Add(-time.Hour), EffectiveAt: end, Shadow: true}
	second := &store.Ban{TenantID: "demo", Ref: "CW-POOL-CAR2", PlayerHash: "carol", Rule: "renderer_replaced", SessionID: "cccc4444", Reason: "connected from the device key of CW-POOL-BOB1",
		BannedBy: store.BanAutomatic, BannedAt: f.now.Add(-10 * time.Minute), EffectiveAt: end, Shadow: true, ShadowOf: "CW-POOL-BOB1"}
	other := &store.Ban{TenantID: "rival", Ref: "CW-POOL-RIV3", PlayerHash: "rival-player", Rule: "foreign_module", BannedBy: store.BanAutomatic, BannedAt: f.now, EffectiveAt: end, Shadow: true}
	for _, b := range []*store.Ban{caught, second, other} {
		if err := f.st.AddBan(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	f.st.PutSession(ctx, &store.Session{SessionID: "bbbb3333", TenantID: "demo", PlayerHash: "bob", DeviceID: "d2", State: store.SessionActive, CreatedAt: f.now.Add(-30 * time.Minute), LastHeartbeat: f.now})
	f.st.PutSession(ctx, &store.Session{SessionID: "bbbb0000", TenantID: "demo", PlayerHash: "bob", DeviceID: "d2", State: store.SessionClosed, CreatedAt: f.now.Add(-72 * time.Hour)})
	f.st.PutSession(ctx, &store.Session{SessionID: "cccc4444", TenantID: "demo", PlayerHash: "carol", DeviceID: "d2", State: store.SessionActive, CreatedAt: f.now.Add(-10 * time.Minute), LastHeartbeat: f.now})
	module := func(session, name, sum string) store.Evidence {
		return store.Evidence{TenantID: "demo", PlayerHash: "bob", SessionID: session, Source: store.SourceClient, Rule: "foreign_module", Severity: 3, Integrity: true, Summary: name,
			Raw: `{"code":"FINDING_CODE_MODULE_SIGNATURE","b":"0x10002","detail":"` + name + `","sha256":"` + sum + `"}`, ObservedAt: f.now}
	}
	if err := f.st.AddEvidence(ctx, []store.Evidence{module("bbbb2222", "wall.dll", strings.Repeat("aa", 32)), module("bbbb3333", "wall.dll", strings.Repeat("aa", 32)),
		module("bbbb3333", "esp.dll", strings.Repeat("bb", 32)), module("bbbb3333", "client.dll", strings.Repeat("cc", 32))}); err != nil {
		t.Fatal(err)
	}

	body = f.get(ron, "/shadow").Body.String()
	for _, want := range []string{"2 players in the pool", "CW-POOL-BOB1", "CW-POOL-CAR2", "renderer_replaced", "another account on the PC of", "in 47 h 0 min", "1h ago", "10m ago", "need the reviewer role"} {
		if !strings.Contains(body, want) {
			t.Errorf("read-only page lacks %q", want)
		}
	}
	// bob: two sessions since entry (not the one of three days ago) and three files.
	cells := regexp.MustCompile(`<td class="num">(\d+)</td>\s*<td class="num">(\d+)</td>`).FindAllStringSubmatch(body, -1)
	if len(cells) != 2 || cells[0][1] != "2" || cells[0][2] != "3" || cells[1][1] != "1" || cells[1][2] != "0" {
		t.Errorf("sessions recorded and files collected: %v", cells)
	}
	if strings.Contains(body, "/ban\"") || strings.Contains(body, "/release\"") || strings.Contains(body, "CW-POOL-RIV3") {
		t.Error("read-only page offers Ban now or Release, or shows another studio's entry")
	}
	if body := f.get(rex, "/shadow").Body.String(); strings.Contains(body, "CW-POOL-BOB1") || !strings.Contains(body, "CW-POOL-RIV3") || !strings.Contains(body, "1 player in the pool") {
		t.Error("another studio's page")
	}
	body = f.get(rev, "/shadow").Body.String()
	if strings.Count(body, `/ban"`) != 2 || strings.Count(body, `/release"`) != 2 || !strings.Contains(body, "with 1 other account on this PC") || strings.Contains(body, `action="/shadow/period"`) {
		t.Error("reviewer page: Ban now and Release are not offered per entry, or the period form is")
	}
	// The other pages say where the player is.
	if body := f.get(rev, "/bans").Body.String(); !strings.Contains(body, "2 in the shadow pool") || !strings.Contains(body, `href="/shadow#pool"`) || !strings.Contains(body, "0 pending") {
		t.Error("Bans page does not show the entries as the shadow pool")
	}
	if body := f.get(rev, "/sessions/bbbb2222").Body.String(); !strings.Contains(body, ">Shadow pool</a>") || !strings.Contains(body, "told nothing") {
		t.Error("session page of a player in the pool does not say so")
	}

	// Who may act, and on what.
	for _, path := range []string{"/shadow/1/ban", "/shadow/1/release"} {
		if w := f.post(ron, path); w.Code != http.StatusForbidden {
			t.Errorf("read-only POST %s: %d, want 403", path, w.Code)
		}
		if w := f.post(rex, path); w.Code != http.StatusNotFound {
			t.Errorf("another studio's POST %s: %d, want 404", path, w.Code)
		}
		if w := f.do("POST", path, rev, nil, sameOriginHdr); w.Code != http.StatusForbidden {
			t.Errorf("POST %s without a CSRF token: %d, want 403", path, w.Code)
		}
	}
	for _, path := range []string{"/shadow/99/ban", "/shadow/x/release", "/shadow/3/release"} {
		if w := f.post(rev, path); w.Code != http.StatusNotFound {
			t.Errorf("POST %s: %d, want 404", path, w.Code)
		}
	}
	if b, _ := f.st.StandingBan(ctx, "demo", "bob", ""); b == nil || !b.InPool(f.now) {
		t.Fatal("a refused request changed the pool")
	}

	// Release the second account alone, then ban the caught player now.
	if w := f.post(rev, "/shadow/2/release", "note", "a brother"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/shadow?released=1" {
		t.Fatalf("release: %d", w.Code)
	}
	if _, err := f.st.StandingBan(ctx, "demo", "carol", ""); err == nil {
		t.Fatal("the released account still has a ban")
	}
	f.wantAudit(t, "demo", "shadow.release", "rev", "ban CW-POOL-CAR2")
	if w := f.post(rev, "/shadow/2/release"); w.Code != http.StatusNotFound {
		t.Errorf("released twice: %d, want 404", w.Code)
	}
	if w := f.post(rev, "/shadow/1/ban"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/shadow?banned=1" {
		t.Fatalf("ban now: %d", w.Code)
	}
	b, err := f.st.StandingBan(ctx, "demo", "bob", "")
	if err != nil || !b.Active(f.now) || !b.LandedAt.Equal(f.now) || b.InPool(f.now) {
		t.Fatalf("after Ban now: %+v %v", b, err)
	}
	f.wantAudit(t, "demo", "shadow.ban_now", "rev", "ban CW-POOL-BOB1")
	if w := f.post(rev, "/shadow/1/ban"); w.Code != http.StatusNotFound {
		t.Errorf("banned twice: %d, want 404", w.Code)
	}
	if w := f.post(rev, "/shadow/1/release"); w.Code != http.StatusNotFound {
		t.Errorf("released after the ban: %d, want 404", w.Code)
	}
	if body := f.get(rev, "/shadow?banned=1").Body.String(); !strings.Contains(body, "Nobody is in the pool") || !strings.Contains(body, "Banned now") {
		t.Error("the page after both actions")
	}
	if body := f.get(rev, "/bans").Body.String(); !strings.Contains(body, "1 active") || strings.Contains(body, "in the shadow pool</a>") {
		t.Error("Bans page after Ban now")
	}
}

// Releasing the caught player releases the accounts that came in from the same PC, and
// the audit entry names them.
func TestShadowPoolReleaseOfTheCaughtPlayer(t *testing.T) {
	f := newOracleFixture(t, testOracle)
	ctx := context.Background()
	f.addUser(t, "demo", "rev", store.RoleReviewer, goodPW)
	rev := f.signIn(t, "demo", "rev", goodPW)
	end := f.now.Add(time.Hour)
	for _, b := range []*store.Ban{
		{TenantID: "demo", Ref: "CW-POOL-BOB1", PlayerHash: "bob", DeviceID: "d2", Rule: "renderer_replaced", BannedBy: store.BanAutomatic, BannedAt: f.now, EffectiveAt: end, Shadow: true},
		{TenantID: "demo", Ref: "CW-POOL-CAR2", PlayerHash: "carol", Rule: "renderer_replaced", BannedBy: store.BanAutomatic, BannedAt: f.now, EffectiveAt: end, Shadow: true, ShadowOf: "CW-POOL-BOB1"},
	} {
		if err := f.st.AddBan(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	if w := f.post(rev, "/shadow/1/release", "note", "false alarm"); w.Code != http.StatusSeeOther {
		t.Fatalf("release: %d", w.Code)
	}
	for _, p := range []string{"bob", "carol"} {
		if _, err := f.st.StandingBan(ctx, "demo", p, "d2"); err == nil {
			t.Fatalf("%s still has a ban", p)
		}
	}
	f.wantAudit(t, "demo", "shadow.release", "rev", "ban CW-POOL-BOB1")
	audit, _ := f.st.ListAudit(ctx, "demo", store.AuditFilter{Limit: 1})
	if len(audit) != 1 || !strings.Contains(audit[0].Detail, "with it CW-POOL-CAR2 of player carol") || !strings.Contains(audit[0].Detail, "note: false alarm") {
		t.Fatalf("audit detail: %+v", audit)
	}
}
