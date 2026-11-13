package dashboard

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

// A new gateway has no dashboard accounts and no password that works out of the box.
func TestNoDefaultAccounts(t *testing.T) {
	f := newFixture(t)
	for _, tenant := range []string{"demo", "rival"} {
		if n, err := f.srv.au.CountDashUsers(context.Background(), tenant); err != nil || n != 0 {
			t.Fatalf("%s starts with %d accounts (%v)", tenant, n, err)
		}
	}
	for _, c := range [][2]string{{"admin", "admin"}, {"admin", "password"}, {"demo", "demo-key"}, {"demo", "demo"}, {"root", ""}, {"admin", "demo-dashboard-key"}} {
		if w := f.tryLogin(t, "demo", c[0], c[1]); w.Code != http.StatusUnauthorized {
			t.Errorf("%s / %s signed in: %d", c[0], c[1], w.Code)
		}
	}
}

// The first admin: the gateway command line makes a one-time link, the person who opens it
// chooses the password.
func TestFirstAdminThroughOneTimeLink(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := Bootstrap{Store: f.srv.au, Now: func() time.Time { return f.now }}
	token, expires, err := b.InviteAdmin(ctx, "demo", " Ala ")
	if err != nil || len(token) != 43 || !expires.Equal(f.now.Add(BootstrapLinkTTL)) {
		t.Fatalf("invite: %q %v %v", token, expires, err)
	}
	// Only the hash of the token is stored.
	open, _ := f.srv.au.ListDashInvites(ctx, "demo", f.now)
	if len(open) != 1 || open[0].TokenHash != hashToken(token) || strings.Contains(open[0].TokenHash, token) || open[0].Role != store.RoleAdmin || open[0].Name != "ala" {
		t.Fatalf("stored invite: %+v", open)
	}
	page := f.get(nil, "/invite/"+token)
	body := page.Body.String()
	pre, tok := cookieNamed(page, preCookieName), formTokenRE.FindStringSubmatch(body)
	if page.Code != 200 || pre == nil || tok == nil || !strings.Contains(body, `<dd class="mono">ala</dd>`) || !strings.Contains(body, "<dd>Admin</dd>") || !strings.Contains(body, "Create your account") {
		t.Fatalf("invite page: %d %s", page.Code, body)
	}
	accept := func(pw, repeat, csrf string) int {
		return f.do("POST", "/invite/"+token, pre, url.Values{"csrf": {csrf}, "password": {pw}, "repeat": {repeat}}, sameOriginHdr).Code
	}
	// A refused attempt does not use the link up, and creates nothing.
	for name, code := range map[string]int{
		"too short":       accept("short", "short", tok[1]),
		"easy to guess":   accept("password123456", "password123456", tok[1]),
		"holds the name":  accept("ala-is-the-admin-here", "ala-is-the-admin-here", tok[1]),
		"repeat differs":  accept(goodPW, goodPW+"x", tok[1]),
		"no form token":   accept(goodPW, goodPW, ""),
		"wrong token":     accept(goodPW, goodPW, strings.Repeat("0", 32)),
		"cross-site post": f.do("POST", "/invite/"+token, pre, url.Values{"csrf": {tok[1]}, "password": {goodPW}, "repeat": {goodPW}}, map[string]string{"Sec-Fetch-Site": "cross-site"}).Code,
	} {
		if code != http.StatusBadRequest && code != http.StatusForbidden {
			t.Errorf("%s: %d", name, code)
		}
	}
	if n, _ := f.srv.au.CountDashUsers(ctx, "demo"); n != 0 {
		t.Fatalf("a refused attempt created %d accounts", n)
	}
	w := f.do("POST", "/invite/"+token, pre, url.Values{"csrf": {tok[1]}, "password": {goodPW}, "repeat": {goodPW}}, sameOriginHdr)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?ok=created" {
		t.Fatalf("accept: %d %s", w.Code, w.Body.String())
	}
	u := f.user(t, "demo", "ala")
	if u.Role != store.RoleAdmin || !strings.HasPrefix(u.PasswordHash, "$argon2id$v=19$") || strings.Contains(u.PasswordHash, goodPW) || u.CreatedBy != "command line" {
		t.Fatalf("created account: %+v", u)
	}
	// The link works once. A used link, an unknown one and a malformed one look the same.
	used := f.get(nil, "/invite/"+token)
	unknown := f.get(nil, "/invite/"+strings.Repeat("A", 43))
	if used.Code != http.StatusNotFound || unknown.Code != http.StatusNotFound || used.Body.String() != unknown.Body.String() || !strings.Contains(used.Body.String(), "This link is not valid") {
		t.Errorf("used link %d, unknown link %d, same page: %v", used.Code, unknown.Code, used.Body.String() == unknown.Body.String())
	}
	if code := accept(goodPW+"2", goodPW+"2", tok[1]); code != http.StatusNotFound {
		t.Errorf("second use of the link: %d", code)
	}
	if got := f.get(nil, "/invite/short").Code; got != http.StatusNotFound {
		t.Errorf("malformed link: %d", got)
	}
	// It expires.
	late, _, err := b.InviteAdmin(ctx, "demo", "late-admin")
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(BootstrapLinkTTL + time.Second)
	if got := f.get(nil, "/invite/"+late).Code; got != http.StatusNotFound {
		t.Errorf("expired link: %d", got)
	}
	if _, _, err := b.InviteAdmin(ctx, "demo", "ala"); err == nil {
		t.Error("a second invite for an existing user name was made")
	}
	c := f.signIn(t, "demo", "ala", goodPW)
	if got := f.get(c, "/users"); got.Code != 200 || !strings.Contains(got.Body.String(), `>ala</a> <span class="tag">you</span>`) {
		t.Errorf("the new admin's users page: %d", got.Code)
	}
	f.wantAudit(t, "demo", "user.invite", "command line", "ala")
	f.wantAudit(t, "demo", "user.create", "ala", "Admin")
	f.wantAudit(t, "demo", "login.ok", "ala", "password")
}

func TestBootstrapCommands(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := Bootstrap{Store: f.srv.au, Now: func() time.Time { return f.now }}
	for _, bad := range [][2]string{{"", "ala"}, {"demo", "a"}, {"demo", "has space"}, {"demo", "ünï"}, {"de\nmo", "ala"}} {
		if _, _, err := b.InviteAdmin(ctx, bad[0], bad[1]); err == nil {
			t.Errorf("invite for tenant %q user %q accepted", bad[0], bad[1])
		}
	}
	if err := b.CreateAdmin(ctx, "demo", "ala", "password123456"); err == nil || !strings.Contains(err.Error(), "easy to guess") {
		t.Errorf("weak password on the command line: %v", err)
	}
	if err := b.CreateAdmin(ctx, "demo", "Ala", goodPW); err != nil {
		t.Fatal(err)
	}
	if err := b.CreateAdmin(ctx, "demo", "ala", goodPW); err == nil {
		t.Error("the same admin was created twice")
	}
	c := f.signIn(t, "demo", "ala", goodPW)
	// The account was hashed with the production cost; signing in moved it to the cost
	// this server runs with (the test's), without changing the password.
	if u := f.user(t, "demo", "ala"); !strings.Contains(u.PasswordHash, "$m=64,t=1,p=1$") {
		t.Errorf("hash was not replaced at sign-in: %s", u.PasswordHash[:40])
	}
	token, _, err := b.ResetPassword(ctx, "demo", "ala")
	if err != nil {
		t.Fatal(err)
	}
	page := f.get(nil, "/invite/"+token)
	pre, tok := cookieNamed(page, preCookieName), formTokenRE.FindStringSubmatch(page.Body.String())
	if page.Code != 200 || tok == nil || !strings.Contains(page.Body.String(), "Set a new password") {
		t.Fatalf("reset page: %d", page.Code)
	}
	newPW := "seven-green-clouds-above"
	if w := f.do("POST", "/invite/"+token, pre, url.Values{"csrf": {tok[1]}, "password": {newPW}, "repeat": {newPW}}, sameOriginHdr); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?ok=password" {
		t.Fatalf("reset: %d", w.Code)
	}
	if f.alive(c) {
		t.Error("a session survived the password reset")
	}
	if w := f.tryLogin(t, "demo", "ala", goodPW); w.Code != http.StatusUnauthorized {
		t.Errorf("old password after a reset: %d", w.Code)
	}
	c = f.signIn(t, "demo", "ala", newPW)
	_, _, _ = f.enrol(t, c, newPW)
	if err := b.ResetTwoFactor(ctx, "demo", "ala"); err != nil {
		t.Fatal(err)
	}
	if u := f.user(t, "demo", "ala"); u.TOTPSecret != nil {
		t.Error("two-factor secret left after the command-line reset")
	}
	f.signIn(t, "demo", "ala", newPW) // no code asked for any more
	list, err := b.List(ctx, "demo")
	if err != nil || len(list) != 1 || list[0].Name != "ala" || list[0].Role != "Admin" || list[0].TwoFactor || list[0].Disabled {
		t.Errorf("list: %+v %v", list, err)
	}
	if _, _, err := b.ResetPassword(ctx, "demo", "nobody"); err == nil {
		t.Error("reset link for a user that does not exist")
	}
	for _, action := range []string{"user.create", "user.reset_link", "totp.reset"} {
		f.wantAudit(t, "demo", action, "command line", "ala")
	}
	f.wantAudit(t, "demo", "password.reset", "ala", "reset link")
}

func TestAdminInvitesAndManagesUsers(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.addUser(t, "demo", "ala", store.RoleAdmin, goodPW)
	f.addUser(t, "rival", "rex", store.RoleAdmin, goodPW)
	admin := f.signIn(t, "demo", "ala", goodPW)

	w := f.post(admin, "/users/invite", "name", " Sam ", "role", "reviewer")
	link := inviteLinkRE.FindStringSubmatch(w.Body.String())
	if w.Code != 200 || link == nil || !strings.Contains(w.Body.String(), "It is not shown again") {
		t.Fatalf("invite: %d %s", w.Code, w.Body.String())
	}
	open, _ := f.srv.au.ListDashInvites(ctx, "demo", f.now)
	if len(open) != 1 || open[0].TokenHash != hashToken(link[1]) || open[0].Role != store.RoleReviewer || open[0].CreatedBy != "ala" || !open[0].ExpiresAt.Equal(f.now.Add(inviteTTL)) {
		t.Fatalf("stored invite: %+v", open)
	}
	// The link is on the page that created it and on no later page.
	if body := f.get(admin, "/users").Body.String(); strings.Contains(body, link[1]) || !strings.Contains(body, "Open links") {
		t.Error("the users page shows the invite token, or does not list the open link")
	}
	for name, want := range map[string]string{"sam": "still open", "x": "3 to 32", "has space": "3 to 32", "ala": "taken", "ALA": "taken"} {
		if w := f.post(admin, "/users/invite", "name", name, "role", "reviewer"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), want) {
			t.Errorf("invite %q: %d, want a message with %q", name, w.Code, want)
		}
	}
	if w := f.post(admin, "/users/invite", "name", "kim", "role", "owner"); w.Code != http.StatusBadRequest {
		t.Errorf("invite with a made-up role: %d", w.Code)
	}

	// Sam accepts and is a reviewer: no user management, no audit log.
	page := f.get(nil, "/invite/"+link[1])
	pre, tok := cookieNamed(page, preCookieName), formTokenRE.FindStringSubmatch(page.Body.String())
	if w := f.do("POST", "/invite/"+link[1], pre, url.Values{"csrf": {tok[1]}, "password": {goodPW}, "repeat": {goodPW}}, sameOriginHdr); w.Code != http.StatusSeeOther {
		t.Fatalf("sam accepts: %d %s", w.Code, w.Body.String())
	}
	sam := f.signIn(t, "demo", "sam", goodPW)
	samID := strconv.FormatInt(f.user(t, "demo", "sam").ID, 10)
	alaID := strconv.FormatInt(f.user(t, "demo", "ala").ID, 10)
	for _, p := range []string{"/users", "/users/" + samID, "/audit"} {
		if w := f.get(sam, p); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "This needs the Admin role") {
			t.Errorf("reviewer GET %s: %d", p, w.Code)
		}
	}
	for _, p := range []string{"/users/invite", "/users/require-two-factor", "/users/invites/revoke", "/users/" + alaID + "/role", "/users/" + alaID + "/disable", "/users/" + samID + "/role"} {
		if w := f.post(sam, p, "name", "eve", "role", "admin", "require", "1"); w.Code != http.StatusForbidden {
			t.Errorf("reviewer POST %s: %d", p, w.Code)
		}
	}
	if u := f.user(t, "demo", "sam"); u.Role != store.RoleReviewer || f.user(t, "demo", "ala").Disabled {
		t.Fatalf("a refused request changed something: %+v", u)
	}
	f.wantAudit(t, "demo", "access.denied", "sam", "admin role")
	if body := f.get(sam, "/").Body.String(); strings.Contains(body, `href="/users"`) || strings.Contains(body, `href="/audit"`) || !strings.Contains(body, `<span class="mono">sam</span> <span class="muted">Reviewer</span>`) {
		t.Error("a reviewer's header: admin links shown, or name and role missing")
	}

	// Role change: takes effect at once, by ending the user's sessions.
	if w := f.post(admin, "/users/"+samID+"/role", "role", "read_only"); w.Code != http.StatusSeeOther {
		t.Fatalf("role change: %d %s", w.Code, w.Body.String())
	}
	if f.alive(sam) {
		t.Error("the session outlived the role change")
	}
	sam = f.signIn(t, "demo", "sam", goodPW)
	if body := f.get(sam, "/account").Body.String(); !strings.Contains(body, "<dd>Read-only</dd>") {
		t.Error("the account page does not show the new role")
	}
	f.wantAudit(t, "demo", "user.role", "ala", "from Reviewer to Read-only")

	// Nobody changes their own role or access, so a studio always keeps an admin.
	for _, action := range []string{"role", "disable", "reset-two-factor", "reset-password", "sign-out"} {
		if w := f.post(admin, "/users/"+alaID+"/"+action, "role", "read_only"); w.Code != http.StatusConflict {
			t.Errorf("admin %s on their own account: %d", action, w.Code)
		}
	}
	if u := f.user(t, "demo", "ala"); u.Role != store.RoleAdmin || u.Disabled || !f.alive(admin) {
		t.Fatal("an admin changed their own account")
	}

	// Disable: signed out, and sign-in is refused with the same message as a wrong password.
	if w := f.post(admin, "/users/"+samID+"/disable"); w.Code != http.StatusSeeOther {
		t.Fatalf("disable: %d", w.Code)
	}
	if f.alive(sam) {
		t.Error("a disabled account still has a session")
	}
	disabled, wrong := f.tryLogin(t, "demo", "sam", goodPW), f.tryLogin(t, "demo", "ala", "not the password")
	if disabled.Code != http.StatusUnauthorized || !strings.Contains(disabled.Body.String(), msgBadLogin) || !strings.Contains(wrong.Body.String(), msgBadLogin) {
		t.Errorf("disabled sign-in: %d", disabled.Code)
	}
	if w := f.post(admin, "/users/"+samID+"/enable"); w.Code != http.StatusSeeOther {
		t.Fatalf("enable: %d", w.Code)
	}
	sam = f.signIn(t, "demo", "sam", goodPW)

	// Admin sign-out of a user, and a password reset link.
	if w := f.post(admin, "/users/"+samID+"/sign-out"); w.Code != http.StatusSeeOther || f.alive(sam) {
		t.Errorf("admin sign-out: %d, session alive %v", w.Code, f.alive(sam))
	}
	w = f.post(admin, "/users/"+samID+"/reset-password")
	reset := inviteLinkRE.FindStringSubmatch(w.Body.String())
	if w.Code != 200 || reset == nil || !strings.Contains(w.Body.String(), "Password reset link for") {
		t.Fatalf("reset link: %d", w.Code)
	}
	sam = f.signIn(t, "demo", "sam", goodPW) // the old password works until the link is used
	page = f.get(nil, "/invite/"+reset[1])
	pre, tok = cookieNamed(page, preCookieName), formTokenRE.FindStringSubmatch(page.Body.String())
	newPW := "orbit-kettle-plum-98"
	if w := f.do("POST", "/invite/"+reset[1], pre, url.Values{"csrf": {tok[1]}, "password": {newPW}, "repeat": {newPW}}, sameOriginHdr); w.Code != http.StatusSeeOther {
		t.Fatalf("use reset link: %d", w.Code)
	}
	if f.alive(sam) || f.tryLogin(t, "demo", "sam", goodPW).Code != http.StatusUnauthorized {
		t.Error("the old password or session works after the reset")
	}
	f.signIn(t, "demo", "sam", newPW)

	// Revoking an open invite kills its link.
	w = f.post(admin, "/users/invite", "name", "kim", "role", "admin")
	kim := inviteLinkRE.FindStringSubmatch(w.Body.String())
	if kim == nil {
		t.Fatal("invite for kim")
	}
	if w := f.post(admin, "/users/invites/revoke", "id", hashToken(kim[1])); w.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", w.Code)
	}
	if got := f.get(nil, "/invite/"+kim[1]).Code; got != http.StatusNotFound {
		t.Errorf("revoked link: %d", got)
	}
	for _, c := range [][3]string{{"user.invite", "ala", "sam"}, {"user.create", "sam", "Reviewer"}, {"user.disable", "ala", "sam"}, {"user.enable", "ala", "sam"},
		{"session.revoke", "ala", "sam"}, {"user.reset_link", "ala", "sam"}, {"password.reset", "sam", "reset link from ala"}, {"invite.revoke", "ala", "kim"}} {
		f.wantAudit(t, "demo", c[0], c[1], c[2])
	}

	// Another studio's admin cannot see or touch these accounts, or their invites.
	rex := f.signIn(t, "rival", "rex", goodPW)
	if w := f.get(rex, "/users/"+samID); w.Code != http.StatusNotFound {
		t.Errorf("rival admin reads a demo user: %d", w.Code)
	}
	for _, action := range []string{"disable", "role", "reset-password", "reset-two-factor", "sign-out"} {
		if w := f.post(rex, "/users/"+samID+"/"+action, "role", "admin"); w.Code != http.StatusNotFound {
			t.Errorf("rival admin %s on a demo user: %d", action, w.Code)
		}
	}
	w = f.post(admin, "/users/invite", "name", "lee", "role", "reviewer")
	lee := inviteLinkRE.FindStringSubmatch(w.Body.String())
	if w := f.post(rex, "/users/invites/revoke", "id", hashToken(lee[1])); w.Code != http.StatusNotFound {
		t.Errorf("rival admin revokes a demo invite: %d", w.Code)
	}
	if got := f.get(nil, "/invite/"+lee[1]).Code; got != 200 {
		t.Errorf("demo invite after the rival's attempt: %d", got)
	}
	if u := f.user(t, "demo", "sam"); u.Disabled || u.Role != store.RoleReadOnly {
		t.Errorf("rival admin changed a demo user: %+v", u)
	}
	if body := f.get(rex, "/users").Body.String(); strings.Contains(body, "sam") || strings.Contains(body, "ala") || !strings.Contains(body, "rex") {
		t.Error("rival's users page lists demo accounts")
	}
}

// Every role against every page and action.
func TestRolesOnEveryRoute(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "demo", "ada", store.RoleAdmin, goodPW)
	f.addUser(t, "demo", "rev", store.RoleReviewer, goodPW)
	ro := f.addUser(t, "demo", "ron", store.RoleReadOnly, goodPW)
	f.addUser(t, "rival", "rex", store.RoleAdmin, goodPW)
	roID := strconv.FormatInt(ro.ID, 10)
	cookies := map[string]*http.Cookie{"admin": f.signIn(t, "demo", "ada", goodPW), "reviewer": f.signIn(t, "demo", "rev", goodPW), "read-only": f.signIn(t, "demo", "ron", goodPW)}
	// The demo login only exists for a studio without accounts, so it gets its own gateway.
	f2 := newFixture(t)
	demo := f2.login(t, "demo", "demo-key")

	studio := []string{"/", "/sessions", "/sessions/aaaa1111", "/players", "/players?all=1", "/players/bob", "/evidence/1", "/account"}
	adminOnly := []string{"/users", "/users/" + roID, "/audit", "/audit?show=signins&check=1"}
	adminPosts := []string{"/users/invite", "/users/invites/revoke", "/users/require-two-factor", "/users/" + roID + "/role", "/users/" + roID + "/disable",
		"/users/" + roID + "/enable", "/users/" + roID + "/sign-out", "/users/" + roID + "/reset-password", "/users/" + roID + "/reset-two-factor"}

	for _, p := range append(append([]string{}, studio...), adminOnly...) {
		if w := f.get(nil, p); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
			t.Errorf("signed out, GET %s: %d", p, w.Code)
		}
	}
	for _, p := range append(append([]string{}, adminPosts...), "/account/password", "/account/sessions/revoke", "/logout/everywhere", "/account/two-factor/disable", "/account/recovery-codes", "/account/two-factor/setup", "/login/code") {
		if w := f.do("POST", p, nil, url.Values{"csrf": {strings.Repeat("0", 32)}}, sameOriginHdr); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
			t.Errorf("signed out, POST %s: %d", p, w.Code)
		}
	}
	for _, role := range []string{"admin", "reviewer", "read-only"} {
		c := cookies[role]
		for _, p := range studio {
			if w := f.get(c, p); w.Code != 200 {
				t.Errorf("%s GET %s: %d", role, p, w.Code)
			}
		}
		wantAdmin := http.StatusForbidden
		if role == "admin" {
			wantAdmin = http.StatusOK
		}
		for _, p := range adminOnly {
			if w := f.get(c, p); w.Code != wantAdmin {
				t.Errorf("%s GET %s: %d, want %d", role, p, w.Code, wantAdmin)
			}
		}
		if role != "admin" {
			for _, p := range adminPosts {
				if w := f.post(c, p, "name", "eve", "role", "admin", "require", "1"); w.Code != http.StatusForbidden {
					t.Errorf("%s POST %s: %d", role, p, w.Code)
				}
			}
		}
	}
	// The demo login reads and reviews; it does not manage users or read the audit log.
	for _, p := range studio {
		if w := f2.get(demo, p); w.Code != 200 {
			t.Errorf("demo login GET %s: %d", p, w.Code)
		}
	}
	for _, p := range adminOnly {
		if w := f2.get(demo, strings.Replace(p, roID, "1", 1)); w.Code != http.StatusForbidden {
			t.Errorf("demo login GET %s: %d", p, w.Code)
		}
	}
	for _, p := range adminPosts {
		if w := f2.post(demo, p, "name", "eve", "role", "admin", "require", "1"); w.Code != http.StatusForbidden {
			t.Errorf("demo login POST %s: %d", p, w.Code)
		}
	}
	if n, _ := f.srv.au.CountDashUsers(context.Background(), "demo"); n != 3 {
		t.Errorf("a refused request created an account: %d", n)
	}
	if u := f.user(t, "demo", "ron"); u.Disabled || u.Role != store.RoleReadOnly {
		t.Errorf("a refused request changed ron: %+v", u)
	}
}

// What a feature added later gets from auth and CurrentViewer without doing anything: a
// route that changes something is closed to read-only users and to forms without a token,
// its handler can ask who is signed in, and the request is in the audit log.
func TestAuthDefaultsForNewRoutes(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "demo", "rev", store.RoleReviewer, goodPW)
	f.addUser(t, "demo", "ron", store.RoleReadOnly, goodPW)
	rev, ron := f.signIn(t, "demo", "rev", goodPW), f.signIn(t, "demo", "ron", goodPW)
	var seen []Viewer
	h := f.srv.auth(func(w http.ResponseWriter, r *http.Request, tenant string) {
		v, ok := f.srv.CurrentViewer(r)
		if !ok || v.Tenant != tenant {
			t.Errorf("CurrentViewer inside a handler: %+v %v", v, ok)
		}
		seen = append(seen, v)
		w.WriteHeader(http.StatusNoContent)
	})
	post := func(c *http.Cookie, token string, hdr map[string]string) int {
		form := url.Values{"label": {"cleared"}}
		if token != "" {
			form.Set("csrf", token)
		}
		return f.doOn(h, "POST", "/sessions/aaaa1111/label", c, form, hdr).Code
	}
	for name, got := range map[string]int{
		"read-only user":        post(ron, csrfFor(ron.Value), sameOriginHdr),
		"no token":              post(rev, "", sameOriginHdr),
		"wrong token":           post(rev, strings.Repeat("0", 32), sameOriginHdr),
		"another user's token":  post(rev, csrfFor(ron.Value), sameOriginHdr),
		"cross-site":            post(rev, csrfFor(rev.Value), map[string]string{"Sec-Fetch-Site": "cross-site"}),
		"another origin":        post(rev, csrfFor(rev.Value), map[string]string{"Origin": "https://evil.example"}),
		"same-site, not origin": post(rev, csrfFor(rev.Value), map[string]string{"Sec-Fetch-Site": "same-site"}),
	} {
		if got != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, got)
		}
	}
	if len(seen) != 0 {
		t.Fatalf("the handler ran for a refused request: %+v", seen)
	}
	if got := post(nil, "", sameOriginHdr); got != http.StatusSeeOther {
		t.Errorf("signed out: %d", got)
	}
	if got := post(rev, csrfFor(rev.Value), sameOriginHdr); got != http.StatusNoContent {
		t.Fatalf("reviewer: %d", got)
	}
	if got := f.doOn(h, "GET", "/sessions/aaaa1111/label", ron, nil, nil).Code; got != http.StatusNoContent {
		t.Errorf("read-only GET: %d", got)
	}
	if len(seen) != 2 || seen[0].Name != "rev" || seen[0].Role != RoleReviewer || !seen[0].Can(RoleReviewer) || seen[0].Can(RoleAdmin) || seen[0].Demo ||
		seen[1].Name != "ron" || seen[1].Role != RoleReadOnly || seen[1].Can(RoleReviewer) || !seen[1].Can(RoleReadOnly) {
		t.Errorf("viewers seen by the handler: %+v", seen)
	}
	// The handler recorded nothing itself, so the request was recorded for it.
	f.wantAudit(t, "demo", "request.post", "rev", "/sessions/aaaa1111/label")
	f.wantAudit(t, "demo", "access.denied", "ron", "/sessions/aaaa1111/label")
	// A handler that records its own entry is not recorded twice.
	own := f.srv.require(RoleReviewer, func(w http.ResponseWriter, r *http.Request, v Viewer) {
		f.srv.Audit(r, "label.set", "aaaa1111", "cleared")
		w.WriteHeader(http.StatusNoContent)
	})
	before := len(f.auditLog(t, "demo"))
	f.doOn(own, "POST", "/x", rev, url.Values{"csrf": {csrfFor(rev.Value)}}, sameOriginHdr)
	if rows := f.auditLog(t, "demo"); len(rows) != before+1 || rows[0].Action != "label.set" || rows[0].Actor != "rev" {
		t.Errorf("audit after a self-recording handler: %d new entries, newest %+v", len(rows)-before, rows[0])
	}

	// Outside a wrapped handler CurrentViewer reads the cookie itself.
	req := func(c *http.Cookie) *http.Request {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr, r.Host = f.remote, f.host
		if c != nil {
			r.AddCookie(c)
		}
		return r
	}
	if v, ok := f.srv.CurrentViewer(req(rev)); !ok || v.Name != "rev" || v.Role != RoleReviewer || v.Tenant != "demo" {
		t.Errorf("CurrentViewer from a cookie: %+v %v", v, ok)
	}
	if _, ok := f.srv.CurrentViewer(req(nil)); ok {
		t.Error("CurrentViewer without a cookie")
	}
	if _, ok := f.srv.CurrentViewer(req(&http.Cookie{Name: cookieName, Value: strings.Repeat("A", 43)})); ok {
		t.Error("CurrentViewer with a made-up cookie")
	}
	// The demo login is a reviewer without a name of its own.
	g := newFixture(t)
	demo := g.login(t, "demo", "demo-key")
	r := req(demo)
	if v, ok := g.srv.CurrentViewer(r); !ok || !v.Demo || v.UserID != 0 || v.Role != RoleReviewer || v.Tenant != "demo" || v.Admin() {
		t.Errorf("CurrentViewer for the demo login: %+v %v", v, ok)
	}
	for key, want := range map[string]Role{"admin": RoleAdmin, "reviewer": RoleReviewer, "read_only": RoleReadOnly, "": RoleNone, "owner": RoleNone, "ADMIN": RoleNone} {
		if got := roleOf(key); got != want || (want != RoleNone && got.Key() != key) {
			t.Errorf("roleOf(%q) = %v", key, got)
		}
	}
	if RoleReadOnly >= RoleReviewer || RoleReviewer >= RoleAdmin || (Viewer{}).Can(RoleNone) || (Viewer{}).Can(RoleReadOnly) {
		t.Error("roles are not ordered, or an empty viewer can do something")
	}
}

var muxRoute = regexp.MustCompile(`mux\.Handle(?:Func)?\("([A-Z]+ [^"]+)",\s*(.*)\)\s*$`)

// Every route is registered through auth, require or stage, or is one of the few that
// must work signed out. A route added without a guard fails here.
func TestEveryRouteIsGuarded(t *testing.T) {
	public := map[string]bool{
		"GET /static/": true, "GET /login": true, "POST /login": true, "POST /logout": true,
		"GET /invite/{token}": true, "POST /invite/{token}": true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	routes := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			m := muxRoute.FindStringSubmatch(strings.TrimSpace(line))
			if m == nil {
				if strings.Contains(line, "mux.Handle") {
					t.Errorf("%s: route registration this test cannot read: %s", file, strings.TrimSpace(line))
				}
				continue
			}
			routes++
			guarded := strings.HasPrefix(m[2], "s.auth(") || strings.HasPrefix(m[2], "s.require(") || strings.HasPrefix(m[2], "s.stage(")
			if guarded == public[m[1]] {
				t.Errorf("%s: route %q: guarded=%v, on the signed-out list=%v", file, m[1], guarded, public[m[1]])
			}
		}
	}
	if routes < 25 {
		t.Errorf("only %d routes found; did the registrations move?", routes)
	}
}
