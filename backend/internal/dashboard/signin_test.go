package dashboard

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

func TestTwoFactor(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.addUser(t, "demo", "ala", store.RoleAdmin, goodPW)
	c := f.signIn(t, "demo", "ala", goodPW)
	elsewhere := f.signIn(t, "demo", "ala", goodPW)

	// The enrolment page draws the QR code itself: an inline SVG, no image from anywhere.
	page := f.get(c, "/account/two-factor/setup")
	body := page.Body.String()
	key, pending, path := setupKeyRE.FindStringSubmatch(body), pendingRE.FindStringSubmatch(body), qrPathRE.FindStringSubmatch(body)
	if page.Code != 200 || key == nil || pending == nil || path == nil || !strings.Contains(body, `<svg class="qr" viewBox="0 0 `) {
		t.Fatalf("setup page: %d", page.Code)
	}
	secret, err := b32.DecodeString(strings.ReplaceAll(key[1], " ", ""))
	if err != nil || len(secret) != totpSecretLen {
		t.Fatalf("key on the page: %v", err)
	}
	uri := otpauthURI(totpIssuer, "ala@demo", secret)
	if want := "otpauth://totp/Carthago%20Watchdog:ala%40demo?secret=" + b32.EncodeToString(secret) + "&issuer=Carthago%20Watchdog"; uri != want {
		t.Errorf("otpauth URI %q", uri)
	}
	qr, err := qrEncode(uri, -1)
	if err != nil {
		t.Fatal(err)
	}
	if want, side := qr.svgPath(); path[1] != want || !strings.Contains(body, fmt.Sprintf(`viewBox="0 0 %d %d"`, side, side)) {
		t.Error("the QR code on the page does not encode the account's otpauth URI")
	}
	// Nothing is stored until a code proves the app has the secret.
	if u := f.user(t, "demo", "ala"); u.TOTPSecret != nil {
		t.Fatal("secret stored before it was confirmed")
	}
	good := func() string { return totpCode(secret, totpStep(f.now)) }
	for name, w := range map[string]int{
		"wrong code":      f.post(c, "/account/two-factor/setup", "pending", pending[1], "password", goodPW, "code", "000000").Code,
		"wrong password":  f.post(c, "/account/two-factor/setup", "pending", pending[1], "password", "not-the-password", "code", good()).Code,
		"no password":     f.post(c, "/account/two-factor/setup", "pending", pending[1], "code", good()).Code,
		"forged pending":  f.post(c, "/account/two-factor/setup", "pending", "AAAA"+pending[1][4:], "password", goodPW, "code", good()).Code,
		"missing pending": f.post(c, "/account/two-factor/setup", "password", goodPW, "code", good()).Code,
	} {
		if w != http.StatusUnauthorized && w != http.StatusBadRequest {
			t.Errorf("%s: %d", name, w)
		}
	}
	if u := f.user(t, "demo", "ala"); u.TOTPSecret != nil {
		t.Fatal("a refused enrolment stored a secret")
	}
	// Another account cannot confirm with this page's sealed secret.
	f.addUser(t, "demo", "bea", store.RoleReviewer, goodPW)
	bea := f.signIn(t, "demo", "bea", goodPW)
	if w := f.post(bea, "/account/two-factor/setup", "pending", pending[1], "password", goodPW, "code", good()); w.Code != http.StatusBadRequest || f.user(t, "demo", "bea").TOTPSecret != nil {
		t.Errorf("another account used the sealed secret: %d", w.Code)
	}

	w := f.post(c, "/account/two-factor/setup", "pending", pending[1], "password", goodPW, "code", good())
	nc := cookieNamed(w, cookieName)
	var codes []string
	for _, m := range recoveryRE.FindAllStringSubmatch(w.Body.String(), -1) {
		codes = append(codes, m[1])
	}
	if w.Code != 200 || nc == nil || nc.Value == c.Value || len(codes) != recoveryCodes || !strings.Contains(w.Body.String(), "They are not shown again") {
		t.Fatalf("enrolment: %d, %d recovery codes", w.Code, len(codes))
	}
	// Turning it on ends the other browsers and gives this one a new session id.
	if f.alive(c) || f.alive(elsewhere) || !f.alive(nc) {
		t.Error("sessions after enrolment: the old id or the other browser still works, or the new one does not")
	}
	c = nc
	u := f.user(t, "demo", "ala")
	if len(u.TOTPSecret) == 0 || bytes.Contains(u.TOTPSecret, secret) {
		t.Fatal("the stored secret is missing or readable")
	}
	if got, err := f.srv.box.open(u.TOTPSecret, totpSealName("demo", u.ID)); err != nil || !bytes.Equal(got, secret) {
		t.Errorf("stored secret does not open for its own account: %v", err)
	}
	if _, err := f.srv.box.open(u.TOTPSecret, totpSealName("demo", u.ID+1)); err == nil {
		t.Error("stored secret opens for another account")
	}
	if n, _ := f.srv.au.CountRecoveryCodes(ctx, u.ID); n != recoveryCodes {
		t.Errorf("%d recovery codes stored", n)
	}
	if body := f.get(c, "/account").Body.String(); !strings.Contains(body, `<span class="mark mark-on">On</span>`) || !strings.Contains(body, "10 recovery codes left") || strings.Contains(body, codes[0]) {
		t.Error("account page after enrolment")
	}
	f.wantAudit(t, "demo", "totp.enrol", "ala", "ala")

	// Signing in now takes two steps. Between them nothing is open.
	w = f.tryLogin(t, "demo", "ala", goodPW)
	step := cookieNamed(w, cookieName)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login/code" || step == nil {
		t.Fatalf("password step: %d -> %s", w.Code, w.Header().Get("Location"))
	}
	if !step.Expires.Equal(f.now.Add(codeSessionTTL)) {
		t.Errorf("code-step cookie lasts %v", step.Expires.Sub(f.now))
	}
	for _, p := range []string{"/", "/sessions", "/players/bob", "/evidence/1", "/account", "/users", "/audit"} {
		if w := f.get(step, p); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login/code" {
			t.Errorf("GET %s before the code: %d -> %s", p, w.Code, w.Header().Get("Location"))
		}
	}
	for _, p := range []string{"/users/invite", "/account/password", "/account/two-factor/disable", "/account/two-factor/setup"} {
		if w := f.post(step, p, "name", "eve", "role", "admin"); w.Code != http.StatusSeeOther {
			t.Errorf("POST %s before the code: %d", p, w.Code)
		}
	}
	if n, _ := f.srv.au.CountDashUsers(ctx, "demo"); n != 2 {
		t.Fatal("a half signed-in session invited a user")
	}
	req, _ := http.NewRequest("GET", "/", nil)
	req.AddCookie(step)
	if _, ok := f.srv.CurrentViewer(req); ok {
		t.Error("CurrentViewer counts a sign-in that still waits for its code")
	}
	if got := f.get(step, "/login/code"); got.Code != 200 || !strings.Contains(got.Body.String(), `Signing in as <span class="mono">ala</span>`) {
		t.Errorf("code page: %d", got.Code)
	}
	if w := f.post(step, "/login/code", "code", "123456"); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "That code did not match") {
		t.Errorf("wrong code: %d", w.Code)
	}
	// The code that confirmed the enrolment was used up by it.
	if w := f.post(step, "/login/code", "code", good()); w.Code != http.StatusUnauthorized {
		t.Errorf("the enrolment's code signed in again: %d", w.Code)
	}
	f.now = f.now.Add(totpPeriod * time.Second)
	code := good()
	w = f.post(step, "/login/code", "code", code[:3]+" "+code[3:])
	full := cookieNamed(w, cookieName)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" || full == nil || full.Value == step.Value || !f.alive(full) {
		t.Fatalf("code step: %d", w.Code)
	}
	if f.get(step, "/login/code").Code != http.StatusSeeOther {
		t.Error("the code-step session survived the sign-in")
	}
	f.wantAudit(t, "demo", "login.ok", "ala", "password and authenticator code")
	// A code works once: seen over a shoulder, it cannot be replayed within its 30 seconds.
	w = f.tryLogin(t, "demo", "ala", goodPW)
	step = cookieNamed(w, cookieName)
	if w := f.post(step, "/login/code", "code", code); w.Code != http.StatusUnauthorized {
		t.Errorf("replayed code: %d", w.Code)
	}
	// The codes one period either side are accepted (clock drift), two periods away not.
	if w := f.post(step, "/login/code", "code", totpCode(secret, totpStep(f.now)+2)); w.Code != http.StatusUnauthorized {
		t.Errorf("a code two periods ahead: %d", w.Code)
	}
	if w := f.post(step, "/login/code", "code", totpCode(secret, totpStep(f.now)+1)); w.Code != http.StatusSeeOther {
		t.Errorf("the next period's code: %d", w.Code)
	}
	f.now = f.now.Add(3 * totpPeriod * time.Second)

	// A recovery code signs in once, typed the way people type.
	w = f.tryLogin(t, "demo", "ala", goodPW)
	step = cookieNamed(w, cookieName)
	typed := " " + strings.ToUpper(strings.ReplaceAll(codes[0], "-", " ")) + " "
	w = f.post(step, "/login/code", "code", typed)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account?ok=recovery" {
		t.Fatalf("recovery code: %d -> %s", w.Code, w.Header().Get("Location"))
	}
	c = cookieNamed(w, cookieName)
	if body := f.get(c, "/account?ok=recovery").Body.String(); !strings.Contains(body, "You signed in with a recovery code. 9 left") {
		t.Error("no notice after a recovery-code sign-in")
	}
	w = f.tryLogin(t, "demo", "ala", goodPW)
	step = cookieNamed(w, cookieName)
	if w := f.post(step, "/login/code", "code", codes[0]); w.Code != http.StatusUnauthorized {
		t.Errorf("a recovery code worked twice: %d", w.Code)
	}
	if w := f.post(step, "/login/code", "code", "0000-0000-0000-0000"); w.Code != http.StatusUnauthorized {
		t.Errorf("a made-up recovery code: %d", w.Code)
	}
	f.wantAudit(t, "demo", "recovery.use", "ala", "recovery code")
	f.wantAudit(t, "demo", "login.fail", "ala", "wrong two-factor code")

	// Recovery codes are stored as keyed hashes: the database does not hold them.
	if h := f.srv.box.recoveryHash(u.ID, codes[1]); len(h) != 64 || strings.Contains(h, strings.ReplaceAll(codes[1], "-", "")) || h == f.srv.box.recoveryHash(u.ID+1, codes[1]) {
		t.Error("recovery hash")
	}

	// New recovery codes and turning it off both take the password and a current code.
	for _, p := range []string{"/account/recovery-codes", "/account/two-factor/disable"} {
		if w := f.post(c, p, "password", "not-the-password", "code", good()); w.Code != http.StatusUnauthorized {
			t.Errorf("%s with a wrong password: %d", p, w.Code)
		}
		if w := f.post(c, p, "password", goodPW, "code", "000000"); w.Code != http.StatusUnauthorized {
			t.Errorf("%s with a wrong code: %d", p, w.Code)
		}
	}
	if f.user(t, "demo", "ala").TOTPSecret == nil {
		t.Fatal("two-factor was turned off without the password and a code")
	}
	f.srv.lim = limiter{} // the refusals above counted as failed attempts
	w = f.post(c, "/account/recovery-codes", "password", goodPW, "code", good())
	fresh := recoveryRE.FindAllStringSubmatch(w.Body.String(), -1)
	if w.Code != 200 || len(fresh) != recoveryCodes || fresh[0][1] == codes[1] {
		t.Fatalf("new recovery codes: %d, %d codes", w.Code, len(fresh))
	}
	if used, _ := f.srv.au.UseRecoveryCode(ctx, u.ID, f.srv.box.recoveryHash(u.ID, codes[1])); used {
		t.Error("an old recovery code works after new ones were made")
	}
	f.now = f.now.Add(totpPeriod * time.Second)
	other := f.signIn2(t, "demo", "ala", goodPW, secret)
	w = f.post(c, "/account/two-factor/disable", "password", goodPW, "code", good())
	nc = cookieNamed(w, cookieName)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account?ok=twofactor-off" || nc == nil {
		t.Fatalf("turn off: %d", w.Code)
	}
	if u := f.user(t, "demo", "ala"); u.TOTPSecret != nil {
		t.Error("secret left after turning two-factor off")
	}
	if n, _ := f.srv.au.CountRecoveryCodes(ctx, u.ID); n != 0 {
		t.Errorf("%d recovery codes left after turning two-factor off", n)
	}
	if f.alive(other) || f.alive(c) || !f.alive(nc) {
		t.Error("sessions after turning two-factor off")
	}
	f.signIn(t, "demo", "ala", goodPW)
	for _, a := range []string{"recovery.regenerate", "totp.disable"} {
		f.wantAudit(t, "demo", a, "ala", "ala")
	}

	// Replacing the authenticator: the old app's codes stop working.
	c, old, _ := f.enrol(t, f.signIn(t, "demo", "ala", goodPW), goodPW)
	c, replaced, _ := f.enrol(t, c, goodPW)
	if bytes.Equal(old, replaced) {
		t.Fatal("the replacement has the same secret")
	}
	w = f.tryLogin(t, "demo", "ala", goodPW)
	step = cookieNamed(w, cookieName)
	if w := f.post(step, "/login/code", "code", totpCode(old, totpStep(f.now))); w.Code != http.StatusUnauthorized {
		t.Errorf("the replaced app's code: %d", w.Code)
	}
	if w := f.post(step, "/login/code", "code", totpCode(replaced, totpStep(f.now))); w.Code != http.StatusSeeOther {
		t.Errorf("the new app's code: %d", w.Code)
	}
	f.wantAudit(t, "demo", "totp.replace", "ala", "replaced")

	// The code step is limited like the password step: five wrong codes lock the account
	// and end the half sign-in.
	f.now = f.now.Add(time.Hour)
	f.srv.lim = limiter{}
	w = f.tryLogin(t, "demo", "ala", goodPW)
	step = cookieNamed(w, cookieName)
	for i := 1; i <= maxFailures; i++ {
		w = f.post(step, "/login/code", "code", "111111")
		if want := map[bool]int{false: http.StatusUnauthorized, true: http.StatusTooManyRequests}[i == maxFailures]; w.Code != want {
			t.Fatalf("wrong code %d: %d, want %d", i, w.Code, want)
		}
	}
	if f.get(step, "/login/code").Code != http.StatusSeeOther {
		t.Error("the half sign-in survived the lock")
	}
	if w := f.tryLogin(t, "demo", "ala", goodPW); w.Code != http.StatusTooManyRequests {
		t.Errorf("sign-in during the lock: %d", w.Code)
	}
	f.wantAudit(t, "demo", "login.lock", "ala", "locked for 1m0s")

	// An admin resets a user's second factor; the user cannot be asked for a code they lost.
	f.now = f.now.Add(time.Hour)
	beaC, _, _ := f.enrol(t, f.signIn(t, "demo", "bea", goodPW), goodPW)
	admin := f.signIn2(t, "demo", "ala", goodPW, replaced)
	beaID := f.user(t, "demo", "bea").ID
	if w := f.post(admin, fmt.Sprintf("/users/%d/reset-two-factor", beaID)); w.Code != http.StatusSeeOther {
		t.Fatalf("admin reset: %d", w.Code)
	}
	if f.user(t, "demo", "bea").TOTPSecret != nil || f.alive(beaC) {
		t.Error("after the admin reset bea still has a secret or a session")
	}
	f.signIn(t, "demo", "bea", goodPW)
	f.wantAudit(t, "demo", "totp.reset", "ala", "bea")
}

func TestStudioCanRequireTwoFactor(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "demo", "ala", store.RoleAdmin, goodPW)
	f.addUser(t, "demo", "sam", store.RoleReviewer, goodPW)
	f.addUser(t, "rival", "rex", store.RoleAdmin, goodPW)
	admin := f.signIn(t, "demo", "ala", goodPW)
	sam := f.signIn(t, "demo", "sam", goodPW)

	// An admin who has not set it up cannot require it of others.
	if w := f.post(admin, "/users/require-two-factor", "require", "1"); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "on your own account first") {
		t.Fatalf("require without own second factor: %d", w.Code)
	}
	if set, _ := f.srv.au.GetTenantSettings(context.Background(), "demo"); set.RequireTOTP {
		t.Fatal("the rule was switched on anyway")
	}
	admin, secret, _ := f.enrol(t, admin, goodPW)
	if w := f.post(admin, "/users/require-two-factor", "require", "1"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/users?ok=required" {
		t.Fatalf("require: %d", w.Code)
	}
	if body := f.get(admin, "/users").Body.String(); !strings.Contains(body, `<span class="mark mark-on">Required</span>`) {
		t.Error("users page does not show the rule")
	}
	f.wantAudit(t, "demo", "tenant.require_2fa", "ala", "required for every account")

	// A session that was already open is held at the setup page from its next click.
	for _, p := range []string{"/", "/sessions", "/players", "/account"} {
		if w := f.get(sam, p); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account/two-factor/setup" {
			t.Errorf("GET %s without the required second factor: %d -> %s", p, w.Code, w.Header().Get("Location"))
		}
	}
	if w := f.post(sam, "/account/password", "current", goodPW, "password", goodPW+"-2", "repeat", goodPW+"-2"); w.Code != http.StatusSeeOther {
		t.Errorf("POST without the required second factor: %d", w.Code)
	}
	req, _ := http.NewRequest("GET", "/", nil)
	req.AddCookie(sam)
	if _, ok := f.srv.CurrentViewer(req); ok {
		t.Error("CurrentViewer counts an account that still has to enrol")
	}
	// Signing out still works.
	if w := f.post(sam, "/logout"); w.Code != http.StatusSeeOther || f.get(sam, "/account/two-factor/setup").Code != http.StatusSeeOther {
		t.Errorf("sign out while held at setup: %d", w.Code)
	}

	// A new sign-in gets a session that opens the setup page and nothing else.
	w := f.tryLogin(t, "demo", "sam", goodPW)
	enrolC := cookieNamed(w, cookieName)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account/two-factor/setup" || enrolC == nil {
		t.Fatalf("sign-in under the rule: %d -> %s", w.Code, w.Header().Get("Location"))
	}
	if w := f.get(enrolC, "/sessions"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account/two-factor/setup" {
		t.Errorf("enrol session on /sessions: %d", w.Code)
	}
	if got := f.get(enrolC, "/login/code"); got.Code != http.StatusSeeOther {
		t.Errorf("enrol session on the code page: %d", got.Code)
	}
	page := f.get(enrolC, "/account/two-factor/setup")
	body := page.Body.String()
	key, pending := setupKeyRE.FindStringSubmatch(body), pendingRE.FindStringSubmatch(body)
	if page.Code != 200 || key == nil || !strings.Contains(body, "Your studio requires it for every account") || strings.Contains(body, `name="password"`) || strings.Contains(body, `<header class="top">`) {
		t.Fatalf("forced setup page: %d", page.Code)
	}
	samSecret, _ := b32.DecodeString(strings.ReplaceAll(key[1], " ", ""))
	w = f.post(enrolC, "/account/two-factor/setup", "pending", pending[1], "code", totpCode(samSecret, totpStep(f.now)))
	sam = cookieNamed(w, cookieName)
	if w.Code != 200 || sam == nil || len(recoveryRE.FindAllString(w.Body.String(), -1)) != recoveryCodes || !f.alive(sam) || f.alive(enrolC) {
		t.Fatalf("forced enrolment: %d", w.Code)
	}
	f.wantAudit(t, "demo", "login.ok", "sam", "two-factor enrolment")
	f.now = f.now.Add(totpPeriod * time.Second)

	// Under the rule it cannot be turned off, and the form is not offered.
	if body := f.get(sam, "/account").Body.String(); strings.Contains(body, `action="/account/two-factor/disable"`) || !strings.Contains(body, "Your studio requires two-factor sign-in") {
		t.Error("account page under the rule")
	}
	if w := f.post(sam, "/account/two-factor/disable", "password", goodPW, "code", totpCode(samSecret, totpStep(f.now))); w.Code != http.StatusConflict || f.user(t, "demo", "sam").TOTPSecret == nil {
		t.Errorf("turning two-factor off under the rule: %d", w.Code)
	}
	// The rule is the studio's own: the rival studio is untouched.
	f.signIn(t, "rival", "rex", goodPW)

	// Optional again.
	admin = f.signIn2(t, "demo", "ala", goodPW, secret)
	if w := f.post(admin, "/users/require-two-factor", "require", "0"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/users?ok=optional" {
		t.Fatalf("make optional: %d", w.Code)
	}
	if w := f.post(sam, "/account/two-factor/disable", "password", goodPW, "code", totpCode(samSecret, totpStep(f.now))); w.Code != http.StatusSeeOther {
		t.Errorf("turning two-factor off once optional: %d", w.Code)
	}
	f.wantAudit(t, "demo", "tenant.require_2fa", "ala", "no longer required")
}

func TestSessions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.addUser(t, "demo", "ala", store.RoleAdmin, goodPW)
	f.addUser(t, "demo", "sam", store.RoleReviewer, goodPW)

	w := f.tryLogin(t, "demo", "ala", goodPW)
	c := cookieNamed(w, cookieName)
	if c == nil || !c.HttpOnly || c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || len(c.Value) != 43 || !c.Expires.Equal(f.now.Add(defaultSessionTTL)) {
		t.Fatalf("session cookie: %+v", c)
	}
	// The cookie is a random id. The store holds its hash, so a copy of the database is
	// not a set of working cookies.
	row, err := f.srv.au.GetDashSession(ctx, hashToken(c.Value))
	if err != nil || row.Kind != store.DashSessionFull || row.IP != "127.0.0.1" || row.TenantID != "demo" {
		t.Fatalf("stored session: %+v %v", row, err)
	}
	if _, err := f.srv.au.GetDashSession(ctx, c.Value); err == nil {
		t.Error("the session is stored under the cookie value itself")
	}
	for name, v := range map[string]string{"made up": strings.Repeat("A", 43), "its own hash": hashToken(c.Value), "empty": "", "oversized": strings.Repeat("A", 500), "old signed format": "demo|9999999999|" + strings.Repeat("ab", 32)} {
		if got := f.get(&http.Cookie{Name: cookieName, Value: v}, "/"); got.Code != http.StatusSeeOther || got.Header().Get("Location") != "/login" {
			t.Errorf("cookie %s: %d", name, got.Code)
		}
	}

	// Signing out needs the form's token, and ends the session on the server: the cookie
	// is dead even if someone kept a copy.
	if w := f.do("POST", "/logout", c, nil, sameOriginHdr); w.Code != http.StatusForbidden || !f.alive(c) {
		t.Errorf("logout without a token: %d", w.Code)
	}
	if w := f.do("POST", "/logout", c, url.Values{"csrf": {csrfFor(c.Value)}}, map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != http.StatusForbidden || !f.alive(c) {
		t.Errorf("cross-site logout: %d", w.Code)
	}
	w = f.post(c, "/logout")
	gone := cookieNamed(w, cookieName)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" || gone == nil || gone.MaxAge >= 0 || gone.Value != "" {
		t.Fatalf("logout: %d %+v", w.Code, gone)
	}
	if f.alive(c) {
		t.Error("the cookie works after signing out")
	}
	if _, err := f.srv.au.GetDashSession(ctx, hashToken(c.Value)); err == nil {
		t.Error("the session row survived signing out")
	}
	f.wantAudit(t, "demo", "logout", "ala", "")

	// Idle expiry: 30 minutes without a request. Activity keeps it open...
	c = f.signIn(t, "demo", "ala", goodPW)
	start := f.now
	for i := 0; i < 5; i++ {
		f.now = f.now.Add(defaultIdleTTL - time.Minute)
		if !f.alive(c) {
			t.Fatalf("an active session ended after %v", f.now.Sub(start))
		}
	}
	// ...and silence closes it.
	f.now = f.now.Add(defaultIdleTTL + time.Second)
	if f.alive(c) {
		t.Error("the session survived 30 idle minutes")
	}
	if _, err := f.srv.au.GetDashSession(ctx, hashToken(c.Value)); err == nil {
		t.Error("an expired session stays in the store")
	}
	// Absolute expiry: 12 hours after sign-in, however active.
	c = f.signIn(t, "demo", "ala", goodPW)
	start = f.now
	for f.now.Sub(start) < defaultSessionTTL-20*time.Minute {
		f.now = f.now.Add(20 * time.Minute)
		if !f.alive(c) {
			t.Fatalf("session ended early, after %v", f.now.Sub(start))
		}
	}
	f.now = start.Add(defaultSessionTTL)
	if f.alive(c) {
		t.Error("the session outlived its 12 hours")
	}

	// Rotation at sign-in: a session id planted in the browser beforehand is not the one
	// that gets signed in, and does not survive.
	attacker := f.signIn(t, "demo", "sam", goodPW)
	pre, tok := f.pre(t)
	w = f.doWith("POST", "/login", url.Values{"csrf": {tok}, "tenant": {"demo"}, "user": {"ala"}, "password": {goodPW}}, sameOriginHdr, pre, attacker)
	c = cookieNamed(w, cookieName)
	if w.Code != http.StatusSeeOther || c == nil || c.Value == attacker.Value {
		t.Fatalf("sign-in over a planted session: %d", w.Code)
	}
	if f.alive(attacker) {
		t.Error("the session the browser arrived with survived the sign-in")
	}
	// Every sign-in has a new id.
	c2 := f.signIn(t, "demo", "ala", goodPW)
	if c2.Value == c.Value || !f.alive(c) || !f.alive(c2) {
		t.Error("two sign-ins share an id, or one ended the other")
	}

	// The account page lists the signed-in browsers; one can be signed out from another.
	body := f.get(c, "/account").Body.String()
	if strings.Count(body, `action="/account/sessions/revoke"`) != 1 || !strings.Contains(body, `<span class="tag">this browser</span>`) || strings.Contains(body, c.Value) || strings.Contains(body, c2.Value) {
		t.Error("signed-in browsers on the account page")
	}
	// Not someone else's session, though.
	sam := f.signIn(t, "demo", "sam", goodPW)
	if w := f.post(sam, "/account/sessions/revoke", "id", hashToken(c2.Value)); w.Code != http.StatusNotFound || !f.alive(c2) {
		t.Errorf("revoking another user's session: %d", w.Code)
	}
	if w := f.post(c, "/account/sessions/revoke", "id", hashToken(c2.Value)); w.Code != http.StatusSeeOther || f.alive(c2) || !f.alive(c) {
		t.Errorf("revoking an own session: %d", w.Code)
	}
	f.wantAudit(t, "demo", "session.revoke", "ala", "signed out")

	// A password change (a privilege change) ends every other session and renews this one.
	c2 = f.signIn(t, "demo", "ala", goodPW)
	newPW := "seven-green-clouds-above"
	for name, kv := range map[string][]string{
		"wrong current": {"current", "not-the-password", "password", newPW, "repeat", newPW},
		"weak":          {"current", goodPW, "password", "password1234", "repeat", "password1234"},
		"repeat":        {"current", goodPW, "password", newPW, "repeat", newPW + "x"},
		"unchanged":     {"current", goodPW, "password", goodPW, "repeat", goodPW},
	} {
		if w := f.post(c, "/account/password", kv...); w.Code != http.StatusUnauthorized && w.Code != http.StatusBadRequest {
			t.Errorf("password change, %s: %d", name, w.Code)
		}
	}
	w = f.post(c, "/account/password", "current", goodPW, "password", newPW, "repeat", newPW)
	nc := cookieNamed(w, cookieName)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account?ok=password" || nc == nil || nc.Value == c.Value {
		t.Fatalf("password change: %d", w.Code)
	}
	if f.alive(c) || f.alive(c2) || !f.alive(nc) {
		t.Error("sessions after a password change: an old id still works, or the new one does not")
	}
	if f.tryLogin(t, "demo", "ala", goodPW).Code != http.StatusUnauthorized {
		t.Error("the old password still signs in")
	}
	f.wantAudit(t, "demo", "password.change", "ala", "ala")

	// Sign out everywhere.
	a, b := f.signIn(t, "demo", "ala", newPW), f.signIn(t, "demo", "ala", newPW)
	if w := f.post(a, "/logout/everywhere"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?ok=signedout" {
		t.Fatalf("sign out everywhere: %d", w.Code)
	}
	if f.alive(a) || f.alive(b) || f.alive(nc) || !f.alive(sam) {
		t.Error("sign out everywhere left a session of the account, or ended someone else's")
	}
	if rows, _ := f.srv.au.ListDashSessions(ctx, "demo", f.user(t, "demo", "ala").ID, f.now); len(rows) != 0 {
		t.Errorf("%d sessions left in the store", len(rows))
	}
	f.wantAudit(t, "demo", "logout.everywhere", "ala", "3 sessions ended")

	// The account is read on every request: a session of a deleted-in-effect account
	// (disabled, or with a role that no longer exists) stops at once.
	off := true
	if err := f.srv.au.UpdateDashUser(ctx, "demo", f.user(t, "demo", "sam").ID, store.DashUserChange{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	if f.alive(sam) {
		t.Error("a disabled account's session still works")
	}
}

func TestSecureCookies(t *testing.T) {
	st := store.NewMemory()
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	srv, err := New(Config{SecureCookie: true, Now: func() time.Time { return now }}, st, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	srv.argon = testArgon
	f := &fixture{srv: srv, h: srv.Handler(), now: now, remote: "203.0.113.9:4000", host: "dash.studio.example"}
	f.addUser(t, "demo", "ala", store.RoleAdmin, goodPW)
	page := f.get(nil, "/login")
	pre := cookieNamed(page, "__Host-cw_pre")
	if pre == nil || !pre.Secure || !pre.HttpOnly || pre.SameSite != http.SameSiteStrictMode || pre.Path != "/" || pre.Domain != "" {
		t.Fatalf("pre-login cookie over HTTPS: %+v", pre)
	}
	w := f.do("POST", "/login", pre, url.Values{"csrf": {formTokenRE.FindStringSubmatch(page.Body.String())[1]}, "tenant": {"demo"}, "user": {"ala"}, "password": {goodPW}}, sameOriginHdr)
	c := cookieNamed(w, "__Host-cw_session")
	if w.Code != http.StatusSeeOther || c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("session cookie over HTTPS: %d %+v", w.Code, c)
	}
	if cookieNamed(w, cookieName) != nil {
		t.Error("an unprefixed session cookie was set as well")
	}
	// The unprefixed name is not read: a cookie planted by a sibling host does nothing.
	if got := f.get(&http.Cookie{Name: cookieName, Value: c.Value}, "/"); got.Code != http.StatusSeeOther {
		t.Errorf("unprefixed cookie accepted over HTTPS: %d", got.Code)
	}
	if got := f.get(c, "/"); got.Code != 200 {
		t.Errorf("signed in over HTTPS: %d", got.Code)
	}
	w = f.post(c, "/logout")
	if gone := cookieNamed(w, "__Host-cw_session"); gone == nil || !gone.Secure || gone.MaxAge >= 0 {
		t.Errorf("cleared cookie over HTTPS: %+v", gone)
	}
}

func TestLoginProtection(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "demo", "ala", store.RoleAdmin, goodPW)
	off := f.addUser(t, "demo", "gone", store.RoleReviewer, goodPW)
	disabled := true
	if err := f.srv.au.UpdateDashUser(context.Background(), "demo", off.ID, store.DashUserChange{Disabled: &disabled}); err != nil {
		t.Fatal(err)
	}

	// No user enumeration: whatever is wrong, the answer is the same page.
	strip := func(body string) string {
		body = formTokenRE.ReplaceAllString(body, "")
		for _, v := range []string{`value="demo"`, `value="nowhere"`, `value="ala"`, `value="gone"`, `value="nobody"`, `value="bad name!"`, `value=""`} {
			body = strings.ReplaceAll(body, v, "")
		}
		return body
	}
	var first string
	for i, c := range [][3]string{
		{"demo", "ala", "not-the-password"}, // wrong password
		{"demo", "nobody", goodPW},          // no such user
		{"nowhere", "ala", goodPW},          // no such studio
		{"demo", "gone", goodPW},            // disabled, right password
		{"demo", "gone", "not-the-password"},
		{"demo", "bad name!", goodPW}, // a name no account can have
		{"demo", "ala", ""},
	} {
		w := f.tryLogin(t, c[0], c[1], c[2])
		body := strip(w.Body.String())
		if i == 0 {
			first = body
		}
		if w.Code != http.StatusUnauthorized || body != first || !strings.Contains(body, msgBadLogin) || cookieNamed(w, cookieName) != nil {
			t.Errorf("sign-in %v: %d, same page as a wrong password: %v", c, w.Code, body == first)
		}
		f.srv.lim = limiter{}
	}
	// The unknown account costs a password hash too, against a hash nobody's password fits.
	if h := f.srv.dummyHash(); !strings.HasPrefix(h, "$argon2id$") || h != f.srv.dummyHash() {
		t.Error("no stable dummy hash for unknown accounts")
	}
	if ok, _ := verifyPassword(f.srv.dummyHash(), ""); ok {
		t.Error("the dummy hash accepts an empty password")
	}
	f.wantAudit(t, "demo", "login.fail", "ala", "wrong password")
	f.wantAudit(t, "demo", "login.fail", "nobody", "no such account")
	f.wantAudit(t, "demo", "login.fail", "gone", "account disabled")
	// A made-up studio name gets no audit log of its own.
	if rows := f.auditLog(t, "nowhere"); len(rows) != 0 {
		t.Errorf("%d audit entries for a studio that does not exist", len(rows))
	}

	// Lockout with backoff: five failures lock the account for a minute, and then each
	// further failure doubles it.
	fail := func() int { return f.tryLogin(t, "demo", "ala", "not-the-password").Code }
	for i := 1; i <= maxFailures; i++ {
		if got := fail(); got != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, got)
		}
	}
	w := f.tryLogin(t, "demo", "ala", goodPW)
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), msgTooMany) || cookieNamed(w, cookieName) != nil {
		t.Fatalf("the right password during the lock: %d", w.Code)
	}
	f.wantAudit(t, "demo", "login.lock", "ala", "locked for 1m0s")
	// The lock is the account's, not the address's: from elsewhere it is locked too, and
	// another account from here is not.
	f.remote = "198.51.100.7:999"
	if got := f.tryLogin(t, "demo", "ala", goodPW).Code; got != http.StatusTooManyRequests {
		t.Errorf("locked account from another address: %d", got)
	}
	f.remote = "127.0.0.1:5555"
	f.addUser(t, "demo", "sam", store.RoleReviewer, goodPW)
	f.signIn(t, "demo", "sam", goodPW)
	for i, lock := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour} {
		f.now = f.now.Add(lock - time.Second)
		if got := f.tryLogin(t, "demo", "ala", goodPW).Code; got != http.StatusTooManyRequests {
			t.Fatalf("lock %d (%v) ended early: %d", i, lock, got)
		}
		f.now = f.now.Add(2 * time.Second)
		f.srv.lim.mu.Lock()
		f.srv.lim.addr = nil // this part is about the account; the address limit is below
		f.srv.lim.mu.Unlock()
		if got := fail(); got != http.StatusUnauthorized {
			t.Fatalf("after lock %d (%v): %d", i, lock, got)
		}
	}
	// After the last lock the right password works, and clears the count.
	f.now = f.now.Add(time.Hour + time.Second)
	f.signIn(t, "demo", "ala", goodPW)
	for i := 1; i < maxFailures; i++ {
		fail()
	}
	f.signIn(t, "demo", "ala", goodPW)
	for i := 1; i < maxFailures; i++ {
		if got := fail(); got != http.StatusUnauthorized {
			t.Fatalf("a success did not clear the count: failure %d gives %d", i, got)
		}
	}
	f.signIn(t, "demo", "ala", goodPW)

	// A name that does not exist locks the same way, so a lock does not confirm a name.
	f.srv.lim = limiter{}
	for i := 1; i <= maxFailures; i++ {
		if got := f.tryLogin(t, "demo", "nobody", "x").Code; got != http.StatusUnauthorized {
			t.Fatalf("unknown name, failure %d: %d", i, got)
		}
	}
	if got := f.tryLogin(t, "demo", "nobody", "x").Code; got != http.StatusTooManyRequests {
		t.Errorf("unknown name after %d failures: %d", maxFailures, got)
	}
	// Capitals do not make it a different account.
	if got := f.tryLogin(t, "demo", "NoBody", "x").Code; got != http.StatusTooManyRequests {
		t.Errorf("the lock is case-sensitive: %d", got)
	}

	// Per address: 20 failures in 10 minutes across any accounts, then everything from
	// that address is refused, including a correct sign-in, until the window has passed.
	f.srv.lim = limiter{}
	f.remote = "203.0.113.50:1234"
	for i := 0; i < addrMaxFailures; i++ {
		if got := f.tryLogin(t, "demo", fmt.Sprintf("guess-%d", i), "x").Code; got != http.StatusUnauthorized {
			t.Fatalf("spray attempt %d: %d", i, got)
		}
	}
	if got := f.tryLogin(t, "demo", "sam", goodPW).Code; got != http.StatusTooManyRequests {
		t.Errorf("address over its limit: %d", got)
	}
	// One-time links are limited by the same count: no guessing tokens from there either.
	if got := f.get(nil, "/invite/"+strings.Repeat("B", 43)).Code; got != http.StatusTooManyRequests {
		t.Errorf("invite link from an address over its limit: %d", got)
	}
	f.remote = "203.0.113.51:1234"
	f.signIn(t, "demo", "sam", goodPW) // another address is not affected
	f.remote = "203.0.113.50:1234"
	f.now = f.now.Add(failureReset + time.Second)
	f.signIn(t, "demo", "sam", goodPW)
	f.remote = "127.0.0.1:5555"

	// The sign-in form is a form like any other: no token, no sign-in.
	pre, tok := f.pre(t)
	form := url.Values{"csrf": {tok}, "tenant": {"demo"}, "user": {"ala"}, "password": {goodPW}}
	for name, w := range map[string]int{
		"cross-site":      f.do("POST", "/login", pre, form, map[string]string{"Sec-Fetch-Site": "cross-site"}).Code,
		"another origin":  f.do("POST", "/login", pre, form, map[string]string{"Origin": "https://evil.example"}).Code,
		"no cookie":       f.do("POST", "/login", nil, form, sameOriginHdr).Code,
		"no token":        f.do("POST", "/login", pre, url.Values{"tenant": {"demo"}, "user": {"ala"}, "password": {goodPW}}, sameOriginHdr).Code,
		"another's token": f.do("POST", "/login", pre, url.Values{"csrf": {csrfFor(strings.Repeat("x", 43))}, "tenant": {"demo"}, "user": {"ala"}, "password": {goodPW}}, sameOriginHdr).Code,
	} {
		if w != http.StatusForbidden {
			t.Errorf("sign-in form, %s: %d", name, w)
		}
	}
	// An oversized form is refused before anything is hashed.
	big := url.Values{"csrf": {tok}, "tenant": {"demo"}, "user": {"ala"}, "password": {strings.Repeat("a", 8<<10)}}
	if got := f.do("POST", "/login", pre, big, sameOriginHdr).Code; got != http.StatusBadRequest {
		t.Errorf("8 KiB password: %d", got)
	}
}

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	var l limiter
	a := accountKey("demo", "ala")
	if accountKey("demo", "ALA") != a || accountKey("demo", "al") == a || accountKey("dem", "o\x00ala") == a || accountKey("rival", "ala") == a {
		t.Error("account keys: case must fold, everything else must differ")
	}
	for i := 1; i < maxFailures; i++ {
		if lock := l.failed("10.0.0.1", a, now); lock != 0 || l.blocked("10.0.0.1", a, now) {
			t.Fatalf("locked after %d failures", i)
		}
	}
	if lock := l.failed("10.0.0.1", a, now); lock != lockBase || !l.blocked("10.0.0.2", a, now) || l.blocked("10.0.0.1", accountKey("demo", "sam"), now) {
		t.Fatalf("fifth failure: lock %v", lock)
	}
	// Failures long ago are forgotten.
	if l.blocked("10.0.0.1", a, now.Add(acctForget+time.Second)) || l.failed("10.0.0.9", a, now.Add(acctForget+2*time.Second)) != 0 {
		t.Error("an account's failures were not forgotten after the quiet time")
	}
	l.succeeded(a)
	if len(l.acct) != 0 {
		t.Error("success left the account's count")
	}
	// The maps cannot grow without bound.
	l = limiter{}
	for i := 0; i < maxAddrSlots+50; i++ {
		l.addrFailed(fmt.Sprintf("a%d", i), now)
	}
	if len(l.addr) > maxAddrSlots {
		t.Errorf("%d address slots", len(l.addr))
	}
	for i := 0; i < maxAcctSlots+50; i++ {
		l.failed("x", accountKey("demo", fmt.Sprintf("u%d", i)), now)
	}
	if len(l.acct) > maxAcctSlots {
		t.Errorf("%d account slots", len(l.acct))
	}
	// A full map drops stale entries first and keeps the live ones.
	l = limiter{}
	for i := 0; i < maxAddrSlots-1; i++ {
		l.addrFailed(fmt.Sprintf("old%d", i), now.Add(-failureReset-time.Minute))
	}
	for i := 0; i < addrMaxFailures; i++ {
		l.addrFailed("live", now)
	}
	l.addrFailed("new", now)
	if len(l.addr) != 2 || !l.addrBlocked("live", now) {
		t.Errorf("after pruning: %d slots, live address blocked %v", len(l.addr), l.addrBlocked("live", now))
	}
}
