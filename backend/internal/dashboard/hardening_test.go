package dashboard

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

func TestAuditLog(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "demo", "ala", store.RoleAdmin, goodPW)
	f.addUser(t, "demo", "sam", store.RoleReviewer, goodPW)
	f.addUser(t, "rival", "rex", store.RoleAdmin, goodPW)
	f.remote = "198.51.100.20:7001"
	admin := f.signIn(t, "demo", "ala", goodPW)
	f.tryLogin(t, "demo", "sam", "not-the-password")
	f.tryLogin(t, "demo", `<script>alert(1)</script>`, "x")
	samID := f.user(t, "demo", "sam").ID
	f.post(admin, fmt.Sprintf("/users/%d/role", samID), "role", "read_only")
	f.post(admin, "/users/invite", "name", "kim", "role", "reviewer")
	rex := f.signIn(t, "rival", "rex", goodPW)

	w := f.get(admin, "/audit")
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("audit page: %d", w.Code)
	}
	// Who, what, on what, when and from where.
	for _, want := range []string{
		`<td class="mono">ala</td>`, `<td class="mono">login.ok</td>`, `<td class="mono">login.fail</td>`, `<td class="mono">user.role</td>`, `<td class="mono">user.invite</td>`,
		`from Reviewer to Read-only`, `<td class="mono">198.51.100.20</td>`, `<span class="mono">2026-11-10 12:00:00</span>`, `<td class="mono">kim</td>`,
		`&lt;script&gt;alert(1)&lt;/script&gt;`, `Check the log for changes`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("audit page lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>") || strings.Contains(body, "rex") || strings.Contains(body, goodPW) || strings.Contains(body, "not-the-password") {
		t.Error("audit page shows markup from a request, another studio's entries, or a password")
	}
	// Tabs.
	signins, changes := f.get(admin, "/audit?show=signins").Body.String(), f.get(admin, "/audit?show=changes").Body.String()
	if !strings.Contains(signins, "login.fail") || strings.Contains(signins, "user.role") || strings.Contains(changes, "login.ok") || !strings.Contains(changes, "user.invite") {
		t.Error("audit tabs do not filter")
	}
	// The other studio's admin sees their own log only.
	if body := f.get(rex, "/audit").Body.String(); strings.Contains(body, "ala") || strings.Contains(body, "user.role") || !strings.Contains(body, `<td class="mono">rex</td>`) {
		t.Error("the rival's audit page shows demo entries")
	}
	// The check walks the chain.
	n := len(f.auditLog(t, "demo"))
	if body := f.get(admin, "/audit?check=1").Body.String(); !strings.Contains(body, fmt.Sprintf("%d entries checked", n)) {
		t.Errorf("check of %d entries: no result on the page", n)
	}
	// Paging.
	for i := 0; i < auditPageSize+20; i++ {
		f.tryLogin(t, "demo", fmt.Sprintf("spray-%d", i), "x")
		f.srv.lim = limiter{}
	}
	body = f.get(admin, "/audit?show=signins").Body.String()
	older := regexp.MustCompile(`href="/audit\?show=signins&amp;before=(\d+)">Older entries</a>`).FindStringSubmatch(body)
	if older == nil || strings.Count(body, "<tr>")-1 != auditPageSize {
		t.Fatalf("first page: %d rows, older link %v", strings.Count(body, "<tr>")-1, older)
	}
	body = f.get(admin, "/audit?show=signins&before="+older[1]).Body.String()
	if !strings.Contains(body, "spray-0<") || strings.Contains(body, "Older entries") {
		t.Error("second page does not hold the oldest entries, or offers more")
	}

	// Append-only: the dashboard has no route that edits or removes an entry, and the
	// store has no method for it. (The SQLite triggers are tested in the store package.)
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		for _, p := range []string{"/audit", "/audit/1", "/audit/clear"} {
			w := f.do(m, p, admin, url.Values{"csrf": {csrfFor(admin.Value)}}, sameOriginHdr)
			if w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusNotFound {
				t.Errorf("%s %s: %d", m, p, w.Code)
			}
		}
	}
	au := reflect.TypeOf((*store.AuthStore)(nil)).Elem()
	var auditMethods []string
	for i := 0; i < au.NumMethod(); i++ {
		if strings.Contains(au.Method(i).Name, "Audit") {
			auditMethods = append(auditMethods, au.Method(i).Name)
		}
	}
	if got := strings.Join(auditMethods, " "); got != "AppendAudit ListAudit VerifyAudit" {
		t.Errorf("audit methods of the store: %s", got)
	}
	if len(f.auditLog(t, "demo")) < n+auditPageSize {
		t.Error("entries went missing")
	}
}

// The whole account life on the SQLite store the gateway runs with, across a restart.
func TestAccountsOnSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.db")
	key := []byte(strings.Repeat("k", 32))
	open := func(k []byte) (*fixture, *store.SQLite) {
		st, err := store.OpenSQLite(path)
		if err != nil {
			t.Fatal(err)
		}
		f := newFixtureOn(t, st)
		if err := f.srv.ConfigureAuth(AuthConfig{Loopback: true, SecretKey: k}); err != nil {
			t.Fatal(err)
		}
		return f, st
	}
	f, st := open(key)
	ctx := context.Background()
	demo := f.login(t, "demo", "demo-key")
	b := Bootstrap{Store: st, Now: func() time.Time { return f.now }}
	token, _, err := b.InviteAdmin(ctx, "demo", "ala")
	if err != nil {
		t.Fatal(err)
	}
	page := f.get(nil, "/invite/"+token)
	pre, tok := cookieNamed(page, preCookieName), formTokenRE.FindStringSubmatch(page.Body.String())
	if w := f.do("POST", "/invite/"+token, pre, url.Values{"csrf": {tok[1]}, "password": {goodPW}, "repeat": {goodPW}}, sameOriginHdr); w.Code != http.StatusSeeOther {
		t.Fatalf("accept: %d %s", w.Code, w.Body.String())
	}
	if f.alive(demo) {
		t.Error("the demo session outlived the first admin")
	}
	admin, secret, codes := f.enrol(t, f.signIn(t, "demo", "ala", goodPW), goodPW)
	w := f.post(admin, "/users/invite", "name", "sam", "role", "reviewer")
	link := inviteLinkRE.FindStringSubmatch(w.Body.String())
	if link == nil {
		t.Fatalf("invite: %d", w.Code)
	}
	page = f.get(nil, "/invite/"+link[1])
	pre, tok = cookieNamed(page, preCookieName), formTokenRE.FindStringSubmatch(page.Body.String())
	if w := f.do("POST", "/invite/"+link[1], pre, url.Values{"csrf": {tok[1]}, "password": {goodPW}, "repeat": {goodPW}}, sameOriginHdr); w.Code != http.StatusSeeOther {
		t.Fatalf("sam accepts: %d", w.Code)
	}
	sam := f.signIn(t, "demo", "sam", goodPW)
	if w := f.post(admin, "/users/require-two-factor", "require", "1"); w.Code != http.StatusSeeOther {
		t.Fatalf("require: %d", w.Code)
	}
	if w := f.get(sam, "/"); w.Header().Get("Location") != "/account/two-factor/setup" {
		t.Errorf("sam under the rule: %d", w.Code)
	}
	if w := f.post(admin, "/users/require-two-factor", "require", "0"); w.Code != http.StatusSeeOther {
		t.Fatalf("optional: %d", w.Code)
	}
	if w := f.get(admin, "/audit?check=1"); w.Code != 200 || !strings.Contains(w.Body.String(), "entries checked") {
		t.Fatalf("audit check: %d", w.Code)
	}
	// What the database file holds: no password, no cookie, no two-factor secret, no
	// recovery code, no link token.
	st.Close()
	var raw []byte
	for _, name := range []string{path, path + "-wal"} {
		if b, err := os.ReadFile(name); err == nil {
			raw = append(raw, b...)
		}
	}
	for what, secretText := range map[string]string{"password": goodPW, "session cookie": admin.Value, "two-factor secret": string(secret), "two-factor key": b32.EncodeToString(secret),
		"recovery code": codes[0], "recovery code without dashes": strings.ReplaceAll(codes[0], "-", ""), "invite token": link[1], "first link token": token} {
		if strings.Contains(string(raw), secretText) {
			t.Errorf("the database file holds the %s in the clear", what)
		}
	}

	// Restart with the same key file: sessions, accounts and the second factor carry over.
	f2, st2 := open(key)
	f2.now = f.now
	if !f2.alive(admin) || !f2.alive(sam) {
		t.Error("sessions did not survive a restart")
	}
	c := f2.signIn2(t, "demo", "ala", goodPW, secret)
	if w := f2.get(c, "/users"); w.Code != 200 || !strings.Contains(w.Body.String(), ">sam</a>") {
		t.Errorf("users after restart: %d", w.Code)
	}
	if w := f2.login2(t, "demo", "demo-key"); w != http.StatusUnauthorized {
		t.Errorf("demo login after restart, with accounts: %d", w)
	}
	// A recovery code works across the restart, once.
	w = f2.tryLogin(t, "demo", "ala", goodPW)
	if w := f2.post(cookieNamed(w, cookieName), "/login/code", "code", codes[3]); w.Code != http.StatusSeeOther {
		t.Errorf("recovery code after restart: %d", w.Code)
	}
	st2.Close()

	// Restart with another key (the key file was lost): passwords still work, the
	// two-factor secret cannot be opened, and sign-in is refused, not waved through.
	f3, st3 := open([]byte(strings.Repeat("z", 32)))
	f3.now = f2.now
	w = f3.tryLogin(t, "demo", "ala", goodPW)
	step := cookieNamed(w, cookieName)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login/code" {
		t.Fatalf("password step with another key: %d", w.Code)
	}
	if w := f3.post(step, "/login/code", "code", totpCode(secret, totpStep(f3.now))); w.Code != http.StatusUnauthorized {
		t.Errorf("code step with another key: %d", w.Code)
	}
	if w := f3.post(step, "/login/code", "code", codes[5]); w.Code != http.StatusUnauthorized {
		t.Errorf("recovery code with another key: %d", w.Code)
	}
	// The way back is the command line.
	if err := (Bootstrap{Store: st3, Now: func() time.Time { return f3.now }}).ResetTwoFactor(ctx, "demo", "ala"); err != nil {
		t.Fatal(err)
	}
	f3.srv.lim = limiter{}
	admin = f3.signIn(t, "demo", "ala", goodPW)

	// Someone with the database file edits the log behind the dashboard's back: the
	// triggers refuse, and with the triggers removed the check finds the entry.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var id int64
	if err := db.QueryRow(`SELECT id FROM dashboard_audit WHERE tenant_id = 'demo' AND action = 'user.invite' ORDER BY id LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE dashboard_audit SET detail = 'nothing to see' WHERE id = ?`, id); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("update of an audit entry: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM dashboard_audit WHERE id = ?`, id); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("delete of an audit entry: %v", err)
	}
	if body := f3.get(admin, "/audit?check=1").Body.String(); !strings.Contains(body, "entries checked") {
		t.Error("the log does not check out before tampering")
	}
	if _, err := db.Exec(`DROP TRIGGER dashboard_audit_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE dashboard_audit SET detail = 'nothing to see' WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	if body := f3.get(admin, "/audit?check=1").Body.String(); !strings.Contains(body, fmt.Sprintf("Entry #%d does not fit", id)) {
		t.Errorf("the check did not find the edited entry #%d", id)
	}
	st3.Close()
}

// login2 posts the demo key form and returns the status.
func (f *fixture) login2(t *testing.T, tenant, key string) int {
	t.Helper()
	return f.do("POST", "/login", nil, url.Values{"tenant": {tenant}, "key": {key}}, sameOriginHdr).Code
}

var postForm = regexp.MustCompile(`(?s)<form method="post"[^>]*>.*?</form>`)

func TestCSRFOnEveryForm(t *testing.T) {
	// Every form that changes something carries the token, in every template. The demo key
	// form is the one exception: the test scripts post to it with curl.
	files, err := filepath.Glob("templates/*.html")
	if err != nil || len(files) < 15 {
		t.Fatalf("templates: %d %v", len(files), err)
	}
	forms := 0
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		text := string(src)
		posts := postForm.FindAllString(text, -1)
		if n := strings.Count(strings.ToLower(text), `method="post"`); n != len(posts) {
			t.Errorf("%s: %d post forms, %d read by this test", file, n, len(posts))
		}
		for _, form := range posts {
			forms++
			demoKey := strings.Contains(form, `name="key"`)
			if has := strings.Contains(form, `<input type="hidden" name="csrf" value="{{`); has == demoKey {
				t.Errorf("%s: form has token=%v, is the demo key form=%v: %s", file, has, demoKey, strings.SplitN(form, ">", 2)[0])
			}
			if demoKey && file != filepath.Join("templates", "login.html") {
				t.Errorf("%s: a key form outside the sign-in page", file)
			}
		}
	}
	if forms < 20 {
		t.Errorf("only %d post forms found", forms)
	}

	// Every POST route refuses a form without the right token, and a form from elsewhere.
	f := newFixture(t)
	f.addUser(t, "demo", "ala", store.RoleAdmin, goodPW)
	sam := f.addUser(t, "demo", "sam", store.RoleReviewer, goodPW)
	admin, other := f.signIn(t, "demo", "ala", goodPW), f.signIn(t, "demo", "sam", goodPW)
	w := f.post(admin, "/users/invite", "name", "kim", "role", "reviewer")
	link := inviteLinkRE.FindStringSubmatch(w.Body.String())
	before := len(f.auditLog(t, "demo"))

	var routes []string
	goFiles, _ := filepath.Glob("*.go")
	for _, file := range goFiles {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, _ := os.ReadFile(file)
		for _, line := range strings.Split(string(src), "\n") {
			if m := muxRoute.FindStringSubmatch(strings.TrimSpace(line)); m != nil && strings.HasPrefix(m[1], "POST ") {
				routes = append(routes, strings.TrimPrefix(m[1], "POST "))
			}
		}
	}
	if len(routes) < 14 {
		t.Fatalf("only %d POST routes found", len(routes))
	}
	samID := strconv.FormatInt(sam.ID, 10)
	fill := strings.NewReplacer("{id}", samID, "{action}", "disable", "{token}", link[1])
	good := csrfFor(admin.Value)
	body := func(token string) url.Values {
		v := url.Values{"name": {"eve"}, "role": {"admin"}, "require": {"1"}, "id": {hashToken(other.Value)}, "current": {goodPW}, "password": {"seven-green-clouds-above"}, "repeat": {"seven-green-clouds-above"}}
		if token != "" {
			v.Set("csrf", token)
		}
		return v
	}
	for _, route := range routes {
		path := fill.Replace(route)
		if route == "/login" {
			continue // the sign-in forms: TestLoginProtection and TestDemoLogin
		}
		c := admin
		switch route {
		case "/invite/{token}":
			// Signed out: the token is tied to the pre-login cookie instead.
			page := f.get(nil, path)
			c = cookieNamed(page, preCookieName)
			good = formTokenRE.FindStringSubmatch(page.Body.String())[1]
		case "/login/code":
			// This form belongs to a sign-in that still waits for its code.
			c = &http.Cookie{Name: cookieName, Value: strings.Repeat("c", 43)}
			row := &store.DashSession{IDHash: hashToken(c.Value), TenantID: "demo", UserID: sam.ID, Kind: store.DashSessionCode, CreatedAt: f.now, LastSeenAt: f.now, ExpiresAt: f.now.Add(codeSessionTTL)}
			if err := f.srv.au.PutDashSession(context.Background(), row); err != nil {
				t.Fatal(err)
			}
			good = csrfFor(c.Value)
		default:
			good = csrfFor(admin.Value)
		}
		for name, got := range map[string]int{
			"no token":                f.do("POST", path, c, body(""), sameOriginHdr).Code,
			"wrong token":             f.do("POST", path, c, body(strings.Repeat("0", 32)), sameOriginHdr).Code,
			"another session's token": f.do("POST", path, c, body(csrfFor(other.Value)), sameOriginHdr).Code,
			"the cookie as token":     f.do("POST", path, c, body(c.Value), sameOriginHdr).Code,
			"cross-site":              f.do("POST", path, c, body(good), map[string]string{"Sec-Fetch-Site": "cross-site"}).Code,
			"same-site":               f.do("POST", path, c, body(good), map[string]string{"Sec-Fetch-Site": "same-site"}).Code,
			"another origin":          f.do("POST", path, c, body(good), map[string]string{"Origin": "http://127.0.0.1:9999"}).Code,
			"token in the query":      f.do("POST", path+"?csrf="+good, c, body(""), sameOriginHdr).Code,
		} {
			if got != http.StatusForbidden {
				t.Errorf("POST %s, %s: %d, want 403", route, name, got)
			}
		}
	}
	// None of it did anything.
	if !f.alive(admin) || !f.alive(other) {
		t.Error("a refused form signed someone out")
	}
	if u := f.user(t, "demo", "sam"); u.Disabled || u.Role != store.RoleReviewer {
		t.Errorf("a refused form changed an account: %+v", u)
	}
	if n, _ := f.srv.au.CountDashUsers(context.Background(), "demo"); n != 2 {
		t.Errorf("a refused form created an account: %d", n)
	}
	if set, _ := f.srv.au.GetTenantSettings(context.Background(), "demo"); set.RequireTOTP {
		t.Error("a refused form changed the studio's rule")
	}
	if f.tryLogin(t, "demo", "ala", goodPW).Code != http.StatusSeeOther {
		t.Error("a refused form changed the password")
	}
	if f.get(nil, "/invite/"+link[1]).Code != 200 {
		t.Error("a refused form used up or revoked the invite")
	}
	if after := f.auditLog(t, "demo"); len(after) != before+1 || after[0].Action != "login.ok" {
		t.Errorf("refused forms left %d audit entries", len(after)-before-1)
	}
	// Nothing changes through a GET: the routes that change something answer POST only.
	for _, p := range []string{"/logout", "/logout/everywhere", "/account/password", "/users/" + samID + "/disable", "/users/require-two-factor?require=1", "/account/two-factor/disable"} {
		if w := f.get(admin, p); w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d", p, w.Code)
		}
	}
	if !f.alive(admin) {
		t.Error("a GET signed the admin out")
	}
	// The token belongs to the session: after signing in again, the old page's forms are dead.
	old := csrfFor(admin.Value)
	renewed := f.signIn(t, "demo", "ala", goodPW)
	if csrfFor(renewed.Value) == old || len(old) != 32 {
		t.Error("the form token did not change with the session")
	}
	if w := f.do("POST", "/users/invite", renewed, url.Values{"csrf": {old}, "name": {"eve"}, "role": {"admin"}}, sameOriginHdr); w.Code != http.StatusForbidden {
		t.Errorf("a token from the previous session: %d", w.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "demo", "ala", store.RoleAdmin, goodPW)
	c := f.signIn(t, "demo", "ala", goodPW)
	want := map[string]string{
		"Content-Security-Policy":      "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Permissions-Policy":           "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
		"X-Robots-Tag":                 "noindex, nofollow",
	}
	pages := []string{"/login", "/", "/users", "/audit", "/account", "/account/two-factor/setup", "/invite/" + strings.Repeat("A", 43), "/nothing-here", "/static/app.css", "/sessions/aaaa1111"}
	for _, p := range pages {
		w := f.get(c, p)
		for h, v := range want {
			if got := w.Header().Get(h); got != v {
				t.Errorf("GET %s: %s = %q", p, h, got)
			}
		}
		if got := w.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("GET %s over plain HTTP sends HSTS %q", p, got)
		}
		if !strings.HasPrefix(p, "/static/") && w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("GET %s may be stored by the browser: %q", p, w.Header().Get("Cache-Control"))
		}
	}
	// Refusals carry them too.
	if w := f.do("POST", "/users/invite", c, nil, sameOriginHdr); w.Code != http.StatusForbidden || w.Header().Get("Content-Security-Policy") != want["Content-Security-Policy"] {
		t.Errorf("a refused form: %d, headers missing", w.Code)
	}
	// The policy allows no script and no inline style, and no page tries to use one. The
	// QR code is inline SVG drawn with classes, which the policy permits.
	for _, p := range pages[:6] {
		body := f.get(c, p).Body.String()
		for _, bad := range []string{"<script", "style=", "<style", "javascript:", "onclick", "onload", "http://", "https://", "data:"} {
			if strings.Contains(strings.ToLower(body), bad) {
				t.Errorf("GET %s: page contains %q", p, bad)
			}
		}
	}

	srv, err := New(Config{SecureCookie: true}, store.NewMemory(), discardLog())
	if err != nil {
		t.Fatal(err)
	}
	g := &fixture{srv: srv, h: srv.Handler(), remote: "203.0.113.9:4000", host: "dash.studio.example"}
	w := g.get(nil, "/login")
	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("HSTS over HTTPS: %q", got)
	}
	for h, v := range want {
		if got := w.Header().Get(h); got != v {
			t.Errorf("over HTTPS: %s = %q", h, got)
		}
	}
}

// The shared studio key: a demo login for local testing, and nothing more.
func TestDemoLogin(t *testing.T) {
	f := newFixture(t)
	demoBlock := `<span class="mark mark-watch">Demo login</span>`
	if body := f.get(nil, "/login").Body.String(); !strings.Contains(body, demoBlock) || !strings.Contains(body, `name="key"`) {
		t.Fatal("the sign-in page on loopback does not offer the demo login")
	}
	// The scripts' way in: a bare form post, no token, no browser headers.
	w := f.do("POST", "/login", nil, url.Values{"tenant": {"demo"}, "key": {"demo-key"}}, nil)
	c := cookieNamed(w, cookieName)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" || c == nil {
		t.Fatalf("demo login: %d", w.Code)
	}
	// Every page says what kind of login this is.
	for _, p := range []string{"/", "/sessions", "/players", "/players/bob", "/sessions/aaaa1111", "/account"} {
		w := f.get(c, p)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `<a class="mark mark-watch" href="/account" title="Signed in with the shared studio key, not as a person">Demo login</a>`) {
			t.Errorf("GET %s with the demo login: %d, marker shown: %v", p, w.Code, strings.Contains(w.Body.String(), "Demo login"))
		}
	}
	if body := f.get(c, "/account").Body.String(); !strings.Contains(body, "dashboard-user add-admin -tenant demo -name YOUR-NAME") || strings.Contains(body, `action="/account/password"`) {
		t.Error("the demo login's account page")
	}
	// It is a reviewer without an account: no user management, no audit log, nothing to
	// set a password or a second factor on.
	for _, p := range []string{"/users", "/audit", "/users/1"} {
		if w := f.get(c, p); w.Code != http.StatusForbidden {
			t.Errorf("demo login GET %s: %d", p, w.Code)
		}
	}
	for _, p := range []string{"/account/password", "/account/two-factor/setup", "/account/two-factor/disable", "/account/recovery-codes", "/account/sessions/revoke"} {
		if w := f.post(c, p, "current", "x", "password", goodPW, "repeat", goodPW); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account" {
			t.Errorf("demo login POST %s: %d -> %s", p, w.Code, w.Header().Get("Location"))
		}
	}
	if w := f.get(c, "/account/two-factor/setup"); w.Code != http.StatusSeeOther {
		t.Errorf("demo login on the two-factor setup page: %d", w.Code)
	}
	// It can do what a reviewer does on a route of the studio view.
	h := f.srv.auth(func(w http.ResponseWriter, r *http.Request, tenant string) { w.WriteHeader(http.StatusNoContent) })
	if w := f.doOn(h, "POST", "/sessions/aaaa1111/label", c, url.Values{"csrf": {csrfFor(c.Value)}}, sameOriginHdr); w.Code != http.StatusNoContent {
		t.Errorf("demo login on a reviewer action: %d", w.Code)
	}
	f.wantAudit(t, "demo", "login.demo", "demo", "shared studio key")
	f.wantAudit(t, "demo", "request.post", "demo", "/sessions/aaaa1111/label")

	// Wrong key and unknown studio look the same.
	bad, unknown := f.do("POST", "/login", nil, url.Values{"tenant": {"demo"}, "key": {"wrong"}}, sameOriginHdr), f.do("POST", "/login", nil, url.Values{"tenant": {"nowhere"}, "key": {"demo-key"}}, sameOriginHdr)
	strip := func(s string) string { return formTokenRE.ReplaceAllString(s, "") }
	if bad.Code != http.StatusUnauthorized || unknown.Code != http.StatusUnauthorized || strip(bad.Body.String()) != strip(unknown.Body.String()) || !strings.Contains(bad.Body.String(), msgBadKey) {
		t.Errorf("wrong key %d, unknown studio %d", bad.Code, unknown.Code)
	}
	for _, key := range []string{"", "rival-key", "demo-key "} {
		if got := f.login2(t, "demo", key); got != http.StatusUnauthorized {
			t.Errorf("key %q: %d", key, got)
		}
	}
	if got := f.do("POST", "/login", nil, url.Values{"tenant": {"demo"}, "key": {"demo-key"}}, map[string]string{"Sec-Fetch-Site": "cross-site"}).Code; got != http.StatusForbidden {
		t.Errorf("cross-site demo login: %d", got)
	}
	// Guessing the key is limited like guessing a password.
	f.srv.lim = limiter{}
	for i := 0; i < maxFailures; i++ {
		f.login2(t, "demo", "guess")
	}
	if got := f.login2(t, "demo", "demo-key"); got != http.StatusTooManyRequests {
		t.Errorf("the right key after %d wrong ones: %d", maxFailures, got)
	}
	f.srv.lim = limiter{}

	// Loopback only. Each of these is the right key, refused.
	local := *f
	for name, change := range map[string]func(g *fixture) map[string]string{
		"from another machine":        func(g *fixture) map[string]string { g.remote = "192.168.1.20:5000"; return nil },
		"from a public address":       func(g *fixture) map[string]string { g.remote = "203.0.113.9:5000"; return nil },
		"under a public name":         func(g *fixture) map[string]string { g.host = "dash.studio.example"; return nil },
		"under the LAN address":       func(g *fixture) map[string]string { g.host = "192.168.1.5:8751"; return nil },
		"through a local proxy":       func(g *fixture) map[string]string { return map[string]string{"X-Forwarded-For": "203.0.113.9"} },
		"through a proxy (Forwarded)": func(g *fixture) map[string]string { return map[string]string{"Forwarded": "for=203.0.113.9"} },
		"through a proxy (Via)":       func(g *fixture) map[string]string { return map[string]string{"Via": "1.1 proxy"} },
		"through a proxy (X-Real-IP)": func(g *fixture) map[string]string { return map[string]string{"X-Real-IP": "203.0.113.9"} },
	} {
		g := local
		hdr := change(&g)
		if w := g.do("POST", "/login", nil, url.Values{"tenant": {"demo"}, "key": {"demo-key"}}, hdr); w.Code != http.StatusUnauthorized || cookieNamed(w, cookieName) != nil {
			t.Errorf("demo login %s: %d", name, w.Code)
		}
		if body := g.do("GET", "/login", nil, nil, hdr).Body.String(); strings.Contains(body, "Demo login") || strings.Contains(body, `name="key"`) {
			t.Errorf("the sign-in page offers the demo login %s", name)
		}
		// A demo session made on this PC does not travel either.
		if w := g.do("GET", "/", c, nil, hdr); w.Code != http.StatusSeeOther {
			t.Errorf("a demo session used %s: %d", name, w.Code)
		}
		f.srv.lim = limiter{}
		c = f.login(t, "demo", "demo-key")
	}
	for _, host := range []string{"localhost:8751", "[::1]:8751", "127.0.0.1"} {
		g := local
		g.host = host
		if got := g.login2(t, "demo", "demo-key"); got != http.StatusSeeOther {
			t.Errorf("demo login under %s: %d", host, got)
		}
	}
	g := local
	g.remote = "[::1]:5000"
	if got := g.login2(t, "demo", "demo-key"); got != http.StatusSeeOther {
		t.Errorf("demo login from ::1: %d", got)
	}

	// Off for a studio from its first account on, for good; open sessions end with it.
	rival := f.login(t, "rival", "rival-key")
	f.addUser(t, "demo", "ala", store.RoleAdmin, goodPW)
	if f.alive(c) {
		t.Error("a demo session outlived the studio's first account")
	}
	w = f.do("POST", "/login", nil, url.Values{"tenant": {"demo"}, "key": {"demo-key"}}, sameOriginHdr)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), msgBadKey) || cookieNamed(w, cookieName) != nil {
		t.Errorf("demo login for a studio with an account: %d", w.Code)
	}
	// Disabling the account does not bring the key back.
	off := true
	f.srv.au.UpdateDashUser(context.Background(), "demo", f.user(t, "demo", "ala").ID, store.DashUserChange{Disabled: &off})
	if got := f.login2(t, "demo", "demo-key"); got != http.StatusUnauthorized {
		t.Errorf("demo login for a studio whose only account is disabled: %d", got)
	}
	// The other studio is untouched, and the page still offers the demo login for it.
	if !f.alive(rival) || f.login2(t, "rival", "rival-key") != http.StatusSeeOther {
		t.Error("the rival studio lost its demo login")
	}
	if body := f.get(nil, "/login").Body.String(); !strings.Contains(body, demoBlock) {
		t.Error("the demo block went away while a studio can still use it")
	}
	f.addUser(t, "rival", "rex", store.RoleAdmin, goodPW)
	if body := f.get(nil, "/login").Body.String(); strings.Contains(body, "Demo login") || strings.Contains(body, `name="key"`) {
		t.Error("the sign-in page offers a demo login no studio can use")
	}
	f.wantAudit(t, "demo", "login.fail", "studio key", "studio key refused")

	// A dashboard that does not listen on loopback has no demo login at all, whatever
	// address the request appears to come from.
	h2 := newFixture(t)
	if err := h2.srv.ConfigureAuth(AuthConfig{Loopback: false}); err != nil {
		t.Fatal(err)
	}
	if got := h2.login2(t, "demo", "demo-key"); got != http.StatusUnauthorized {
		t.Errorf("demo login on a listener that is not loopback: %d", got)
	}
	// And without any configured key there is nothing to try.
	srv, err := New(Config{}, store.NewMemory(), discardLog())
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ConfigureAuth(AuthConfig{Loopback: true}); err != nil {
		t.Fatal(err)
	}
	k := &fixture{srv: srv, h: srv.Handler(), remote: "127.0.0.1:5555", host: "127.0.0.1:8751"}
	if got := k.login2(t, "demo", ""); got != http.StatusUnauthorized {
		t.Errorf("empty key with no keys configured: %d", got)
	}
	if got := k.login2(t, "", ""); got != http.StatusUnauthorized {
		t.Errorf("empty studio and key: %d", got)
	}
}

func TestClientAddress(t *testing.T) {
	f := newFixture(t)
	req := func(remote string, xff ...string) *http.Request {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	// Without a configured proxy the header is ignored: anyone can send it.
	if got := f.srv.clientIP(req("203.0.113.9:1000", "10.9.9.9")); got != "203.0.113.9" {
		t.Errorf("no proxies configured: %s", got)
	}
	if err := f.srv.ConfigureAuth(AuthConfig{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("::1/128")}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		remote string
		xff    []string
		want   string
	}{
		{"10.0.0.1:1000", []string{"203.0.113.7"}, "203.0.113.7"},
		{"10.0.0.1:1000", []string{"203.0.113.7, 10.0.0.2"}, "203.0.113.7"},  // through two of our proxies
		{"10.0.0.1:1000", []string{"1.2.3.4, 203.0.113.7"}, "203.0.113.7"},   // the client put 1.2.3.4 there itself
		{"10.0.0.1:1000", []string{"1.2.3.4", "203.0.113.7"}, "203.0.113.7"}, // same, as two header lines
		{"10.0.0.1:1000", []string{"::ffff:203.0.113.7"}, "203.0.113.7"},
		{"10.0.0.1:1000", nil, "10.0.0.1"},
		{"10.0.0.1:1000", []string{"not an address"}, "10.0.0.1"},
		{"10.0.0.1:1000", []string{"203.0.113.7, garbage"}, "10.0.0.1"},
		{"10.0.0.1:1000", []string{"10.0.0.3, 10.0.0.2"}, "10.0.0.1"},
		{"203.0.113.9:1000", []string{"198.51.100.1"}, "203.0.113.9"}, // not from a trusted proxy: header ignored
		{"[::1]:1000", []string{"2001:db8::5"}, "2001:db8::5"},
	} {
		if got := f.srv.clientIP(req(c.remote, c.xff...)); got != c.want {
			t.Errorf("client address for %s via %v: %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
	// That address is what the limits count and the audit log records.
	f.addUser(t, "demo", "ala", store.RoleAdmin, goodPW)
	f.remote = "10.0.0.1:1000"
	page := f.do("GET", "/login", nil, nil, nil)
	pre, tok := cookieNamed(page, preCookieName), formTokenRE.FindStringSubmatch(page.Body.String())[1]
	hdr := map[string]string{"Sec-Fetch-Site": "same-origin", "X-Forwarded-For": "203.0.113.77"}
	if w := f.do("POST", "/login", pre, url.Values{"csrf": {tok}, "tenant": {"demo"}, "user": {"ala"}, "password": {goodPW}}, hdr); w.Code != http.StatusSeeOther {
		t.Fatalf("sign-in through the proxy: %d", w.Code)
	}
	if rows := f.auditLog(t, "demo"); len(rows) == 0 || rows[0].Action != "login.ok" || rows[0].IP != "203.0.113.77" {
		t.Errorf("audit entry through the proxy: %+v", rows)
	}
	for i := 0; i < addrMaxFailures; i++ {
		f.do("POST", "/login", pre, url.Values{"csrf": {tok}, "tenant": {"demo"}, "user": {fmt.Sprintf("u%d", i)}, "password": {"x"}}, hdr)
	}
	if w := f.do("POST", "/login", pre, url.Values{"csrf": {tok}, "tenant": {"demo"}, "user": {"ala"}, "password": {goodPW}}, hdr); w.Code != http.StatusTooManyRequests {
		t.Errorf("the client behind the proxy is not limited: %d", w.Code)
	}
	hdr["X-Forwarded-For"] = "203.0.113.78"
	if w := f.do("POST", "/login", pre, url.Values{"csrf": {tok}, "tenant": {"demo"}, "user": {"ala"}, "password": {goodPW}}, hdr); w.Code != http.StatusSeeOther {
		t.Errorf("another client behind the same proxy was limited too: %d", w.Code)
	}
}
