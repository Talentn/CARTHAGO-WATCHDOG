package dashboard

import (
	"context"
	"encoding/base32"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

// goodPW passes the password policy for every name used in these tests.
const goodPW = "plum-kettle-orbit-97"

var (
	sameOriginHdr = map[string]string{"Sec-Fetch-Site": "same-origin"}
	formTokenRE   = regexp.MustCompile(`name="csrf" value="([0-9a-f]{32})"`)
	pendingRE     = regexp.MustCompile(`name="pending" value="([A-Za-z0-9_-]+)"`)
	setupKeyRE    = regexp.MustCompile(`<pre>([A-Z2-7 ]+)</pre>`)
	qrPathRE      = regexp.MustCompile(`<path class="qr-fg" d="([^"]+)"`)
	recoveryRE    = regexp.MustCompile(`<li>([0-9a-z]{4}(?:-[0-9a-z]{4}){3})</li>`)
	inviteLinkRE  = regexp.MustCompile(`http://127\.0\.0\.1:8751/invite/([A-Za-z0-9_-]{43})`)
)

func (f *fixture) addUser(t *testing.T, tenant, name, role, pw string) *store.DashUser {
	t.Helper()
	h, err := hashPassword(pw, testArgon)
	if err != nil {
		t.Fatal(err)
	}
	u := &store.DashUser{TenantID: tenant, Name: name, Role: role, PasswordHash: h, CreatedAt: f.now, CreatedBy: "test", PasswordChangedAt: f.now}
	if err := f.srv.au.CreateDashUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *fixture) user(t *testing.T, tenant, name string) *store.DashUser {
	t.Helper()
	u, err := f.srv.au.GetDashUserByName(context.Background(), tenant, name)
	if err != nil {
		t.Fatalf("user %s/%s: %v", tenant, name, err)
	}
	return u
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// pre opens the sign-in page like a browser and returns the cookie and form token it got.
func (f *fixture) pre(t *testing.T) (*http.Cookie, string) {
	t.Helper()
	w := f.do("GET", "/login", nil, nil, nil)
	c := cookieNamed(w, f.srv.preCookie())
	m := formTokenRE.FindStringSubmatch(w.Body.String())
	if c == nil || m == nil {
		t.Fatalf("sign-in page: cookie %v, token %v", c, m)
	}
	return c, m[1]
}

// tryLogin submits the account sign-in form.
func (f *fixture) tryLogin(t *testing.T, tenant, name, pw string) *httptest.ResponseRecorder {
	t.Helper()
	pre, tok := f.pre(t)
	return f.do("POST", "/login", pre, url.Values{"csrf": {tok}, "tenant": {tenant}, "user": {name}, "password": {pw}}, sameOriginHdr)
}

// signIn signs in an account that has no second factor and returns its session cookie.
func (f *fixture) signIn(t *testing.T, tenant, name, pw string) *http.Cookie {
	t.Helper()
	w := f.tryLogin(t, tenant, name, pw)
	c := cookieNamed(w, f.srv.cookie())
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" || c == nil {
		t.Fatalf("sign in %s/%s: %d -> %q", tenant, name, w.Code, w.Header().Get("Location"))
	}
	return c
}

func (f *fixture) get(c *http.Cookie, path string) *httptest.ResponseRecorder {
	return f.do("GET", path, c, nil, nil)
}

// post submits a form the way the browser holding c would: with the page's token and
// from the same origin.
func (f *fixture) post(c *http.Cookie, path string, kv ...string) *httptest.ResponseRecorder {
	form := url.Values{"csrf": {csrfFor(c.Value)}}
	for i := 0; i+1 < len(kv); i += 2 {
		form.Set(kv[i], kv[i+1])
	}
	return f.do("POST", path, c, form, sameOriginHdr)
}

// alive reports whether a session cookie still opens the overview.
func (f *fixture) alive(c *http.Cookie) bool { return f.get(c, "/").Code == http.StatusOK }

func (f *fixture) auditLog(t *testing.T, tenant string) []store.AuditEntry {
	t.Helper()
	rows, err := f.srv.au.ListAudit(context.Background(), tenant, store.AuditFilter{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// wantAudit checks that the tenant's log has an entry with that action by that actor whose
// target or detail holds part, and that it says where and when.
func (f *fixture) wantAudit(t *testing.T, tenant, action, actor, part string) {
	t.Helper()
	var near *store.AuditEntry
	for _, e := range f.auditLog(t, tenant) {
		if e.Action != action || e.Actor != actor {
			continue
		}
		near = &e
		if strings.Contains(e.Target+" "+e.Detail, part) {
			if e.IP == "" || e.At.IsZero() || e.TenantID != tenant || e.Hash == "" {
				t.Errorf("audit %s by %q lacks where or when: %+v", action, actor, e)
			}
			return
		}
	}
	if near != nil {
		t.Errorf("audit %s by %q: target %q detail %q, want %q", action, actor, near.Target, near.Detail, part)
		return
	}
	t.Errorf("audit log of %s has no %s by %q", tenant, action, actor)
}

// enrol sets up two-factor sign-in for the account behind c through the pages, and returns
// the new session cookie, the secret the page showed and the recovery codes.
func (f *fixture) enrol(t *testing.T, c *http.Cookie, pw string) (*http.Cookie, []byte, []string) {
	t.Helper()
	page := f.get(c, "/account/two-factor/setup")
	body := page.Body.String()
	key, pending := setupKeyRE.FindStringSubmatch(body), pendingRE.FindStringSubmatch(body)
	if page.Code != 200 || key == nil || pending == nil {
		t.Fatalf("setup page: %d key %v pending %v", page.Code, key, pending != nil)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(key[1], " ", ""))
	if err != nil || len(secret) != totpSecretLen {
		t.Fatalf("secret on the page: %v", err)
	}
	w := f.post(c, "/account/two-factor/setup", "pending", pending[1], "password", pw, "code", totpCode(secret, totpStep(f.now)))
	nc := cookieNamed(w, f.srv.cookie())
	var codes []string
	for _, m := range recoveryRE.FindAllStringSubmatch(w.Body.String(), -1) {
		codes = append(codes, m[1])
	}
	if w.Code != 200 || nc == nil || len(codes) != recoveryCodes {
		t.Fatalf("enrolment: %d, new cookie %v, %d recovery codes: %s", w.Code, nc != nil, len(codes), w.Body.String())
	}
	// The code that confirmed the enrolment is spent; move to the next one.
	f.now = f.now.Add(totpPeriod * time.Second)
	return nc, secret, codes
}

// signIn2 signs in an account that has a second factor: password, then the code.
func (f *fixture) signIn2(t *testing.T, tenant, name, pw string, secret []byte) *http.Cookie {
	t.Helper()
	w := f.tryLogin(t, tenant, name, pw)
	step := cookieNamed(w, f.srv.cookie())
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login/code" || step == nil {
		t.Fatalf("password step for %s: %d -> %q", name, w.Code, w.Header().Get("Location"))
	}
	w = f.post(step, "/login/code", "code", totpCode(secret, totpStep(f.now)))
	c := cookieNamed(w, f.srv.cookie())
	if w.Code != http.StatusSeeOther || c == nil {
		t.Fatalf("code step for %s: %d %s", name, w.Code, w.Body.String())
	}
	f.now = f.now.Add(totpPeriod * time.Second)
	return c
}
