package dashboard

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

type fixture struct {
	srv *Server
	h   http.Handler
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	st := store.NewMemory()
	ctx := context.Background()
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for _, s := range []store.Session{
		{SessionID: "aaaa1111", TenantID: "demo", PlayerHash: "alice", DeviceID: "d1", TrustLevel: 3, AttestFlags: 0x3ff, State: store.SessionActive, CreatedAt: now.Add(-time.Hour), LastHeartbeat: now},
		{SessionID: "bbbb2222", TenantID: "demo", PlayerHash: "bob", DeviceID: "d2", TrustLevel: 0, State: store.SessionKicked, KickReason: "integrity_violation: code_patch", CreatedAt: now.Add(-time.Minute), LastHeartbeat: now},
		{SessionID: "xxxx9999", TenantID: "rival", PlayerHash: "rival-player", DeviceID: "d9", State: store.SessionActive, CreatedAt: now, LastHeartbeat: now},
	} {
		st.PutSession(ctx, &s)
	}
	st.AddEvidence(ctx, []store.Evidence{
		{TenantID: "demo", PlayerHash: "bob", SessionID: "bbbb2222", Source: store.SourceClient, Rule: "code_patch", Severity: 4, Score: 0.9, Integrity: true,
			Summary: `.text patched: d3d11.dll><script>alert(1)</script>`, Raw: `{"code":"FINDING_CODE_CODE_PATCH","detail":"d3d11.dll>?"}`, ObservedAt: now},
		{TenantID: "demo", PlayerHash: "alice", SessionID: "aaaa1111", Source: store.SourceClient, Rule: "overlay_window", Severity: 0, Score: 0.1, Summary: "allowlisted overlay steam.exe", ObservedAt: now},
		{TenantID: "rival", PlayerHash: "rival-player", SessionID: "xxxx9999", Source: store.SourceClient, Rule: "api_hook", Severity: 3, Score: 0.8, Summary: "rival secret", ObservedAt: now},
	})
	st.PutTelemetry(ctx, &store.Telemetry{SessionID: "aaaa1111", UpdatedAt: now, WorkerCPUNs: 18e9, Slices: 9000, MitigationsApplied: 3,
		Coverage: `[{"job":"api_hooks","runs":120,"overruns":1},{"job":"text_integrity","runs":0,"overruns":0,"quarantined":true}]`})
	srv, err := New(Config{Keys: map[string]string{"demo": "demo-key", "rival": "rival-key"}, Now: func() time.Time { return now }}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{srv: srv, h: srv.Handler(), now: now}
}

func (f *fixture) do(method, path string, cookie *http.Cookie, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = "192.0.2.1:5555"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

func (f *fixture) login(t *testing.T, tenant, key string) *http.Cookie {
	t.Helper()
	w := f.do("POST", "/login", nil, url.Values{"tenant": {tenant}, "key": {key}}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login %s: %d %s", tenant, w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Fatalf("cookie flags: %+v", c)
			}
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestRequiresLogin(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"/", "/sessions", "/sessions/aaaa1111", "/players", "/players/bob", "/evidence/1"} {
		w := f.do("GET", p, nil, nil, nil)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
			t.Errorf("%s: %d -> %q", p, w.Code, w.Header().Get("Location"))
		}
	}
	w := f.do("GET", "/login", nil, nil, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Carthago <b>Watchdog</b>") {
		t.Fatalf("login page: %d", w.Code)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe") {
		t.Fatalf("CSP: %q", csp)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("framing allowed")
	}
}

func TestLoginChecks(t *testing.T) {
	f := newFixture(t)
	sameSite := map[string]string{"Sec-Fetch-Site": "same-origin"}
	if w := f.do("POST", "/login", nil, url.Values{"tenant": {"demo"}, "key": {"demo-key"}}, map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site login: %d", w.Code)
	}
	if w := f.do("POST", "/login", nil, url.Values{"tenant": {"demo"}, "key": {"demo-key"}}, map[string]string{"Origin": "https://evil.example"}); w.Code != http.StatusForbidden {
		t.Fatalf("foreign origin login: %d", w.Code)
	}
	// A valid key for the wrong tenant does not log in.
	if w := f.do("POST", "/login", nil, url.Values{"tenant": {"demo"}, "key": {"rival-key"}}, sameSite); w.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant key: %d", w.Code)
	}
	for range maxFailures - 1 {
		f.do("POST", "/login", nil, url.Values{"tenant": {"demo"}, "key": {"guess"}}, sameSite)
	}
	if w := f.do("POST", "/login", nil, url.Values{"tenant": {"demo"}, "key": {"demo-key"}}, sameSite); w.Code != http.StatusTooManyRequests {
		t.Fatalf("throttle after %d failures: %d", maxFailures, w.Code)
	}
}

func TestPagesRenderTenantScoped(t *testing.T) {
	f := newFixture(t)
	c := f.login(t, "demo", "demo-key")
	for _, p := range []string{"/", "/sessions", "/sessions/aaaa1111", "/sessions/bbbb2222", "/players", "/players?all=1", "/players/bob", "/players/alice", "/evidence/1"} {
		w := f.do("GET", p, c, nil, nil)
		body := w.Body.String()
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", p, w.Code, body)
		}
		if strings.Contains(body, "rival") {
			t.Errorf("%s leaks the other tenant", p)
		}
		if strings.Contains(body, "<script>") {
			t.Errorf("%s renders unescaped client data", p)
		}
		if strings.Contains(body, "Sentinel") {
			t.Errorf("%s uses the old product name", p)
		}
	}
	home := f.do("GET", "/", c, nil, nil).Body.String()
	for _, want := range []string{"Carthago <b>Watchdog</b>", "Flagged players", "code_patch", "Ranked boot", "&lt;script&gt;"} {
		if !strings.Contains(home, want) {
			t.Errorf("overview missing %q", want)
		}
	}
	sess := f.do("GET", "/sessions/aaaa1111", c, nil, nil).Body.String()
	for _, want := range []string{"Secure Boot", "no remote images", "quarantined", "0.50%" /* 18 s of worker CPU over a 1 h session */} {
		if !strings.Contains(sess, want) {
			t.Errorf("session page missing %q", want)
		}
	}
	flagged := f.do("GET", "/players", c, nil, nil).Body.String()
	if !strings.Contains(flagged, "/players/bob") || strings.Contains(flagged, "/players/alice") {
		t.Error("flagged list: bob (critical) in, alice (info only) out")
	}

	for _, p := range []string{"/sessions/xxxx9999", "/players/rival-player", "/evidence/3", "/evidence/abc", "/sessions/nope"} {
		if w := f.do("GET", p, c, nil, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s from demo: %d", p, w.Code)
		}
	}
	rc := f.login(t, "rival", "rival-key")
	if w := f.do("GET", "/evidence/3", rc, nil, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "rival secret") {
		t.Errorf("rival's own evidence: %d", w.Code)
	}
}

func TestCookieTamperingAndExpiry(t *testing.T) {
	f := newFixture(t)
	c := f.login(t, "demo", "demo-key")
	parts := strings.Split(c.Value, ".")
	forged := *c
	forged.Value = f.srv.signCookie("rival", f.now.Add(time.Hour))[:len(parts[0])] + "." + parts[1] + "." + parts[2]
	if w := f.do("GET", "/", &forged, nil, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("tenant swapped under the demo signature: %d", w.Code)
	}
	expired := *c
	expired.Value = f.srv.signCookie("demo", f.now.Add(-time.Second))
	if w := f.do("GET", "/", &expired, nil, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("expired cookie accepted: %d", w.Code)
	}
	if w := f.do("POST", "/logout", c, url.Values{}, map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site logout: %d", w.Code)
	}
	w := f.do("POST", "/logout", c, url.Values{}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if w.Code != http.StatusSeeOther || w.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatalf("logout: %d %+v", w.Code, w.Result().Cookies())
	}
}

func TestStaticAssets(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"/static/app.css", "/static/carthago-watchdog.svg"} {
		if w := f.do("GET", p, nil, nil, nil); w.Code != 200 || w.Body.Len() == 0 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
}

func TestBotEvidenceIsLabelledAndNotFlagged(t *testing.T) {
	f := newFixture(t)
	st := f.srv.st.(*store.Memory)
	st.AddEvidence(context.Background(), []store.Evidence{
		{TenantID: "demo", PlayerHash: "bot:Hawk", MatchID: "m1", Source: store.SourceGameplay, Rule: "angle_snap", Severity: 3, Score: 0.99, Bot: true, Summary: "24 snap-and-lock aim movements", ObservedAt: f.now},
	})
	c := f.login(t, "demo", "demo-key")
	if body := f.do("GET", "/players", c, nil, nil).Body.String(); strings.Contains(body, "bot:Hawk") {
		t.Error("a bot is on the flagged list")
	}
	all := f.do("GET", "/players?all=1", c, nil, nil).Body.String()
	if !strings.Contains(all, "/players/bot:Hawk") || !strings.Contains(all, ">bot</span>") {
		t.Error("all players: the bot row or its label is missing")
	}
	page := f.do("GET", "/players/bot:Hawk", c, nil, nil)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "excluded from risk") || !strings.Contains(page.Body.String(), "angle_snap") {
		t.Errorf("bot player page: %d", page.Code)
	}
	ev := f.do("GET", "/evidence/4", c, nil, nil)
	if ev.Code != 200 || !strings.Contains(ev.Body.String(), "not evidence against anyone") {
		t.Errorf("bot evidence page: %d", ev.Code)
	}
	// The overview's detection feed shows it, labelled; the flagged card and count do not.
	home := f.do("GET", "/", c, nil, nil).Body.String()
	if !strings.Contains(home, ">bot</span>") || strings.Count(home, "/players/bot:Hawk") != 1 {
		t.Error("overview: the bot belongs in the detection feed only, with its label")
	}
}
