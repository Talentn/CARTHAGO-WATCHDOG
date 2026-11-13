package dashboard

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

// oracleFixture is the usual fixture plus what the Oracle wrote about two sessions: bob's
// was flagged and has an analyst opinion, alice's is clear.
type oracleFixture struct {
	*fixture
	st  *store.Memory
	bob int64 // id of bob's code_patch evidence
}

const (
	secretFeatures = `{"aim_snap_rate":0.4242,"integrity_findings":7.7171}`
	secretCase     = `{"schema":1,"subject":"P-0123456789","session":"S-abcdef0123","evidence":[{"id":"E1","rule":"code_patch"}]}`
)

func newOracleFixture(t *testing.T, info *OracleInfo) *oracleFixture {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for _, s := range []store.Session{
		{SessionID: "aaaa1111", TenantID: "demo", PlayerHash: "alice", DeviceID: "d1", TrustLevel: 3, State: store.SessionActive, CreatedAt: now.Add(-time.Hour), LastHeartbeat: now},
		{SessionID: "bbbb2222", TenantID: "demo", PlayerHash: "bob", DeviceID: "d2", State: store.SessionClosed, CreatedAt: now.Add(-time.Hour), LastHeartbeat: now.Add(-10 * time.Minute)},
		{SessionID: "cccc3333", TenantID: "demo", PlayerHash: "carol", DeviceID: "d3", State: store.SessionClosed, CreatedAt: now.Add(-time.Hour), LastHeartbeat: now.Add(-10 * time.Minute)},
		{SessionID: "xxxx9999", TenantID: "rival", PlayerHash: "rival-player", DeviceID: "d9", State: store.SessionActive, CreatedAt: now, LastHeartbeat: now},
	} {
		st.PutSession(ctx, &s)
	}
	st.AddEvidence(ctx, []store.Evidence{
		{TenantID: "demo", PlayerHash: "bob", SessionID: "bbbb2222", Source: store.SourceClient, Rule: "code_patch", Severity: 4, Score: 0.9, Integrity: true, Summary: ".text patched", ObservedAt: now},
		{TenantID: "demo", PlayerHash: "carol", SessionID: "cccc3333", Source: store.SourceGameplay, Rule: "angle_snap", Severity: 3, Score: 0.8, Summary: "snaps", ObservedAt: now},
	})
	evs, _ := st.ListEvidence(ctx, "demo", store.EvidenceFilter{SessionID: "bbbb2222"})
	f := &oracleFixture{st: st, bob: evs[0].ID}
	st.PutOracleScore(ctx, &store.OracleScore{TenantID: "demo", SessionID: "bbbb2222", PlayerHash: "bob", ModelID: "cob-0123456789ab", FeatureVersion: 1, Score: 0.874, Band: store.OracleBandReview,
		Signals:  `[{"key":"integrity_findings","label":"Client integrity findings","family":"integrity","effect":3.1},{"key":"trust_level","label":"Device trust level","family":"trust","effect":0.9},{"key":"headshot_excess","label":"Headshot rate above expectation","family":"aim","effect":-0.4}]`,
		Features: secretFeatures, UpdatedAt: now.Add(-5 * time.Minute)})
	st.PutOracleVerdict(ctx, &store.OracleVerdict{TenantID: "demo", SessionID: "bbbb2222", PlayerHash: "bob", CaseHash: "h1", Status: store.OracleVerdictOK, Provider: "local", AnalystModel: "oracle-analyst-test",
		PromptVersion: "oracle-analyst-1", CheatType: "client_tampering", Confidence: 82, Action: "priority_review", Summary: "The client reported patched game code <b>twice</b>.",
		Cited: `[{"id":"E1","rule":"code_patch","evidence":[` + itoa(int(f.bob)) + `]}]`, CaseFile: secretCase, CreatedAt: now.Add(-4 * time.Minute)})
	st.PutOracleScore(ctx, &store.OracleScore{TenantID: "demo", SessionID: "aaaa1111", PlayerHash: "alice", MatchID: "m-1", ModelID: "cob-0123456789ab", FeatureVersion: 1, Score: 0.031, Band: store.OracleBandClear,
		Signals: `[]`, Features: secretFeatures, UpdatedAt: now})
	st.PutOracleScore(ctx, &store.OracleScore{TenantID: "rival", SessionID: "xxxx9999", PlayerHash: "rival-player", ModelID: "cob-rival", Score: 0.99, Band: store.OracleBandReview, Signals: `[]`, UpdatedAt: now})
	srv, err := New(Config{Keys: map[string]string{"demo": "demo-key", "rival": "rival-key"}, Now: func() time.Time { return now }, Oracle: info}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	f.fixture = &fixture{srv: srv, h: srv.Handler(), now: now}
	return f
}

var testOracle = &OracleInfo{BundleID: "cb-feedfacecafe", ModelID: "cob-0123456789ab", Analyst: "local", AnalystModel: "oracle-analyst-test", PromptVersion: "oracle-analyst-1"}

var csrfField = regexp.MustCompile(`name="csrf" value="([0-9a-f]{32})"`)

func (f *oracleFixture) csrf(t *testing.T, c *http.Cookie, session string) string {
	t.Helper()
	m := csrfField.FindStringSubmatch(f.do("GET", "/sessions/"+session, c, nil, nil).Body.String())
	if m == nil {
		t.Fatal("the label form carries no CSRF token")
	}
	return m[1]
}

var sameSiteHdr = map[string]string{"Sec-Fetch-Site": "same-origin"}

func TestOracleCardOnSessionPage(t *testing.T) {
	f := newOracleFixture(t, testOracle)
	c := f.login(t, "demo", "demo-key")
	w := f.do("GET", "/sessions/bbbb2222", c, nil, nil)
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("session page: %d %s", w.Code, body)
	}
	for _, want := range []string{
		"<h2>Carthago Oracle</h2>", `engine <span class="mono">cb-feedfacecafe</span> · analyst local`,
		`<div class="oscore"><b>87</b>`, `<span class="tier tier-review">review</span>`,
		"Client integrity findings", "Device trust level", "Headshot rate above expectation",
		`raises <span class="muted">strong</span>`, `lowers <span class="muted">weak</span>`, `<rect class="down"`,
		`<p class="lead olead">Client tampering</p>`, `<span class="mono">82%</span>`, "Review by a person, first",
		"The client reported patched game code &lt;b&gt;twice&lt;/b&gt;.",
		`href="/evidence/` + itoa(int(f.bob)) + `">E1 · code_patch · #` + itoa(int(f.bob)) + `</a>`,
		`<span class="mono">local</span>`, "oracle-analyst-test", "oracle-analyst-1",
		"It is advisory: it never kicks, bans or changes a player's risk", "from client evidence only, no match played",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("session page lacks %q", want)
		}
	}
	// The page still obeys the dashboard's content policy: nothing inline, no scripts.
	csp := w.Header().Get("Content-Security-Policy")
	if csp != "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" {
		t.Errorf("CSP changed: %q", csp)
	}
	for _, bad := range []string{"<script", " style=", "onclick", "javascript:"} {
		if strings.Contains(body, bad) {
			t.Errorf("session page contains %q", bad)
		}
	}

	// A clear session shows its score and says why there is no opinion.
	body = f.do("GET", "/sessions/aaaa1111", c, nil, nil).Body.String()
	for _, want := range []string{`<div class="oscore"><b>3</b>`, `tier-clear`, "No signal stands out", "Not sent to the analyst"} {
		if !strings.Contains(body, want) {
			t.Errorf("clear session page lacks %q", want)
		}
	}
	// A session the Oracle has not scored still gets the card while the engine runs.
	if body = f.do("GET", "/sessions/cccc3333", c, nil, nil).Body.String(); !strings.Contains(body, "This session has not been scored") {
		t.Error("an unscored session does not say so")
	}
}

// What the engine keeps to itself never reaches a page: the feature vector, the case
// file, thresholds, prompts. The dashboard has no route to the bundle at all.
func TestOracleSecretsAreNotServed(t *testing.T) {
	f := newOracleFixture(t, testOracle)
	c := f.login(t, "demo", "demo-key")
	for _, p := range []string{"/", "/sessions", "/sessions/bbbb2222", "/sessions/aaaa1111", "/players", "/players/bob", "/players?all=1", "/evidence/" + itoa(int(f.bob))} {
		body := f.do("GET", p, c, nil, nil).Body.String()
		for _, secret := range []string{"0.4242", "7.7171", "aim_snap_rate", "integrity_findings", "P-0123456789", "S-abcdef0123", `"schema"`, "threshold", "0.874", "3.1"} {
			if strings.Contains(body, secret) {
				t.Errorf("%s shows %q", p, secret)
			}
		}
	}
	for _, p := range []string{"/oracle", "/oracle/manifest.json", "/static/manifest.json", "/static/behaviour-model.json", "/static/prompts/system.txt",
		"/static/../oracle/manifest.json", "/sessions/bbbb2222/case", "/sessions/bbbb2222/features", "/sessions/bbbb2222/label"} {
		if w := f.do("GET", p, c, nil, nil); w.Code == 200 {
			t.Errorf("GET %s answered 200", p)
		}
	}
}

func TestOracleIsTenantScoped(t *testing.T) {
	f := newOracleFixture(t, testOracle)
	rival := f.login(t, "rival", "rival-key")
	if w := f.do("GET", "/sessions/bbbb2222", rival, nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("another studio's session: %d", w.Code)
	}
	if w := f.do("GET", "/players/bob", rival, nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("another studio's player: %d", w.Code)
	}
	body := f.do("GET", "/sessions/xxxx9999", rival, nil, nil).Body.String()
	if !strings.Contains(body, `<div class="oscore"><b>99</b>`) || strings.Contains(body, "cob-0123456789ab") && !strings.Contains(body, "cob-rival") {
		t.Error("the rival studio does not see its own score")
	}
	// A label cannot be written onto another studio's session, even with a valid token.
	tok := f.csrf(t, rival, "xxxx9999")
	w := f.do("POST", "/sessions/bbbb2222/label", rival, url.Values{"csrf": {tok}, "label": {"cleared"}}, sameSiteHdr)
	if w.Code != http.StatusNotFound {
		t.Fatalf("label on another studio's session: %d", w.Code)
	}
	if l, _ := f.st.GetSessionLabel(context.Background(), "demo", "bbbb2222"); l != nil {
		t.Fatal("the label was stored")
	}
	if l, _ := f.st.GetSessionLabel(context.Background(), "rival", "bbbb2222"); l != nil {
		t.Fatal("a label was stored under the wrong studio")
	}
}

func TestReviewerLabel(t *testing.T) {
	f := newOracleFixture(t, testOracle)
	ctx := context.Background()
	c := f.login(t, "demo", "demo-key")
	form := func(tok string, kv ...string) url.Values {
		v := url.Values{"csrf": {tok}}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	tok := f.csrf(t, c, "cccc3333")

	// Like the other actions, a label needs a same-origin request and the form's token.
	for name, w := range map[string]int{
		"no token":     f.do("POST", "/sessions/cccc3333/label", c, url.Values{"label": {"cleared"}}, sameSiteHdr).Code,
		"wrong token":  f.do("POST", "/sessions/cccc3333/label", c, form(strings.Repeat("0", 32), "label", "cleared"), sameSiteHdr).Code,
		"cross-site":   f.do("POST", "/sessions/cccc3333/label", c, form(tok, "label", "cleared"), map[string]string{"Sec-Fetch-Site": "cross-site"}).Code,
		"other origin": f.do("POST", "/sessions/cccc3333/label", c, form(tok, "label", "cleared"), map[string]string{"Origin": "https://evil.example"}).Code,
	} {
		if w != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, w)
		}
	}
	if w := f.do("POST", "/sessions/cccc3333/label", nil, form(tok, "label", "cleared"), sameSiteHdr); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Errorf("signed out: %d", w.Code)
	}
	// Another sign-in's token does not work for this one.
	other := f.login(t, "demo", "demo-key")
	if other.Value != c.Value {
		if w := f.do("POST", "/sessions/cccc3333/label", other, form(tok, "label", "cleared"), sameSiteHdr); w.Code != http.StatusForbidden {
			t.Errorf("token of another sign-in: %d", w.Code)
		}
	}
	for name, v := range map[string]url.Values{
		"unknown label": form(tok, "label", "banned"),
		"unknown type":  form(tok, "label", "confirmed_cheat", "cheat_type", "ban_now"),
	} {
		if w := f.do("POST", "/sessions/cccc3333/label", c, v, sameSiteHdr); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, w.Code)
		}
	}
	if l, _ := f.st.GetSessionLabel(ctx, "demo", "cccc3333"); l != nil {
		t.Fatalf("a refused request stored a label: %+v", l)
	}
	if au, _ := f.st.ListLabelAudit(ctx, "demo", "cccc3333", 0); len(au) != 0 {
		t.Fatalf("a refused request was audited as a change: %+v", au)
	}

	// A valid label is stored with who and when, and audited.
	w := f.do("POST", "/sessions/cccc3333/label", c, form(tok, "label", "confirmed_cheat", "cheat_type", "aim_assistance",
		"note", "  watched the demo:\n<b>locks</b> through smoke\x00  "+strings.Repeat("x", 400), "reviewer", " Sam <script> "), sameSiteHdr)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/sessions/cccc3333?labelled=1#label" {
		t.Fatalf("label: %d %q %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	l, err := f.st.GetSessionLabel(ctx, "demo", "cccc3333")
	if err != nil || l.Label != store.LabelConfirmedCheat || l.CheatType != "aim_assistance" || l.PlayerHash != "carol" || l.Reviewer != "Sam <script>" || !l.LabelledAt.Equal(f.now) {
		t.Fatalf("stored label: %+v %v", l, err)
	}
	if n := len([]rune(l.Note)); n != 280 || !strings.HasPrefix(l.Note, "watched the demo: <b>locks</b> through smoke xxx") {
		t.Fatalf("note (%d runes): %q", n, l.Note)
	}
	var reviewer *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == reviewerCookie {
			reviewer = ck
		}
	}
	if reviewer == nil || !reviewer.HttpOnly || reviewer.SameSite != http.SameSiteStrictMode {
		t.Fatalf("reviewer cookie: %+v", reviewer)
	}
	r := f.do("GET", "/sessions/cccc3333?labelled=1", c, nil, nil)
	body := r.Body.String()
	for _, want := range []string{`<span class="mark lbl-confirmed_cheat">Confirmed cheat</span>`, "Aim assistance", "Sam &lt;script&gt;", "&lt;b&gt;locks&lt;/b&gt;",
		`<p class="saved">Label saved</p>`, `<option value="confirmed_cheat" selected>`, `<option value="aim_assistance" selected>`, "History (1)", "192.0.2.1"} {
		if !strings.Contains(body, want) {
			t.Errorf("labelled session page lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>") || strings.Contains(body, "<b>locks") {
		t.Error("reviewer text is not escaped")
	}

	// A label can be changed and removed; the history keeps every step.
	if w := f.do("POST", "/sessions/cccc3333/label", c, form(tok, "label", "cleared", "cheat_type", "aim_assistance", "reviewer", "Kim"), sameSiteHdr); w.Code != http.StatusSeeOther {
		t.Fatalf("relabel: %d", w.Code)
	}
	if l, _ := f.st.GetSessionLabel(ctx, "demo", "cccc3333"); l == nil || l.Label != store.LabelCleared || l.CheatType != "" || l.Reviewer != "Kim" {
		t.Fatalf("relabel: %+v", l)
	}
	if w := f.do("POST", "/sessions/cccc3333/label", c, form(tok, "label", "", "reviewer", "Kim"), sameSiteHdr); w.Code != http.StatusSeeOther {
		t.Fatalf("remove: %d", w.Code)
	}
	if l, _ := f.st.GetSessionLabel(ctx, "demo", "cccc3333"); l != nil {
		t.Fatalf("label after removal: %+v", l)
	}
	au, _ := f.st.ListLabelAudit(ctx, "demo", "cccc3333", 0)
	if len(au) != 3 || au[0].Action != store.LabelRemove || au[1].Label != store.LabelCleared || au[2].Action != store.LabelSet || au[2].Remote != "192.0.2.1" || au[2].Reviewer != "Sam <script>" {
		t.Fatalf("audit: %+v", au)
	}

	// A label is a note. It never touches the session, its evidence or the player's risk.
	f.do("POST", "/sessions/aaaa1111/label", c, form(f.csrf(t, c, "aaaa1111"), "label", "confirmed_cheat", "cheat_type", "mixed"), sameSiteHdr)
	if s, _ := f.st.GetSession(ctx, "aaaa1111"); s.State != store.SessionActive || s.KickReason != "" {
		t.Fatalf("labelling changed the session: %+v", s)
	}
	if evs, _ := f.st.ListEvidence(ctx, "demo", store.EvidenceFilter{SessionID: "aaaa1111"}); len(evs) != 0 {
		t.Fatalf("labelling wrote evidence: %+v", evs)
	}
	rows, _ := f.st.ListPlayers(ctx, "demo", store.PlayerFilter{})
	for _, row := range rows {
		if row.PlayerHash == "alice" && row.Risk != 0 {
			t.Fatalf("labelling raised the player's risk: %+v", row)
		}
	}
}

// Hard integrity evidence proposes a label; a person decides. It works for a session that
// never played a match.
func TestLabelSuggestionFromIntegrityEvidence(t *testing.T) {
	f := newOracleFixture(t, nil)
	ctx := context.Background()
	c := f.login(t, "demo", "demo-key")
	body := f.do("GET", "/sessions/bbbb2222", c, nil, nil).Body.String()
	for _, want := range []string{"Suggested: <b>Confirmed cheat</b> · Client tampering", "1 client integrity finding of critical severity", "Accept suggestion",
		`name="suggested" value="1"`, "Not labelled yet"} {
		if !strings.Contains(body, want) {
			t.Errorf("session page lacks %q", want)
		}
	}
	if l, _ := f.st.GetSessionLabel(ctx, "demo", "bbbb2222"); l != nil {
		t.Fatal("a suggestion was stored before anyone accepted it")
	}
	// Behavioural evidence alone suggests nothing.
	if body := f.do("GET", "/sessions/cccc3333", c, nil, nil).Body.String(); strings.Contains(body, "Suggested:") {
		t.Error("a suggestion was made without integrity evidence")
	}
	tok := f.csrf(t, c, "bbbb2222")
	w := f.do("POST", "/sessions/bbbb2222/label", c, url.Values{"csrf": {tok}, "suggested": {"1"}, "label": {"confirmed_cheat"}, "cheat_type": {"client_tampering"}, "reviewer": {"Ala"}}, sameSiteHdr)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("accept: %d", w.Code)
	}
	l, _ := f.st.GetSessionLabel(ctx, "demo", "bbbb2222")
	au, _ := f.st.ListLabelAudit(ctx, "demo", "bbbb2222", 0)
	if l == nil || l.Label != store.LabelConfirmedCheat || l.CheatType != "client_tampering" || len(au) != 1 || au[0].Action != store.LabelAcceptSuggestion {
		t.Fatalf("accepted suggestion: %+v %+v", l, au)
	}
	body = f.do("GET", "/sessions/bbbb2222", c, nil, nil).Body.String()
	if strings.Contains(body, "Suggested:") || !strings.Contains(body, "Accepted suggestion") {
		t.Error("the accepted suggestion is still offered, or its history is missing")
	}
	// The player page lists the label beside the score and the opinion.
	body = f.do("GET", "/players/bob", c, nil, nil).Body.String()
	for _, want := range []string{"<h2>Carthago Oracle</h2>", `<td class="num">87</td>`, "Client tampering", `<td class="num">82%</td>`, `<span class="mark lbl-confirmed_cheat">Confirmed cheat</span>`, "engine off · showing stored results"} {
		if !strings.Contains(body, want) {
			t.Errorf("player page lacks %q", want)
		}
	}
}

func TestOracleUnavailableAndOff(t *testing.T) {
	f := newOracleFixture(t, testOracle)
	ctx := context.Background()
	c := f.login(t, "demo", "demo-key")
	f.st.PutOracleVerdict(ctx, &store.OracleVerdict{TenantID: "demo", SessionID: "bbbb2222", PlayerHash: "bob", Status: store.OracleVerdictUnavailable, Reason: "timeout", Provider: "local",
		Summary: "must not show", CreatedAt: f.now})
	body := f.do("GET", "/sessions/bbbb2222", c, nil, nil).Body.String()
	if !strings.Contains(body, "No opinion: the analyst took too long.") || strings.Contains(body, "must not show") {
		t.Error("an unavailable analyst is not reported as designed")
	}
	// A reason the dashboard does not know is not echoed.
	f.st.PutOracleVerdict(ctx, &store.OracleVerdict{TenantID: "demo", SessionID: "bbbb2222", PlayerHash: "bob", Status: store.OracleVerdictUnavailable, Reason: "<i>raw provider text</i>", CreatedAt: f.now})
	if body := f.do("GET", "/sessions/bbbb2222", c, nil, nil).Body.String(); strings.Contains(body, "raw provider text") {
		t.Error("a free-text reason reached the page")
	}

	// With the engine off and nothing stored there is no Oracle card, and labels still work.
	off := newFixture(t)
	oc := off.login(t, "demo", "demo-key")
	body = off.do("GET", "/sessions/aaaa1111", oc, nil, nil).Body.String()
	if strings.Contains(body, "Carthago Oracle") || !strings.Contains(body, "<h2>Reviewer label</h2>") {
		t.Error("engine off: the Oracle card shows, or the label card is missing")
	}
}

func TestCleanText(t *testing.T) {
	for in, want := range map[string]string{
		"  a  b\tc\n": "a b c", "x\x00y\x1b[31m": "x y [31m", "é\u202eabc": "éabc", "\xff\xfeok": "ok", "": "",
	} {
		if got := cleanText(in, 64); got != want {
			t.Errorf("cleanText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := cleanText(strings.Repeat("ab ", 100), 10); got != "ab ab ab a" {
		t.Errorf("cut: %q", got)
	}
}
