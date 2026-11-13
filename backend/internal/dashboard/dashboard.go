// Package dashboard is the Carthago Watchdog studio dashboard (plan Phase 1): a web UI served
// by the gateway on its own listener, where a studio sees live sessions, trust levels,
// flagged players, the evidence behind each flag and what Carthago Oracle makes of it. It is
// read-only apart from one thing: a reviewer can label a session, which is a note for the
// studio and changes nothing about the player.
//
// Each tenant logs in with its dashboard key and only ever sees its own rows: the tenant id
// comes from an HMAC-signed cookie and every store query is scoped by it. Pages are rendered
// server-side with html/template (contextual escaping of everything a client or game server
// sent us) and served with a strict Content-Security-Policy and no scripts at all.
package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"carthago/backend/internal/protocol"
	"carthago/backend/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Store is what the dashboard reads; store.SQLite and store.Memory implement it.
type Store interface {
	store.EvidenceStore
	store.OracleStore
	GetSession(ctx context.Context, id string) (*store.Session, error)
}

type Config struct {
	// Keys maps tenant id to the key that tenant's staff log in with.
	Keys map[string]string
	// SecureCookie sets the cookie's Secure flag; enable it when the dashboard is served
	// over HTTPS (directly or behind a TLS-terminating proxy).
	SecureCookie bool
	// AllowedHosts, when not empty, are the only Host header names (without port) the
	// dashboard answers to. For a loopback listener this stops DNS rebinding: a web page
	// that points its own name at 127.0.0.1 would otherwise be same-origin with the
	// dashboard and could sign in with a known or default key.
	AllowedHosts []string
	// OnlineWindow: a session counts as online if it heartbeated within this window.
	OnlineWindow time.Duration
	Now          func() time.Time
	// Oracle names the Carthago Oracle this gateway runs; nil when it is off.
	Oracle *OracleInfo
}

type Server struct {
	st           Store
	keys         map[string]string
	secret       []byte
	secureCookie bool
	online       time.Duration
	now          func() time.Time
	log          *slog.Logger
	pages        map[string]*template.Template
	lim          limiter
	hosts        map[string]bool
	oracle       *OracleInfo
}

func New(cfg Config, st Store, log *slog.Logger) (*Server, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.OnlineWindow == 0 {
		cfg.OnlineWindow = 2 * time.Minute
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	s := &Server{st: st, keys: cfg.Keys, secret: secret, secureCookie: cfg.SecureCookie, online: cfg.OnlineWindow, now: cfg.Now, log: log, oracle: cfg.Oracle}
	if len(cfg.AllowedHosts) > 0 {
		s.hosts = map[string]bool{}
		for _, h := range cfg.AllowedHosts {
			s.hosts[strings.ToLower(strings.Trim(h, "[]"))] = true
		}
	}
	if err := s.parse(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) parse() error {
	funcs := template.FuncMap{
		"trust":      trustName,
		"trustDesc":  trustDesc,
		"sev":        sevName,
		"ago":        func(t time.Time) string { return ago(s.now(), t) },
		"when":       func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
		"short":      short,
		"pct":        pct,
		"ms":         func(ns uint64) string { return fmt.Sprintf("%.2f ms", float64(ns)/1e6) },
		"tier":       tier,
		"risk":       func(r float64) string { return strconv.FormatFloat(r, 'f', 1, 64) },
		"score":      func(f float64) string { return strconv.FormatFloat(f*100, 'f', 0, 64) + "%" },
		"flags":      attestFlags,
		"mitig":      mitigations,
		"pretty":     prettyJSON,
		"path":       url.PathEscape,
		"query":      url.QueryEscape,
		"add":        func(a, b int) int { return a + b },
		"bar":        trustBar,
		"leak":       parseLeak,
		"decoy":      parseDecoy,
		"fixed":      fixed,
		"add2":       func(a, b float64) float64 { return a + b },
		"pctOf":      func(f float64) float64 { return f * 100 },
		"cheatName":  named(cheatNames),
		"actionName": named(actionNames),
		"labelName":  named(labelNames),
		"reason":     named(unavailableReasons),
		"auditName":  named(map[string]string{store.LabelSet: "Set", store.LabelAcceptSuggestion: "Accepted suggestion", store.LabelRemove: "Removed"}),
	}
	s.pages = map[string]*template.Template{}
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	for _, n := range names {
		base := strings.TrimSuffix(strings.TrimPrefix(n, "templates/"), ".html")
		if base == "layout" || base == "partials" || base == "decoy" || base == "oracle" {
			continue
		}
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/partials.html", "templates/decoy.html", "templates/oracle.html", n)
		if err != nil {
			return err
		}
		s.pages[base] = t
	}
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticFiles()))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /{$}", s.auth(s.overview))
	mux.HandleFunc("GET /sessions", s.auth(s.sessions))
	mux.HandleFunc("GET /sessions/{id}", s.auth(s.session))
	mux.HandleFunc("POST /sessions/{id}/label", s.auth(s.setLabel))
	mux.HandleFunc("GET /players", s.auth(s.players))
	mux.HandleFunc("GET /players/{hash}", s.auth(s.player))
	mux.HandleFunc("GET /evidence/{id}", s.auth(s.evidence))
	return securityHeaders(s.hostCheck(mux))
}

// hostCheck refuses requests addressed to a name the dashboard is not served under.
func (s *Server) hostCheck(h http.Handler) http.Handler {
	if s.hosts == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if hn, _, err := net.SplitHostPort(host); err == nil {
			host = hn
		}
		if !s.hosts[strings.ToLower(strings.Trim(host, "[]"))] {
			http.Error(w, "this dashboard is not served under that host name", http.StatusMisdirectedRequest)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// staticFiles serves the embedded stylesheet, logo and fonts, which are the same for every
// studio and hold nothing private, so a browser may keep them. Each file's ETag is a hash
// of its content. Fonts are reused for a week without asking; the stylesheet and the logo
// are checked on every use and answered with 304 while unchanged, so a page from an
// upgraded gateway never meets the previous version's CSS. Only the embedded files are
// served: there are no directory listings.
func staticFiles() http.Handler {
	static, _ := fs.Sub(staticFS, "static")
	etags := map[string]string{}
	_ = fs.WalkDir(static, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(static, name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		etags[name] = `"` + hex.EncodeToString(sum[:12]) + `"`
		return nil
	})
	files := http.FileServerFS(static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tag, ok := etags[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		hd := w.Header()
		hd.Set("ETag", tag)
		if strings.HasSuffix(r.URL.Path, ".woff2") {
			hd.Set("Cache-Control", "public, max-age=604800")
		} else {
			hd.Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

// securityHeaders applies to every response. Pages are never stored by the browser;
// staticFiles replaces that for the files it serves.
func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

type handler func(w http.ResponseWriter, r *http.Request, tenant string)

func (s *Server) auth(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := s.tenantOf(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r, tenant)
	}
}

type page struct {
	Title  string
	Nav    string
	Tenant string
	Data   any
}

func (s *Server) render(w http.ResponseWriter, status int, name string, p page) {
	t := s.pages[name]
	if t == nil {
		http.Error(w, "template missing", http.StatusInternalServerError)
		return
	}
	var b strings.Builder
	if err := t.Execute(&b, p); err != nil {
		s.log.Error("dashboard render", "page", name, "err", err)
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.log.Error("dashboard query", "err", err)
	http.Error(w, "query failed", http.StatusInternalServerError)
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.tenantOf(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "login", page{Title: "Sign in"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-site request", http.StatusForbidden)
		return
	}
	ip := clientIP(r)
	if s.lim.blocked(ip, s.now()) {
		s.render(w, http.StatusTooManyRequests, "login", page{Title: "Sign in", Data: "Too many failed attempts. Try again in a few minutes."})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	tenant, key := strings.TrimSpace(r.PostFormValue("tenant")), r.PostFormValue("key")
	if !s.checkKey(tenant, key) {
		s.lim.failed(ip, s.now())
		s.log.Warn("dashboard login failed", "remote", ip, "tenant", tenant)
		s.render(w, http.StatusUnauthorized, "login", page{Title: "Sign in", Data: "Unknown studio or key"})
		return
	}
	s.lim.reset(ip)
	s.setSession(w, tenant)
	s.log.Info("dashboard login", "remote", ip, "tenant", tenant)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-site request", http.StatusForbidden)
		return
	}
	s.clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type overviewData struct {
	O        store.Overview
	Flagged  []store.PlayerRow
	Recent   []store.Evidence
	Sessions []store.SessionRow
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request, tenant string) {
	ctx := r.Context()
	now := s.now()
	o, err := s.st.Overview(ctx, tenant, now.Add(-24*time.Hour), now.Add(-s.online))
	if err != nil {
		s.fail(w, err)
		return
	}
	flagged, err := s.st.ListPlayers(ctx, tenant, store.PlayerFilter{FlaggedOnly: true, Limit: 8})
	if err != nil {
		s.fail(w, err)
		return
	}
	recent, err := s.st.ListEvidence(ctx, tenant, store.EvidenceFilter{MinSeverity: 1, Limit: 10})
	if err != nil {
		s.fail(w, err)
		return
	}
	sess, err := s.st.ListSessions(ctx, tenant, store.SessionFilter{Limit: 8})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "overview", page{Title: "Overview", Nav: "overview", Tenant: tenant, Data: overviewData{o, flagged, recent, sess}})
}

func (s *Server) sessions(w http.ResponseWriter, r *http.Request, tenant string) {
	rows, err := s.st.ListSessions(r.Context(), tenant, store.SessionFilter{Limit: 200})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "sessions", page{Title: "Sessions", Nav: "sessions", Tenant: tenant, Data: rows})
}

type sessionData struct {
	S         *store.Session
	Telemetry *store.Telemetry
	Coverage  []coverage
	Evidence  []store.Evidence
	CPUShare  float64 // worker CPU as a fraction of one core over the session
	Gameplay  []store.GameplaySummary
	Leaks     []*leakView
	Decoys    []*decoyView
	Oracle    *oracleView
	Label     labelCard
}

type labelCard struct {
	View      *labelView
	CSRF      string
	SessionID string
}

type coverage struct {
	Job         string `json:"job"`
	Runs        uint64 `json:"runs"`
	Overruns    uint64 `json:"overruns"`
	Quarantined bool   `json:"quarantined"`
}

func (s *Server) session(w http.ResponseWriter, r *http.Request, tenant string) {
	ctx := r.Context()
	id := r.PathValue("id")
	sess, err := s.st.GetSession(ctx, id)
	if err == nil && sess.TenantID != tenant {
		err = store.ErrNotFound
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	d := sessionData{S: sess}
	if t, err := s.st.GetTelemetry(ctx, tenant, id); err == nil {
		d.Telemetry = t
		_ = json.Unmarshal([]byte(t.Coverage), &d.Coverage)
		if span := t.UpdatedAt.Sub(sess.CreatedAt); span > 0 {
			d.CPUShare = float64(t.WorkerCPUNs+t.InputThreadCPUNs) / float64(span.Nanoseconds())
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		s.fail(w, err)
		return
	}
	if d.Evidence, err = s.st.ListEvidence(ctx, tenant, store.EvidenceFilter{SessionID: id, Limit: 200}); err != nil {
		s.fail(w, err)
		return
	}
	d.Leaks = leakOf(d.Evidence)
	d.Decoys = decoysOf(d.Evidence)
	if d.Gameplay, err = s.st.ListGameplaySummaries(ctx, tenant, store.GameplayFilter{SessionID: id, Limit: 50}); err != nil {
		s.fail(w, err)
		return
	}
	if d.Oracle, err = s.oracleFor(ctx, tenant, sess, d.Evidence); err != nil {
		s.fail(w, err)
		return
	}
	lv, err := s.labelFor(r, tenant, sess, d.Evidence)
	if err != nil {
		s.fail(w, err)
		return
	}
	d.Label = labelCard{View: lv, CSRF: s.csrfToken(r), SessionID: id}
	s.render(w, http.StatusOK, "session", page{Title: "Session " + short(id), Nav: "sessions", Tenant: tenant, Data: d})
}

type playersData struct {
	All  bool
	Rows []store.PlayerRow
}

func (s *Server) players(w http.ResponseWriter, r *http.Request, tenant string) {
	all := r.URL.Query().Get("all") == "1"
	rows, err := s.st.ListPlayers(r.Context(), tenant, store.PlayerFilter{FlaggedOnly: !all, Limit: 200})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "players", page{Title: "Players", Nav: "players", Tenant: tenant, Data: playersData{all, rows}})
}

type playerData struct {
	Row      store.PlayerRow
	Sessions []store.SessionRow
	Evidence []store.Evidence
	Oracle   *playerOracle
}

func (s *Server) player(w http.ResponseWriter, r *http.Request, tenant string) {
	ctx := r.Context()
	hash := r.PathValue("hash")
	sess, err := s.st.ListSessions(ctx, tenant, store.SessionFilter{PlayerHash: hash, Limit: 100})
	if err != nil {
		s.fail(w, err)
		return
	}
	evs, err := s.st.ListEvidence(ctx, tenant, store.EvidenceFilter{PlayerHash: hash, Limit: 200})
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(sess) == 0 && len(evs) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	row := store.PlayerRow{PlayerHash: hash, Sessions: len(sess), MaxSeverity: -1}
	if len(sess) > 0 {
		row.TrustLevel, row.LastSeen = sess[0].TrustLevel, sess[0].CreatedAt
	}
	bots := 0
	for _, e := range evs {
		if e.Severity <= 0 {
			continue
		}
		row.EvidenceCount++
		if e.Bot {
			bots++
		} else {
			row.Risk += store.RiskWeight[min(e.Severity, len(store.RiskWeight)-1)] * e.Score
		}
		row.MaxSeverity = max(row.MaxSeverity, e.Severity)
		if e.Integrity {
			row.Integrity++
		}
	}
	row.Bot = len(sess) == 0 && bots > 0 && bots == row.EvidenceCount
	po, err := s.playerOracleFor(ctx, tenant, hash)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "player", page{Title: "Player " + short(hash), Nav: "players", Tenant: tenant, Data: playerData{row, sess, evs, po}})
}

func (s *Server) evidence(w http.ResponseWriter, r *http.Request, tenant string) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	e, err := s.st.GetEvidence(r.Context(), tenant, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "evidence", page{Title: "Evidence #" + strconv.FormatInt(id, 10), Nav: "players", Tenant: tenant, Data: e})
}

var trustNames = [...]string{"Software", "TPM key", "Attested", "Ranked boot"}

func trustName(l uint32) string {
	if int(l) < len(trustNames) {
		return trustNames[l]
	}
	return "Unknown"
}

func trustDesc(l uint32) string {
	switch l {
	case protocol.TrustSoftware:
		return "software device key, no TPM"
	case protocol.TrustTPMKey:
		return "TPM key claimed, attestation missing or failed"
	case protocol.TrustAttested:
		return "TPM-resident key, AK bound to EK, quote verified"
	case protocol.TrustRankedBoot:
		return "attested, and the boot state meets the ranked policy"
	}
	return ""
}

var sevNames = [...]string{"info", "low", "medium", "high", "critical"}

func sevName(s int) string {
	if s >= 0 && s < len(sevNames) {
		return sevNames[s]
	}
	return "none"
}

func tier(risk float64) string {
	switch {
	case risk >= 8:
		return "review"
	case risk >= store.FlaggedRisk:
		return "watch"
	}
	return "clear"
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

func pct(f float64) string { return strconv.FormatFloat(f*100, 'f', 2, 64) + "%" }

func ago(now, t time.Time) string {
	if t.IsZero() || t.Unix() <= 0 {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < 0:
		return "just now"
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s ago"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m ago"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h ago"
	}
	return strconv.Itoa(int(d.Hours()/24)) + "d ago"
}

var flagNames = []struct {
	bit  uint64
	name string
}{
	{protocol.FlagTPMDeviceKey, "TPM device key"}, {protocol.FlagDeviceKeyCertified, "key certified"}, {protocol.FlagAKBoundToEK, "AK bound to EK"},
	{protocol.FlagQuoteVerified, "quote verified"}, {protocol.FlagSecureBoot, "Secure Boot"}, {protocol.FlagHVCI, "HVCI"},
	{protocol.FlagTestSigningOff, "test signing off"}, {protocol.FlagKernelDebugOff, "kernel debug off"}, {protocol.FlagBootDebugOff, "boot debug off"},
	{protocol.FlagCodeIntegrity, "code integrity"}, {protocol.FlagEKCertMatches, "EK cert matches"}, {protocol.FlagEKChainVerified, "EK chain verified"},
}

func attestFlags(f uint64) []string {
	var out []string
	for _, n := range flagNames {
		if f&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

// mitigations names carthago-harden's applied/failed bits.
func mitigations(bits uint64) []string {
	names := []string{"no remote images", "no low-label images", "System32 images first", "extension points disabled"}
	var out []string
	for i, n := range names {
		if bits&(1<<i) != 0 {
			out = append(out, n)
		}
	}
	return out
}

func prettyJSON(s string) string {
	if s == "" {
		return ""
	}
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return s
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

type barSeg struct {
	Level   int
	Name    string
	Count   int
	X, W    float64
	Percent string
}

// trustBar lays the trust-level distribution out as SVG rectangles (percent widths), which
// renders under the CSP without inline styles.
func trustBar(levels [4]int) []barSeg {
	total := 0
	for _, n := range levels {
		total += n
	}
	var out []barSeg
	x := 0.0
	for lvl, n := range levels {
		w := 0.0
		if total > 0 {
			w = 100 * float64(n) / float64(total)
		}
		out = append(out, barSeg{Level: lvl, Name: trustNames[lvl], Count: n, X: x, W: w, Percent: strconv.FormatFloat(math.Round(w), 'f', 0, 64) + "%"})
		x += w
	}
	return out
}
