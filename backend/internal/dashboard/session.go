package dashboard

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"carthago/backend/internal/store"
)

// AuthConfig is how people sign in to the dashboard. The zero value is the strict one: no
// shared-key login, a 12 hour session, 30 minutes of idle time.
type AuthConfig struct {
	// Loopback: the dashboard's listener is on a loopback address. The shared studio keys
	// in Config.Keys sign in only then, only from this machine, and only for a studio that
	// has no user accounts yet.
	Loopback bool
	// SecretKey (32 bytes or more) seals two-factor secrets and keys the recovery-code
	// hashes. It must stay the same across restarts, and belongs next to the database.
	// When empty a random key is used for the life of the process, which suits tests and
	// the in-memory store only.
	SecretKey []byte
	// SessionTTL ends a session this long after sign-in, whatever happens (default 12 h).
	SessionTTL time.Duration
	// IdleTimeout ends a session that made no request for this long (default 30 min).
	IdleTimeout time.Duration
	// TrustedProxies are the reverse proxies whose X-Forwarded-For header names the real
	// client. Without them the address in rate limits and the audit log is the peer's.
	TrustedProxies []netip.Prefix
	// DataDir is the gateway's data directory, shown in the command that creates the
	// first admin so it can be copied as it stands. Display only.
	DataDir string
}

const (
	cookieName    = "cw_session"
	preCookieName = "cw_pre"
	// On HTTPS the cookies take the __Host- prefix: the browser then accepts them only
	// from this exact host, over TLS, for the whole site, so a sibling subdomain cannot
	// plant one.
	hostPrefix = "__Host-"

	defaultSessionTTL = 12 * time.Hour
	defaultIdleTTL    = 30 * time.Minute
	// A sign-in that still waits for its two-factor code, or for enrolment, is short.
	codeSessionTTL  = 5 * time.Minute
	enrolSessionTTL = 15 * time.Minute
	// lastSeenStep: how stale a session's last-seen time may get before it is written.
	lastSeenStep = time.Minute
	tokenBytes   = 32
)

// authState is the sign-in half of the Server.
type authState struct {
	au         store.AuthStore
	loopback   bool
	box        *secretBox
	sessionTTL time.Duration
	idleTTL    time.Duration
	proxies    []netip.Prefix
	dataDir    string
	argon      argonParams
	// hashing bounds how many password hashes run at once: each takes argon.MemoryKiB.
	hashing chan struct{}
	// adminMu makes "check the actor is still an admin, then change a user" one step.
	adminMu sync.Mutex

	mu        sync.Mutex
	dummy     string // a hash nobody's password matches, for sign-ins to unknown accounts
	dummyFor  argonParams
	lastPrune time.Time
}

func (s *Server) initAuth(st Store) error {
	au, ok := st.(store.AuthStore)
	if !ok {
		return errors.New("dashboard: the store does not keep user accounts")
	}
	s.au = au
	s.argon = defaultArgon
	s.hashing = make(chan struct{}, 4)
	return s.ConfigureAuth(AuthConfig{})
}

// ConfigureAuth sets how people sign in. Call it before Handler.
func (s *Server) ConfigureAuth(c AuthConfig) error {
	key := c.SecretKey
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
	}
	box, err := newSecretBox(key)
	if err != nil {
		return err
	}
	s.box, s.loopback, s.proxies, s.dataDir = box, c.Loopback, c.TrustedProxies, c.DataDir
	s.sessionTTL, s.idleTTL = c.SessionTTL, c.IdleTimeout
	if s.sessionTTL <= 0 {
		s.sessionTTL = defaultSessionTTL
	}
	if s.idleTTL <= 0 {
		s.idleTTL = defaultIdleTTL
	}
	return nil
}

func (s *Server) cookie() string {
	if s.secureCookie {
		return hostPrefix + cookieName
	}
	return cookieName
}

func (s *Server) preCookie() string {
	if s.secureCookie {
		return hostPrefix + preCookieName
	}
	return preCookieName
}

func newToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken is how a session or link token is stored: someone who reads the database
// cannot turn a row back into a cookie or a link.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// startSession signs the browser in as userID (0 for the demo login) and returns the new
// cookie value. Whatever session the browser came with is ended first, so a session id
// never survives a sign-in, a completed second factor or a change of password.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, tenant string, userID int64, kind string) (string, error) {
	ctx := r.Context()
	if c, err := r.Cookie(s.cookie()); err == nil && c.Value != "" {
		_ = s.au.DeleteDashSession(ctx, hashToken(c.Value))
	}
	token, err := newToken()
	if err != nil {
		return "", err
	}
	now := s.now()
	ttl := s.sessionTTL
	switch kind {
	case store.DashSessionCode:
		ttl = codeSessionTTL
	case store.DashSessionEnrol:
		ttl = enrolSessionTTL
	}
	row := &store.DashSession{IDHash: hashToken(token), TenantID: tenant, UserID: userID, Kind: kind, CreatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(ttl), IP: s.clientIP(r), UserAgent: cleanLine(r.UserAgent(), 200)}
	if err := s.au.PutDashSession(ctx, row); err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookie(), Value: token, Path: "/", Expires: row.ExpiresAt,
		HttpOnly: true, Secure: s.secureCookie, SameSite: http.SameSiteStrictMode})
	if st := stateOf(r); st != nil {
		// The rest of this request (its page, its form token) belongs to the new session.
		st.token, st.sess = token, row
	}
	s.prune(r)
	return token, nil
}

func (s *Server) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: s.cookie(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookie, SameSite: http.SameSiteStrictMode})
}

// prune drops expired sessions from the store now and then.
func (s *Server) prune(r *http.Request) {
	now := s.now()
	s.mu.Lock()
	due := now.Sub(s.lastPrune) > 10*time.Minute
	if due {
		s.lastPrune = now
	}
	s.mu.Unlock()
	if due {
		if err := s.au.PruneDashSessions(r.Context(), now); err != nil {
			s.log.Warn("dashboard session prune", "err", err)
		}
	}
}

// resolve finds the session a request's cookie names and the account behind it. The
// account is read on every request, so a role change, a disabled account or a revoked
// session takes effect on the next click.
func (s *Server) resolve(r *http.Request) (*reqState, bool) {
	c, err := r.Cookie(s.cookie())
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return nil, false
	}
	ctx, now := r.Context(), s.now()
	idHash := hashToken(c.Value)
	row, err := s.au.GetDashSession(ctx, idHash)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("dashboard session lookup", "err", err)
		}
		return nil, false
	}
	end := func() (*reqState, bool) {
		_ = s.au.DeleteDashSession(ctx, idHash)
		return nil, false
	}
	if !now.Before(row.ExpiresAt) || now.Sub(row.LastSeenAt) > s.idleTTL {
		return end()
	}
	st := &reqState{sess: row, token: c.Value}
	if row.UserID == 0 {
		// The demo login is checked again on every request: it ends the moment the studio
		// gets its first account, or the request stops being local.
		if !s.demoAllowed(r, row.TenantID) {
			return end()
		}
		st.viewer = Viewer{Tenant: row.TenantID, Name: "demo", Role: RoleReviewer, Demo: true}
	} else {
		u, err := s.au.GetDashUser(ctx, row.TenantID, row.UserID)
		if err != nil || u.Disabled || roleOf(u.Role) == RoleNone {
			return end()
		}
		st.user = u
		st.viewer = Viewer{Tenant: u.TenantID, UserID: u.ID, Name: u.Name, Role: roleOf(u.Role), TwoFactor: len(u.TOTPSecret) > 0}
		if row.Kind == store.DashSessionFull && !st.viewer.TwoFactor {
			set, err := s.au.GetTenantSettings(ctx, u.TenantID)
			if err != nil {
				s.log.Error("dashboard tenant settings", "err", err)
				return nil, false
			}
			st.mustEnrol = set.RequireTOTP
		}
	}
	if now.Sub(row.LastSeenAt) >= lastSeenStep {
		if err := s.au.TouchDashSession(ctx, idHash, now); err != nil {
			s.log.Warn("dashboard session touch", "err", err)
		}
		row.LastSeenAt = now
	}
	return st, true
}

// csrfFor derives a form token from a cookie value. Only the browser that holds the cookie
// (and this server) can compute it, and it changes whenever the session does.
func csrfFor(cookieValue string) string {
	if cookieValue == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("cw-csrf\x00" + cookieValue))
	return hex.EncodeToString(sum[:16])
}

func tokenMatches(want, got string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// csrfToken is the token a signed-in page puts in its forms, in a hidden field named csrf.
func (s *Server) csrfToken(r *http.Request) string {
	c, err := r.Cookie(s.cookie())
	if err != nil {
		return ""
	}
	return csrfFor(c.Value)
}

// csrfOK checks the csrf field of a submitted form against the session it came with.
func (s *Server) csrfOK(r *http.Request) bool {
	return tokenMatches(s.csrfToken(r), r.PostFormValue("csrf"))
}

// preToken is the CSRF token for forms shown before anyone is signed in (the account
// sign-in and the invite page). It is tied to a short-lived cookie set with the page, so
// another site can neither read the token nor make the browser send a matching pair.
func (s *Server) preToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(s.preCookie()); err == nil && len(c.Value) >= 32 && len(c.Value) <= 128 {
		return csrfFor(c.Value)
	}
	v, err := newToken()
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{Name: s.preCookie(), Value: v, Path: "/", MaxAge: 3600, HttpOnly: true, Secure: s.secureCookie, SameSite: http.SameSiteStrictMode})
	return csrfFor(v)
}

func (s *Server) preOK(r *http.Request) bool {
	c, err := r.Cookie(s.preCookie())
	if err != nil || len(c.Value) < 32 {
		return false
	}
	return tokenMatches(csrfFor(c.Value), r.PostFormValue("csrf"))
}

// sameOrigin rejects cross-site form posts. SameSite=Strict already keeps the cookie off
// them and every form carries a token; this is the third check, and the only one the demo
// key form has.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	if o := r.Header.Get("Origin"); o != "" {
		return o == "http://"+r.Host || o == "https://"+r.Host
	}
	return true
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) trustedProxy(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP is the address sign-in limits and the audit log use. Behind a configured
// reverse proxy it is the last X-Forwarded-For entry that is not itself such a proxy;
// otherwise the header is ignored, since anyone can send it.
func (s *Server) clientIP(r *http.Request) string {
	host := remoteHost(r)
	if len(s.proxies) == 0 {
		return host
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !s.trustedProxy(peer) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if !s.trustedProxy(a) {
			return a.Unmap().String()
		}
	}
	return host
}

// localRequest: the request came from this machine straight to a loopback listener, under
// a loopback name. A reverse proxy on the same machine also connects from 127.0.0.1, so
// any forwarding header disqualifies the request.
func (s *Server) localRequest(r *http.Request) bool {
	if !s.loopback {
		return false
	}
	peer, err := netip.ParseAddr(remoteHost(r))
	if err != nil || !peer.Unmap().IsLoopback() {
		return false
	}
	for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip", "Forwarded", "Via"} {
		if r.Header.Get(h) != "" {
			return false
		}
	}
	host := r.Host
	if hn, _, err := net.SplitHostPort(host); err == nil {
		host = hn
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback()
}

// demoAllowed: the shared studio key may sign in for tenant on this request. It is a
// local testing aid: loopback only, and off for good once the studio has an account.
func (s *Server) demoAllowed(r *http.Request, tenant string) bool {
	if s.keys[tenant] == "" || !s.localRequest(r) {
		return false
	}
	n, err := s.au.CountDashUsers(r.Context(), tenant)
	if err != nil {
		s.log.Error("dashboard user count", "err", err)
		return false
	}
	return n == 0
}

// demoOffered: whether to show the demo block on the sign-in page at all.
func (s *Server) demoOffered(r *http.Request) bool {
	for tenant := range s.keys {
		if s.demoAllowed(r, tenant) {
			return true
		}
	}
	return false
}

// checkKey compares in constant time against every tenant so timing does not reveal which
// tenant ids exist. Both sides are hashed first, so the comparison time does not depend on
// the length of the stored key either.
func (s *Server) checkKey(tenant, key string) bool {
	gotKey, gotTenant := sha256.Sum256([]byte(key)), sha256.Sum256([]byte(tenant))
	ok := 0
	for t, k := range s.keys {
		wantKey, wantTenant := sha256.Sum256([]byte(k)), sha256.Sum256([]byte(t))
		ok |= subtle.ConstantTimeCompare(wantKey[:], gotKey[:]) & subtle.ConstantTimeCompare(wantTenant[:], gotTenant[:])
	}
	return ok == 1 && key != ""
}

// cleanLine makes text from a request safe to store and show on one line: no control
// characters, valid UTF-8, at most max bytes.
func cleanLine(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, " "))
	s = strings.Join(strings.Fields(s), " ")
	for len(s) > max {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}
