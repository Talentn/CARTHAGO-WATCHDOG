package dashboard

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cookieName   = "cw_session"
	sessionTTL   = 12 * time.Hour
	maxFailures  = 5
	failureReset = 10 * time.Minute
)

// signCookie encodes tenant|expiry with an HMAC so the tenant id in the cookie cannot be
// changed by the browser. The secret is per process: restarting the gateway logs everyone out.
func (s *Server) signCookie(tenant string, exp time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(tenant)) + "." + strconv.FormatInt(exp.Unix(), 10)
	return payload + "." + base64.RawURLEncoding.EncodeToString(s.mac(payload))
}

func (s *Server) mac(payload string) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

func (s *Server) verifyCookie(v string) (string, bool) {
	i := strings.LastIndexByte(v, '.')
	if i < 0 {
		return "", false
	}
	payload, sig := v[:i], v[i+1:]
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(want, s.mac(payload)) {
		return "", false
	}
	t64, expS, ok := strings.Cut(payload, ".")
	if !ok {
		return "", false
	}
	exp, err := strconv.ParseInt(expS, 10, 64)
	if err != nil || s.now().Unix() >= exp {
		return "", false
	}
	tenant, err := base64.RawURLEncoding.DecodeString(t64)
	if err != nil {
		return "", false
	}
	if _, known := s.keys[string(tenant)]; !known {
		return "", false
	}
	return string(tenant), true
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

func (s *Server) tenantOf(r *http.Request) (string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	return s.verifyCookie(c.Value)
}

func (s *Server) setSession(w http.ResponseWriter, tenant string) {
	exp := s.now().Add(sessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: s.signCookie(tenant, exp), Path: "/", Expires: exp,
		HttpOnly: true, Secure: s.secureCookie, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookie, SameSite: http.SameSiteStrictMode})
}

// sameOrigin rejects cross-site form posts. SameSite=Strict already keeps the cookie off
// them; this also covers the login form itself (login CSRF).
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	if o := r.Header.Get("Origin"); o != "" {
		return o == "http://"+r.Host || o == "https://"+r.Host
	}
	return true
}

// limiter throttles failed logins per client IP.
type limiter struct {
	mu   sync.Mutex
	fail map[string]failures
}

type failures struct {
	n     int
	first time.Time
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (l *limiter) blocked(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.fail[ip]
	if ok && now.Sub(f.first) > failureReset {
		delete(l.fail, ip)
		return false
	}
	return ok && f.n >= maxFailures
}

func (l *limiter) failed(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail == nil {
		l.fail = map[string]failures{}
	}
	if len(l.fail) > 10_000 {
		for k, f := range l.fail {
			if now.Sub(f.first) > failureReset {
				delete(l.fail, k)
			}
		}
		// Still full of live entries (failures from very many addresses): start over
		// rather than grow without bound.
		if len(l.fail) > 10_000 {
			l.fail = map[string]failures{}
		}
	}
	f := l.fail[ip]
	if f.n == 0 {
		f.first = now
	}
	f.n++
	l.fail[ip] = f
}

func (l *limiter) reset(ip string) {
	l.mu.Lock()
	delete(l.fail, ip)
	l.mu.Unlock()
}
