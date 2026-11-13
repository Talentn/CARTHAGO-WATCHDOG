package dashboard

import (
	"context"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"carthago/backend/internal/store"
)

// Role is what a signed-in person may do in their studio's dashboard. Roles are ordered:
// each one can do everything the one before it can.
type Role int

const (
	RoleNone     Role = iota
	RoleReadOnly      // sees every page of the studio
	RoleReviewer      // also acts on what the pages show, such as labelling a session
	RoleAdmin         // also manages users and sign-in rules, and reads the audit log
)

var roleKeys = [...]string{RoleReadOnly: store.RoleReadOnly, RoleReviewer: store.RoleReviewer, RoleAdmin: store.RoleAdmin}
var roleLabels = [...]string{RoleNone: "No access", RoleReadOnly: "Read-only", RoleReviewer: "Reviewer", RoleAdmin: "Admin"}

// roleOf reads a stored role; anything unknown is no access.
func roleOf(key string) Role {
	for r, k := range roleKeys {
		if k == key && k != "" {
			return Role(r)
		}
	}
	return RoleNone
}

// Key is the role as it is stored and submitted in forms.
func (r Role) Key() string {
	if r > RoleNone && int(r) < len(roleKeys) {
		return roleKeys[r]
	}
	return ""
}

// Label is the role as pages show it.
func (r Role) Label() string {
	if r >= 0 && int(r) < len(roleLabels) {
		return roleLabels[r]
	}
	return roleLabels[RoleNone]
}

// Viewer is the person a request is signed in as.
type Viewer struct {
	// Tenant is the studio every query for this request is scoped to.
	Tenant string
	// UserID is the account's id; 0 for the demo login, which has no account.
	UserID int64
	Name   string
	Role   Role
	// Demo: signed in with the shared studio key (loopback only, while the studio has no
	// accounts), not as a person.
	Demo bool
	// TwoFactor: the account has an authenticator app enrolled.
	TwoFactor bool
}

// Can reports whether the viewer holds at least the role min.
func (v Viewer) Can(min Role) bool { return min > RoleNone && v.Role >= min }

func (v Viewer) Admin() bool    { return v.Can(RoleAdmin) }
func (v Viewer) Reviewer() bool { return v.Can(RoleReviewer) }

// reqState is what the sign-in check learned about a request, kept for its handler.
type reqState struct {
	viewer Viewer
	sess   *store.DashSession
	user   *store.DashUser // nil for the demo login
	token  string          // the session cookie's value
	// mustEnrol: the studio requires two-factor sign-in and this account has none yet.
	mustEnrol bool
	audited   bool
}

type stateKey struct{}

func stateOf(r *http.Request) *reqState {
	st, _ := r.Context().Value(stateKey{}).(*reqState)
	return st
}

// CurrentViewer returns who is signed in on r and with which role. It is the one place a
// dashboard feature asks "who is this and what may they do":
//
//	v, ok := s.CurrentViewer(r)
//	if !ok || !v.Can(RoleReviewer) { ... }
//
// Inside a handler registered through auth or require it costs nothing; elsewhere it
// checks the session cookie against the store. A sign-in that still waits for its
// two-factor code is not signed in.
func (s *Server) CurrentViewer(r *http.Request) (Viewer, bool) {
	if st := stateOf(r); st != nil {
		return st.viewer, true
	}
	st, ok := s.resolve(r)
	if !ok || st.sess.Kind != store.DashSessionFull || st.mustEnrol {
		return Viewer{}, false
	}
	return st.viewer, true
}

type handler func(w http.ResponseWriter, r *http.Request, tenant string)

// vhandler is a handler that wants the viewer, not only the tenant.
type vhandler func(w http.ResponseWriter, r *http.Request, v Viewer)

// auth wraps a page or action of the studio view. Reading needs any signed-in role. A
// request that changes something (any method but GET and HEAD) needs the reviewer role,
// the form's CSRF token and the same origin, so a route registered without further thought
// is closed to read-only users and to other sites.
func (s *Server) auth(h handler) http.HandlerFunc {
	return s.guard(RoleNone, func(w http.ResponseWriter, r *http.Request, v Viewer) { h(w, r, v.Tenant) })
}

// require is auth with an explicit minimum role.
func (s *Server) require(min Role, h vhandler) http.HandlerFunc { return s.guard(min, h) }

func safeMethod(m string) bool { return m == http.MethodGet || m == http.MethodHead }

// maxFormBytes bounds the body of any dashboard form.
const maxFormBytes = 16 << 10

func (s *Server) guard(min Role, h vhandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, ok := s.resolve(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		switch {
		case st.sess.Kind == store.DashSessionCode:
			http.Redirect(w, r, "/login/code", http.StatusSeeOther)
			return
		case st.sess.Kind == store.DashSessionEnrol || st.mustEnrol:
			http.Redirect(w, r, "/account/two-factor/setup", http.StatusSeeOther)
			return
		}
		s.serve(w, r, st, min, h)
	}
}

// serve runs h for a request whose session is already known: the CSRF and role checks,
// then the handler, then an audit entry if the request changed something and the handler
// recorded none itself.
func (s *Server) serve(w http.ResponseWriter, r *http.Request, st *reqState, min Role, h vhandler) {
	unsafe := !safeMethod(r.Method)
	if min == RoleNone {
		min = RoleReadOnly
		if unsafe {
			min = RoleReviewer
		}
	}
	r = r.WithContext(context.WithValue(r.Context(), stateKey{}, st))
	rw := &respWriter{ResponseWriter: w, st: st, status: http.StatusOK}
	if unsafe {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if !sameOrigin(r) || !s.csrfOK(r) {
			http.Error(w, "cross-site request, or a form from a session that has ended; reload the page and try again", http.StatusForbidden)
			return
		}
	}
	if !st.viewer.Can(min) {
		if unsafe {
			s.Audit(r, "access.denied", r.URL.Path, "needs the "+strings.ToLower(min.Label())+" role")
		}
		s.render(rw, http.StatusForbidden, "denied", page{Title: "Not allowed", Tenant: st.viewer.Tenant, Data: min.Label()})
		return
	}
	h(rw, r, st.viewer)
	if unsafe && !st.audited {
		outcome := "accepted"
		if rw.status >= 400 {
			outcome = "refused"
		}
		s.Audit(r, "request."+strings.ToLower(r.Method), r.URL.Path, outcome+" ("+strconv.Itoa(rw.status)+")")
	}
}

// respWriter carries the viewer to render, so every page gets the signed-in user, the role
// and the CSRF token without each handler passing them along.
type respWriter struct {
	http.ResponseWriter
	st     *reqState
	status int
	wrote  bool
}

func (w *respWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *respWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

type page struct {
	Title  string
	Nav    string
	Tenant string
	Data   any
	// Viewer and CSRF are filled in by render for signed-in pages. Forms that change
	// something carry CSRF in a hidden field named csrf.
	Viewer Viewer
	CSRF   string
}

func (s *Server) render(w http.ResponseWriter, status int, name string, p page) {
	t := s.pages[name]
	if t == nil {
		http.Error(w, "template missing", http.StatusInternalServerError)
		return
	}
	if rw, ok := w.(*respWriter); ok {
		p.Viewer = rw.st.viewer
		if p.CSRF == "" {
			p.CSRF = csrfFor(rw.st.token)
		}
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

// authFuncs are the template helpers of the account, users and audit pages.
func authFuncs() template.FuncMap {
	return template.FuncMap{
		"roleLabel": func(key string) string { return roleOf(key).Label() },
		"count":     plural,
	}
}
