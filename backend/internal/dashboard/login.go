package dashboard

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"carthago/backend/internal/store"
)

type loginData struct {
	Error  string
	Notice string
	// Demo: this request may use the shared studio key, so the page offers it.
	Demo   bool
	Tenant string
	User   string
}

// Every failed account sign-in gets this one message, whatever was wrong: an unknown
// studio, an unknown user, a wrong password or a disabled account.
const (
	msgBadLogin = "Wrong studio, user name or password"
	msgBadKey   = "Unknown studio or key"
	msgTooMany  = "Too many failed attempts. Try again in a few minutes."
	msgExpired  = "That page was open too long. Try again"
)

var loginNotices = map[string]string{
	"created":   "Account created, sign in to continue",
	"password":  "Password set, sign in to continue",
	"signedout": "Signed out everywhere",
}

// userNameRE: 3 to 32 of a-z, 0-9, dot, dash and underscore, starting with a letter or digit.
var userNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)

func normName(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func (s *Server) authRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login/code", s.stage(s.codePage, store.DashSessionCode))
	mux.HandleFunc("POST /login/code", s.stage(s.loginCode, store.DashSessionCode))
	mux.HandleFunc("GET /invite/{token}", s.invitePage)
	mux.HandleFunc("POST /invite/{token}", s.inviteAccept)

	mux.HandleFunc("GET /account", s.require(RoleReadOnly, s.account))
	mux.HandleFunc("POST /account/password", s.require(RoleReadOnly, s.changePassword))
	mux.HandleFunc("POST /account/sessions/revoke", s.require(RoleReadOnly, s.revokeOwnSession))
	mux.HandleFunc("POST /logout/everywhere", s.require(RoleReadOnly, s.logoutEverywhere))
	mux.HandleFunc("GET /account/two-factor/setup", s.stage(s.setupPage, store.DashSessionFull, store.DashSessionEnrol))
	mux.HandleFunc("POST /account/two-factor/setup", s.stage(s.setupConfirm, store.DashSessionFull, store.DashSessionEnrol))
	mux.HandleFunc("POST /account/two-factor/disable", s.require(RoleReadOnly, s.disableTwoFactor))
	mux.HandleFunc("POST /account/recovery-codes", s.require(RoleReadOnly, s.regenerateRecovery))

	mux.HandleFunc("GET /users", s.require(RoleAdmin, s.users))
	mux.HandleFunc("POST /users/invite", s.require(RoleAdmin, s.inviteUser))
	mux.HandleFunc("POST /users/invites/revoke", s.require(RoleAdmin, s.revokeInvite))
	mux.HandleFunc("POST /users/require-two-factor", s.require(RoleAdmin, s.requireTwoFactor))
	mux.HandleFunc("GET /users/{id}", s.require(RoleAdmin, s.user))
	mux.HandleFunc("POST /users/{id}/{action}", s.require(RoleAdmin, s.userAction))
	mux.HandleFunc("GET /audit", s.require(RoleAdmin, s.auditPage))
}

// stage wraps the pages of a sign-in that is still under way. kinds are the session kinds
// it admits; any other session is sent to where it belongs.
func (s *Server) stage(h vhandler, kinds ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, ok := s.resolve(r)
		switch {
		case !ok:
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		case slices.Contains(kinds, st.sess.Kind):
			s.serve(w, r, st, RoleReadOnly, h)
		case st.sess.Kind == store.DashSessionCode:
			http.Redirect(w, r, "/login/code", http.StatusSeeOther)
		case st.sess.Kind == store.DashSessionEnrol:
			http.Redirect(w, r, "/account/two-factor/setup", http.StatusSeeOther)
		default:
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	}
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, d loginData) {
	d.Demo = s.demoOffered(r)
	s.render(w, status, "login", page{Title: "Sign in", Data: d, CSRF: s.preToken(w, r)})
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if st, ok := s.resolve(r); ok && st.sess.Kind == store.DashSessionFull {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderLogin(w, r, http.StatusOK, loginData{Notice: loginNotices[r.URL.Query().Get("ok")]})
}

// login takes both sign-in forms: the account form (studio, user, password) and the demo
// form (studio, key).
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-site request", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if _, key := r.PostForm["key"]; key {
		s.keyLogin(w, r)
		return
	}
	s.accountLogin(w, r)
}

// keyLogin is the demo login with the shared studio key. It has no form token so that the
// test scripts can post to it; it is open on loopback only and closes for a studio once
// that studio has an account (see demoAllowed).
func (s *Server) keyLogin(w http.ResponseWriter, r *http.Request) {
	tenant, key := strings.TrimSpace(r.PostFormValue("tenant")), r.PostFormValue("key")
	addr, acct, now := s.clientIP(r), accountKey(tenant, "\x00studio key"), s.now()
	if s.lim.blocked(addr, acct, now) {
		s.renderLogin(w, r, http.StatusTooManyRequests, loginData{Error: msgTooMany})
		return
	}
	if !s.checkKey(tenant, key) || !s.demoAllowed(r, tenant) {
		s.loginFailed(r, tenant, "studio key", addr, acct, "studio key refused")
		s.renderLogin(w, r, http.StatusUnauthorized, loginData{Error: msgBadKey})
		return
	}
	s.lim.succeeded(acct)
	if _, err := s.startSession(w, r, tenant, 0, store.DashSessionFull); err != nil {
		s.fail(w, err)
		return
	}
	s.log.Info("dashboard demo login", "remote", addr, "tenant", tenant)
	s.auditAs(r, tenant, 0, "demo", "login.demo", "", "shared studio key")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// loginFailed counts a failed attempt and records it. Only a studio that exists gets an
// audit entry; an attempt on a made-up studio name goes to the gateway log.
func (s *Server) loginFailed(r *http.Request, tenant, name, addr string, acct acctKey, why string) (locked bool) {
	lock := s.lim.failed(addr, acct, s.now())
	s.log.Warn("dashboard login failed", "remote", addr, "tenant", cleanLine(tenant, 64), "user", cleanLine(name, 64), "why", why, "locked_for", lock)
	if !s.tenantKnown(r.Context(), tenant) {
		return lock > 0
	}
	s.auditAs(r, tenant, 0, cleanLine(name, 64), "login.fail", "", why)
	if lock > 0 {
		s.auditAs(r, tenant, 0, cleanLine(name, 64), "login.lock", "", "sign-in locked for "+lock.String()+" after repeated failures")
	}
	return lock > 0
}

func (s *Server) tenantKnown(ctx context.Context, tenant string) bool {
	if tenant == "" || len(tenant) > 128 {
		return false
	}
	if s.keys[tenant] != "" {
		return true
	}
	n, err := s.au.CountDashUsers(ctx, tenant)
	return err == nil && n > 0
}

// checkPasswordHash verifies with at most cap(s.hashing) hashes running at once.
func (s *Server) checkPasswordHash(ctx context.Context, hash, pw string) (bool, argonParams) {
	select {
	case s.hashing <- struct{}{}:
		defer func() { <-s.hashing }()
	case <-ctx.Done():
		return false, argonParams{}
	}
	return verifyPassword(hash, pw)
}

func (s *Server) newPasswordHash(ctx context.Context, pw string) (string, error) {
	select {
	case s.hashing <- struct{}{}:
		defer func() { <-s.hashing }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	return hashPassword(pw, s.argon)
}

// dummyHash is verified when the account does not exist, so that attempt takes as long as
// one against a real account.
func (s *Server) dummyHash() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dummy == "" || s.dummyFor != s.argon {
		pw, err := newToken()
		if err != nil {
			return ""
		}
		h, err := hashPassword(pw, s.argon)
		if err != nil {
			return ""
		}
		s.dummy, s.dummyFor = h, s.argon
	}
	return s.dummy
}

func (s *Server) accountLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant, name, pw := strings.TrimSpace(r.PostFormValue("tenant")), normName(r.PostFormValue("user")), r.PostFormValue("password")
	back := loginData{Tenant: cleanLine(tenant, 64), User: cleanLine(name, 32)}
	if !s.preOK(r) {
		back.Error = msgExpired
		s.renderLogin(w, r, http.StatusForbidden, back)
		return
	}
	addr, acct := s.clientIP(r), accountKey(tenant, name)
	if s.lim.blocked(addr, acct, s.now()) {
		back.Error = msgTooMany
		s.renderLogin(w, r, http.StatusTooManyRequests, back)
		return
	}
	var u *store.DashUser
	hash, why := s.dummyHash(), "no such account"
	if userNameRE.MatchString(name) && tenant != "" {
		found, err := s.au.GetDashUserByName(ctx, tenant, name)
		switch {
		case err == nil:
			u, hash, why = found, found.PasswordHash, "wrong password"
		case !errors.Is(err, store.ErrNotFound):
			s.fail(w, err)
			return
		}
	}
	ok, params := s.checkPasswordHash(ctx, hash, pw)
	if u != nil && ok && u.Disabled {
		why = "account disabled"
	}
	if u == nil || !ok || u.Disabled {
		s.loginFailed(r, tenant, name, addr, acct, why)
		back.Error = msgBadLogin
		s.renderLogin(w, r, http.StatusUnauthorized, back)
		return
	}
	s.lim.succeeded(acct)
	if params != s.argon {
		// The cost settings changed since this hash was made: replace it now that the
		// password is at hand. PasswordChangedAt stays, the password did not change.
		if h, err := s.newPasswordHash(ctx, pw); err == nil {
			_ = s.au.UpdateDashUser(ctx, u.TenantID, u.ID, store.DashUserChange{PasswordHash: &h, PasswordChangedAt: u.PasswordChangedAt})
		}
	}
	set, err := s.au.GetTenantSettings(ctx, u.TenantID)
	if err != nil {
		s.fail(w, err)
		return
	}
	switch {
	case len(u.TOTPSecret) > 0:
		if _, err := s.startSession(w, r, u.TenantID, u.ID, store.DashSessionCode); err != nil {
			s.fail(w, err)
			return
		}
		http.Redirect(w, r, "/login/code", http.StatusSeeOther)
	case set.RequireTOTP:
		if _, err := s.startSession(w, r, u.TenantID, u.ID, store.DashSessionEnrol); err != nil {
			s.fail(w, err)
			return
		}
		http.Redirect(w, r, "/account/two-factor/setup", http.StatusSeeOther)
	default:
		s.completeLogin(w, r, u, "password", "/")
	}
}

// completeLogin turns a checked sign-in into a full session.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, u *store.DashUser, how, next string) {
	if _, err := s.startSession(w, r, u.TenantID, u.ID, store.DashSessionFull); err != nil {
		s.fail(w, err)
		return
	}
	now := s.now()
	if err := s.au.UpdateDashUser(r.Context(), u.TenantID, u.ID, store.DashUserChange{LastLoginAt: &now}); err != nil {
		s.log.Warn("dashboard last login", "err", err)
	}
	s.log.Info("dashboard login", "remote", s.clientIP(r), "tenant", u.TenantID, "user", u.Name)
	s.auditAs(r, u.TenantID, u.ID, u.Name, "login.ok", "", how)
	if next != "" {
		http.Redirect(w, r, next, http.StatusSeeOther)
	}
}

type codeData struct {
	Error string
	Name  string
}

func (s *Server) codePage(w http.ResponseWriter, r *http.Request, v Viewer) {
	s.render(w, http.StatusOK, "code", page{Title: "Two-factor code", Data: codeData{Name: v.Name}})
}

// secondFactor checks an authenticator code or a recovery code for u. An authenticator
// code is accepted once: its time step is recorded, and that step or an older one is
// refused afterwards.
func (s *Server) secondFactor(ctx context.Context, u *store.DashUser, input string) (how string, ok bool) {
	if looksLikeRecoveryCode(input) {
		used, err := s.au.UseRecoveryCode(ctx, u.ID, s.box.recoveryHash(u.ID, input))
		return "recovery code", err == nil && used
	}
	secret, err := s.box.open(u.TOTPSecret, totpSealName(u.TenantID, u.ID))
	if err != nil {
		s.log.Error("dashboard two-factor secret does not open; was the dashboard key file replaced?", "tenant", u.TenantID, "user", u.Name)
		return "", false
	}
	step, ok := totpVerify(secret, input, s.now())
	if !ok {
		return "", false
	}
	fresh, err := s.au.AdvanceTOTPStep(ctx, u.ID, step)
	return "authenticator code", err == nil && fresh
}

func (s *Server) loginCode(w http.ResponseWriter, r *http.Request, v Viewer) {
	st := stateOf(r)
	st.audited = true // this handler writes its own entries
	u := st.user
	addr, acct := s.clientIP(r), accountKey(u.TenantID, u.Name)
	end := func() {
		_ = s.au.DeleteDashSession(r.Context(), st.sess.IDHash)
		s.clearSession(w)
		s.renderLogin(w, r, http.StatusTooManyRequests, loginData{Error: msgTooMany})
	}
	if s.lim.blocked(addr, acct, s.now()) {
		end()
		return
	}
	how, ok := s.secondFactor(r.Context(), u, r.PostFormValue("code"))
	if !ok {
		if s.loginFailed(r, u.TenantID, u.Name, addr, acct, "wrong two-factor code") {
			end()
			return
		}
		s.render(w, http.StatusUnauthorized, "code", page{Title: "Two-factor code", Data: codeData{Name: u.Name, Error: "That code did not match"}})
		return
	}
	s.lim.succeeded(acct)
	next := "/"
	if how == "recovery code" {
		s.auditAs(r, u.TenantID, u.ID, u.Name, "recovery.use", u.Name, "signed in with a recovery code")
		next = "/account?ok=recovery"
	}
	s.completeLogin(w, r, u, "password and "+how, next)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-site request", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if st, ok := s.resolve(r); ok {
		if !s.csrfOK(r) {
			http.Error(w, "cross-site request, or a form from a session that has ended; reload the page and try again", http.StatusForbidden)
			return
		}
		if err := s.au.DeleteDashSession(r.Context(), st.sess.IDHash); err != nil {
			s.fail(w, err)
			return
		}
		if st.sess.Kind == store.DashSessionFull {
			s.auditAs(r, st.viewer.Tenant, st.viewer.UserID, st.viewer.Name, "logout", "", "")
		}
	}
	s.clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// confirmPassword checks the current password on a form that changes how the account
// signs in. Wrong guesses count like failed sign-ins, so a stolen session cannot be used to
// try passwords without limit.
func (s *Server) confirmPassword(r *http.Request, u *store.DashUser, pw string) (ok bool, msg string) {
	addr, acct := s.clientIP(r), accountKey(u.TenantID, u.Name)
	if s.lim.blocked(addr, acct, s.now()) {
		return false, msgTooMany
	}
	if good, _ := s.checkPasswordHash(r.Context(), u.PasswordHash, pw); !good {
		s.loginFailed(r, u.TenantID, u.Name, addr, acct, "wrong current password on an account form")
		return false, "The current password is wrong"
	}
	s.lim.succeeded(acct)
	return true, ""
}
