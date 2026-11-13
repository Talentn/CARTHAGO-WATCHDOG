package dashboard

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"carthago/backend/internal/store"
)

type sessionLine struct {
	ID       string // the stored hash of the session id: it names the row, it is not the cookie
	Created  time.Time
	LastSeen time.Time
	IP       string
	Browser  string
	Current  bool
}

type accountData struct {
	Notice, Error string
	User          *store.DashUser // nil for the demo login
	// Required: the studio requires two-factor sign-in.
	Required bool
	Recovery int
	Sessions []sessionLine
	// IdleText and TTLText say when a session ends, in words.
	IdleText, TTLText string
}

// spanText writes a duration the way the pages say it: "30 minutes", "12 hours".
func spanText(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return plural(int(d/time.Hour), "hour", "hours")
	case d >= time.Minute:
		return plural(int(d.Round(time.Minute)/time.Minute), "minute", "minutes")
	}
	return plural(int(d/time.Second), "second", "seconds")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func accountNotice(key string, recoveryLeft int) string {
	switch key {
	case "password":
		return "Password changed. Other browsers were signed out"
	case "twofactor-off":
		return "Two-factor sign-in is off. Other browsers were signed out"
	case "session":
		return "That browser was signed out"
	case "recovery":
		return "You signed in with a recovery code. " + strconv.Itoa(recoveryLeft) + " left: make new ones if you are running low"
	}
	return ""
}

// browserName turns a User-Agent header into the two words a person recognises their
// browser by. The header is whatever the client sent, so this is a hint, not evidence.
func browserName(ua string) string {
	if ua == "" {
		return "Unknown browser"
	}
	has := func(s string) bool { return strings.Contains(ua, s) }
	name := "Browser"
	switch {
	case has("Edg/"):
		name = "Edge"
	case has("OPR/"):
		name = "Opera"
	case has("Firefox/"):
		name = "Firefox"
	case has("Chrome/"), has("Chromium/"):
		name = "Chrome"
	case has("Safari/"):
		name = "Safari"
	case has("curl/"):
		return "curl"
	}
	switch {
	case has("Windows"):
		return name + " on Windows"
	case has("Android"):
		return name + " on Android"
	case has("iPhone"), has("iPad"):
		return name + " on iOS"
	case has("Mac OS X"), has("Macintosh"):
		return name + " on macOS"
	case has("Linux"), has("X11"):
		return name + " on Linux"
	}
	return name
}

func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, status int, notice, errMsg string) {
	st := stateOf(r)
	ctx := r.Context()
	d := accountData{Error: errMsg, User: st.user, IdleText: spanText(s.idleTTL), TTLText: spanText(s.sessionTTL)}
	if u := st.user; u != nil {
		set, err := s.au.GetTenantSettings(ctx, u.TenantID)
		if err != nil {
			s.fail(w, err)
			return
		}
		d.Required = set.RequireTOTP
		if d.Recovery, err = s.au.CountRecoveryCodes(ctx, u.ID); err != nil {
			s.fail(w, err)
			return
		}
		rows, err := s.au.ListDashSessions(ctx, u.TenantID, u.ID, s.now())
		if err != nil {
			s.fail(w, err)
			return
		}
		for _, x := range rows {
			if x.Kind != store.DashSessionFull || s.now().Sub(x.LastSeenAt) > s.idleTTL {
				continue
			}
			d.Sessions = append(d.Sessions, sessionLine{ID: x.IDHash, Created: x.CreatedAt, LastSeen: x.LastSeenAt, IP: x.IP, Browser: browserName(x.UserAgent), Current: x.IDHash == st.sess.IDHash})
		}
	}
	d.Notice = accountNotice(notice, d.Recovery)
	s.render(w, status, "account", page{Title: "Account", Nav: "account", Tenant: st.viewer.Tenant, Data: d})
}

func (s *Server) account(w http.ResponseWriter, r *http.Request, _ Viewer) {
	s.renderAccount(w, r, http.StatusOK, r.URL.Query().Get("ok"), "")
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, v Viewer) {
	st := stateOf(r)
	u := st.user
	if u == nil {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	ctx := r.Context()
	cur, pw := r.PostFormValue("current"), r.PostFormValue("password")
	if ok, msg := s.confirmPassword(r, u, cur); !ok {
		s.renderAccount(w, r, http.StatusUnauthorized, "", msg)
		return
	}
	msg := checkPassword(pw, u.Name, u.TenantID)
	switch {
	case msg != "":
	case pw != r.PostFormValue("repeat"):
		msg = "The two new passwords are not the same"
	case pw == cur:
		msg = "The new password is the same as the current one"
	}
	if msg != "" {
		s.renderAccount(w, r, http.StatusBadRequest, "", msg)
		return
	}
	hash, err := s.newPasswordHash(ctx, pw)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.au.UpdateDashUser(ctx, u.TenantID, u.ID, store.DashUserChange{PasswordHash: &hash, PasswordChangedAt: s.now()}); err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "password.change", u.Name, "changed their own password")
	// Whoever knew the old password may still hold a session: end them all, and give this
	// browser a new one.
	if _, err := s.au.DeleteDashSessions(ctx, u.TenantID, u.ID, st.sess.IDHash); err != nil {
		s.fail(w, err)
		return
	}
	if _, err := s.startSession(w, r, u.TenantID, u.ID, store.DashSessionFull); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/account?ok=password", http.StatusSeeOther)
}

func (s *Server) revokeOwnSession(w http.ResponseWriter, r *http.Request, v Viewer) {
	st := stateOf(r)
	id := r.PostFormValue("id")
	if st.user == nil || id == st.sess.IDHash {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	// Only a session of this very account can be named: the list is read for the viewer's
	// tenant and user, and the id must be in it.
	rows, err := s.au.ListDashSessions(r.Context(), v.Tenant, v.UserID, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, x := range rows {
		if tokenMatches(x.IDHash, id) {
			if err := s.au.DeleteDashSession(r.Context(), x.IDHash); err != nil {
				s.fail(w, err)
				return
			}
			s.Audit(r, "session.revoke", v.Name, "signed out "+browserName(x.UserAgent)+" at "+x.IP)
			http.Redirect(w, r, "/account?ok=session", http.StatusSeeOther)
			return
		}
	}
	http.Error(w, "not found", http.StatusNotFound)
}

// logoutEverywhere ends every session of the account, this one included.
func (s *Server) logoutEverywhere(w http.ResponseWriter, r *http.Request, v Viewer) {
	n, err := s.au.DeleteDashSessions(r.Context(), v.Tenant, v.UserID, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "logout.everywhere", v.Name, strconv.Itoa(n)+" sessions ended")
	s.clearSession(w)
	http.Redirect(w, r, "/login?ok=signedout", http.StatusSeeOther)
}
