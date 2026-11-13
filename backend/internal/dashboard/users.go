package dashboard

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"carthago/backend/internal/store"
)

const (
	inviteTTL = 72 * time.Hour
	resetTTL  = 24 * time.Hour
)

type usersData struct {
	Notice, Error string
	Users         []store.DashUser
	Invites       []store.DashInvite
	Required      bool
	// Self is the viewer's own account id, marked in the list.
	Self int64
	// Name and Role refill the invite form after a refused attempt.
	Name, Role string
}

var usersNotices = map[string]string{
	"revoked":   "Invite revoked",
	"required":  "Two-factor sign-in is now required. Users without it set it up at their next sign-in",
	"optional":  "Two-factor sign-in is no longer required",
	"role":      "Role changed. That user was signed out",
	"disabled":  "Account disabled and signed out",
	"enabled":   "Account enabled",
	"signedout": "That user was signed out everywhere",
	"twofactor": "Two-factor sign-in reset. That user was signed out",
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, status int, d usersData) {
	ctx, v := r.Context(), stateOf(r).viewer
	var err error
	if d.Users, err = s.au.ListDashUsers(ctx, v.Tenant); err != nil {
		s.fail(w, err)
		return
	}
	if d.Invites, err = s.au.ListDashInvites(ctx, v.Tenant, s.now()); err != nil {
		s.fail(w, err)
		return
	}
	set, err := s.au.GetTenantSettings(ctx, v.Tenant)
	if err != nil {
		s.fail(w, err)
		return
	}
	d.Required, d.Self = set.RequireTOTP, v.UserID
	if d.Role == "" {
		d.Role = store.RoleReviewer
	}
	s.render(w, status, "users", page{Title: "Users", Nav: "users", Tenant: v.Tenant, Data: d})
}

func (s *Server) users(w http.ResponseWriter, r *http.Request, _ Viewer) {
	s.renderUsers(w, r, http.StatusOK, usersData{Notice: usersNotices[r.URL.Query().Get("ok")]})
}

var errNotAdmin = errors.New("no longer an admin")

// asAdmin runs fn while holding the lock that orders admin changes, after reading the
// actor's account again. Two admins demoting each other at the same moment therefore
// cannot both succeed, and since nobody can change their own role or disable themselves,
// a studio always keeps an admin.
func (s *Server) asAdmin(ctx context.Context, v Viewer, fn func() error) error {
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	me, err := s.au.GetDashUser(ctx, v.Tenant, v.UserID)
	if err != nil || me.Disabled || roleOf(me.Role) != RoleAdmin {
		return errNotAdmin
	}
	return fn()
}

type linkData struct {
	Reset   bool
	Name    string
	Role    Role
	Link    string
	Expires time.Time
}

// baseURL is how this dashboard is addressed from the admin's browser, for the links it
// hands out.
func (s *Server) baseURL(r *http.Request) string {
	scheme := "http"
	if s.secureCookie || r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (s *Server) inviteUser(w http.ResponseWriter, r *http.Request, v Viewer) {
	ctx := r.Context()
	name, role := normName(r.PostFormValue("name")), roleOf(r.PostFormValue("role"))
	back := usersData{Name: cleanLine(name, 32), Role: role.Key()}
	switch {
	case !userNameRE.MatchString(name):
		back.Error = "A user name is 3 to 32 characters: a to z, 0 to 9, dot, dash and underscore"
	case role == RoleNone:
		back.Error = "Choose a role"
	}
	if back.Error == "" {
		if _, err := s.au.GetDashUserByName(ctx, v.Tenant, name); err == nil {
			back.Error = "That user name is taken"
		} else if !errors.Is(err, store.ErrNotFound) {
			s.fail(w, err)
			return
		}
	}
	if back.Error == "" {
		pending, err := s.au.ListDashInvites(ctx, v.Tenant, s.now())
		if err != nil {
			s.fail(w, err)
			return
		}
		for _, inv := range pending {
			if inv.Kind == store.InviteNew && inv.Name == name {
				back.Error = "An invite for that name is still open. Revoke it first"
			}
		}
	}
	if back.Error != "" {
		s.renderUsers(w, r, http.StatusBadRequest, back)
		return
	}
	token, err := newToken()
	if err != nil {
		s.fail(w, err)
		return
	}
	inv := &store.DashInvite{TokenHash: hashToken(token), TenantID: v.Tenant, Kind: store.InviteNew, Name: name, Role: role.Key(),
		CreatedBy: v.Name, CreatedAt: s.now(), ExpiresAt: s.now().Add(inviteTTL)}
	if err := s.asAdmin(ctx, v, func() error { return s.au.CreateDashInvite(ctx, inv) }); err != nil {
		s.adminFail(w, err)
		return
	}
	s.Audit(r, "user.invite", name, "invited as "+role.Label()+", link valid until "+inv.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"))
	s.render(w, http.StatusOK, "link", page{Title: "Invite link", Nav: "users", Tenant: v.Tenant,
		Data: linkData{Name: name, Role: role, Link: s.baseURL(r) + "/invite/" + token, Expires: inv.ExpiresAt}})
}

func (s *Server) adminFail(w http.ResponseWriter, err error) {
	if errors.Is(err, errNotAdmin) {
		http.Error(w, "your account is no longer an admin", http.StatusForbidden)
		return
	}
	s.fail(w, err)
}

func (s *Server) revokeInvite(w http.ResponseWriter, r *http.Request, v Viewer) {
	ctx := r.Context()
	id := r.PostFormValue("id")
	pending, err := s.au.ListDashInvites(ctx, v.Tenant, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, inv := range pending {
		if tokenMatches(inv.TokenHash, id) {
			if err := s.asAdmin(ctx, v, func() error { return s.au.RevokeDashInvite(ctx, v.Tenant, inv.TokenHash) }); err != nil {
				s.adminFail(w, err)
				return
			}
			what := "invite revoked"
			if inv.Kind == store.InviteReset {
				what = "password reset link revoked"
			}
			s.Audit(r, "invite.revoke", inv.Name, what)
			http.Redirect(w, r, "/users?ok=revoked", http.StatusSeeOther)
			return
		}
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (s *Server) requireTwoFactor(w http.ResponseWriter, r *http.Request, v Viewer) {
	ctx := r.Context()
	on := r.PostFormValue("require") == "1"
	if on && !v.TwoFactor {
		// Otherwise the admin would lock the studio into a rule they have not tried themselves.
		s.renderUsers(w, r, http.StatusConflict, usersData{Error: "Set up two-factor sign-in on your own account first, under Account"})
		return
	}
	if err := s.asAdmin(ctx, v, func() error { return s.au.PutTenantSettings(ctx, v.Tenant, store.TenantSettings{RequireTOTP: on}) }); err != nil {
		s.adminFail(w, err)
		return
	}
	if on {
		s.Audit(r, "tenant.require_2fa", v.Tenant, "two-factor sign-in required for every account")
		http.Redirect(w, r, "/users?ok=required", http.StatusSeeOther)
		return
	}
	s.Audit(r, "tenant.require_2fa", v.Tenant, "two-factor sign-in no longer required")
	http.Redirect(w, r, "/users?ok=optional", http.StatusSeeOther)
}

type userData struct {
	Notice, Error string
	U             *store.DashUser
	Self          bool
	Sessions      int
	Roles         []Role
}

func (s *Server) target(w http.ResponseWriter, r *http.Request, v Viewer) (*store.DashUser, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return nil, false
	}
	u, err := s.au.GetDashUser(r.Context(), v.Tenant, id)
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	return u, true
}

func (s *Server) renderUser(w http.ResponseWriter, r *http.Request, status int, u *store.DashUser, notice, errMsg string) {
	v := stateOf(r).viewer
	rows, err := s.au.ListDashSessions(r.Context(), v.Tenant, u.ID, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	n := 0
	for _, x := range rows {
		if x.Kind == store.DashSessionFull && s.now().Sub(x.LastSeenAt) <= s.idleTTL {
			n++
		}
	}
	s.render(w, status, "user", page{Title: "User " + u.Name, Nav: "users", Tenant: v.Tenant,
		Data: userData{Notice: notice, Error: errMsg, U: u, Self: u.ID == v.UserID, Sessions: n, Roles: []Role{RoleReadOnly, RoleReviewer, RoleAdmin}}})
}

func (s *Server) user(w http.ResponseWriter, r *http.Request, v Viewer) {
	if u, ok := s.target(w, r, v); ok {
		s.renderUser(w, r, http.StatusOK, u, usersNotices[r.URL.Query().Get("ok")], "")
	}
}

// userAction is everything an admin does to another account. None of it applies to the
// admin's own account: their password and second factor are under Account, and their role
// is for another admin to change.
func (s *Server) userAction(w http.ResponseWriter, r *http.Request, v Viewer) {
	u, ok := s.target(w, r, v)
	if !ok {
		return
	}
	ctx := r.Context()
	action := r.PathValue("action")
	if u.ID == v.UserID {
		s.renderUser(w, r, http.StatusConflict, u, "", "This is your own account. Another admin has to make this change")
		return
	}
	// signOut ends the user's sessions: a change of role or access takes a new sign-in.
	signOut := func() error {
		_, err := s.au.DeleteDashSessions(ctx, u.TenantID, u.ID, "")
		return err
	}
	back := "/users/" + strconv.FormatInt(u.ID, 10)
	var err error
	switch action {
	case "role":
		role := roleOf(r.PostFormValue("role"))
		if role == RoleNone {
			s.renderUser(w, r, http.StatusBadRequest, u, "", "Choose a role")
			return
		}
		if role.Key() == u.Role {
			http.Redirect(w, r, back, http.StatusSeeOther)
			return
		}
		key := role.Key()
		if err = s.asAdmin(ctx, v, func() error {
			if err := s.au.UpdateDashUser(ctx, u.TenantID, u.ID, store.DashUserChange{Role: &key}); err != nil {
				return err
			}
			return signOut()
		}); err == nil {
			s.Audit(r, "user.role", u.Name, "role changed from "+roleOf(u.Role).Label()+" to "+role.Label())
			back += "?ok=role"
		}
	case "disable", "enable":
		disabled := action == "disable"
		if err = s.asAdmin(ctx, v, func() error {
			if err := s.au.UpdateDashUser(ctx, u.TenantID, u.ID, store.DashUserChange{Disabled: &disabled}); err != nil {
				return err
			}
			return signOut()
		}); err == nil {
			s.Audit(r, "user."+action, u.Name, "account "+action+"d")
			back += "?ok=" + action + "d"
		}
	case "sign-out":
		var n int
		if err = s.asAdmin(ctx, v, func() error {
			var err error
			n, err = s.au.DeleteDashSessions(ctx, u.TenantID, u.ID, "")
			return err
		}); err == nil {
			s.Audit(r, "session.revoke", u.Name, "signed out everywhere by an admin, "+strconv.Itoa(n)+" sessions ended")
			back += "?ok=signedout"
		}
	case "reset-two-factor":
		var none []byte
		if err = s.asAdmin(ctx, v, func() error {
			if err := s.au.UpdateDashUser(ctx, u.TenantID, u.ID, store.DashUserChange{TOTPSecret: &none}); err != nil {
				return err
			}
			if err := s.au.SetRecoveryCodes(ctx, u.ID, nil); err != nil {
				return err
			}
			return signOut()
		}); err == nil {
			s.Audit(r, "totp.reset", u.Name, "two-factor sign-in and recovery codes removed by an admin")
			back += "?ok=twofactor"
		}
	case "reset-password":
		token, terr := newToken()
		if terr != nil {
			s.fail(w, terr)
			return
		}
		inv := &store.DashInvite{TokenHash: hashToken(token), TenantID: u.TenantID, Kind: store.InviteReset, Name: u.Name, Role: u.Role, UserID: u.ID,
			CreatedBy: v.Name, CreatedAt: s.now(), ExpiresAt: s.now().Add(resetTTL)}
		if err = s.asAdmin(ctx, v, func() error { return s.au.CreateDashInvite(ctx, inv) }); err == nil {
			s.Audit(r, "user.reset_link", u.Name, "password reset link made, valid until "+inv.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"))
			s.render(w, http.StatusOK, "link", page{Title: "Password reset link", Nav: "users", Tenant: v.Tenant,
				Data: linkData{Reset: true, Name: u.Name, Role: roleOf(u.Role), Link: s.baseURL(r) + "/invite/" + token, Expires: inv.ExpiresAt}})
			return
		}
	default:
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		s.adminFail(w, err)
		return
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}
