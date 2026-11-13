package dashboard

import (
	"errors"
	"net/http"

	"carthago/backend/internal/store"
)

// One-time links. An admin (or the gateway command line, for the first admin) creates a
// link; whoever opens it chooses the password for the account it names. The link holds a
// random token of which only the hash is stored. It works once and expires.

type inviteData struct {
	Error string
	// Gone: the link is unknown, used or expired. All three look the same from outside.
	Gone   bool
	Reset  bool
	Tenant string
	Name   string
	Role   Role
	Token  string
}

func (s *Server) lookupInvite(w http.ResponseWriter, r *http.Request) (*store.DashInvite, string, bool) {
	addr := s.clientAddr(r)
	gone := func(status int) (*store.DashInvite, string, bool) {
		s.render(w, status, "invite", page{Title: "Link not valid", Data: inviteData{Gone: true}})
		return nil, "", false
	}
	if s.lim.addrBlocked(addr, s.now()) {
		return gone(http.StatusTooManyRequests)
	}
	token := r.PathValue("token")
	if len(token) < 32 || len(token) > 128 {
		s.lim.addrFailed(addr, s.now())
		return gone(http.StatusNotFound)
	}
	inv, err := s.au.GetDashInvite(r.Context(), hashToken(token), s.now())
	if errors.Is(err, store.ErrNotFound) {
		s.lim.addrFailed(addr, s.now())
		return gone(http.StatusNotFound)
	}
	if err != nil {
		s.fail(w, err)
		return nil, "", false
	}
	return inv, token, true
}

func (s *Server) renderInvite(w http.ResponseWriter, r *http.Request, status int, inv *store.DashInvite, token, errMsg string) {
	title := "Create your account"
	if inv.Kind == store.InviteReset {
		title = "Set a new password"
	}
	s.render(w, status, "invite", page{Title: title, CSRF: s.preToken(w, r),
		Data: inviteData{Error: errMsg, Reset: inv.Kind == store.InviteReset, Tenant: inv.TenantID, Name: inv.Name, Role: roleOf(inv.Role), Token: token}})
}

func (s *Server) invitePage(w http.ResponseWriter, r *http.Request) {
	if inv, token, ok := s.lookupInvite(w, r); ok {
		s.renderInvite(w, r, http.StatusOK, inv, token, "")
	}
}

func (s *Server) inviteAccept(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-site request", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	inv, token, ok := s.lookupInvite(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if !s.preOK(r) {
		s.renderInvite(w, r, http.StatusForbidden, inv, token, msgExpired)
		return
	}
	pw := r.PostFormValue("password")
	msg := checkPassword(pw, inv.Name, inv.TenantID)
	if msg == "" && pw != r.PostFormValue("repeat") {
		msg = "The two passwords are not the same"
	}
	if msg != "" {
		s.renderInvite(w, r, http.StatusBadRequest, inv, token, msg)
		return
	}
	// Hash first, redeem second: a link is not spent on a request that then fails.
	hash, err := s.newPasswordHash(ctx, pw)
	if err != nil {
		s.fail(w, err)
		return
	}
	if inv, err = s.au.RedeemDashInvite(ctx, hashToken(token), s.now()); err != nil {
		if errors.Is(err, store.ErrNotFound) { // used by another request in the meantime
			s.render(w, http.StatusNotFound, "invite", page{Title: "Link not valid", Data: inviteData{Gone: true}})
			return
		}
		s.fail(w, err)
		return
	}
	now := s.now()
	if inv.Kind == store.InviteReset {
		if err := s.au.UpdateDashUser(ctx, inv.TenantID, inv.UserID, store.DashUserChange{PasswordHash: &hash, PasswordChangedAt: now}); err != nil {
			s.fail(w, err)
			return
		}
		if _, err := s.au.DeleteDashSessions(ctx, inv.TenantID, inv.UserID, ""); err != nil {
			s.fail(w, err)
			return
		}
		s.lim.succeeded(accountKey(inv.TenantID, inv.Name))
		s.auditAs(r, inv.TenantID, inv.UserID, inv.Name, "password.reset", inv.Name, "new password set through a reset link from "+inv.CreatedBy)
		http.Redirect(w, r, "/login?ok=password", http.StatusSeeOther)
		return
	}
	u := &store.DashUser{TenantID: inv.TenantID, Name: inv.Name, Role: inv.Role, PasswordHash: hash, CreatedAt: now, CreatedBy: inv.CreatedBy, PasswordChangedAt: now}
	if err := s.au.CreateDashUser(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.render(w, http.StatusConflict, "invite", page{Title: "Link not valid", Data: inviteData{Gone: true}})
			return
		}
		s.fail(w, err)
		return
	}
	s.auditAs(r, inv.TenantID, u.ID, u.Name, "user.create", u.Name, "account created as "+roleOf(u.Role).Label()+" through an invite from "+inv.CreatedBy)
	http.Redirect(w, r, "/login?ok=created", http.StatusSeeOther)
}
