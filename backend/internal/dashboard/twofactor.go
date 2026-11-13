package dashboard

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"carthago/backend/internal/store"
)

// Two-factor enrolment. The new secret is not stored until the user has proved, with a
// code, that their app holds it. Until then it travels in the form itself, sealed with the
// dashboard key and tied to the account, so nothing half-enrolled is ever in the database
// and a second browser tab cannot swap secrets.

const (
	totpIssuer   = "Carthago Watchdog"
	enrolWindow  = 15 * time.Minute
	enrolSealFor = "totp-enrol\x00"
)

type setupData struct {
	Error string
	// Replace: the account already has an authenticator; this one takes its place.
	Replace bool
	// Forced: the studio requires two-factor sign-in, so there is no way around this page.
	Forced bool
	// NeedPassword: the form asks for the current password (not right after signing in).
	NeedPassword bool
	Account      string
	User         string
	QRPath       string
	QRSide       int
	Key          string // the secret in base32, in groups of four, for typing by hand
	Pending      string
}

func enrolSealName(u *store.DashUser) string {
	return enrolSealFor + u.TenantID + "\x00" + strconv.FormatInt(u.ID, 10)
}

func (s *Server) sealPending(u *store.DashUser, secret []byte) (string, error) {
	plain := binary.BigEndian.AppendUint64(append([]byte(nil), secret...), uint64(s.now().Add(enrolWindow).Unix()))
	sealed, err := s.box.seal(plain, enrolSealName(u))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Server) openPending(u *store.DashUser, pending string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(pending)
	if err != nil {
		return nil, err
	}
	plain, err := s.box.open(sealed, enrolSealName(u))
	if err != nil {
		return nil, err
	}
	if len(plain) != totpSecretLen+8 || s.now().Unix() >= int64(binary.BigEndian.Uint64(plain[totpSecretLen:])) {
		return nil, errors.New("enrolment expired")
	}
	return plain[:totpSecretLen], nil
}

func groupsOf4(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i:min(i+4, len(s))])
	}
	return b.String()
}

// renderSetup shows the enrolment page for secret (a new one when nil).
func (s *Server) renderSetup(w http.ResponseWriter, r *http.Request, status int, secret []byte, errMsg string) {
	st := stateOf(r)
	u := st.user
	if u == nil {
		http.Redirect(w, r, "/account", http.StatusSeeOther) // the demo login has no account to protect
		return
	}
	var err error
	if secret == nil {
		if secret, err = newTOTPSecret(); err != nil {
			s.fail(w, err)
			return
		}
	}
	account := u.Name + "@" + u.TenantID
	qr, err := qrEncode(otpauthURI(totpIssuer, account, secret), -1)
	if err != nil {
		s.fail(w, err)
		return
	}
	pending, err := s.sealPending(u, secret)
	if err != nil {
		s.fail(w, err)
		return
	}
	d := setupData{Error: errMsg, Replace: len(u.TOTPSecret) > 0, Forced: st.sess.Kind == store.DashSessionEnrol || st.mustEnrol,
		NeedPassword: st.sess.Kind == store.DashSessionFull, Account: account, User: u.Name, Key: groupsOf4(b32.EncodeToString(secret)), Pending: pending}
	d.QRPath, d.QRSide = qr.svgPath()
	p := page{Title: "Two-factor sign-in", Nav: "account", Data: d}
	if st.sess.Kind == store.DashSessionFull && !st.mustEnrol {
		p.Tenant = u.TenantID // the full page with its header; otherwise a bare card like sign-in
	}
	s.render(w, status, "setup", p)
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request, _ Viewer) {
	s.renderSetup(w, r, http.StatusOK, nil, "")
}

func (s *Server) setupConfirm(w http.ResponseWriter, r *http.Request, v Viewer) {
	st := stateOf(r)
	u := st.user
	if u == nil {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	ctx := r.Context()
	secret, err := s.openPending(u, r.PostFormValue("pending"))
	if err != nil {
		s.renderSetup(w, r, http.StatusBadRequest, nil, "That page was open too long. Scan the new code below")
		return
	}
	if st.sess.Kind == store.DashSessionFull {
		if ok, msg := s.confirmPassword(r, u, r.PostFormValue("password")); !ok {
			s.renderSetup(w, r, http.StatusUnauthorized, secret, msg)
			return
		}
	}
	step, ok := totpVerify(secret, r.PostFormValue("code"), s.now())
	if !ok {
		s.renderSetup(w, r, http.StatusUnauthorized, secret, "That code did not match. Check that the phone's clock is right, then try the next code")
		return
	}
	sealed, err := s.box.seal(secret, totpSealName(u.TenantID, u.ID))
	if err != nil {
		s.fail(w, err)
		return
	}
	replaced := len(u.TOTPSecret) > 0
	if err := s.au.UpdateDashUser(ctx, u.TenantID, u.ID, store.DashUserChange{TOTPSecret: &sealed}); err != nil {
		s.fail(w, err)
		return
	}
	// The code that confirmed the enrolment is used up.
	_, _ = s.au.AdvanceTOTPStep(ctx, u.ID, step)
	codes, err := s.newRecoverySet(r, u)
	if err != nil {
		s.fail(w, err)
		return
	}
	action, detail := "totp.enrol", "authenticator app added"
	if replaced {
		action, detail = "totp.replace", "authenticator app replaced"
	}
	s.Audit(r, action, u.Name, detail)
	// How the account signs in changed: every other session ends and this one gets a new id.
	wasEnrol := st.sess.Kind == store.DashSessionEnrol
	if _, err := s.au.DeleteDashSessions(ctx, u.TenantID, u.ID, st.sess.IDHash); err != nil {
		s.fail(w, err)
		return
	}
	if wasEnrol {
		s.completeLogin(w, r, u, "password, then two-factor enrolment", "")
	} else if _, err := s.startSession(w, r, u.TenantID, u.ID, store.DashSessionFull); err != nil {
		s.fail(w, err)
		return
	}
	st.viewer.TwoFactor, st.mustEnrol = true, false
	s.renderRecovery(w, u, codes, "Two-factor sign-in is on")
}

// newRecoverySet replaces the account's recovery codes and returns the new ones, which
// are shown once and stored only as keyed hashes.
func (s *Server) newRecoverySet(r *http.Request, u *store.DashUser) ([]string, error) {
	codes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = s.box.recoveryHash(u.ID, c)
	}
	return codes, s.au.SetRecoveryCodes(r.Context(), u.ID, hashes)
}

type recoveryData struct {
	Notice string
	Codes  []string
}

func (s *Server) renderRecovery(w http.ResponseWriter, u *store.DashUser, codes []string, notice string) {
	s.render(w, http.StatusOK, "recovery", page{Title: "Recovery codes", Nav: "account", Tenant: u.TenantID, Data: recoveryData{Notice: notice, Codes: codes}})
}

// reauth checks the current password and a current two-factor code on a form that weakens
// or resets the account's second factor.
func (s *Server) reauth(r *http.Request, u *store.DashUser) (bool, string) {
	if ok, msg := s.confirmPassword(r, u, r.PostFormValue("password")); !ok {
		return false, msg
	}
	if _, ok := s.secondFactor(r.Context(), u, r.PostFormValue("code")); !ok {
		addr, acct := s.clientIP(r), accountKey(u.TenantID, u.Name)
		s.loginFailed(r, u.TenantID, u.Name, addr, acct, "wrong two-factor code on an account form")
		return false, "That two-factor code did not match"
	}
	return true, ""
}

func (s *Server) disableTwoFactor(w http.ResponseWriter, r *http.Request, v Viewer) {
	st := stateOf(r)
	u := st.user
	if u == nil || len(u.TOTPSecret) == 0 {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	ctx := r.Context()
	set, err := s.au.GetTenantSettings(ctx, u.TenantID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if set.RequireTOTP {
		s.renderAccount(w, r, http.StatusConflict, "", "This studio requires two-factor sign-in, so it cannot be turned off. You can replace the authenticator app instead")
		return
	}
	if ok, msg := s.reauth(r, u); !ok {
		s.renderAccount(w, r, http.StatusUnauthorized, "", msg)
		return
	}
	var none []byte
	if err := s.au.UpdateDashUser(ctx, u.TenantID, u.ID, store.DashUserChange{TOTPSecret: &none}); err != nil {
		s.fail(w, err)
		return
	}
	if err := s.au.SetRecoveryCodes(ctx, u.ID, nil); err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "totp.disable", u.Name, "two-factor sign-in turned off")
	if _, err := s.au.DeleteDashSessions(ctx, u.TenantID, u.ID, st.sess.IDHash); err != nil {
		s.fail(w, err)
		return
	}
	if _, err := s.startSession(w, r, u.TenantID, u.ID, store.DashSessionFull); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/account?ok=twofactor-off", http.StatusSeeOther)
}

func (s *Server) regenerateRecovery(w http.ResponseWriter, r *http.Request, v Viewer) {
	u := stateOf(r).user
	if u == nil || len(u.TOTPSecret) == 0 {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if ok, msg := s.reauth(r, u); !ok {
		s.renderAccount(w, r, http.StatusUnauthorized, "", msg)
		return
	}
	codes, err := s.newRecoverySet(r, u)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "recovery.regenerate", u.Name, "new recovery codes, the old ones no longer work")
	s.renderRecovery(w, u, codes, "New recovery codes. The old ones no longer work")
}
