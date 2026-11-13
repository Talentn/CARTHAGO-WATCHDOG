package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"carthago/backend/internal/bans"
	"carthago/backend/internal/store"
)

// banCard is the "Ban" card of a session page.
type banCard struct {
	CSRF      string
	SessionID string
	// CanBan: the viewer holds the reviewer role.
	CanBan bool
	// Standing is the ban that stands for this session's account or device key, nil for
	// none. Pending: it does not refuse the player yet.
	Standing *store.Ban
	Pending  bool
	Saved    bool
	Types    []string
}

func (s *Server) banCardFor(r *http.Request, tenant string, sess *store.Session) (banCard, error) {
	c := banCard{CSRF: s.csrfToken(r), SessionID: sess.SessionID, Saved: r.URL.Query().Get("banned") == "1", Types: labelCheatTypes}
	if v, ok := s.CurrentViewer(r); ok {
		c.CanBan = v.Reviewer()
	}
	b, err := s.st.StandingBan(r.Context(), tenant, sess.PlayerHash, sess.DeviceID)
	if errors.Is(err, store.ErrNotFound) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	c.Standing, c.Pending = b, b.Pending(s.now())
	return c, nil
}

// bannedBy is the name a ban or a lift is recorded under.
func bannedBy(v Viewer) string {
	if v.Demo || v.Name == "" {
		return "demo login"
	}
	return v.Name
}

// banSession bans the account and the device key of one session.
func (s *Server) banSession(w http.ResponseWriter, r *http.Request, v Viewer) {
	ctx := r.Context()
	id := r.PathValue("id")
	sess, err := s.st.GetSession(ctx, id)
	if err == nil && sess.TenantID != v.Tenant {
		err = store.ErrNotFound
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	category := r.PostFormValue("category")
	ok := category == ""
	for _, t := range labelCheatTypes {
		ok = ok || t == category
	}
	if !ok {
		http.Error(w, "unknown category", http.StatusBadRequest)
		return
	}
	b, created, err := s.bans.Ban(ctx, bans.Request{Session: *sess, By: bannedBy(v), Reason: cleanText(r.PostFormValue("reason"), 280), Rule: category})
	if err != nil {
		s.fail(w, err)
		return
	}
	if created {
		detail := fmt.Sprintf("ban %s; player %s; device key %s", b.Ref, b.PlayerHash, orNone(b.DeviceID))
		if b.Rule != "" {
			detail += "; category " + b.Rule
		}
		if b.Reason != "" {
			detail += "; reason: " + b.Reason
		}
		s.Audit(r, "ban.add", "session "+id, detail)
		s.log.Info("dashboard ban", "tenant", v.Tenant, "session", id, "ref", b.Ref, "by", v.Name, "remote", s.clientAddr(r))
	}
	http.Redirect(w, r, "/sessions/"+url.PathEscape(id)+"?banned=1#ban", http.StatusSeeOther)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

type banRow struct {
	store.Ban
	// State is "active", "pending" or "lifted".
	State string
}

type bansData struct {
	Rows                    []banRow
	Active, Pending, Lifted int
	DelayMinutes            int
	// CanAct: the viewer may lift. CanSet: the viewer may change the delay.
	CanAct, CanSet bool
	Lifted1, Saved bool
}

func (s *Server) bansPage(w http.ResponseWriter, r *http.Request, tenant string) {
	ctx := r.Context()
	list, err := s.st.ListBans(ctx, tenant, 500)
	if err != nil {
		s.fail(w, err)
		return
	}
	delay, err := s.st.BanDelay(ctx, tenant)
	if err != nil {
		s.fail(w, err)
		return
	}
	q := r.URL.Query()
	d := bansData{DelayMinutes: int(delay / time.Minute), Lifted1: q.Get("lifted") == "1", Saved: q.Get("saved") == "1"}
	if v, ok := s.CurrentViewer(r); ok {
		d.CanAct, d.CanSet = v.Reviewer(), v.Admin()
	}
	now := s.now()
	for _, b := range list {
		row := banRow{Ban: b, State: "active"}
		switch {
		case b.Lifted():
			row.State = "lifted"
			d.Lifted++
		case b.Pending(now):
			row.State = "pending"
			d.Pending++
		default:
			d.Active++
		}
		d.Rows = append(d.Rows, row)
	}
	s.render(w, http.StatusOK, "bans", page{Title: "Bans", Nav: "bans", Tenant: tenant, Data: d})
}

func (s *Server) liftBan(w http.ResponseWriter, r *http.Request, v Viewer) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	note := cleanText(r.PostFormValue("note"), 280)
	b, err := s.bans.Lift(r.Context(), v.Tenant, id, bannedBy(v), note)
	if err != nil {
		s.fail(w, err)
		return
	}
	detail := "player " + b.PlayerHash
	if note != "" {
		detail += "; note: " + note
	}
	s.Audit(r, "ban.lift", "ban "+b.Ref, detail)
	s.log.Info("dashboard ban lifted", "tenant", v.Tenant, "ref", b.Ref, "by", v.Name, "remote", s.clientAddr(r))
	http.Redirect(w, r, "/bans?lifted=1", http.StatusSeeOther)
}

// setBanDelay changes how long the studio's automatic bans wait before they take effect.
func (s *Server) setBanDelay(w http.ResponseWriter, r *http.Request, v Viewer) {
	min, err := strconv.Atoi(r.PostFormValue("minutes"))
	if err != nil || min < 0 || time.Duration(min)*time.Minute > store.MaxBanDelay {
		http.Error(w, fmt.Sprintf("the delay is a number of minutes from 0 to %d", int(store.MaxBanDelay/time.Minute)), http.StatusBadRequest)
		return
	}
	if err := s.st.SetBanDelay(r.Context(), v.Tenant, time.Duration(min)*time.Minute); err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "ban.delay", "automatic bans", fmt.Sprintf("delay set to %d minutes", min))
	http.Redirect(w, r, "/bans?saved=1", http.StatusSeeOther)
}
