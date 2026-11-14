package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"carthago/backend/internal/store"
)

// poolRow is one player of the shadow pool.
type poolRow struct {
	store.Ban
	// Sessions the player has started since entering, with the one the player was caught
	// in; Files is how many distinct files outside the Windows folder the player's
	// sessions have reported.
	Sessions, Files int
	// Accounts joined the pool through this player's device key (the caught player only).
	Accounts int
	// Ends says how long until the ban takes effect.
	Ends string
}

type poolData struct {
	Rows []poolRow
	// Period is the studio's shadow period, PeriodText that in words ("off", "2 days").
	Period     time.Duration
	PeriodText string
	// Amount and Unit fill the period form.
	Amount int
	Unit   string
	// MaxDays bounds the form.
	MaxDays int
	// CanAct: the viewer may ban now and release. CanSet: the viewer may set the period.
	CanAct, CanSet          bool
	Banned, Released, Saved bool
}

// maxPoolSessions bounds the sessions of one player counted on the page.
const maxPoolSessions = 1000

// periodText spells a shadow period.
func periodText(d time.Duration) string {
	switch {
	case d <= 0:
		return "off"
	case d%(24*time.Hour) == 0:
		return plural(int(d/(24*time.Hour)), "day", "days")
	case d%time.Hour == 0:
		return plural(int(d/time.Hour), "hour", "hours")
	case d%time.Minute == 0:
		return plural(int(d/time.Minute), "minute", "minutes")
	}
	return plural(int(d/time.Second), "second", "seconds")
}

// until says how far ahead of now a time is.
func until(now, t time.Time) string {
	d := t.Sub(now)
	switch {
	case d <= 0:
		return "now"
	case d < time.Minute:
		return fmt.Sprintf("in %d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("in %d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("in %d h %d min", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("in %d d %d h", int(d.Hours())/24, int(d.Hours())%24)
}

func (s *Server) shadowPage(w http.ResponseWriter, r *http.Request, tenant string) {
	ctx := r.Context()
	period, err := s.st.ShadowPeriod(ctx, tenant)
	if err != nil {
		s.fail(w, err)
		return
	}
	pool, err := s.bans.Pool(ctx, tenant)
	if err != nil {
		s.fail(w, err)
		return
	}
	q := r.URL.Query()
	d := poolData{Period: period, PeriodText: periodText(period), Amount: int(period / time.Hour), Unit: "hours", MaxDays: int(store.MaxShadowPeriod / (24 * time.Hour)),
		Banned: q.Get("banned") == "1", Released: q.Get("released") == "1", Saved: q.Get("saved") == "1"}
	if period > 0 && period%(24*time.Hour) == 0 {
		d.Amount, d.Unit = int(period/(24*time.Hour)), "days"
	}
	if v, ok := s.CurrentViewer(r); ok {
		d.CanAct, d.CanSet = v.Reviewer(), v.Admin()
	}
	files := map[string]map[string]bool{}
	if len(pool) > 0 {
		sightings, err := s.st.ListModuleSightings(ctx, tenant)
		if err != nil {
			s.fail(w, err)
			return
		}
		for _, m := range sightings {
			if files[m.PlayerHash] == nil {
				files[m.PlayerHash] = map[string]bool{}
			}
			files[m.PlayerHash][m.SHA256] = true
		}
	}
	now := s.now()
	accounts := map[string]int{}
	for _, b := range pool {
		accounts[b.ShadowOf]++
	}
	for _, b := range pool {
		row := poolRow{Ban: b, Files: len(files[b.PlayerHash]), Ends: until(now, b.EffectiveAt)}
		if b.ShadowOf == "" {
			row.Accounts = accounts[b.Ref]
		}
		sessions, err := s.st.ListSessions(ctx, tenant, store.SessionFilter{PlayerHash: b.PlayerHash, Limit: maxPoolSessions})
		if err != nil {
			s.fail(w, err)
			return
		}
		for _, sess := range sessions {
			if sess.SessionID == b.SessionID || !sess.CreatedAt.Before(b.BannedAt) {
				row.Sessions++
			}
		}
		d.Rows = append(d.Rows, row)
	}
	s.render(w, http.StatusOK, "shadow", page{Title: "Shadow pool", Nav: "shadow", Tenant: tenant, Data: d})
}

func poolID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil
}

// poolDetail is the audit detail of an action on one entry of the pool.
func poolDetail(b *store.Ban, with []store.Ban, note string, err error) string {
	detail := fmt.Sprintf("player %s; device key %s", b.PlayerHash, orNone(b.DeviceID))
	if b.ShadowOf != "" {
		detail = fmt.Sprintf("player %s, in the pool through the device key of %s", b.PlayerHash, b.ShadowOf)
	}
	detail += alsoBans(with)
	if note != "" {
		detail += "; note: " + note
	}
	if err != nil {
		// Done for this entry; one that follows it could not be.
		detail += "; failed part-way: " + err.Error()
	}
	return detail
}

// shadowBanNow ends the shadow pool early for one entry: its ban takes effect now.
func (s *Server) shadowBanNow(w http.ResponseWriter, r *http.Request, v Viewer) {
	id, ok := poolID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, with, err := s.bans.BanNow(r.Context(), v.Tenant, id)
	if b == nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "shadow.ban_now", "ban "+b.Ref, poolDetail(b, with, "", err))
	s.log.Info("dashboard shadow pool: ban now", "tenant", v.Tenant, "ref", b.Ref, "with", len(with), "by", v.Name, "remote", s.clientAddr(r))
	http.Redirect(w, r, "/shadow?banned=1", http.StatusSeeOther)
}

// shadowRelease takes one entry out of the pool: the player is normal again and what
// the entry caused is undone.
func (s *Server) shadowRelease(w http.ResponseWriter, r *http.Request, v Viewer) {
	id, ok := poolID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	note := cleanText(r.PostFormValue("note"), 280)
	b, with, err := s.bans.Release(r.Context(), v.Tenant, id, bannedBy(v), note)
	if b == nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "shadow.release", "ban "+b.Ref, poolDetail(b, with, note, err))
	s.log.Info("dashboard shadow pool: release", "tenant", v.Tenant, "ref", b.Ref, "with", len(with), "by", v.Name, "remote", s.clientAddr(r))
	http.Redirect(w, r, "/shadow?released=1", http.StatusSeeOther)
}

// setShadowPeriod sets how long the studio keeps a caught player in the pool. Zero turns
// the pool off for players caught from now on; those in it stay until their end.
func (s *Server) setShadowPeriod(w http.ResponseWriter, r *http.Request, v Viewer) {
	n, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("amount")))
	unit := time.Hour
	switch r.PostFormValue("unit") {
	case "hours":
	case "days":
		unit = 24 * time.Hour
	default:
		err = errors.New("unit")
	}
	if err != nil || n < 0 || n > int(store.MaxShadowPeriod/unit) {
		http.Error(w, fmt.Sprintf("the period is a number of hours or days, from 0 (off) to %d days", int(store.MaxShadowPeriod/(24*time.Hour))), http.StatusBadRequest)
		return
	}
	period := time.Duration(n) * unit
	if err := s.st.SetShadowPeriod(r.Context(), v.Tenant, period); err != nil {
		s.fail(w, err)
		return
	}
	detail := "period set to " + periodText(period)
	if period == 0 {
		detail = "turned off: an automatic ban is immediate again"
	}
	s.Audit(r, "shadow.period", "shadow pool", detail)
	http.Redirect(w, r, "/shadow?saved=1", http.StatusSeeOther)
}
