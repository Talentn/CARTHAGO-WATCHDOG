package dashboard

import (
	"net/http"
	"strconv"

	"carthago/backend/internal/store"
)

// Audit records that the signed-in viewer did something: action is a short dotted name
// ("user.role"), target what it was done to, detail the rest in plain words. Who, when and
// from which address are filled in. Every handler that changes something calls it; one that
// does not still leaves a generic "request.post" entry behind (see serve).
func (s *Server) Audit(r *http.Request, action, target, detail string) {
	st := stateOf(r)
	if st == nil {
		s.log.Error("dashboard audit without a signed-in viewer", "action", action)
		return
	}
	st.audited = true
	s.auditAs(r, st.viewer.Tenant, st.viewer.UserID, st.viewer.Name, action, target, detail)
}

// auditAs writes an entry for an actor who is not (or not yet) the request's viewer: a
// sign-in, a failed attempt, an accepted invite.
func (s *Server) auditAs(r *http.Request, tenant string, actorID int64, actor, action, target, detail string) {
	e := &store.AuditEntry{TenantID: tenant, At: s.now(), ActorID: actorID, Actor: actor, IP: s.clientAddr(r),
		Action: action, Target: cleanLine(target, 200), Detail: cleanLine(detail, 300)}
	if err := s.au.AppendAudit(r.Context(), e); err != nil {
		s.log.Error("dashboard audit log write failed", "action", action, "tenant", tenant, "actor", actor, "err", err)
	}
}

const auditPageSize = 100

// auditTabs: which actions each tab of the audit page shows.
var auditTabs = map[string][]string{
	"signins": {"login.", "logout", "session."},
	"changes": {"user.", "invite.", "password.", "totp.", "recovery.", "tenant.", "request.", "access."},
}

type auditData struct {
	Show    string
	Entries []store.AuditEntry
	// Older is the id to page back from; 0 on the last page.
	Older int64
	// Checked is set after "check the log": Count entries read, Broken the first entry
	// that does not fit the chain (0 when all do).
	Checked bool
	Count   int
	Broken  int64
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request, v Viewer) {
	q := r.URL.Query()
	d := auditData{Show: q.Get("show")}
	if _, ok := auditTabs[d.Show]; !ok {
		d.Show = ""
	}
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	rows, err := s.au.ListAudit(r.Context(), v.Tenant, store.AuditFilter{BeforeID: max(before, 0), ActionPrefixes: auditTabs[d.Show], Limit: auditPageSize + 1})
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(rows) > auditPageSize {
		rows = rows[:auditPageSize]
		d.Older = rows[len(rows)-1].ID
	}
	d.Entries = rows
	if q.Get("check") == "1" {
		d.Checked = true
		if d.Count, d.Broken, err = s.au.VerifyAudit(r.Context(), v.Tenant); err != nil {
			s.fail(w, err)
			return
		}
	}
	s.render(w, http.StatusOK, "audit", page{Title: "Audit log", Nav: "audit", Tenant: v.Tenant, Data: d})
}
