package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"carthago/backend/internal/reports"
	"carthago/backend/internal/store"
)

// Player reports (internal/reports) are advice. The dashboard is the only reader of the
// reports table: this file lists them, lets a reviewer set their state, and counts them
// on the player pages. Nothing here writes evidence, bans, or the shadow pool.

// reportWindow is how far back the report counts look.
const reportWindow = 30 * 24 * time.Hour

var reportReasons = map[string]string{
	"cheating":        "Cheating",
	"toxic_behaviour": "Toxic behaviour",
	"griefing":        "Griefing",
	"other":           "Other",
}

// reporterWeight is a reporter's weight as the pages show it.
type reporterWeight struct {
	reports.Weight
	Text  string // "0.67"
	Basis string // "1 confirmed, 0 dismissed, 2 without an outcome yet"
}

type reportRow struct {
	store.PlayerReport
	ReasonLabel string
	At          string // mm:ss into the match; empty when the report names no moment
	Recorded    bool   // the match has a replay
	Weight      reporterWeight
	Tally       store.ReportTally // the reported player's last 30 days
}

type reportTab struct {
	State, Label string
	N            int
}

type reportsData struct {
	State  string
	Tabs   []reportTab
	Rows   []reportRow
	Player string // only reports about this player
	More   bool
	CanAct bool
	Saved  bool
}

const reportsPageSize = 100

// reportWeights works out the weight of each reporter among rows. A reported player
// counts as confirmed with a ban that stands or a session labelled a confirmed cheat;
// the newest 1000 of each are looked at.
func (s *Server) reportWeights(ctx context.Context, tenant string, rows []store.PlayerReport) (map[string]reporterWeight, error) {
	out := map[string]reporterWeight{}
	if len(rows) == 0 {
		return out, nil
	}
	confirmed := map[string]bool{}
	bans, err := s.st.ListBans(ctx, tenant, 1000)
	if err != nil {
		return nil, err
	}
	for _, b := range bans {
		if b.LiftedAt.IsZero() {
			confirmed[b.PlayerHash] = true
		}
	}
	labels, err := s.st.ListSessionLabels(ctx, tenant, store.OracleFilter{Limit: 1000})
	if err != nil {
		return nil, err
	}
	for _, l := range labels {
		if l.Label == store.LabelConfirmedCheat {
			confirmed[l.PlayerHash] = true
		}
	}
	for _, r := range rows {
		if _, done := out[r.Reporter]; done {
			continue
		}
		theirs, err := s.st.ListPlayerReports(ctx, tenant, store.ReportFilter{Reporter: r.Reporter, Limit: 1000})
		if err != nil {
			return nil, err
		}
		w := reports.WeightOf(theirs, func(p string) bool { return confirmed[p] })
		out[r.Reporter] = reporterWeight{Weight: w, Text: fmt.Sprintf("%.2f", w.Value),
			Basis: fmt.Sprintf("%d confirmed, %d dismissed, %d without an outcome yet", w.Confirmed, w.Rejected, w.Pending)}
	}
	return out, nil
}

// reportRows fills in what the pages show next to each report.
func (s *Server) reportRows(ctx context.Context, tenant string, rows []store.PlayerReport) ([]reportRow, error) {
	weights, err := s.reportWeights(ctx, tenant, rows)
	if err != nil {
		return nil, err
	}
	tally, err := s.st.TallyPlayerReports(ctx, tenant, s.now().Add(-reportWindow))
	if err != nil {
		return nil, err
	}
	recorded := map[string]bool{}
	out := make([]reportRow, 0, len(rows))
	for _, r := range rows {
		row := reportRow{PlayerReport: r, ReasonLabel: reportReasons[r.Reason], Weight: weights[r.Reporter], Tally: tally[r.Reported]}
		if r.MatchMs >= 0 {
			row.At = clock(r.MatchMs)
		}
		has, seen := recorded[r.MatchID]
		if !seen {
			_, err := s.st.GetMatchReplay(ctx, tenant, r.MatchID)
			has = err == nil
			recorded[r.MatchID] = has
		}
		row.Recorded = has
		out = append(out, row)
	}
	return out, nil
}

func (s *Server) reportsPage(w http.ResponseWriter, r *http.Request, tenant string) {
	ctx := r.Context()
	q := r.URL.Query()
	d := reportsData{State: q.Get("state"), Player: q.Get("player"), Saved: q.Get("saved") == "1"}
	if !store.ValidReportState(d.State) {
		d.State = store.ReportOpen
	}
	if v, ok := s.CurrentViewer(r); ok {
		d.CanAct = v.Reviewer()
	}
	for _, t := range []reportTab{{State: store.ReportOpen, Label: "Open"}, {State: store.ReportReviewed, Label: "Reviewed"}, {State: store.ReportDismissed, Label: "Dismissed"}} {
		n, err := s.st.CountPlayerReports(ctx, tenant, store.ReportFilter{State: t.State, Reported: d.Player})
		if err != nil {
			s.fail(w, err)
			return
		}
		t.N = n
		d.Tabs = append(d.Tabs, t)
	}
	rows, err := s.st.ListPlayerReports(ctx, tenant, store.ReportFilter{State: d.State, Reported: d.Player, Limit: reportsPageSize + 1})
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(rows) > reportsPageSize {
		rows, d.More = rows[:reportsPageSize], true
	}
	if d.Rows, err = s.reportRows(ctx, tenant, rows); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, "reports", page{Title: "Reports", Nav: "reports", Tenant: tenant, Data: d})
}

// setReportState is a reviewer marking a report reviewed, dismissing it or opening it
// again. It changes the report and the audit log and nothing else.
func (s *Server) setReportState(w http.ResponseWriter, r *http.Request, v Viewer) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	state := r.PostFormValue("state")
	if err != nil || !store.ValidReportState(state) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	ctx := r.Context()
	rep, err := s.st.GetPlayerReport(ctx, v.Tenant, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	back := "/reports?state=" + url.QueryEscape(rep.State)
	if rep.State != state {
		if err := s.st.SetPlayerReportState(ctx, v.Tenant, id, state, bannedBy(v), s.now()); err != nil {
			s.fail(w, err)
			return
		}
		action := map[string]string{store.ReportOpen: "report.reopen", store.ReportReviewed: "report.review", store.ReportDismissed: "report.dismiss"}[state]
		// The note stays out of the audit log: it is a player's own words.
		s.Audit(r, action, "report #"+strconv.FormatInt(id, 10), fmt.Sprintf("about %s, by %s, reason %s, match %s", rep.Reported, rep.Reporter, rep.Reason, rep.MatchID))
		s.log.Info("dashboard report", "tenant", v.Tenant, "id", id, "state", state, "by", v.Name, "remote", s.clientAddr(r))
		back += "&saved=1"
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// playerReports is the Reports card of a player's page.
type playerReports struct {
	Tally store.ReportTally // last 30 days, dismissed reports left out
	Rows  []reportRow
	More  int
}

const maxPlayerReportRows = 10

// reportsAbout builds the card for a player, or nil when nobody reported them in the
// last 30 days.
func (s *Server) reportsAbout(ctx context.Context, tenant, hash string) (*playerReports, error) {
	rows, err := s.st.ListPlayerReports(ctx, tenant, store.ReportFilter{Reported: hash, Since: s.now().Add(-reportWindow), Limit: 1000})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	v := &playerReports{}
	if len(rows) > maxPlayerReportRows {
		v.More, rows = len(rows)-maxPlayerReportRows, rows[:maxPlayerReportRows]
	}
	if v.Rows, err = s.reportRows(ctx, tenant, rows); err != nil {
		return nil, err
	}
	v.Tally = v.Rows[0].Tally
	return v, nil
}
