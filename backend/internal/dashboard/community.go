package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"carthago/backend/internal/review"
	"carthago/backend/internal/store"
)

// Community review (internal/review): players give verdicts on anonymised replays. The
// dashboard lists the cases and the reviewers, lets a studio reviewer confirm or dismiss
// what the players decided and add calibration cases, and lets an admin turn the feature
// on. Confirming a case records the studio's conclusion and scores the players who voted;
// it does not ban. A ban stays what it is everywhere else: a reviewer's own action on
// the player's page.

var reviewSources = map[string]string{
	store.ReviewSourceOracle:      "Oracle review flag",
	store.ReviewSourceReports:     "Player reports",
	store.ReviewSourceFinding:     "Gameplay finding",
	store.ReviewSourceCalibration: "Calibration",
}

var reviewAnswers = map[string]string{
	review.ClassCheating:     "Cheating",
	review.ClassToxic:        "Toxic behaviour",
	review.ClassInsufficient: "Not enough evidence",
}

var reviewVerdicts = map[string]string{
	review.VerdictAim:          "aim",
	review.VerdictWalls:        "sees through walls",
	review.VerdictOther:        "other cheating",
	review.VerdictToxic:        "toxic",
	review.VerdictInsufficient: "not enough",
}

var reviewKinds = map[string]string{"aim": "aim", "walls": "sees through walls", "other": "something else"}

var reviewBadges = map[string]string{
	"first_correct_verdict": "First correct verdict",
	"investigator":          "Investigator",
	"senior_investigator":   "Senior investigator",
	"veteran":               "Veteran",
}

type caseSplit struct {
	Label string
	N     int
}

type caseRow struct {
	review.CaseInfo
	SourceLabel string
	Answer      string // the reviewers' answer, in words
	Expected    string // a calibration case's known answer, in words
	Split       []caseSplit
	Recorded    bool
	// Correct and Wrong count the scored verdicts of a calibration case.
	Correct, Wrong int
}

type caseTab struct {
	Key, Label string
	N          int
}

type communityData struct {
	Tab      string
	Tabs     []caseTab
	Rows     []caseRow
	Set      store.ReviewSettings
	AgreePct int
	CanAct   bool
	CanAdmin bool
	Notice   string
	Error    string
}

const communityPageSize = 200

func (s *Server) communityRows(r *http.Request, tenant, tab string) ([]caseRow, error) {
	f := store.ReviewCaseFilter{State: tab, Calibration: -1, Limit: communityPageSize}
	if tab == "calibration" {
		f = store.ReviewCaseFilter{Calibration: 1, Limit: communityPageSize}
	}
	cases, err := s.rev.Cases(r.Context(), tenant, f)
	if err != nil {
		return nil, err
	}
	rows := make([]caseRow, 0, len(cases))
	for _, c := range cases {
		row := caseRow{CaseInfo: c, SourceLabel: reviewSources[c.Source], Answer: reviewAnswers[c.Verdict], Expected: reviewAnswers[c.Expected]}
		if c.Verdict == review.ClassCheating && c.Kind != "" {
			row.Answer += ": " + reviewKinds[c.Kind]
		}
		for _, v := range review.Verdicts {
			if n := c.Tally.Count[v]; n > 0 {
				row.Split = append(row.Split, caseSplit{reviewVerdicts[v], n})
			}
		}
		if _, err := s.st.GetMatchReplay(r.Context(), tenant, c.MatchID); err == nil {
			row.Recorded = true
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if c.Calibration {
			votes, err := s.st.ListReviewAssignments(r.Context(), tenant, store.ReviewAssignmentFilter{CaseID: c.ID})
			if err != nil {
				return nil, err
			}
			for _, a := range votes {
				switch a.Outcome {
				case store.ReviewCorrect:
					row.Correct++
				case store.ReviewWrong:
					row.Wrong++
				}
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func (s *Server) communityPage(w http.ResponseWriter, r *http.Request, tenant string) {
	notice := map[string]string{"settings": "Settings saved", "confirmed": "Case confirmed", "dismissed": "Case dismissed", "calibration": "Calibration case added"}[r.URL.Query().Get("ok")]
	s.renderCommunity(w, r, http.StatusOK, tenant, notice, "")
}

func (s *Server) renderCommunity(w http.ResponseWriter, r *http.Request, status int, tenant, notice, errText string) {
	ctx := r.Context()
	d := communityData{Tab: r.URL.Query().Get("tab"), Notice: notice, Error: errText}
	if v, ok := s.CurrentViewer(r); ok {
		d.CanAct, d.CanAdmin = v.Reviewer(), v.Can(RoleAdmin)
	}
	var err error
	if d.Set, err = s.rev.Settings(ctx, tenant); err != nil {
		s.fail(w, err)
		return
	}
	d.AgreePct = int(d.Set.Agreement*100 + 0.5)
	// What the gateway already holds becomes cases when the page is opened, as it does
	// when a game server asks for a link.
	if _, err := s.rev.Sweep(ctx, tenant); err != nil {
		s.fail(w, err)
		return
	}
	d.Tabs = []caseTab{{Key: store.ReviewDecided, Label: "Decided"}, {Key: store.ReviewOpen, Label: "Open"}, {Key: store.ReviewUndecided, Label: "Undecided"}, {Key: "calibration", Label: "Calibration"}}
	known := false
	for i := range d.Tabs {
		t := &d.Tabs[i]
		known = known || t.Key == d.Tab
		rows, err := s.communityRows(r, tenant, t.Key)
		if err != nil {
			s.fail(w, err)
			return
		}
		t.N = len(rows)
	}
	if !known {
		d.Tab = store.ReviewDecided
	}
	if d.Rows, err = s.communityRows(r, tenant, d.Tab); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, status, "community", page{Title: "Community review", Nav: "community", Tenant: tenant, Data: d})
}

func (s *Server) setCommunitySettings(w http.ResponseWriter, r *http.Request, v Viewer) {
	ctx := r.Context()
	set := store.ReviewSettings{Enabled: r.PostFormValue("enabled") == "1"}
	quorum, err1 := strconv.Atoi(r.PostFormValue("quorum"))
	agree, err2 := strconv.Atoi(r.PostFormValue("agreement"))
	weight, err3 := strconv.ParseFloat(r.PostFormValue("report_weight"), 64)
	set.Quorum, set.Agreement, set.ReportWeight = quorum, float64(agree)/100, weight
	err := errors.Join(err1, err2, err3)
	if err == nil {
		err = s.rev.SetSettings(ctx, v.Tenant, set)
	} else {
		err = &review.InvalidError{Msg: "the quorum, the agreement and the report weight are numbers"}
	}
	var bad *review.InvalidError
	if errors.As(err, &bad) {
		s.Audit(r, "community.settings", v.Tenant, "refused: "+bad.Msg)
		s.renderCommunity(w, r, http.StatusBadRequest, v.Tenant, "", strings.ToUpper(bad.Msg[:1])+bad.Msg[1:])
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	state := "off"
	if set.Enabled {
		state = "on"
	}
	s.Audit(r, "community.settings", v.Tenant, fmt.Sprintf("community review %s, %d verdicts close a case, %d%% agreement decides it, reports make a case from weight %.2f", state, set.Quorum, agree, set.ReportWeight))
	http.Redirect(w, r, "/community?ok=settings", http.StatusSeeOther)
}

func (s *Server) decideCommunityCase(w http.ResponseWriter, r *http.Request, v Viewer) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	decision := r.PostFormValue("decision")
	c, err := s.rev.Decide(r.Context(), v.Tenant, id, decision, bannedBy(v))
	var bad *review.InvalidError
	if errors.As(err, &bad) {
		s.renderCommunity(w, r, http.StatusBadRequest, v.Tenant, "", strings.ToUpper(bad.Msg[:1])+bad.Msg[1:])
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "community."+decision, "case #"+strconv.FormatInt(id, 10), fmt.Sprintf("%s in match %s, the players' answer: %s (%.0f%% agreement)", c.Suspect, c.MatchID, c.Verdict, c.Agreement*100))
	s.log.Info("dashboard community case", "tenant", v.Tenant, "id", id, "decision", decision, "by", v.Name, "remote", s.clientAddr(r))
	http.Redirect(w, r, "/community?ok="+decision, http.StatusSeeOther)
}

func (s *Server) addCalibrationCase(w http.ResponseWriter, r *http.Request, v Viewer) {
	match, suspect, expected := strings.TrimSpace(r.PostFormValue("match")), strings.TrimSpace(r.PostFormValue("suspect")), r.PostFormValue("expected")
	c, err := s.rev.AddCalibration(r.Context(), v.Tenant, match, suspect, expected)
	var bad *review.InvalidError
	if errors.As(err, &bad) {
		s.Audit(r, "community.calibration", match, "refused: "+bad.Msg)
		s.renderCommunity(w, r, http.StatusBadRequest, v.Tenant, "", strings.ToUpper(bad.Msg[:1])+bad.Msg[1:])
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "community.calibration", "case #"+strconv.FormatInt(c.ID, 10), fmt.Sprintf("%s in match %s, known answer %s", suspect, match, expected))
	http.Redirect(w, r, "/community?tab=calibration&ok=calibration", http.StatusSeeOther)
}

type reviewerRow struct {
	review.Standing
	Badges []string
}

type reviewersData struct {
	Rows      []reviewerRow
	MinWeight float64
	MinScored int
	Levels    []review.Level
}

func (s *Server) reviewersPage(w http.ResponseWriter, r *http.Request, tenant string) {
	list, err := s.rev.Reviewers(r.Context(), tenant)
	if err != nil {
		s.fail(w, err)
		return
	}
	d := reviewersData{MinWeight: review.MinWeight, MinScored: review.MinScored, Levels: review.Levels}
	for _, st := range list {
		row := reviewerRow{Standing: st}
		for _, b := range st.Badges {
			name := reviewBadges[b.Badge]
			if name == "" {
				name = b.Badge
			}
			row.Badges = append(row.Badges, name)
		}
		d.Rows = append(d.Rows, row)
	}
	s.render(w, http.StatusOK, "reviewers", page{Title: "Reviewers", Nav: "community", Tenant: tenant, Data: d})
}
