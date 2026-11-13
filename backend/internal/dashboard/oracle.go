package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"carthago/backend/internal/store"
)

// OracleInfo names the Carthago Oracle the gateway runs, for the label on its cards. It
// holds names and versions only. The dashboard has no access to the engine's bundle: the
// model, its thresholds and the analyst's prompts never pass through this package, so no
// page can show them.
type OracleInfo struct {
	BundleID      string
	ModelID       string
	Analyst       string // local, stub, openai, anthropic or off
	AnalystModel  string
	PromptVersion string
}

// oracleView is what the Oracle card shows for one session.
type oracleView struct {
	Engine  *OracleInfo
	Score   *store.OracleScore
	Percent int
	Signals []signalRow
	Verdict *verdictView
	// Waiting explains why a flagged session has no analyst opinion yet.
	Waiting string
}

type signalRow struct {
	Label    string
	Raises   bool
	Strength string
	// X and W place the bar in a 0..100 box whose centre line is 50: bars to the right
	// raise the score, bars to the left lower it. Widths are relative to the strongest
	// signal and stepped, so the page ranks the signals without publishing model weights.
	X, W float64
}

type verdictView struct {
	V     *store.OracleVerdict
	Cited []citedRow
	OK    bool
}

type citedRow struct {
	ID       string  `json:"id"`
	Rule     string  `json:"rule"`
	Evidence []int64 `json:"evidence"`
}

func signalRows(raw string) []signalRow {
	var sigs []struct {
		Label  string  `json:"label"`
		Effect float64 `json:"effect"`
	}
	if json.Unmarshal([]byte(raw), &sigs) != nil {
		return nil
	}
	top := 0.0
	for _, s := range sigs {
		top = math.Max(top, math.Abs(s.Effect))
	}
	var out []signalRow
	for _, s := range sigs {
		if s.Label == "" || s.Effect == 0 || top == 0 {
			continue
		}
		r := signalRow{Label: s.Label, Raises: s.Effect > 0, Strength: "weak", W: math.Max(5, 5*math.Round(10*math.Abs(s.Effect)/top))}
		switch a := math.Abs(s.Effect); {
		case a >= 2:
			r.Strength = "strong"
		case a >= 0.75:
			r.Strength = "moderate"
		}
		r.X = 50
		if !r.Raises {
			r.X = 50 - r.W
		}
		out = append(out, r)
	}
	return out
}

// ruleFlagged reports whether the rules stored something of medium severity or above
// about the session: the engine sends those to the analyst whatever the model says.
func ruleFlagged(evidence []store.Evidence) bool {
	for i := range evidence {
		if !evidence[i].Bot && evidence[i].Severity >= 2 {
			return true
		}
	}
	return false
}

func (s *Server) oracleFor(ctx context.Context, tenant string, sess *store.Session, evidence []store.Evidence) (*oracleView, error) {
	v := &oracleView{Engine: s.oracle}
	sc, err := s.st.GetOracleScore(ctx, tenant, sess.SessionID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if sc != nil {
		v.Score, v.Percent, v.Signals = sc, int(math.Round(100*sc.Score)), signalRows(sc.Signals)
	}
	vd, err := s.st.GetOracleVerdict(ctx, tenant, sess.SessionID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if vd != nil {
		vv := &verdictView{V: vd, OK: vd.Status == store.OracleVerdictOK}
		var cited []citedRow
		if json.Unmarshal([]byte(vd.Cited), &cited) == nil {
			vv.Cited = cited
		}
		v.Verdict = vv
	} else if sc != nil && (sc.Band == store.OracleBandReview || ruleFlagged(evidence)) && s.oracle != nil && s.oracle.Analyst != "off" {
		v.Waiting = "The analyst reviews a session after it has ended."
		if sess.State != store.SessionActive {
			v.Waiting = "Waiting for the analyst."
		}
	}
	if v.Score == nil && v.Verdict == nil && s.oracle == nil {
		return nil, nil // the engine is off and never saw this session: no card
	}
	return v, nil
}

var cheatNames = map[string]string{
	"none": "No cheating indicated", "aim_assistance": "Aim assistance", "wallhack_information": "Wallhack or other hidden information",
	"input_automation": "Input automation", "speed_manipulation": "Speed or clock manipulation", "client_tampering": "Client tampering",
	"mixed": "Several kinds", "inconclusive": "Inconclusive",
}

var actionNames = map[string]string{
	"no_action": "No action", "monitor": "Keep watching", "manual_review": "Review by a person", "priority_review": "Review by a person, first",
}

var labelNames = map[string]string{store.LabelConfirmedCheat: "Confirmed cheat", store.LabelCleared: "Cleared", store.LabelUnsure: "Unsure"}

var unavailableReasons = map[string]string{
	"timeout": "the analyst took too long", "provider_error": "the analyst could not be reached", "invalid_output": "the analyst's answer failed the output check",
	"rate_limited": "this studio's hourly case limit was reached", "budget_exhausted": "this studio's daily analyst budget is used up",
	"external_not_allowed": "this studio has not opted in to an external analyst", "case_rejected": "the case file failed the gateway's own check",
}

func named(m map[string]string) func(string) string {
	return func(k string) string {
		if n, ok := m[k]; ok {
			return n
		}
		return "Unknown"
	}
}

// labelCheatTypes are the kinds a reviewer can attach to a label, in form order.
var labelCheatTypes = []string{"aim_assistance", "wallhack_information", "input_automation", "speed_manipulation", "client_tampering", "mixed"}

// labelView is the reviewer-label card of a session.
type labelView struct {
	Label     *store.SessionLabel
	Suggested *store.SessionLabel
	Why       string
	Audit     []store.LabelAudit
	// CanLabel: the viewer holds the reviewer role, so the card shows its forms.
	CanLabel bool
	// Demo: signed in with the shared studio key. Nobody is known by name, so the form
	// asks for one; Reviewer is the name last given in this browser.
	Demo     bool
	Reviewer string
	// Name is the account a label will be recorded under.
	Name string
	// ShowRemote: the address a label was set from is shown to admins only, as in the
	// audit log.
	ShowRemote bool
	Types      []string
	Saved      bool
}

// reviewerCookie remembers the name a person gave with the demo login. Accounts do not
// use it: their labels carry the account's name.
const reviewerCookie = "cw_reviewer"

func (s *Server) labelFor(r *http.Request, tenant string, sess *store.Session, evidence []store.Evidence) (*labelView, error) {
	ctx := r.Context()
	v := &labelView{Types: labelCheatTypes, Saved: r.URL.Query().Get("labelled") == "1"}
	if viewer, ok := s.CurrentViewer(r); ok {
		v.CanLabel, v.Demo, v.Name, v.ShowRemote = viewer.Reviewer(), viewer.Demo, viewer.Name, viewer.Admin()
	}
	l, err := s.st.GetSessionLabel(ctx, tenant, sess.SessionID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	v.Label = l
	if v.Audit, err = s.st.ListLabelAudit(ctx, tenant, sess.SessionID, 20); err != nil {
		return nil, err
	}
	if v.Demo {
		if c, err := r.Cookie(reviewerCookie); err == nil {
			if name, err := url.QueryUnescape(c.Value); err == nil {
				v.Reviewer = cleanText(name, 64)
			}
		}
	}
	if l == nil && v.CanLabel {
		v.Suggested, v.Why = suggestLabel(sess, evidence)
	}
	return v, nil
}

// suggestLabel proposes a label for a session whose client was found tampered with: hard
// evidence the reviewer can accept with one click or overrule. Nothing is stored until a
// person accepts it.
func suggestLabel(sess *store.Session, evidence []store.Evidence) (*store.SessionLabel, string) {
	n, critical := 0, false
	for i := range evidence {
		if e := &evidence[i]; e.Integrity && !e.Bot && e.Severity >= 3 {
			n++
			critical = critical || e.Severity >= 4
		}
	}
	if n == 0 {
		return nil, ""
	}
	why := "client integrity findings of high severity"
	if critical {
		why = "client integrity findings of critical severity"
	}
	if n == 1 {
		why = strings.Replace(why, "findings", "finding", 1)
	}
	return &store.SessionLabel{TenantID: sess.TenantID, SessionID: sess.SessionID, PlayerHash: sess.PlayerHash,
		Label: store.LabelConfirmedCheat, CheatType: "client_tampering"}, itoa(n) + " " + why
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// cleanText keeps printable text on one line, at most max runes.
func cleanText(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	var b strings.Builder
	n, space := 0, true
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			r = ' '
		}
		if !unicode.IsPrint(r) {
			continue
		}
		if r == ' ' {
			if space {
				continue
			}
			space = true
		} else {
			space = false
		}
		if n == max {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// setLabel stores a reviewer's label for a session. It changes the label and its audit
// trail and nothing else: no session state, no evidence, no risk, no kick.
//
// The route needs the reviewer role, the form's CSRF token and the same origin (require).
// The label is recorded under the signed-in account's name; a name typed into the form
// is used only with the demo login, which is not a person.
func (s *Server) setLabel(w http.ResponseWriter, r *http.Request, v Viewer) {
	ctx := r.Context()
	tenant := v.Tenant
	id := r.PathValue("id")
	sess, err := s.st.GetSession(ctx, id)
	if err == nil && sess.TenantID != tenant {
		err = store.ErrNotFound
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	reviewer := v.Name
	if v.Demo {
		reviewer = cleanText(r.PostFormValue("reviewer"), 64)
	}
	l := &store.SessionLabel{TenantID: tenant, SessionID: id, PlayerHash: sess.PlayerHash, Label: r.PostFormValue("label"),
		CheatType: r.PostFormValue("cheat_type"), Note: cleanText(r.PostFormValue("note"), 280), Reviewer: reviewer, LabelledAt: s.now()}
	action := store.LabelSet
	switch l.Label {
	case store.LabelConfirmedCheat, store.LabelUnsure:
		ok := l.CheatType == ""
		for _, t := range labelCheatTypes {
			ok = ok || t == l.CheatType
		}
		if !ok {
			http.Error(w, "unknown cheat type", http.StatusBadRequest)
			return
		}
	case store.LabelCleared:
		l.CheatType = ""
	case "":
		action, l.CheatType, l.Note = store.LabelRemove, "", ""
	default:
		http.Error(w, "unknown label", http.StatusBadRequest)
		return
	}
	if r.PostFormValue("suggested") == "1" && action == store.LabelSet {
		action = store.LabelAcceptSuggestion
	}
	remote := s.clientAddr(r)
	if err := s.st.SetSessionLabel(ctx, l, action, remote); err != nil {
		s.fail(w, err)
		return
	}
	detail := "label removed"
	if action != store.LabelRemove {
		detail = l.Label
		if l.CheatType != "" {
			detail += " (" + l.CheatType + ")"
		}
		if action == store.LabelAcceptSuggestion {
			detail += ", suggestion accepted"
		}
	}
	detail += "; player " + sess.PlayerHash
	if v.Demo {
		detail += "; demo login, name given: "
		if reviewer == "" {
			detail += "none"
		} else {
			detail += reviewer
		}
	}
	s.Audit(r, "label."+action, "session "+id, detail)
	s.log.Info("dashboard label", "tenant", tenant, "session", id, "action", action, "label", l.Label, "by", v.Name, "remote", remote)
	if v.Demo && reviewer != "" {
		http.SetCookie(w, &http.Cookie{Name: reviewerCookie, Value: url.QueryEscape(reviewer), Path: "/", MaxAge: 90 * 24 * 3600,
			HttpOnly: true, Secure: s.secureCookie, SameSite: http.SameSiteStrictMode})
	}
	http.Redirect(w, r, "/sessions/"+url.PathEscape(id)+"?labelled=1#label", http.StatusSeeOther)
}

// playerOracleRow is one of a player's sessions as the Oracle and its reviewers see it.
type playerOracleRow struct {
	SessionID string
	Score     *store.OracleScore
	Percent   int
	Verdict   *store.OracleVerdict
	Label     *store.SessionLabel
}

type playerOracle struct {
	Engine *OracleInfo
	Rows   []playerOracleRow
	// Top is the highest-scoring session.
	Top *playerOracleRow
}

func (s *Server) playerOracleFor(ctx context.Context, tenant, hash string) (*playerOracle, error) {
	f := store.OracleFilter{PlayerHash: hash, Limit: 50}
	scores, err := s.st.ListOracleScores(ctx, tenant, f)
	if err != nil {
		return nil, err
	}
	verdicts, err := s.st.ListOracleVerdicts(ctx, tenant, f)
	if err != nil {
		return nil, err
	}
	labels, err := s.st.ListSessionLabels(ctx, tenant, f)
	if err != nil {
		return nil, err
	}
	if len(scores) == 0 && len(verdicts) == 0 && len(labels) == 0 {
		return nil, nil
	}
	p := &playerOracle{Engine: s.oracle}
	idx := map[string]int{}
	row := func(id string) *playerOracleRow {
		i, ok := idx[id]
		if !ok {
			i = len(p.Rows)
			idx[id] = i
			p.Rows = append(p.Rows, playerOracleRow{SessionID: id})
		}
		return &p.Rows[i]
	}
	for i := range scores {
		r := row(scores[i].SessionID)
		r.Score, r.Percent = &scores[i], int(math.Round(100*scores[i].Score))
	}
	for i := range verdicts {
		if verdicts[i].Status == store.OracleVerdictOK {
			row(verdicts[i].SessionID).Verdict = &verdicts[i]
		}
	}
	for i := range labels {
		row(labels[i].SessionID).Label = &labels[i]
	}
	for i := range p.Rows {
		if r := &p.Rows[i]; r.Score != nil && (p.Top == nil || r.Score.Score > p.Top.Score.Score) {
			p.Top = r
		}
	}
	return p, nil
}
