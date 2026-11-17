package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"carthago/backend/internal/reports"
	"carthago/backend/internal/review"
	"carthago/backend/internal/sim/localgw"
	"carthago/backend/internal/store"
)

// reviewLinkTTL is how long a review link of the demo works, so the one printed at the
// end can still be opened after a coffee. A gateway's default is 30 minutes.
const reviewLinkTTL = 12 * time.Hour

// The reviewers of the story: players of the studio's game who were in neither match.
var (
	reviewers       = []string{"lina", "mehdi", "nadia", "oussama", "rania"}
	carelessPlayer  = "karim"
	visitorReviewer = "ala"
)

// post is the studio's game server calling the game-server API with a JSON body. It
// returns the HTTP status with the answer in into.
func (s *story) post(path string, body, into any) (int, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(s.ctx, "POST", s.gw.API+path, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+localgw.ServerKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if into != nil && len(out) > 0 {
		if err := json.Unmarshal(out, into); err != nil {
			return resp.StatusCode, fmt.Errorf("POST %s: HTTP %d %s", path, resp.StatusCode, strings.TrimSpace(string(out)))
		}
	}
	return resp.StatusCode, nil
}

type reviewLink struct {
	Status    string `json:"status"`
	URL       string `json:"url"`
	ExpiresMs int64  `json:"expires_ms"`
}

// reviewLink is the game server asking for a review link for one of its players.
func (s *story) reviewLink(player string) (int, reviewLink, error) {
	var out reviewLink
	code, err := s.post("/v1/review/links", map[string]string{"player": player}, &out)
	return code, out, err
}

// pending is the case the gateway handed a reviewer and has no verdict on yet. The demo
// looks it up in the gateway's store to narrate; a game server is never told.
func (s *story) pending(player string) (*store.ReviewCase, error) {
	rows, err := s.gw.Store.ListReviewAssignments(s.ctx, localgw.Tenant, store.ReviewAssignmentFilter{Reviewer: player})
	if err != nil {
		return nil, err
	}
	for _, a := range rows {
		if a.Verdict == "" {
			return s.gw.Store.GetReviewCase(s.ctx, localgw.Tenant, a.CaseID)
		}
	}
	return nil, errors.New("no case is waiting for " + player)
}

// openReview is a player opening a review link in a browser: the page and the recording
// it plays. It fails when either names a player of the match.
func (s *story) openReview(link string, names []string) error {
	for _, path := range []string{"", "/replay.json"} {
		resp, err := http.Get(link + path)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("the review page%s: HTTP %d", path, resp.StatusCode)
		}
		// Go's client undoes the gzip the gateway declares; a recording read raw is undone here.
		if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			body, _ = io.ReadAll(zr)
		}
		text := string(body)
		if path == "" && !strings.Contains(text, "Suspect") {
			return errors.New("the review page does not name the suspect \"Suspect\"")
		}
		for _, n := range append([]string{demoMatch, toxicMatch, "information_leak"}, names...) {
			if strings.Contains(text, n) {
				return fmt.Errorf("the review page%s shows %q", path, n)
			}
		}
	}
	return nil
}

// giveVerdict is the player pressing the button of the review page.
func (s *story) giveVerdict(link, verdict string) (int, error) {
	req, err := http.NewRequestWithContext(s.ctx, "POST", link+"/verdict", strings.NewReader(url.Values{"verdict": {verdict}}.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// review has one player ask for a link, open it and give a verdict: answer(case) says
// which. It returns the case that was reviewed.
func (s *story) review(player string, names []string, answer func(*store.ReviewCase) string) (*store.ReviewCase, error) {
	code, link, err := s.reviewLink(player)
	if err != nil || code != http.StatusCreated || link.Status != "assigned" {
		return nil, fmt.Errorf("a review link for %s: HTTP %d %q %v", player, code, link.Status, err)
	}
	c, err := s.pending(player)
	if err != nil {
		return nil, err
	}
	if err := s.openReview(link.URL, names); err != nil {
		return nil, err
	}
	if code, err := s.giveVerdict(link.URL, answer(c)); err != nil || code != http.StatusOK {
		return nil, fmt.Errorf("%s's verdict: HTTP %d %v", player, code, err)
	}
	// A link gives one verdict.
	if code, _ := s.giveVerdict(link.URL, review.VerdictInsufficient); code != http.StatusConflict {
		return nil, fmt.Errorf("a second verdict on %s's link: HTTP %d, want 409", player, code)
	}
	return c, nil
}

type standingOut struct {
	Verdicts int     `json:"verdicts"`
	Scored   int     `json:"scored"`
	Correct  int     `json:"correct"`
	Weight   float64 `json:"weight"`
	Level    string  `json:"level_name"`
	Eligible bool    `json:"eligible"`
}

func (s *story) community() error {
	st := s.gw.Store
	names := append(append([]string{}, cast...), "ilyes", "sami", toxicPlayer)
	evidenceBefore, err := st.ListEvidence(s.ctx, localgw.Tenant, store.EvidenceFilter{Limit: 1000})
	if err != nil {
		return err
	}
	bansBefore, _ := st.ListBans(s.ctx, localgw.Tenant, 200)
	labelsBefore, _ := st.ListSessionLabels(s.ctx, localgw.Tenant, store.OracleFilter{Limit: 1000})

	// Off until the studio turns it on.
	if code, link, _ := s.reviewLink(reviewers[0]); code != http.StatusForbidden || link.Status != "off" {
		return fmt.Errorf("a review link with the feature off: HTTP %d %q, want 403 off", code, link.Status)
	}
	set, err := s.gw.Review.Settings(s.ctx, localgw.Tenant)
	if err != nil {
		return err
	}
	set.Enabled = true
	if err := s.gw.Review.SetSettings(s.ctx, localgw.Tenant, set); err != nil {
		return err
	}
	_ = st.AppendAudit(s.ctx, &store.AuditEntry{TenantID: localgw.Tenant, At: time.Now(), Actor: "demo", Action: "community.settings", Target: localgw.Tenant,
		Detail: fmt.Sprintf("community review on, %d verdicts close a case, %d%% agreement decides it", set.Quorum, int(set.Agreement*100+0.5))})

	// A second teammate reports walid: two reporters of weight 0.50 reach the threshold.
	mate := ""
	for _, n := range cast {
		if n != s.teamKilled {
			mate = n
			break
		}
	}
	if code, _, err := s.sendReport(reports.Submission{Reporter: mate, Reported: toxicPlayer, Match: toxicMatch, Reason: "toxic_behaviour"}); err != nil || code != http.StatusCreated {
		return fmt.Errorf("%s reports %s: HTTP %d %v", mate, toxicPlayer, code, err)
	}
	// Calibration cases: players the studio knows played fairly.
	calibration := []struct{ match, player string }{{demoMatch, "amira"}, {toxicMatch, "bilel"}, {demoMatch, "chiraz"}}
	for _, c := range calibration {
		row, err := s.gw.Review.AddCalibration(s.ctx, localgw.Tenant, c.match, c.player, review.ClassInsufficient)
		if err != nil {
			return fmt.Errorf("the calibration case %s in %s: %w", c.player, c.match, err)
		}
		_ = st.AppendAudit(s.ctx, &store.AuditEntry{TenantID: localgw.Tenant, At: time.Now(), Actor: "demo", Action: "community.calibration", Target: fmt.Sprintf("case #%d", row.ID),
			Detail: fmt.Sprintf("%s in match %s, known answer %s", c.player, c.match, review.ClassInsufficient)})
	}

	// A player of a match is never handed it, and bilel played both.
	if code, link, err := s.reviewLink("bilel"); err != nil || code != http.StatusOK || link.Status != "none" {
		return fmt.Errorf("a review link for a player of both matches: HTTP %d %q %v, want 200 none", code, link.Status, err)
	}
	cases, err := s.gw.Review.Cases(s.ctx, localgw.Tenant, store.ReviewCaseFilter{Calibration: -1})
	if err != nil {
		return err
	}
	source := map[string]string{}
	for _, c := range cases {
		source[c.Suspect+" in "+c.MatchID] = c.Source
	}
	samiCase, walidCase := source["sami in "+demoMatch], source[toxicPlayer+" in "+toxicMatch]
	if len(cases) != 2 || samiCase == "" || walidCase != store.ReviewSourceReports {
		return fmt.Errorf("the cases are %v, want sami in %s and %s in %s", source, demoMatch, toxicPlayer, toxicMatch)
	}

	// The careless reviewer convicts everyone. Every reviewer's first case is a
	// calibration case; a wrong answer there keeps the next ones calibration cases too.
	var weights []string
	for i := 0; i < review.MinScored; i++ {
		c, err := s.review(carelessPlayer, names, func(*store.ReviewCase) string { return review.VerdictAim })
		if err != nil {
			return err
		}
		if !c.Calibration {
			return fmt.Errorf("%s was handed a real case after a wrong calibration answer", carelessPlayer)
		}
		var got standingOut
		if err := s.call("/v1/review/standing?player="+carelessPlayer, &got); err != nil {
			return err
		}
		weights = append(weights, fmt.Sprintf("%.2f", got.Weight))
	}
	var careless standingOut
	if err := s.call("/v1/review/standing?player="+carelessPlayer, &careless); err != nil {
		return err
	}
	code, refused, _ := s.reviewLink(carelessPlayer)
	if careless.Eligible || careless.Correct != 0 || code != http.StatusForbidden || refused.Status != "not_eligible" {
		return fmt.Errorf("the careless reviewer is still handed cases: %+v, HTTP %d %q", careless, code, refused.Status)
	}

	// Five careful reviewers: a calibration case each, answered right, then sami's match.
	verdicts := []string{review.VerdictWalls, review.VerdictWalls, review.VerdictAim, review.VerdictWalls, review.VerdictInsufficient}
	var decided *store.ReviewCase
	for i, name := range reviewers {
		first, err := s.review(name, names, func(c *store.ReviewCase) string { return review.VerdictInsufficient })
		if err != nil {
			return err
		}
		if !first.Calibration {
			return fmt.Errorf("%s's first case was not a calibration case", name)
		}
		c, err := s.review(name, names, func(*store.ReviewCase) string { return verdicts[i] })
		if err != nil {
			return err
		}
		if c.Calibration || c.Suspect != "sami" {
			return fmt.Errorf("%s's second case was %s in %s, want sami's match", name, c.Suspect, c.MatchID)
		}
		decided = c
	}
	if decided, err = st.GetReviewCase(s.ctx, localgw.Tenant, decided.ID); err != nil {
		return err
	}
	if decided.State != store.ReviewDecided || decided.Verdict != review.ClassCheating || decided.Kind != "walls" || decided.Agreement < 0.79 || decided.Decision != "" {
		return fmt.Errorf("sami's case closed as %s %s %s with %.0f%% agreement", decided.State, decided.Verdict, decided.Kind, decided.Agreement*100)
	}

	// Advice only.
	evidenceAfter, _ := st.ListEvidence(s.ctx, localgw.Tenant, store.EvidenceFilter{Limit: 1000})
	bansAfter, _ := st.ListBans(s.ctx, localgw.Tenant, 200)
	labelsAfter, _ := st.ListSessionLabels(s.ctx, localgw.Tenant, store.OracleFilter{Limit: 1000})
	if len(evidenceAfter) != len(evidenceBefore) || len(bansAfter) != len(bansBefore) || len(labelsAfter) != len(labelsBefore) {
		return errors.New("community review added evidence, a ban or a label for the Oracle")
	}
	for _, n := range []string{"sami", toxicPlayer} {
		status, err := s.shadowStatus(n)
		if err != nil {
			return err
		}
		if s.ban(n) != nil || status != "normal" || !s.players[n].Online() || s.players[n].Seen().Notices != 0 {
			return fmt.Errorf("community review banned, pooled, ended or told %s", n)
		}
	}

	// Badges: the game server reads the new ones, grants what the studio grants, and
	// acknowledges them.
	var fresh struct {
		Badges []struct{ Player, Badge string }
	}
	if err := s.call("/v1/review/badges", &fresh); err != nil {
		return err
	}
	if len(fresh.Badges) != len(reviewers) {
		return fmt.Errorf("%d new badges, want one for each of the %d careful reviewers", len(fresh.Badges), len(reviewers))
	}
	for _, b := range fresh.Badges {
		var ack struct{ Acknowledged int }
		if code, err := s.post("/v1/review/badges/ack", map[string]any{"player": b.Player, "badges": []string{b.Badge}}, &ack); err != nil || code != http.StatusOK || ack.Acknowledged != 1 {
			return fmt.Errorf("acknowledging %s's badge: HTTP %d %v", b.Player, code, err)
		}
	}
	if err := s.call("/v1/review/badges", &fresh); err != nil || len(fresh.Badges) != 0 {
		return fmt.Errorf("%d badges are still new after the acknowledgement (%v)", len(fresh.Badges), err)
	}
	var careful standingOut
	if err := s.call("/v1/review/standing?player="+reviewers[0], &careful); err != nil {
		return err
	}

	// A link for the person watching the demo.
	code, mine, err := s.reviewLink(visitorReviewer)
	if err != nil || code != http.StatusCreated {
		return fmt.Errorf("a review link for %s: HTTP %d %v", visitorReviewer, code, err)
	}
	first, err := s.pending(visitorReviewer)
	if err != nil {
		return err
	}
	s.reviewURL = mine.URL

	s.say("The studio turns community review on (it is off by default) and adds %d calibration cases: players of the", len(calibration))
	s.say("two recorded matches it knows played fairly. sami's match is a case already (source: %s),", strings.ReplaceAll(reviewSourceName(samiCase), "_", " "))
	s.say("and a second report about %s, by %s, brings his reports to weight 1.00: a second case.", toxicPlayer, mate)
	s.say("Reviewers are players. The game server asks POST /v1/review/links for a player it finds eligible and gets a")
	s.say("signed link; the gateway picks the case. bilel, who played both matches, gets none.")
	s.say("- %s calls everyone a cheater. His first case is a calibration case, as every reviewer's is; he is wrong,", carelessPlayer)
	s.say("  so the next are calibration cases too. Weight 0.50 > %s. After %d wrong answers the", strings.Join(weights, " > "), review.MinScored)
	s.say("  gateway hands him no more cases (HTTP 403 not_eligible). He never reached a real case.")
	s.say("- %s each get a calibration case, answer it right (weight %.2f), and then", list(reviewers), careful.Weight)
	s.say("  sami's match from above: \"Suspect\" and nine numbered players, no names, no findings, no scores.")
	s.say("  3 say sees through walls, 1 says aim, 1 says not enough evidence. Five verdicts close the case:")
	s.say("  decided, cheating (sees through walls), %.0f%% weighted agreement.", decided.Agreement*100)
	s.say("That is advice for the studio's reviewer, who confirms or dismisses it: %s/community", s.gw.Dashboard)
	s.say("sami is not banned, not pooled, not ended, not told; no evidence was added and the Oracle got no label.")
	s.say("Each careful reviewer earned the badge first_correct_verdict (level %s). The game server read the %d new", careful.Level, len(reviewers))
	s.say("badges from GET /v1/review/badges, would grant what the studio grants for them, and acknowledged them.")
	s.say("Your turn: a review link for the player \"%s\" is printed below.", visitorReviewer)
	if first.Calibration {
		s.say("It opens a calibration case, as every reviewer's first is, so your verdict is scored the moment you give it.")
	}
	return nil
}

func reviewSourceName(source string) string {
	switch source {
	case store.ReviewSourceOracle:
		return "an Oracle review flag"
	case store.ReviewSourceFinding:
		return "a gameplay finding"
	case store.ReviewSourceReports:
		return "player reports"
	}
	return source
}
