// Package review is community review: players watch the anonymised replay of a suspicious
// match and say what they saw, several players per case, and the studio's reviewers get
// the result as advice.
//
// A case is one suspect in one recorded match. It comes from an Oracle review flag, from
// reports whose reporters weigh enough together, or from a gameplay finding. The studio's
// game server asks for a review link for a player it considers eligible; the gateway picks
// the case (never the player), and the player opens the link, watches and gives a verdict.
// When enough verdicts are in, the case closes: decided when the weighted share behind
// the leading answer passes the studio's threshold, undecided otherwise.
//
// Everything here is advice. This package reads evidence, Oracle scores, reports and bans
// to find cases, and writes only its own tables. It holds no ban service, no session
// table, no shadow pool and no label store, so it cannot ban, kick, pool or teach the
// Oracle; a decided case waits for a studio reviewer, who confirms or dismisses it.
//
// Reviewers are scored against what is known: calibration cases with a set answer, mixed
// in among the real ones, and the studio's decision on the cases they voted on. A weight
// follows from that score, and levels and badges from the number of correct verdicts. The
// gateway grants nothing in a game: the game server reads standing and badges and grants
// what the studio wants.
package review

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"carthago/backend/internal/reports"
	"carthago/backend/internal/store"
)

// Store is what community review reads and writes. It writes through ReviewStore only.
type Store interface {
	store.ReviewStore
	GetMatchReplay(ctx context.Context, tenant, matchID string) (*store.MatchReplay, error)
	ListEvidence(ctx context.Context, tenant string, f store.EvidenceFilter) ([]store.Evidence, error)
	ListOracleScores(ctx context.Context, tenant string, f store.OracleFilter) ([]store.OracleScore, error)
	ListPlayerReports(ctx context.Context, tenant string, f store.ReportFilter) ([]store.PlayerReport, error)
	ListBans(ctx context.Context, tenant string, limit int) ([]store.Ban, error)
	GetMapOutline(ctx context.Context, tenant, mapID string) (*store.MapOutline, error)
}

// The verdicts a reviewer can give, and the three answers they fall into.
const (
	VerdictAim          = "cheating_aim"
	VerdictWalls        = "cheating_walls"
	VerdictOther        = "cheating_other"
	VerdictToxic        = "toxic"
	VerdictInsufficient = "insufficient"

	ClassCheating     = "cheating"
	ClassToxic        = "toxic"
	ClassInsufficient = "insufficient"
)

// Verdicts lists the verdicts in the order the review page offers them.
var Verdicts = []string{VerdictAim, VerdictWalls, VerdictOther, VerdictToxic, VerdictInsufficient}

// ClassOf is the answer a verdict stands for; empty for something that is not a verdict.
func ClassOf(verdict string) string {
	switch verdict {
	case VerdictAim, VerdictWalls, VerdictOther:
		return ClassCheating
	case VerdictToxic:
		return ClassToxic
	case VerdictInsufficient:
		return ClassInsufficient
	}
	return ""
}

func validClass(c string) bool {
	return c == ClassCheating || c == ClassToxic || c == ClassInsufficient
}

const (
	// DefaultLinkTTL is how long a review link works.
	DefaultLinkTTL = 30 * time.Minute
	// DefaultPerHour and DefaultPerDay are how many cases one reviewer is handed.
	DefaultPerHour = 6
	DefaultPerDay  = 20
	// MinWeight and MinScored: a reviewer whose weight is below MinWeight once at least
	// MinScored verdicts were scored is no longer handed cases.
	MinWeight = 0.25
	MinScored = 3
	// calibrationEvery: one case in this many is a calibration case, besides a reviewer's
	// first case and every case of a reviewer who has been wrong more often than right.
	calibrationEvery = 4
	// reportWindow is how far back reports count toward a case.
	reportWindow = 30 * 24 * time.Hour
	// sweepRows bounds each list a sweep looks at.
	sweepRows = 500
)

var (
	// ErrOff: the studio has not turned community review on.
	ErrOff = errors.New("review: community review is off for this studio")
	// ErrNotEligible: the reviewer's verdicts were wrong too often.
	ErrNotEligible = errors.New("review: this player is no longer eligible to review")
	// ErrNothing: there is no case this reviewer may be handed.
	ErrNothing = errors.New("review: no case to review")
	// ErrBadLink: the link is not one the gateway signed, or it has expired.
	ErrBadLink = errors.New("review: the link is not valid or has expired")
	// ErrVoted: the verdict of this link was already given.
	ErrVoted = errors.New("review: the verdict was already given")
	// ErrClosed: the case closed before this verdict came in.
	ErrClosed = errors.New("review: the case is closed")
)

// InvalidError says what is wrong with a call, in words for whoever made it.
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &InvalidError{fmt.Sprintf(format, a...)} }

// RateError: the reviewer was handed as many cases as one reviewer gets for now.
type RateError struct{ RetryAfter time.Duration }

func (e *RateError) Error() string {
	return fmt.Sprintf("this player has been handed as many cases as one reviewer gets; try again in %s", e.RetryAfter.Round(time.Minute))
}

type Config struct {
	// Key signs review links. Without it the service hands out none; the dashboard runs
	// one like that.
	Key []byte
	// LinkTTL is how long a link works; DefaultLinkTTL when zero.
	LinkTTL time.Duration
	// PerHour and PerDay bound the cases handed to one reviewer.
	PerHour, PerDay int
	Now             func() time.Time
}

type Service struct {
	st  Store
	cfg Config
}

func New(st Store, cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.LinkTTL <= 0 {
		cfg.LinkTTL = DefaultLinkTTL
	}
	if cfg.PerHour <= 0 {
		cfg.PerHour = DefaultPerHour
	}
	if cfg.PerDay <= 0 {
		cfg.PerDay = DefaultPerDay
	}
	return &Service{st: st, cfg: cfg}
}

func validID(s string) bool {
	return s != "" && len(s) <= 128 && utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) })
}

// Settings is the studio's switch and thresholds.
func (s *Service) Settings(ctx context.Context, tenant string) (store.ReviewSettings, error) {
	return s.st.ReviewSettings(ctx, tenant)
}

// SetSettings stores the studio's switch and thresholds.
func (s *Service) SetSettings(ctx context.Context, tenant string, v store.ReviewSettings) error {
	if v.Quorum < 3 || v.Quorum > 25 {
		return invalid("a case closes after 3 to 25 verdicts")
	}
	if v.Agreement < 0.5 || v.Agreement > 1 {
		return invalid("the agreement a decision needs is between 50%% and 100%%")
	}
	if v.ReportWeight < 0.5 || v.ReportWeight > 20 {
		return invalid("the report weight that makes a case is between 0.5 and 20")
	}
	return s.st.PutReviewSettings(ctx, tenant, v, s.cfg.Now())
}

// suspectIn reports whether the match was recorded with that player in it.
func (s *Service) suspectIn(ctx context.Context, tenant, matchID, player string) (bool, error) {
	rec, err := s.st.GetMatchReplay(ctx, tenant, matchID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, p := range rec.Players {
		if p.PlayerHash == player && !p.Bot {
			return true, nil
		}
	}
	return false, nil
}

// Sweep makes cases of what the gateway already holds: Oracle review flags, gameplay
// findings, and reports whose reporters weigh enough together. A case needs a recorded
// match with the suspect in it, since the replay is all a reviewer sees. It returns how
// many cases were added, and does nothing while the studio has the feature off.
func (s *Service) Sweep(ctx context.Context, tenant string) (int, error) {
	set, err := s.st.ReviewSettings(ctx, tenant)
	if err != nil || !set.Enabled {
		return 0, err
	}
	type cand struct{ match, suspect, source string }
	var cands []cand
	scores, err := s.st.ListOracleScores(ctx, tenant, store.OracleFilter{Limit: sweepRows})
	if err != nil {
		return 0, err
	}
	for _, sc := range scores {
		if sc.Band == store.OracleBandReview && sc.MatchID != "" {
			cands = append(cands, cand{sc.MatchID, sc.PlayerHash, store.ReviewSourceOracle})
		}
	}
	evs, err := s.st.ListEvidence(ctx, tenant, store.EvidenceFilter{MinSeverity: 2, Limit: sweepRows})
	if err != nil {
		return 0, err
	}
	for _, e := range evs {
		if e.Source == store.SourceGameplay && e.MatchID != "" && !e.Bot {
			cands = append(cands, cand{e.MatchID, e.PlayerHash, store.ReviewSourceFinding})
		}
	}
	rows, err := s.st.ListPlayerReports(ctx, tenant, store.ReportFilter{State: store.ReportOpen, Since: s.cfg.Now().Add(-reportWindow), Limit: sweepRows})
	if err != nil {
		return 0, err
	}
	if len(rows) > 0 {
		confirmed, err := s.confirmed(ctx, tenant)
		if err != nil {
			return 0, err
		}
		weights := map[string]float64{}
		sum := map[cand]float64{}
		var order []cand
		for _, r := range rows {
			w, ok := weights[r.Reporter]
			if !ok {
				theirs, err := s.st.ListPlayerReports(ctx, tenant, store.ReportFilter{Reporter: r.Reporter, Limit: sweepRows})
				if err != nil {
					return 0, err
				}
				w = reports.WeightOf(theirs, confirmed).Value
				weights[r.Reporter] = w
			}
			k := cand{r.MatchID, r.Reported, store.ReviewSourceReports}
			if _, seen := sum[k]; !seen {
				order = append(order, k)
			}
			sum[k] += w
		}
		for _, k := range order {
			if sum[k] >= set.ReportWeight {
				cands = append(cands, k)
			}
		}
	}
	added := 0
	for _, c := range cands {
		if ok, err := s.suspectIn(ctx, tenant, c.match, c.suspect); err != nil {
			return added, err
		} else if !ok {
			continue
		}
		ok, err := s.st.AddReviewCase(ctx, &store.ReviewCase{TenantID: tenant, MatchID: c.match, Suspect: c.suspect, Source: c.source, CreatedAt: s.cfg.Now()})
		if err != nil {
			return added, err
		}
		if ok {
			added++
		}
	}
	return added, nil
}

// confirmed says whether a reported player has a ban that stands, as the Reports page
// counts it for a reporter's weight.
func (s *Service) confirmed(ctx context.Context, tenant string) (func(string) bool, error) {
	bans, err := s.st.ListBans(ctx, tenant, 1000)
	if err != nil {
		return nil, err
	}
	banned := map[string]bool{}
	for _, b := range bans {
		if b.LiftedAt.IsZero() {
			banned[b.PlayerHash] = true
		}
	}
	return func(p string) bool { return banned[p] }, nil
}

// AddCalibration makes a calibration case: a recorded match and a player in it whose
// answer the studio knows. It is handed to reviewers among the real cases and never
// closes; a reviewer's verdict on it is scored at once.
func (s *Service) AddCalibration(ctx context.Context, tenant, matchID, suspect, expected string) (*store.ReviewCase, error) {
	if !validClass(expected) {
		return nil, invalid("the known answer is cheating, toxic or insufficient")
	}
	if ok, err := s.suspectIn(ctx, tenant, matchID, suspect); err != nil {
		return nil, err
	} else if !ok {
		return nil, invalid("there is no recorded match %q with the player %q in it", matchID, suspect)
	}
	c := &store.ReviewCase{TenantID: tenant, MatchID: matchID, Suspect: suspect, Source: store.ReviewSourceCalibration, Calibration: true, Expected: expected, CreatedAt: s.cfg.Now()}
	added, err := s.st.AddReviewCase(ctx, c)
	if err != nil {
		return nil, err
	}
	if !added {
		return nil, invalid("that player in that match is a case already")
	}
	return c, nil
}

// Link is a review link handed to one reviewer.
type Link struct {
	// Path is the page's path on the gateway, /review/<token>.
	Path      string
	ExpiresAt time.Time
	// Assignment is the row behind the link. It is for the gateway's own callers and
	// tests; a game server is not told which case a link opens.
	Assignment store.ReviewAssignment
}

// Assign hands the reviewer a case and returns the link to it. The gateway chooses the
// case: never a match the reviewer played in, a suspect the reviewer reported or was
// already handed, or a case the reviewer has seen. A reviewer who still has a case
// without a verdict gets that one again.
func (s *Service) Assign(ctx context.Context, tenant, reviewer string) (*Link, error) {
	if len(s.cfg.Key) == 0 {
		return nil, errors.New("review: no key to sign links with")
	}
	if !validID(reviewer) {
		return nil, invalid("player must be 1 to 128 bytes without spaces or control characters")
	}
	set, err := s.st.ReviewSettings(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if !set.Enabled {
		return nil, ErrOff
	}
	if _, err := s.Sweep(ctx, tenant); err != nil {
		return nil, err
	}
	mine, err := s.st.ListReviewAssignments(ctx, tenant, store.ReviewAssignmentFilter{Reviewer: reviewer})
	if err != nil {
		return nil, err
	}
	standing := standingOf(reviewer, mine)
	if !standing.Eligible {
		return nil, ErrNotEligible
	}
	now := s.cfg.Now()
	seenCase, seenSuspect := map[int64]bool{}, map[string]bool{}
	var hour, day int
	var oldestHour, oldestDay time.Time
	for i := range mine {
		a := &mine[i]
		seenCase[a.CaseID], seenSuspect[a.Suspect] = true, true
		if age := now.Sub(a.AssignedAt); age < 24*time.Hour {
			if day++; oldestDay.IsZero() {
				oldestDay = a.AssignedAt
			}
			if age < time.Hour {
				if hour++; oldestHour.IsZero() {
					oldestHour = a.AssignedAt
				}
			}
		}
	}
	// A case still waiting for this reviewer's verdict is handed out again.
	for i := range mine {
		a := &mine[i]
		if a.Verdict != "" {
			continue
		}
		c, err := s.st.GetReviewCase(ctx, tenant, a.CaseID)
		if err != nil || (!c.Calibration && c.State != store.ReviewOpen) {
			continue
		}
		a.ExpiresAt = now.Add(s.cfg.LinkTTL)
		if err := s.st.ExtendReviewAssignment(ctx, tenant, a.ID, a.ExpiresAt); err != nil {
			return nil, err
		}
		return s.link(a), nil
	}
	if hour >= s.cfg.PerHour {
		return nil, &RateError{RetryAfter: oldestHour.Add(time.Hour).Sub(now)}
	}
	if day >= s.cfg.PerDay {
		return nil, &RateError{RetryAfter: oldestDay.Add(24 * time.Hour).Sub(now)}
	}

	allowed := func(c *store.ReviewCase) (bool, error) {
		if seenCase[c.ID] || seenSuspect[c.Suspect] || c.Suspect == reviewer {
			return false, nil
		}
		rec, err := s.st.GetMatchReplay(ctx, tenant, c.MatchID)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		for _, p := range rec.Players {
			if p.PlayerHash == reviewer {
				return false, nil
			}
		}
		reported, err := s.st.ListPlayerReports(ctx, tenant, store.ReportFilter{Reporter: reviewer, Reported: c.Suspect, Limit: 1})
		return len(reported) == 0, err
	}
	pick := func(calibration bool) (*store.ReviewCase, error) {
		f := store.ReviewCaseFilter{Calibration: -1, State: store.ReviewOpen}
		if calibration {
			f = store.ReviewCaseFilter{Calibration: 1}
		}
		cases, err := s.st.ListReviewCases(ctx, tenant, f)
		if err != nil {
			return nil, err
		}
		type ranked struct {
			c     *store.ReviewCase
			votes int
			key   [32]byte
		}
		var open []ranked
		for i := range cases {
			c := &cases[i]
			if ok, err := allowed(c); err != nil {
				return nil, err
			} else if !ok {
				continue
			}
			r := ranked{c: c, key: sha256.Sum256(fmt.Appendf(nil, "%s\x00%d", reviewer, c.ID))}
			if !calibration {
				votes, err := s.st.ListReviewAssignments(ctx, tenant, store.ReviewAssignmentFilter{CaseID: c.ID})
				if err != nil {
					return nil, err
				}
				for _, v := range votes {
					if v.Verdict != "" {
						r.votes++
					}
				}
			}
			open = append(open, r)
		}
		if len(open) == 0 {
			return nil, nil
		}
		// A real case: the one nearest its quorum, then the oldest. A calibration case:
		// in an order of the reviewer's own, so two reviewers do not get the same first.
		sort.SliceStable(open, func(i, j int) bool {
			if calibration {
				return string(open[i].key[:]) < string(open[j].key[:])
			}
			return open[i].votes > open[j].votes
		})
		return open[0].c, nil
	}
	due := len(mine) == 0 || standing.Weight < 0.5 || len(mine)%calibrationEvery == 0
	var c *store.ReviewCase
	for _, calibration := range []bool{due, !due} {
		if c, err = pick(calibration); err != nil {
			return nil, err
		}
		if c != nil {
			break
		}
	}
	if c == nil {
		return nil, ErrNothing
	}
	a := &store.ReviewAssignment{TenantID: tenant, CaseID: c.ID, Reviewer: reviewer, Suspect: c.Suspect, Calibration: c.Calibration, AssignedAt: now, ExpiresAt: now.Add(s.cfg.LinkTTL)}
	if err := s.st.AddReviewAssignment(ctx, a); err != nil {
		return nil, err
	}
	return s.link(a), nil
}

func (s *Service) link(a *store.ReviewAssignment) *Link {
	return &Link{Path: "/review/" + s.sign(a.TenantID, a.ID, a.ExpiresAt), ExpiresAt: a.ExpiresAt, Assignment: *a}
}

// Session is what a valid link opens: the assignment and its case.
type Session struct {
	Assignment *store.ReviewAssignment
	Case       *store.ReviewCase
}

// Open checks a link's token and returns what it opens. Every failure is ErrBadLink: a
// token the gateway did not sign, one that expired, one whose assignment is gone, and one
// of a studio that turned the feature off look the same from outside.
func (s *Service) Open(ctx context.Context, token string) (*Session, error) {
	tenant, id, ok := s.verify(token)
	if !ok {
		return nil, ErrBadLink
	}
	set, err := s.st.ReviewSettings(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if !set.Enabled {
		return nil, ErrBadLink
	}
	a, err := s.st.GetReviewAssignment(ctx, tenant, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrBadLink
	}
	if err != nil {
		return nil, err
	}
	c, err := s.st.GetReviewCase(ctx, tenant, a.CaseID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrBadLink
	}
	if err != nil {
		return nil, err
	}
	return &Session{Assignment: a, Case: c}, nil
}

// Vote records the verdict of a link. A link gives one verdict.
func (s *Service) Vote(ctx context.Context, token, verdict string) error {
	sess, err := s.Open(ctx, token)
	if err != nil {
		return err
	}
	class := ClassOf(verdict)
	if class == "" {
		return invalid("that is not one of the verdicts")
	}
	a, c := sess.Assignment, sess.Case
	if a.Verdict != "" {
		return ErrVoted
	}
	if !c.Calibration && c.State != store.ReviewOpen {
		return ErrClosed
	}
	mine, err := s.st.ListReviewAssignments(ctx, a.TenantID, store.ReviewAssignmentFilter{Reviewer: a.Reviewer})
	if err != nil {
		return err
	}
	outcome := ""
	if c.Calibration {
		if outcome = store.ReviewWrong; class == c.Expected {
			outcome = store.ReviewCorrect
		}
	}
	cast, err := s.st.CastReviewVerdict(ctx, a.TenantID, a.ID, verdict, standingOf(a.Reviewer, mine).Weight, outcome, s.cfg.Now())
	if err != nil {
		return err
	}
	if !cast {
		return ErrVoted
	}
	if c.Calibration {
		return s.award(ctx, a.TenantID, a.Reviewer)
	}
	return s.closeIfDue(ctx, c)
}

// Tally is how the verdicts of a case stand.
type Tally struct {
	Votes int
	// Count and Weight are per verdict (cheating_aim, ...); ClassWeight per answer.
	Count       map[string]int
	Weight      map[string]float64
	ClassWeight map[string]float64
	Total       float64
	// Lead is the answer with the most weight behind it, Share its part of the total, and
	// Kind the kind of cheating with the most weight when Lead is cheating.
	Lead  string
	Share float64
	Kind  string
}

// TallyOf counts the verdicts among a case's assignments.
func TallyOf(rows []store.ReviewAssignment) Tally {
	t := Tally{Count: map[string]int{}, Weight: map[string]float64{}, ClassWeight: map[string]float64{}}
	for _, a := range rows {
		if a.Verdict == "" {
			continue
		}
		t.Votes++
		t.Count[a.Verdict]++
		t.Weight[a.Verdict] += a.Weight
		t.ClassWeight[ClassOf(a.Verdict)] += a.Weight
		t.Total += a.Weight
	}
	for _, class := range []string{ClassCheating, ClassToxic, ClassInsufficient} {
		if t.ClassWeight[class] > t.ClassWeight[t.Lead] {
			t.Lead = class
		}
	}
	if t.Total > 0 {
		t.Share = t.ClassWeight[t.Lead] / t.Total
	}
	if t.Lead == ClassCheating {
		for _, v := range []string{VerdictAim, VerdictWalls, VerdictOther} {
			if t.Weight[v] > t.Weight["cheating_"+t.Kind] {
				t.Kind = strings.TrimPrefix(v, "cheating_")
			}
		}
	}
	return t
}

// closeIfDue closes a case once its quorum of verdicts is in.
func (s *Service) closeIfDue(ctx context.Context, c *store.ReviewCase) error {
	set, err := s.st.ReviewSettings(ctx, c.TenantID)
	if err != nil {
		return err
	}
	rows, err := s.st.ListReviewAssignments(ctx, c.TenantID, store.ReviewAssignmentFilter{CaseID: c.ID})
	if err != nil {
		return err
	}
	t := TallyOf(rows)
	if t.Votes < set.Quorum {
		return nil
	}
	c.State, c.Verdict, c.Kind, c.Agreement, c.ClosedAt = store.ReviewUndecided, "", "", t.Share, s.cfg.Now()
	if t.Lead != "" && t.Share >= set.Agreement {
		c.State, c.Verdict, c.Kind = store.ReviewDecided, t.Lead, t.Kind
	}
	return s.st.UpdateReviewCase(ctx, c)
}

// Decide records what a studio reviewer made of a decided case, and scores the reviewers
// who voted on it: with the case confirmed, those who gave its answer were right and the
// others wrong; with it dismissed, those who gave its answer were wrong, those who said
// there was not enough evidence were right, and the rest are not scored. It changes
// nothing about the suspect: a ban is the studio reviewer's own, separate, action.
func (s *Service) Decide(ctx context.Context, tenant string, id int64, decision, by string) (*store.ReviewCase, error) {
	if decision != store.ReviewConfirmed && decision != store.ReviewDismissed {
		return nil, invalid("a case is confirmed or dismissed")
	}
	c, err := s.st.GetReviewCase(ctx, tenant, id)
	if err != nil {
		return nil, err
	}
	if c.Calibration || c.State != store.ReviewDecided {
		return nil, invalid("only a case the reviewers decided can be confirmed or dismissed")
	}
	c.Decision, c.DecidedBy, c.DecidedAt = decision, by, s.cfg.Now()
	if err := s.st.UpdateReviewCase(ctx, c); err != nil {
		return nil, err
	}
	rows, err := s.st.ListReviewAssignments(ctx, tenant, store.ReviewAssignmentFilter{CaseID: id})
	if err != nil {
		return nil, err
	}
	for _, a := range rows {
		if a.Verdict == "" {
			continue
		}
		class, outcome := ClassOf(a.Verdict), ""
		switch {
		case decision == store.ReviewConfirmed && class == c.Verdict:
			outcome = store.ReviewCorrect
		case decision == store.ReviewConfirmed:
			outcome = store.ReviewWrong
		case class == c.Verdict:
			outcome = store.ReviewWrong
		case class == ClassInsufficient:
			outcome = store.ReviewCorrect
		}
		if err := s.st.SetReviewOutcome(ctx, tenant, a.ID, outcome); err != nil {
			return nil, err
		}
		if err := s.award(ctx, tenant, a.Reviewer); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Level is a step a reviewer reaches with correct verdicts. Reaching it earns its badge.
type Level struct {
	Correct int
	Name    string
	Badge   string
}

// Levels are the steps, lowest first.
var Levels = []Level{
	{1, "Reviewer", "first_correct_verdict"},
	{5, "Investigator", "investigator"},
	{25, "Senior investigator", "senior_investigator"},
	{100, "Veteran", "veteran"},
}

// Standing is how a reviewer has done.
type Standing struct {
	Reviewer string
	// Assigned cases, Verdicts given, and of those the Scored ones (the answer is known)
	// and the Correct ones. Calibration and CalibrationCorrect are the part of Scored and
	// Correct that came from calibration cases.
	Assigned, Verdicts, Scored, Correct int
	Calibration, CalibrationCorrect     int
	// Accuracy is Correct / Scored, 0 without a scored verdict.
	Accuracy float64
	// Weight is (Correct + 1) / (Scored + 2): 0.50 for a new reviewer.
	Weight float64
	// Level counts the Levels reached; LevelName is "New" at 0.
	Level     int
	LevelName string
	// Eligible is false once the weight fell below MinWeight with MinScored verdicts scored.
	Eligible bool
	LastAt   time.Time
	Badges   []store.ReviewBadge
}

func standingOf(reviewer string, rows []store.ReviewAssignment) Standing {
	st := Standing{Reviewer: reviewer, LevelName: "New"}
	for _, a := range rows {
		st.Assigned++
		if a.AssignedAt.After(st.LastAt) {
			st.LastAt = a.AssignedAt
		}
		if a.Verdict == "" {
			continue
		}
		st.Verdicts++
		if a.Outcome == "" {
			continue
		}
		st.Scored++
		if a.Calibration {
			st.Calibration++
		}
		if a.Outcome == store.ReviewCorrect {
			st.Correct++
			if a.Calibration {
				st.CalibrationCorrect++
			}
		}
	}
	if st.Scored > 0 {
		st.Accuracy = float64(st.Correct) / float64(st.Scored)
	}
	st.Weight = float64(st.Correct+1) / float64(st.Scored+2)
	for _, l := range Levels {
		if st.Correct >= l.Correct {
			st.Level++
			st.LevelName = l.Name
		}
	}
	st.Eligible = st.Scored < MinScored || st.Weight >= MinWeight
	return st
}

// award records the badges of the levels a reviewer has reached.
func (s *Service) award(ctx context.Context, tenant, reviewer string) error {
	rows, err := s.st.ListReviewAssignments(ctx, tenant, store.ReviewAssignmentFilter{Reviewer: reviewer})
	if err != nil {
		return err
	}
	st := standingOf(reviewer, rows)
	for _, l := range Levels {
		if st.Correct >= l.Correct {
			if _, err := s.st.AddReviewBadge(ctx, tenant, reviewer, l.Badge, s.cfg.Now()); err != nil {
				return err
			}
		}
	}
	return nil
}

// Standing is one reviewer's standing with the badges earned. A player who never
// reviewed has the standing of a new reviewer.
func (s *Service) Standing(ctx context.Context, tenant, reviewer string) (Standing, error) {
	if !validID(reviewer) {
		return Standing{}, invalid("player must be 1 to 128 bytes without spaces or control characters")
	}
	rows, err := s.st.ListReviewAssignments(ctx, tenant, store.ReviewAssignmentFilter{Reviewer: reviewer})
	if err != nil {
		return Standing{}, err
	}
	st := standingOf(reviewer, rows)
	st.Badges, err = s.st.ListReviewBadges(ctx, tenant, reviewer, false, 0)
	return st, err
}

// Reviewers is the standing of every reviewer of the studio, the most verdicts first.
func (s *Service) Reviewers(ctx context.Context, tenant string) ([]Standing, error) {
	rows, err := s.st.ListReviewAssignments(ctx, tenant, store.ReviewAssignmentFilter{})
	if err != nil {
		return nil, err
	}
	by := map[string][]store.ReviewAssignment{}
	var order []string
	for _, a := range rows {
		if _, ok := by[a.Reviewer]; !ok {
			order = append(order, a.Reviewer)
		}
		by[a.Reviewer] = append(by[a.Reviewer], a)
	}
	badges, err := s.st.ListReviewBadges(ctx, tenant, "", false, 1000)
	if err != nil {
		return nil, err
	}
	out := make([]Standing, 0, len(order))
	for _, r := range order {
		st := standingOf(r, by[r])
		for _, b := range badges {
			if b.Reviewer == r {
				st.Badges = append(st.Badges, b)
			}
		}
		out = append(out, st)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Verdicts > out[j].Verdicts })
	return out, nil
}

// NewBadges are the badges the studio's game server has not acknowledged yet.
func (s *Service) NewBadges(ctx context.Context, tenant string) ([]store.ReviewBadge, error) {
	return s.st.ListReviewBadges(ctx, tenant, "", true, 500)
}

// AckBadges marks a reviewer's badges as seen by the game server, so they are not
// reported as new again. It returns how many were new.
func (s *Service) AckBadges(ctx context.Context, tenant, reviewer string, badges []string) (int, error) {
	if !validID(reviewer) || len(badges) == 0 || len(badges) > 32 {
		return 0, invalid("name the player and 1 to 32 of that player's badges")
	}
	return s.st.AckReviewBadges(ctx, tenant, reviewer, badges, s.cfg.Now())
}

// CaseInfo is a case with its verdicts, for the dashboard.
type CaseInfo struct {
	store.ReviewCase
	Tally Tally
	// Handed is how many reviewers were handed the case, with or without a verdict yet.
	Handed int
}

// Cases lists the studio's cases with how their verdicts stand, the newest first.
func (s *Service) Cases(ctx context.Context, tenant string, f store.ReviewCaseFilter) ([]CaseInfo, error) {
	cases, err := s.st.ListReviewCases(ctx, tenant, f)
	if err != nil {
		return nil, err
	}
	out := make([]CaseInfo, 0, len(cases))
	for i := len(cases) - 1; i >= 0; i-- {
		rows, err := s.st.ListReviewAssignments(ctx, tenant, store.ReviewAssignmentFilter{CaseID: cases[i].ID})
		if err != nil {
			return nil, err
		}
		out = append(out, CaseInfo{ReviewCase: cases[i], Tally: TallyOf(rows), Handed: len(rows)})
	}
	return out, nil
}
