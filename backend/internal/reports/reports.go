// Package reports takes the reports players make about other players, as a studio's game
// server passes them on, and works out how much a reporter's word has been worth so far.
//
// A report is advice for a reviewer. It is stored in a table of its own and read by the
// dashboard only: it adds nothing to a player's risk, cannot kick or ban, does not put
// anyone in the shadow pool and is not something the Oracle or its baseline learns from.
package reports

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"carthago/backend/internal/store"
)

// Reasons is the fixed list a report's reason comes from.
var Reasons = []string{"cheating", "toxic_behaviour", "griefing", "other"}

const (
	// MaxNote is the longest note, in characters. A longer one is refused, not cut.
	MaxNote = 280
	// MaxID is the longest player or match identifier, in bytes.
	MaxID = 128
	// MaxPerHour and MaxPerDay are how many reports one reporter may make.
	MaxPerHour = 6
	MaxPerDay  = 20
	// MaxMatchMs is the latest moment of a match a report can name: a day.
	MaxMatchMs = 24 * 60 * 60 * 1000
	// Retention is how long a report is kept.
	Retention = 90 * 24 * time.Hour
)

// Submission is a report as the game server sends it. The moment is optional and given
// either as Tick with TickRate, as in the match's telemetry, or as TimeMs, milliseconds
// from the start of the match.
type Submission struct {
	Reporter string  `json:"reporter"`
	Reported string  `json:"reported"`
	Match    string  `json:"match"`
	Tick     *uint32 `json:"tick,omitempty"`
	TickRate uint32  `json:"tick_rate,omitempty"`
	TimeMs   *int64  `json:"time_ms,omitempty"`
	Reason   string  `json:"reason"`
	Note     string  `json:"note,omitempty"`
}

// Outcome is the answer to a submission.
type Outcome struct {
	ID int64 `json:"id"`
	// Status is "accepted", or "duplicate" when the reporter had already reported that
	// player in that match: the first report stands and nothing was added.
	Status string `json:"status"`
}

const (
	StatusAccepted  = "accepted"
	StatusDuplicate = "duplicate"
)

// InvalidError says what is wrong with a submission, in words for the caller.
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return e.Msg }

// RateError: the reporter has made as many reports as allowed. RetryAfter is how long
// until the next one is taken.
type RateError struct{ RetryAfter time.Duration }

func (e *RateError) Error() string {
	return fmt.Sprintf("this reporter has made as many reports as allowed (%d an hour, %d a day)", MaxPerHour, MaxPerDay)
}

func invalid(format string, a ...any) error { return &InvalidError{fmt.Sprintf(format, a...)} }

func validID(s string) bool {
	if s == "" || len(s) > MaxID || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

// cleanNote makes a note one line and checks its length.
func cleanNote(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", invalid("note is not valid UTF-8")
	}
	s = strings.Join(strings.Fields(s), " ")
	if strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == utf8.RuneError }) {
		return "", invalid("note contains control characters")
	}
	if utf8.RuneCountInString(s) > MaxNote {
		return "", invalid("note is longer than %d characters", MaxNote)
	}
	return s, nil
}

// check validates a submission and turns it into the row to store.
func check(tenant string, in Submission, at time.Time) (*store.PlayerReport, error) {
	switch {
	case !validID(in.Reporter):
		return nil, invalid("reporter is missing or not an identifier of 1 to %d bytes", MaxID)
	case !validID(in.Reported):
		return nil, invalid("reported is missing or not an identifier of 1 to %d bytes", MaxID)
	case in.Reporter == in.Reported:
		return nil, invalid("a player cannot report themselves")
	case !validID(in.Match):
		return nil, invalid("match is missing or not an identifier of 1 to %d bytes", MaxID)
	}
	ok := false
	for _, r := range Reasons {
		ok = ok || r == in.Reason
	}
	if !ok {
		return nil, invalid("reason must be one of %s", strings.Join(Reasons, ", "))
	}
	ms := int64(-1)
	switch {
	case in.Tick != nil && in.TimeMs != nil:
		return nil, invalid("give the moment as tick with tick_rate or as time_ms, not both")
	case in.Tick != nil:
		if in.TickRate == 0 || in.TickRate > 1000 {
			return nil, invalid("tick needs tick_rate, 1 to 1000")
		}
		ms = int64(*in.Tick) * 1000 / int64(in.TickRate)
	case in.TimeMs != nil:
		ms = *in.TimeMs
	case in.TickRate != 0:
		return nil, invalid("tick_rate is given without tick")
	}
	if ms < -1 || ms > MaxMatchMs {
		return nil, invalid("the moment is outside a match of at most a day")
	}
	note, err := cleanNote(in.Note)
	if err != nil {
		return nil, err
	}
	return &store.PlayerReport{TenantID: tenant, Reporter: in.Reporter, Reported: in.Reported, MatchID: in.Match, MatchMs: ms,
		Reason: in.Reason, Note: note, State: store.ReportOpen, CreatedAt: at}, nil
}

// Service takes submissions.
type Service struct {
	st  store.ReportStore
	now func() time.Time

	mu     sync.Mutex // one submission at a time, so the limits hold under concurrency
	pruned time.Time
}

func New(st store.ReportStore, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{st: st, now: now}
}

// Submit stores a report. The error is an *InvalidError, a *RateError, or the store's.
func (s *Service) Submit(ctx context.Context, tenant string, in Submission) (Outcome, error) {
	now := s.now()
	r, err := check(tenant, in, now)
	if err != nil {
		return Outcome{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.pruned) >= time.Hour {
		s.pruned = now
		if _, err := s.st.PrunePlayerReports(ctx, now.Add(-Retention)); err != nil {
			return Outcome{}, err
		}
	}
	// A repeat is answered before the limits: saying the same thing twice costs nothing
	// and adds nothing.
	same, err := s.st.ListPlayerReports(ctx, tenant, store.ReportFilter{Reporter: r.Reporter, Reported: r.Reported, MatchID: r.MatchID, Limit: 1})
	if err != nil {
		return Outcome{}, err
	}
	if len(same) > 0 {
		return Outcome{ID: same[0].ID, Status: StatusDuplicate}, nil
	}
	for _, lim := range []struct {
		window time.Duration
		max    int
	}{{time.Hour, MaxPerHour}, {24 * time.Hour, MaxPerDay}} {
		recent, err := s.st.ListPlayerReports(ctx, tenant, store.ReportFilter{Reporter: r.Reporter, Since: now.Add(-lim.window), Limit: lim.max})
		if err != nil {
			return Outcome{}, err
		}
		if len(recent) >= lim.max {
			// The oldest report in the window is the last of the list.
			return Outcome{}, &RateError{RetryAfter: recent[len(recent)-1].CreatedAt.Add(lim.window).Sub(now)}
		}
	}
	added, err := s.st.AddPlayerReport(ctx, r)
	if err != nil {
		return Outcome{}, err
	}
	if !added {
		return Outcome{ID: r.ID, Status: StatusDuplicate}, nil
	}
	return Outcome{ID: r.ID, Status: StatusAccepted}, nil
}

// Weight is what a reporter's earlier reports came to.
type Weight struct {
	// Confirmed: reports about a player who was then banned or whose session a reviewer
	// labelled a confirmed cheat. Rejected: reports a reviewer dismissed, the confirmed
	// ones aside. Pending: the rest, which say nothing yet.
	Confirmed, Rejected, Pending int
	// Value is (Confirmed+1) / (Confirmed+Rejected+2): 0.50 for a reporter with no
	// outcome yet, toward 1 as reports are confirmed, toward 0 as they are dismissed.
	Value float64
}

// WeightOf works out a reporter's weight from that reporter's reports. confirmed says
// whether a reported player was banned or confirmed as cheating.
func WeightOf(rows []store.PlayerReport, confirmed func(player string) bool) Weight {
	var w Weight
	for i := range rows {
		switch {
		case confirmed(rows[i].Reported):
			w.Confirmed++
		case rows[i].State == store.ReportDismissed:
			w.Rejected++
		default:
			w.Pending++
		}
	}
	w.Value = float64(w.Confirmed+1) / float64(w.Confirmed+w.Rejected+2)
	return w
}
