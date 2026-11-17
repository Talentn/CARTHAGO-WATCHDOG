package store

import (
	"context"
	"time"
)

// PlayerReport is what one player reported about another, as the studio's game server
// sent it (internal/reports). Reports are advice for reviewers. They are kept apart from
// evidence on purpose: nothing that scores, kicks, bans or pools a player, and nothing
// the Oracle or its baseline learns from, reads this table.
type PlayerReport struct {
	ID       int64
	TenantID string
	Reporter string
	Reported string
	MatchID  string
	MatchMs  int64  // the moment in the match the report is about; -1 when none was given
	Reason   string // one of reports.Reasons
	Note     string // what the reporter typed, capped; personal data
	State    string // ReportOpen, ReportReviewed or ReportDismissed
	// CreatedAt is when the gateway received the report.
	CreatedAt time.Time
	// DecidedBy and DecidedAt: who last set the state, and when. Empty while never set.
	DecidedBy string
	DecidedAt time.Time
}

const (
	ReportOpen      = "open"
	ReportReviewed  = "reviewed"
	ReportDismissed = "dismissed"
)

// ValidReportState reports whether s is a state a report can be in.
func ValidReportState(s string) bool {
	return s == ReportOpen || s == ReportReviewed || s == ReportDismissed
}

type ReportFilter struct {
	State    string
	Reporter string
	Reported string
	MatchID  string
	Since    time.Time // zero for no lower bound
	Limit    int
}

// ReportTally is how often a player was reported: the reports and the distinct reporters.
type ReportTally struct {
	Reports   int
	Reporters int
}

// ReportStore keeps player reports. Reads are tenant-scoped.
type ReportStore interface {
	// AddPlayerReport stores a report and sets its ID. A reporter has one report per
	// reported player and match: for a second one nothing is stored, the ID is set to the
	// first one's and added is false.
	AddPlayerReport(ctx context.Context, r *PlayerReport) (added bool, err error)
	GetPlayerReport(ctx context.Context, tenant string, id int64) (*PlayerReport, error)
	// ListPlayerReports returns reports newest first.
	ListPlayerReports(ctx context.Context, tenant string, f ReportFilter) ([]PlayerReport, error)
	CountPlayerReports(ctx context.Context, tenant string, f ReportFilter) (int, error)
	// SetPlayerReportState sets a report's state; ErrNotFound for another tenant's report.
	SetPlayerReportState(ctx context.Context, tenant string, id int64, state, by string, at time.Time) error
	// TallyPlayerReports counts, per reported player, the reports since a time that were
	// not dismissed, and their distinct reporters.
	TallyPlayerReports(ctx context.Context, tenant string, since time.Time) (map[string]ReportTally, error)
	PrunePlayerReports(ctx context.Context, before time.Time) (int64, error)
}

var (
	_ ReportStore = (*SQLite)(nil)
	_ ReportStore = (*Memory)(nil)
)
