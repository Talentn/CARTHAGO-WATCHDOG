package store

import (
	"context"
	"time"
)

// OracleScore is the behaviour model's score for one session. It is not evidence: it adds
// nothing to a player's risk and can kick nobody.
type OracleScore struct {
	TenantID       string
	SessionID      string
	PlayerHash     string
	MatchID        string // the match the gameplay part comes from; empty when the session played none
	ModelID        string
	FeatureVersion int
	Score          float64 // 0..1
	Band           string  // OracleBandClear, OracleBandWatch or OracleBandReview
	Signals        string  // JSON list of the top contributing signals
	Features       string  // JSON feature vector, for the gateway only
	UpdatedAt      time.Time
}

const (
	OracleBandClear  = "clear"
	OracleBandWatch  = "watch"
	OracleBandReview = "review"
)

// OracleVerdict is the analyst's latest opinion about one session.
type OracleVerdict struct {
	TenantID      string
	SessionID     string
	PlayerHash    string
	CaseHash      string
	Status        string // OracleVerdictOK or OracleVerdictUnavailable
	Reason        string // why there is no verdict, as a fixed word
	Provider      string
	AnalystModel  string
	PromptVersion string
	CheatType     string
	Confidence    int // 0..100
	Action        string
	Summary       string
	Cited         string // JSON list of evidence ids
	CaseFile      string // the pseudonymised case, for the gateway only
	LatencyMs     int64
	TokensIn      int64
	TokensOut     int64
	CreatedAt     time.Time
}

const (
	OracleVerdictOK          = "ok"
	OracleVerdictUnavailable = "unavailable"
)

// OracleUsage is one tenant's analyst use on one UTC day.
type OracleUsage struct {
	Cases  int64
	Tokens int64
}

// OracleReview is a reviewer's own conclusion about a case.
type OracleReview struct {
	TenantID   string
	SessionID  string
	CaseHash   string
	CheatType  string
	Action     string
	Note       string
	ReviewedAt time.Time
}

// OracleCase is a stored case with the analyst's verdict and, when there is one, the review.
type OracleCase struct {
	Verdict OracleVerdict
	Review  *OracleReview
}

type OracleFilter struct {
	PlayerHash string
	Limit      int
}

// OracleStore keeps what the Carthago Oracle produces. Reads are tenant-scoped.
type OracleStore interface {
	PutOracleScore(ctx context.Context, s *OracleScore) error
	GetOracleScore(ctx context.Context, tenant, sessionID string) (*OracleScore, error)
	ListOracleScores(ctx context.Context, tenant string, f OracleFilter) ([]OracleScore, error)
	PutOracleVerdict(ctx context.Context, v *OracleVerdict) error
	GetOracleVerdict(ctx context.Context, tenant, sessionID string) (*OracleVerdict, error)
	ListOracleVerdicts(ctx context.Context, tenant string, f OracleFilter) ([]OracleVerdict, error)
	// AddOracleUsage adds to a tenant's counters for a day and returns the new totals.
	AddOracleUsage(ctx context.Context, tenant, day string, cases, tokens int64) (OracleUsage, error)
	PutOracleReview(ctx context.Context, r *OracleReview) error
	// ListOracleCases returns stored cases with a verdict, newest first; reviewedOnly keeps
	// those a reviewer has labelled.
	ListOracleCases(ctx context.Context, tenant string, reviewedOnly bool, limit int) ([]OracleCase, error)
}

var (
	_ OracleStore = (*SQLite)(nil)
	_ OracleStore = (*Memory)(nil)
)
