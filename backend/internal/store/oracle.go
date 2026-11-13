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

// SessionLabel is a reviewer's conclusion about a session. It is a note for the studio and
// for tuning data: it never kicks, bans or changes a player's risk.
type SessionLabel struct {
	TenantID   string
	SessionID  string
	PlayerHash string
	Label      string // LabelConfirmedCheat, LabelCleared or LabelUnsure
	CheatType  string // optional
	Note       string
	Reviewer   string // the dashboard account that set the label; with the demo login, the name the person gave
	LabelledAt time.Time
}

const (
	LabelConfirmedCheat = "confirmed_cheat"
	LabelCleared        = "cleared"
	LabelUnsure         = "unsure"
)

// LabelAudit is one change to a session's label.
type LabelAudit struct {
	ID        int64
	TenantID  string
	SessionID string
	Action    string // LabelSet, LabelAcceptSuggestion or LabelRemove
	Label     string
	CheatType string
	Note      string
	Reviewer  string
	Remote    string
	At        time.Time
}

const (
	LabelSet              = "set"
	LabelAcceptSuggestion = "accept_suggestion"
	LabelRemove           = "remove"
)

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

	// SetSessionLabel stores a session's label, replacing the previous one, and appends
	// the change to the audit trail in the same step. An empty label removes it.
	SetSessionLabel(ctx context.Context, l *SessionLabel, action, remote string) error
	GetSessionLabel(ctx context.Context, tenant, sessionID string) (*SessionLabel, error)
	ListSessionLabels(ctx context.Context, tenant string, f OracleFilter) ([]SessionLabel, error)
	// ListLabelAudit returns a session's label changes, newest first.
	ListLabelAudit(ctx context.Context, tenant, sessionID string, limit int) ([]LabelAudit, error)
}

var (
	_ OracleStore = (*SQLite)(nil)
	_ OracleStore = (*Memory)(nil)
)
