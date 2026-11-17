package store

import (
	"context"
	"time"
)

// ToxicityFinding is one kind of spoiling behaviour by one player in one match (see
// internal/toxicity). These rows are advice for a studio's community team. They are kept
// apart from evidence on purpose: nothing that scores, kicks, bans or pools a player reads
// this table.
type ToxicityFinding struct {
	ID         int64
	TenantID   string
	PlayerHash string
	SessionID  string // empty for a slot without a verified session
	MatchID    string
	Slot       uint32
	Kind       string // toxicity.Kind*
	Count      int    // hits, kills, idle seconds, percent of the match missed, or deaths
	MatchMs    int64  // the moment in the match to look at
	Summary    string
	Bot        bool
	ObservedAt time.Time
}

type ToxicityFilter struct {
	PlayerHash string
	MatchID    string
	Since      time.Time // zero for no lower bound
	Limit      int
}

// ToxicityStore keeps behaviour findings and each studio's limits. Reads are tenant-scoped.
type ToxicityStore interface {
	AddToxicityFindings(ctx context.Context, rows []ToxicityFinding) error
	// ListToxicityFindings returns findings newest first.
	ListToxicityFindings(ctx context.Context, tenant string, f ToxicityFilter) ([]ToxicityFinding, error)
	PruneToxicityFindings(ctx context.Context, before time.Time) (int64, error)
	// GetToxicityLimits returns the limits a studio stored (toxicity.Limits.Encode), or ""
	// when it has set none.
	GetToxicityLimits(ctx context.Context, tenant string) (string, error)
	// SetToxicityLimits stores a studio's limits; "" removes them.
	SetToxicityLimits(ctx context.Context, tenant, limits string, at time.Time) error
}

var (
	_ ToxicityStore = (*SQLite)(nil)
	_ ToxicityStore = (*Memory)(nil)
)
