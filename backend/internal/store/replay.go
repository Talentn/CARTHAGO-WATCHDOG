package store

import (
	"context"
	"time"
)

// MatchReplay is the top-down recording of one match (see internal/replay). Data is the
// encoded recording; the other fields are what lists and links need without reading it.
type MatchReplay struct {
	TenantID   string
	MatchID    string
	StartedAt  time.Time // when the gateway received the first batch with positions
	UpdatedAt  time.Time
	DurationMs int64
	Samples    int
	Truncated  bool // the match ran past the recording's size cap
	Players    []ReplayPlayer
	Data       []byte
}

// ReplayPlayer is one slot of a recorded match.
type ReplayPlayer struct {
	Slot       uint32
	PlayerHash string
	SessionID  string // empty for a slot without a verified session
	Bot        bool
}

type ReplayFilter struct {
	PlayerHash string
	SessionID  string
	Limit      int
}

// ReplayStore keeps match recordings. Reads are tenant-scoped.
type ReplayStore interface {
	// PutMatchReplay stores a match's recording, replacing the previous one and its
	// player list.
	PutMatchReplay(ctx context.Context, r *MatchReplay) error
	GetMatchReplay(ctx context.Context, tenant, matchID string) (*MatchReplay, error)
	// ListMatchReplays returns recordings without Data and Players, newest first.
	ListMatchReplays(ctx context.Context, tenant string, f ReplayFilter) ([]MatchReplay, error)
	// PruneMatchReplays deletes recordings last written before the cutoff.
	PruneMatchReplays(ctx context.Context, before time.Time) (int64, error)
}

var (
	_ ReplayStore = (*SQLite)(nil)
	_ ReplayStore = (*Memory)(nil)
)
