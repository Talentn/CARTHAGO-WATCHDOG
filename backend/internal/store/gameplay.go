package store

import (
	"context"
	"errors"
	"time"
)

// MapRecord is an uploaded map geometry. A (tenant, map, version) is immutable:
// a second upload with the same version must carry the same bytes.
type MapRecord struct {
	TenantID  string
	MapID     string
	Version   uint32
	Hash      string // hex SHA-256 of Geometry
	Geometry  []byte // deterministic protobuf encoding of MapGeometry
	CreatedAt time.Time
}

// ErrMapConflict is returned when a map version is uploaded again with different contents.
var ErrMapConflict = errors.New("map version already exists with different geometry")

// GameplayBatchRow is one raw v2 batch kept for re-scoring and review.
type GameplayBatchRow struct {
	TenantID   string
	MatchID    string
	BatchSeq   uint64
	ReceivedAt time.Time
	Data       []byte
}

// GameplaySummary is what the gateway knows about one slot of one match: the
// v2 telemetry it received and, once the match is over, the leak score.
type GameplaySummary struct {
	TenantID      string
	MatchID       string
	Slot          uint32
	SessionID     string
	PlayerHash    string
	Team          uint32
	Device        string
	AimAssist     bool
	Mode          string
	MapID         string
	MapVersion    uint32
	SchemaVersion uint32
	Batches       uint64
	MotionSamples uint64
	Sounds        uint64
	TeamInfo      uint64
	Shots         uint64
	DroppedEvents uint64 // events the game server SDK dropped at its caps, for the whole match
	LeakScored    bool
	LeakScore     float64
	LeakFlagged   bool
	UpdatedAt     time.Time
}

type GameplayFilter struct {
	SessionID string
	MatchID   string
	Limit     int
}

// GameplayStore keeps telemetry v2: map geometry, raw batches for a bounded
// retention window, and per-slot summaries. Reads are tenant-scoped.
type GameplayStore interface {
	// PutMap stores a map version, or checks an existing one has the same hash.
	PutMap(ctx context.Context, m *MapRecord) error
	GetMap(ctx context.Context, tenant, mapID string, version uint32) (*MapRecord, error)
	PutGameplayBatch(ctx context.Context, b *GameplayBatchRow) error
	ListGameplayBatches(ctx context.Context, tenant, matchID string, limit int) ([]GameplayBatchRow, error)
	// PruneGameplayBatches deletes raw batches received before the cutoff.
	PruneGameplayBatches(ctx context.Context, before time.Time) (int64, error)
	UpsertGameplaySummaries(ctx context.Context, rows []GameplaySummary) error
	ListGameplaySummaries(ctx context.Context, tenant string, f GameplayFilter) ([]GameplaySummary, error)
}

var (
	_ GameplayStore = (*SQLite)(nil)
	_ GameplayStore = (*Memory)(nil)
)
