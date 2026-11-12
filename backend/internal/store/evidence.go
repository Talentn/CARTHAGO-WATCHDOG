package store

import (
	"context"
	"sort"
	"time"
)

// Evidence is one detection verdict about one player, from a client finding or a gameplay
// rule. Severity follows analyzer.Severity (0 info .. 4 critical).
type Evidence struct {
	ID         int64
	TenantID   string
	PlayerHash string
	SessionID  string
	MatchID    string
	Source     string // "client" | "gameplay"
	Rule       string
	Severity   int
	Score      float64
	Integrity  bool
	Summary    string
	Raw        string
	ObservedAt time.Time
}

const (
	SourceClient   = "client"
	SourceGameplay = "gameplay"
)

// Telemetry is the latest scanner health a session reported.
type Telemetry struct {
	SessionID          string
	UpdatedAt          time.Time
	Activity           uint32
	WorkerCPUNs        uint64
	Slices             uint64
	SliceCPUMaxNs      uint64
	SliceOverruns      uint64
	Frames             uint64
	JobsQuarantined    uint32
	FindingsDropped    uint64
	FindingsTotal      uint64
	InputThreadCPUNs   uint64
	MouseEvents        uint64
	InjectedEvents     uint64
	MitigationsApplied uint64
	MitigationsFailed  uint64
	Coverage           string // JSON list of per-job coverage
}

// SessionRow is a session as the dashboard lists it.
type SessionRow struct {
	Session
	EvidenceCount int
	MaxSeverity   int // -1 when there is no evidence
}

// PlayerRow aggregates one player's sessions and evidence for a tenant.
type PlayerRow struct {
	PlayerHash    string
	Sessions      int
	LastSeen      time.Time
	TrustLevel    uint32 // of the most recent session
	EvidenceCount int
	MaxSeverity   int
	Integrity     int     // integrity (client-tamper) evidence count
	Risk          float64 // see RiskWeight
	TopRule       string  // rule of the highest-severity evidence
}

// Overview is the dashboard's headline numbers for a tenant.
type Overview struct {
	OnlineSessions int
	Sessions       int // created since the window start
	Players        int
	FlaggedPlayers int
	Evidence       int // above info, since the window start
	TrustLevels    [4]int
	Matches        int
}

type EvidenceFilter struct {
	PlayerHash  string
	SessionID   string
	MinSeverity int
	Limit       int
}

type SessionFilter struct {
	PlayerHash string
	Limit      int
}

type PlayerFilter struct {
	FlaggedOnly bool
	Limit       int
}

// EvidenceStore persists detections for the pipeline and serves the dashboard's read-only,
// tenant-scoped queries. Every read takes the tenant id and must never return another
// tenant's rows.
type EvidenceStore interface {
	AddEvidence(ctx context.Context, ev []Evidence) error
	PutTelemetry(ctx context.Context, t *Telemetry) error
	// AdvanceMatch records batch seq for a match; fresh=false means seq was not above the last
	// accepted one (a retry or replay) and the batch must not be analysed.
	AdvanceMatch(ctx context.Context, tenant, matchID string, seq uint64, at time.Time, over bool) (fresh bool, err error)

	Overview(ctx context.Context, tenant string, since, online time.Time) (Overview, error)
	ListSessions(ctx context.Context, tenant string, f SessionFilter) ([]SessionRow, error)
	GetTelemetry(ctx context.Context, tenant, sessionID string) (*Telemetry, error)
	ListEvidence(ctx context.Context, tenant string, f EvidenceFilter) ([]Evidence, error)
	GetEvidence(ctx context.Context, tenant string, id int64) (*Evidence, error)
	ListPlayers(ctx context.Context, tenant string, f PlayerFilter) ([]PlayerRow, error)

	GameplayStore
}

// RiskWeight is a severity's contribution to a player's risk, multiplied by the evidence score.
// Info evidence (allowlisted overlays) adds nothing.
var RiskWeight = [5]float64{0, 1, 3, 6, 10}

// FlaggedRisk is the risk at which a player is listed as flagged: one confident medium, or any
// high or critical verdict.
const FlaggedRisk = 1.5

func riskOf(severity int, score float64) float64 {
	if severity < 0 || severity >= len(RiskWeight) {
		return 0
	}
	return RiskWeight[severity] * score
}

func limitOr(n, def int) int {
	if n <= 0 || n > 1000 {
		return def
	}
	return n
}

func sortPlayers(rows []PlayerRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Risk != rows[j].Risk {
			return rows[i].Risk > rows[j].Risk
		}
		return rows[i].LastSeen.After(rows[j].LastSeen)
	})
}

var (
	_ EvidenceStore = (*SQLite)(nil)
	_ EvidenceStore = (*Memory)(nil)
)
