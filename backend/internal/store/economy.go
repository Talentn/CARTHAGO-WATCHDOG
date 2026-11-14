package store

import (
	"context"
	"time"
)

// EconomyEntry is one change of a player's money or items that a game server reported,
// or one the ledger wrote itself to stay in step with a reported balance.
type EconomyEntry struct {
	ID         int64
	TenantID   string
	EventID    string
	PlayerHash string
	Currency   string
	// Amount in the currency's smallest unit: positive received, negative spent or given.
	Amount       int64
	Source       string
	Counterparty string
	// At is the game server's time of the change.
	At         time.Time
	ReceivedAt time.Time
	// Dirty is the part of a credit that should not exist: money no report explains, or
	// money received from a banned player, who is DirtyFrom.
	Dirty     int64
	DirtyFrom string
}

// EconomyFlag is one thing the ledger found about a player.
type EconomyFlag struct {
	ID         int64
	TenantID   string
	PlayerHash string
	Rule       string
	// Certain flags ban; the others are for review.
	Certain  bool
	Currency string
	Amount   int64
	Source   string
	Summary  string
	EventID  string
	// BanRef is the ban a certain flag led to, empty when automatic bans are off.
	BanRef string
	At     time.Time
}

// EconomyLimit is a studio's earning limit for one source and currency; 0 is no limit.
type EconomyLimit struct {
	TenantID        string
	Source          string
	Currency        string
	PerHour, PerDay int64
}

// EconomyFilter selects ledger entries. Zero fields do not filter.
type EconomyFilter struct {
	PlayerHash   string
	Currency     string
	Counterparty string
	DirtyFrom    string
	DirtyOnly    bool
	Since        time.Time
	// OldestFirst reverses the order, which is newest first.
	OldestFirst bool
	Limit       int
}

// EconomySum selects the entries of one player and currency to add up.
type EconomySum struct {
	// Source, when set, counts only entries of that source.
	Source      string
	CreditsOnly bool
	// After and Until bound the game server's time of the entries: After < at <= Until.
	After, Until time.Time
}

// EconomyStore keeps the economy ledger of each studio.
type EconomyStore interface {
	// AddEconomyEntry stores e and sets its ID. ErrDuplicate when the studio already has
	// an entry with this event id.
	AddEconomyEntry(ctx context.Context, e *EconomyEntry) error
	ListEconomyEntries(ctx context.Context, tenant string, f EconomyFilter) ([]EconomyEntry, error)
	// SumEconomy adds up a player's entries in one currency and counts them.
	SumEconomy(ctx context.Context, tenant, player, currency string, f EconomySum) (sum int64, n int, err error)
	SetEconomyDirty(ctx context.Context, tenant string, id, dirty int64, from string) error
	AddEconomyFlag(ctx context.Context, f *EconomyFlag) error
	// ListEconomyFlags returns flags newest first, of one player when player is set.
	ListEconomyFlags(ctx context.Context, tenant, player string, limit int) ([]EconomyFlag, error)
	EconomyLimits(ctx context.Context, tenant string) ([]EconomyLimit, error)
	SetEconomyLimit(ctx context.Context, l EconomyLimit) error
	RemoveEconomyLimit(ctx context.Context, tenant, source, currency string) error
	// EconomyTolerance is how far a reported balance may be from the ledger; 0 by default.
	EconomyTolerance(ctx context.Context, tenant string) (int64, error)
	SetEconomyTolerance(ctx context.Context, tenant string, tolerance int64) error
}
