package store

import (
	"context"
	"time"
)

// BanAutomatic is who banned when the gateway did it by itself.
const BanAutomatic = "automatic"

// Ban refuses one studio's sessions to a player account and to the device key that account
// was using. Either one matching is enough: a new account on the same device key is
// refused, and so is the same account on another machine.
type Ban struct {
	ID       int64
	TenantID string
	// Ref is what a banned player is shown and can quote to the studio. It says nothing
	// about why.
	Ref        string
	PlayerHash string
	// DeviceID is the device key of the session the ban was made from; empty for a ban
	// made without one. DeviceTPM: that key lives in the machine's TPM. A software key is
	// replaced by reinstalling, so only a TPM key ties the ban to the machine.
	DeviceID  string
	DeviceTPM bool
	Reason    string
	// Rule is the rule (automatic) or category the ban rests on; empty when a person
	// banned without naming one.
	Rule      string
	SessionID string
	BannedBy  string // a dashboard account's name, or BanAutomatic
	BannedAt  time.Time
	// EffectiveAt is later than BannedAt for an automatic ban made while the studio has a
	// delay set. Until then the ban is pending: listed, liftable, and refusing nobody.
	EffectiveAt time.Time
	LiftedBy    string
	LiftedAt    time.Time // zero while the ban stands
	LiftNote    string
	// Shadow: the ban was made while the studio's shadow period was on. Until EffectiveAt
	// the player is in the shadow pool: playing, told nothing, matched with the others in
	// it. LandedAt is when the gateway applied the ban, at the end of the period or on a
	// reviewer's "Ban now"; zero while the player is in the pool.
	Shadow   bool
	LandedAt time.Time
	// ShadowOf is empty for the player who was caught. For another account that connected
	// from that player's device key it is the reference of that player's ban.
	ShadowOf string
}

func (b *Ban) Lifted() bool { return !b.LiftedAt.IsZero() }

// Pending: the ban stands but does not refuse anybody yet.
func (b *Ban) Pending(now time.Time) bool { return !b.Lifted() && b.EffectiveAt.After(now) }

// Active: the ban refuses handshakes now.
func (b *Ban) Active(now time.Time) bool { return !b.Lifted() && !b.EffectiveAt.After(now) }

// InPool: the player of this ban is in the shadow pool now.
func (b *Ban) InPool(now time.Time) bool { return b.Shadow && b.LandedAt.IsZero() && b.Pending(now) }

// BanStore keeps bans. Everything is scoped to a tenant.
type BanStore interface {
	// AddBan stores a ban and sets b.ID.
	AddBan(ctx context.Context, b *Ban) error
	// LiftBan marks a standing ban as lifted and returns it; ErrNotFound when the tenant
	// has no standing ban with that id.
	LiftBan(ctx context.Context, tenant string, id int64, by, note string, at time.Time) (*Ban, error)
	// ListBans returns the tenant's bans, newest first.
	ListBans(ctx context.Context, tenant string, limit int) ([]Ban, error)
	// StandingBan returns a ban that is not lifted and names the account or the device key,
	// the one that takes effect first; pending ones are included. ErrNotFound when there is
	// none. An empty deviceID matches no ban by device.
	StandingBan(ctx context.Context, tenant, playerHash, deviceID string) (*Ban, error)
	// BanDelay is how long the tenant's automatic bans wait before they take effect.
	BanDelay(ctx context.Context, tenant string) (time.Duration, error)
	SetBanDelay(ctx context.Context, tenant string, d time.Duration) error

	// ShadowPeriod is how long the tenant keeps a caught player in the shadow pool before
	// the ban takes effect. Zero is off.
	ShadowPeriod(ctx context.Context, tenant string) (time.Duration, error)
	SetShadowPeriod(ctx context.Context, tenant string, d time.Duration) error
	// ListShadowBans returns the bans of the shadow pool that stand and have not landed,
	// the one that ends first first. An empty tenant lists every tenant's.
	ListShadowBans(ctx context.Context, tenant string) ([]Ban, error)
	// LandShadowBan marks a ban of the shadow pool as applied at a time and, when that is
	// before the end of its period, makes it take effect then. ErrNotFound when the
	// tenant has no such ban that stands and has not landed, so one caller applies it.
	LandShadowBan(ctx context.Context, tenant string, id int64, at time.Time) (*Ban, error)
	// ListShadowMembers returns the bans, lifted or not, of the accounts that came into
	// the pool through the device key of the ban with reference of, newest first.
	ListShadowMembers(ctx context.Context, tenant, of string) ([]Ban, error)
}

// MaxBanDelay bounds the delay of automatic bans.
const MaxBanDelay = 7 * 24 * time.Hour

// MaxShadowPeriod bounds the shadow period.
const MaxShadowPeriod = 90 * 24 * time.Hour

func clampShadowPeriod(d time.Duration) time.Duration {
	return min(max(d, 0), MaxShadowPeriod).Truncate(time.Second)
}

var (
	_ BanStore = (*SQLite)(nil)
	_ BanStore = (*Memory)(nil)
)
