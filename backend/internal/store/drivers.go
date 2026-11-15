package store

import (
	"context"
	"time"
)

// How the gateway read a session's driver list.
const (
	DriversVerified    = "verified"
	DriversUnverified  = "unverified"
	DriversUnavailable = "unavailable"
	DriversRejected    = "rejected"
	DriversNotSent     = "not_sent"
)

// Why a driver of the list is raised for review.
const (
	DriverFlagUnsigned   = "unsigned"
	DriverFlagTestSigned = "test_signed"
	DriverFlagVulnerable = "vulnerable"
)

// ListedDriver is one kernel driver of a session's list, as stored.
type ListedDriver struct {
	Name      string   `json:"name"`
	HashAlg   string   `json:"hash_alg"`
	ImageHash string   `json:"image_hash"`
	Signer    string   `json:"signer,omitempty"`
	OEM       string   `json:"oem,omitempty"`
	Loads     int      `json:"loads"`
	Unloaded  bool     `json:"unloaded,omitempty"`
	Boot      bool     `json:"boot,omitempty"`
	Flags     []string `json:"flags,omitempty"`
}

// DriverList is what a session's client sent of Windows' signed driver list and how the
// gateway read it.
type DriverList struct {
	TenantID   string
	SessionID  string
	PlayerHash string
	// TrustLevel is the session's trust level, kept here so the attested answer needs one
	// lookup.
	TrustLevel int
	Status     string
	// Reason says why the list is unverified, unavailable or rejected.
	Reason string
	// Overflowed: Windows' table was full, so the list is incomplete.
	Overflowed bool
	// TestSigning: the session's verified boot record says Windows accepts test-signed
	// drivers.
	TestSigning bool
	// Flagged counts the drivers with at least one flag.
	Flagged    int
	Drivers    []ListedDriver
	ReceivedAt time.Time
}

// Attested is the answer of the unattested pool for the session this list belongs to:
// hardware-attested boot at the ranked level, and a verified, complete driver list with
// nothing raised in it.
func (d *DriverList) Attested() bool {
	const rankedBoot = 3
	return d != nil && d.TrustLevel >= rankedBoot && d.Status == DriversVerified && !d.Overflowed && !d.TestSigning && d.Flagged == 0 && len(d.Drivers) > 0
}

// DriverStore keeps the driver list of each session and the studio's unattested-pool
// switch.
type DriverStore interface {
	// PutDriverList stores the list of a session, replacing an earlier one.
	PutDriverList(ctx context.Context, d *DriverList) error
	// SessionDriverList is the list of one session, ErrNotFound when it has none.
	SessionDriverList(ctx context.Context, tenant, sessionID string) (*DriverList, error)
	// LatestDriverList is the list of the player's most recent session, ErrNotFound when
	// the player has none.
	LatestDriverList(ctx context.Context, tenant, playerHash string) (*DriverList, error)

	// UnattestedPool reports whether the studio turned the unattested pool on. Off until
	// set.
	UnattestedPool(ctx context.Context, tenant string) (bool, error)
	SetUnattestedPool(ctx context.Context, tenant string, on bool) error
}
