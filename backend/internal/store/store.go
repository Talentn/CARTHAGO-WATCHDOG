// Package store persists devices, sessions and attestation outcomes for the gateway.
// Implementations: in-memory (tests, ephemeral dev runs) and SQLite (single-node dev);
// Postgres follows the same schema in Phase 1 (migrations/).
package store

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("not found")

// Device is one device key as seen by one tenant (client device keys are per tenant).
type Device struct {
	DeviceID       string
	TenantID       string
	KeyAlg         int32
	PublicKey      []byte
	AKPublic       []byte // TPMT_PUBLIC of the AK once bound to the EK; nil until then
	EKPublicSHA256 string
	EKCertMatches  bool
	// EKChain is the EK certificate chain status (ekroots.Status: verified, unknown_vendor,
	// invalid, no_cert); empty for devices bound before chains were verified.
	EKChain     string
	EKChainRoot string // subject of the manufacturer root reached, when verified
	BoundVia    string // "ek-certify"
	FirstSeen   time.Time
	LastSeen    time.Time
}

type SessionState string

const (
	SessionActive SessionState = "active"
	SessionKicked SessionState = "kicked"
	SessionClosed SessionState = "closed"
)

type Session struct {
	SessionID     string
	TenantID      string
	PlayerHash    string
	DeviceID      string
	TrustLevel    uint32
	AttestFlags   uint64
	State         SessionState
	KickReason    string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastHeartbeat time.Time
	Heartbeats    uint64
}

// Attestation keeps only derived booleans and hashes (plan §10): never the raw WBCL.
type Attestation struct {
	SessionID     string
	DeviceID      string
	VerifiedAt    time.Time
	QuoteOK       bool
	SecureBoot    bool
	HVCI          bool
	TestSigning   bool
	KernelDebug   bool
	BootDebug     bool
	CodeIntegrity string
	RankedPolicy  bool
	Failures      string
}

type Store interface {
	GetDevice(ctx context.Context, deviceID string) (*Device, error)
	UpsertDevice(ctx context.Context, d *Device) error
	PutSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	AddAttestation(ctx context.Context, a *Attestation) error
	Close() error
}
