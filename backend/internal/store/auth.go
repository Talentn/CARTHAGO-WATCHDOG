package store

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

// ErrConflict: the row would duplicate one that must be unique (a user name in a tenant).
var ErrConflict = errors.New("already exists")

// Dashboard roles, from least to most privileged.
const (
	RoleReadOnly = "read_only"
	RoleReviewer = "reviewer"
	RoleAdmin    = "admin"
)

// DashUser is one person's dashboard account in one tenant.
type DashUser struct {
	ID           int64
	TenantID     string
	Name         string
	Role         string
	PasswordHash string
	// TOTPSecret is the sealed two-factor secret; nil until the user has enrolled.
	TOTPSecret []byte
	// TOTPLastStep is the last time step a code was accepted for, so a code works once.
	TOTPLastStep      int64
	Disabled          bool
	CreatedAt         time.Time
	CreatedBy         string
	PasswordChangedAt time.Time
	LastLoginAt       time.Time
}

// DashUserChange names the fields of an account to write. Fields left nil are not written,
// so two changes to different fields of one account (a sign-in recording its time while an
// admin disables the account) cannot undo each other.
type DashUserChange struct {
	Role     *string
	Disabled *bool
	// PasswordHash also sets PasswordChangedAt, which must be given with it.
	PasswordHash      *string
	PasswordChangedAt time.Time
	// TOTPSecret replaces the sealed two-factor secret; a pointer to nil removes it. Either
	// way the last used time step starts again, since it belonged to the old secret.
	TOTPSecret  *[]byte
	LastLoginAt *time.Time
}

// One-time link kinds.
const (
	InviteNew   = "invite"
	InviteReset = "reset"
)

// DashInvite is a one-time link: an invitation to create the account Name with Role, or a
// password reset for UserID. Only the hash of its token is stored.
type DashInvite struct {
	TokenHash string
	TenantID  string
	Kind      string
	Name      string
	Role      string
	UserID    int64
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
}

// Dashboard session kinds.
const (
	DashSessionFull  = "full"
	DashSessionCode  = "code"  // password accepted, two-factor code pending
	DashSessionEnrol = "enrol" // password accepted, the tenant requires two-factor and the user has none
)

// DashSession is one signed-in browser. UserID 0 is the shared demo login.
type DashSession struct {
	IDHash     string
	TenantID   string
	UserID     int64
	Kind       string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	IP         string
	UserAgent  string
}

type TenantSettings struct {
	// RequireTOTP: every account in the tenant must sign in with a second factor.
	RequireTOTP bool
}

// AuditEntry is one line of a tenant's dashboard audit log.
type AuditEntry struct {
	ID       int64
	TenantID string
	At       time.Time
	ActorID  int64  // 0 when nobody was signed in, or for the demo login
	Actor    string // the name as it was at the time
	IP       string
	Action   string
	Target   string
	Detail   string
	PrevHash string
	Hash     string
}

type AuditFilter struct {
	// BeforeID, when above zero, returns entries older than that id (for paging).
	BeforeID int64
	// ActionPrefixes, when not empty, keeps entries whose action starts with one of them.
	ActionPrefixes []string
	Limit          int
}

// AuthStore persists dashboard accounts, sign-in sessions, invites and the audit log.
// Reads and writes take the tenant id wherever a row belongs to one.
type AuthStore interface {
	CountDashUsers(ctx context.Context, tenant string) (int, error)
	// CreateDashUser sets u.ID. ErrConflict when the tenant already has that name.
	CreateDashUser(ctx context.Context, u *DashUser) error
	GetDashUser(ctx context.Context, tenant string, id int64) (*DashUser, error)
	GetDashUserByName(ctx context.Context, tenant, name string) (*DashUser, error)
	ListDashUsers(ctx context.Context, tenant string) ([]DashUser, error)
	// UpdateDashUser writes the fields named in ch and leaves the others as they are.
	UpdateDashUser(ctx context.Context, tenant string, id int64, ch DashUserChange) error
	// AdvanceTOTPStep records step as used; false when that step or a later one already was.
	AdvanceTOTPStep(ctx context.Context, userID, step int64) (bool, error)
	SetRecoveryCodes(ctx context.Context, userID int64, hashes []string) error
	// UseRecoveryCode removes the code; false when the user has no such code.
	UseRecoveryCode(ctx context.Context, userID int64, hash string) (bool, error)
	CountRecoveryCodes(ctx context.Context, userID int64) (int, error)

	CreateDashInvite(ctx context.Context, inv *DashInvite) error
	// GetDashInvite returns a link that is unused and not expired at now.
	GetDashInvite(ctx context.Context, tokenHash string, now time.Time) (*DashInvite, error)
	// RedeemDashInvite marks the link used and returns it; ErrNotFound when it is unknown,
	// already used or expired. Of two concurrent calls one succeeds.
	RedeemDashInvite(ctx context.Context, tokenHash string, now time.Time) (*DashInvite, error)
	ListDashInvites(ctx context.Context, tenant string, now time.Time) ([]DashInvite, error)
	RevokeDashInvite(ctx context.Context, tenant, tokenHash string) error

	PutDashSession(ctx context.Context, s *DashSession) error
	GetDashSession(ctx context.Context, idHash string) (*DashSession, error)
	TouchDashSession(ctx context.Context, idHash string, at time.Time) error
	DeleteDashSession(ctx context.Context, idHash string) error
	// DeleteDashSessions removes a user's sessions except exceptHash and returns how many.
	DeleteDashSessions(ctx context.Context, tenant string, userID int64, exceptHash string) (int, error)
	ListDashSessions(ctx context.Context, tenant string, userID int64, now time.Time) ([]DashSession, error)
	PruneDashSessions(ctx context.Context, now time.Time) error

	GetTenantSettings(ctx context.Context, tenant string) (TenantSettings, error)
	PutTenantSettings(ctx context.Context, tenant string, s TenantSettings) error

	// AppendAudit sets e.ID, e.PrevHash and e.Hash. There is no update or delete.
	AppendAudit(ctx context.Context, e *AuditEntry) error
	ListAudit(ctx context.Context, tenant string, f AuditFilter) ([]AuditEntry, error)
	// VerifyAudit walks a tenant's log from the start. brokenID is the first entry whose
	// hash does not follow from its content and the entry before it, or 0.
	VerifyAudit(ctx context.Context, tenant string) (entries int, brokenID int64, err error)
}

// auditHash chains an entry to the one before it. Every field is length-prefixed, so two
// different entries cannot serialise to the same bytes.
func auditHash(prev string, e *AuditEntry) string {
	h := sha256.New()
	var n [8]byte
	put := func(s string) {
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	num := func(v int64) {
		binary.BigEndian.PutUint64(n[:], uint64(v))
		h.Write(n[:])
	}
	put(prev)
	put(e.TenantID)
	num(e.At.UnixMilli())
	num(e.ActorID)
	put(e.Actor)
	put(e.IP)
	put(e.Action)
	put(e.Target)
	put(e.Detail)
	return hex.EncodeToString(h.Sum(nil))
}

func matchesAction(action string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if len(action) >= len(p) && action[:len(p)] == p {
			return true
		}
	}
	return false
}

var (
	_ AuthStore = (*SQLite)(nil)
	_ AuthStore = (*Memory)(nil)
)
