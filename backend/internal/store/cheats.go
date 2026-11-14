package store

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// KnownCheat is one entry of a studio's list of known cheat files.
type KnownCheat struct {
	ID       int64
	TenantID string
	// SHA256 of the file: 64 lower-case hex digits.
	SHA256  string
	Name    string
	Note    string
	AddedBy string
	AddedAt time.Time
}

// ErrDuplicate: the entry is already there.
var ErrDuplicate = errors.New("store: already exists")

// CheatStore keeps the known cheat files of each studio.
type CheatStore interface {
	// AddKnownCheat stores c and sets its ID. ErrDuplicate when the studio already lists
	// the hash.
	AddKnownCheat(ctx context.Context, c *KnownCheat) error
	// RemoveKnownCheat deletes one entry and returns it. ErrNotFound for no such entry.
	RemoveKnownCheat(ctx context.Context, tenant string, id int64) (*KnownCheat, error)
	// ListKnownCheats returns the studio's entries, newest first.
	ListKnownCheats(ctx context.Context, tenant string) ([]KnownCheat, error)
	// KnownCheat returns the entry with this hash. ErrNotFound for none.
	KnownCheat(ctx context.Context, tenant, sha256 string) (*KnownCheat, error)
}

// CleanSHA256 returns s as 64 lower-case hex digits, and false when it is not a SHA-256.
func CleanSHA256(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if b, err := hex.DecodeString(s); err != nil || len(b) != 32 {
		return "", false
	}
	return s, true
}
