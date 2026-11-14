package store

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
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

	// ListModuleSightings returns who loaded which file: one row for each file hash,
	// module name, signature and account in the studio's stored module evidence.
	ListModuleSightings(ctx context.Context, tenant string) ([]ModuleSighting, error)
	// CheatProposalAccounts is how many distinct banned accounts a file must be seen in
	// before it is proposed as a known cheat (DefaultProposalAccounts until set).
	CheatProposalAccounts(ctx context.Context, tenant string) (int, error)
	SetCheatProposalAccounts(ctx context.Context, tenant string, n int) error
	// DismissCheatProposal keeps a file from being proposed again.
	DismissCheatProposal(ctx context.Context, tenant, sha256, by string, at time.Time) error
	DismissedCheatProposals(ctx context.Context, tenant string) (map[string]bool, error)
}

// DefaultProposalAccounts is the threshold of a studio that has not set one.
const DefaultProposalAccounts = 2

// MaxProposalAccounts bounds the threshold a studio can set.
const MaxProposalAccounts = 1000

// ModuleSighting is one account's loads of one file, as its client reported them.
type ModuleSighting struct {
	SHA256     string
	Module     string // the name the file was loaded under
	PlayerHash string
	// Signature and PathClass are pb.ModuleSignature and pb.ModulePathClass of the report.
	// Files under the Windows folder are not in this evidence at all.
	Signature uint8
	PathClass uint8
	Sessions  int
	LastSeen  time.Time
}

// moduleSignatureCode is the finding whose evidence carries a module's file hash,
// signature state and path class.
const moduleSignatureCode = "FINDING_CODE_MODULE_SIGNATURE"

// moduleBits reads the signature state and path class from the end of a finding's b as
// the evidence keeps it ("0x..." hex): its low 16 bits.
func moduleBits(b string) (signature, class uint8) {
	if i := strings.LastIndexAny(b, "xX"); i >= 0 {
		b = b[i+1:]
	}
	if len(b) > 4 {
		b = b[len(b)-4:]
	}
	v, err := strconv.ParseUint(b, 16, 16)
	if err != nil {
		return 0, 0
	}
	return uint8(v), uint8(v >> 8)
}

// CleanSHA256 returns s as 64 lower-case hex digits, and false when it is not a SHA-256.
func CleanSHA256(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if b, err := hex.DecodeString(s); err != nil || len(b) != 32 {
		return "", false
	}
	return s, true
}
