package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"carthago/backend/internal/protocol"
)

// Keys are the gateway's long-term Ed25519 keys. Phase 0 keeps the seeds in files under
// the data directory; production moves them to KMS (plan §4 signer).
type Keys struct {
	Identity    ed25519.PrivateKey // signs Challenges; its public key is pinned in the client
	IdentityKID string
	Token       ed25519.PrivateKey // signs session tokens; game servers verify offline
	TokenKID    string
	// TLSPins are the hex SHA-256 SPKI pins of the gateway TLS keys (current, then
	// backups) that clients and game servers pin; empty when serving plaintext.
	TLSPins []string
}

type PublishedKey struct {
	KID       string `json:"kid"`
	PublicKey string `json:"public_key"`
}

// PublicKeys is the key set studios provision into game servers and clients.
type PublicKeys struct {
	ServerIdentity PublishedKey   `json:"server_identity"`
	TokenKeys      []PublishedKey `json:"token_keys"`
	TLSPins        []string       `json:"tls_spki_sha256,omitempty"`
}

func loadOrCreateSeed(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s: want a %d-byte hex seed", path, ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func LoadOrCreateKeys(dir string) (*Keys, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	id, err := loadOrCreateSeed(filepath.Join(dir, "identity.key"))
	if err != nil {
		return nil, err
	}
	tok, err := loadOrCreateSeed(filepath.Join(dir, "token.key"))
	if err != nil {
		return nil, err
	}
	return &Keys{
		Identity: id, IdentityKID: protocol.KeyID(id.Public().(ed25519.PublicKey)),
		Token: tok, TokenKID: protocol.KeyID(tok.Public().(ed25519.PublicKey)),
	}, nil
}

func (k *Keys) Public() PublicKeys {
	pub := func(p ed25519.PrivateKey, kid string) PublishedKey {
		return PublishedKey{KID: kid, PublicKey: hex.EncodeToString(p.Public().(ed25519.PublicKey))}
	}
	return PublicKeys{ServerIdentity: pub(k.Identity, k.IdentityKID), TokenKeys: []PublishedKey{pub(k.Token, k.TokenKID)}, TLSPins: k.TLSPins}
}

func (k *Keys) WritePublic(path string) error {
	b, err := json.MarshalIndent(k.Public(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
