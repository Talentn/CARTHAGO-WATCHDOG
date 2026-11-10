package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Session tokens are PASETO v4.public (Ed25519) with a JSON claims payload and a
// {"kid":...} footer. Game servers verify them offline (carthago-server) against the gateway's
// published token keys.

const tokenHeader = "v4.public."

const TokenIssuer = "carthago-gateway"

// DefaultLeeway is the clock-skew tolerance applied to exp and iat.
const DefaultLeeway = 30 * time.Second

// Claims field order is part of the golden vectors: keep it in sync with carthago-crypto.
type Claims struct {
	Iss         string `json:"iss"`
	Tenant      string `json:"tenant"`
	PlayerHash  string `json:"player_hash"`
	DeviceID    string `json:"device_id"`
	SessionID   string `json:"session_id"`
	Iat         string `json:"iat"`
	Exp         string `json:"exp"`
	TrustLevel  uint32 `json:"trust_level"`
	AttestFlags uint64 `json:"attest_flags"`
}

type footer struct {
	Kid string `json:"kid"`
}

// Verification error classes, also named in the golden vectors.
var (
	ErrTokenMalformed   = errors.New("malformed")
	ErrTokenUnknownKey  = errors.New("unknown_key")
	ErrTokenSignature   = errors.New("bad_signature")
	ErrTokenExpired     = errors.New("expired")
	ErrTokenNotYetValid = errors.New("not_yet_valid")
)

var b64 = base64.RawURLEncoding

// FormatTime renders the RFC 3339 form used in claims (UTC, whole seconds).
func FormatTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

// KeyID names a token key: hex of the first 8 bytes of SHA-256 over the public key.
func KeyID(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:8])
}

// pae is PASETO pre-authentication encoding.
func pae(pieces ...[]byte) []byte {
	var out []byte
	le64 := func(n uint64) { out = binary.LittleEndian.AppendUint64(out, n&^(1<<63)) }
	le64(uint64(len(pieces)))
	for _, p := range pieces {
		le64(uint64(len(p)))
		out = append(out, p...)
	}
	return out
}

func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func SignToken(priv ed25519.PrivateKey, c Claims) (string, error) {
	msg, err := encodeJSON(c)
	if err != nil {
		return "", err
	}
	f, err := encodeJSON(footer{Kid: KeyID(priv.Public().(ed25519.PublicKey))})
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, pae([]byte(tokenHeader), msg, f, nil))
	return tokenHeader + b64.EncodeToString(append(msg, sig...)) + "." + b64.EncodeToString(f), nil
}

// VerifyToken checks signature, key id, iat and exp. It never contacts the gateway.
func VerifyToken(keys map[string]ed25519.PublicKey, token string, now time.Time, leeway time.Duration) (*Claims, error) {
	if !strings.HasPrefix(token, tokenHeader) {
		return nil, fmt.Errorf("%w: not v4.public", ErrTokenMalformed)
	}
	parts := strings.Split(token[len(tokenHeader):], ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: want payload.footer", ErrTokenMalformed)
	}
	body, err1 := b64.DecodeString(parts[0])
	f, err2 := b64.DecodeString(parts[1])
	if err1 != nil || err2 != nil || len(body) < ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: bad base64url or short payload", ErrTokenMalformed)
	}
	var ft footer
	if err := json.Unmarshal(f, &ft); err != nil {
		return nil, fmt.Errorf("%w: footer: %v", ErrTokenMalformed, err)
	}
	pub, ok := keys[ft.Kid]
	if !ok {
		return nil, fmt.Errorf("%w: kid %q", ErrTokenUnknownKey, ft.Kid)
	}
	msg, sig := body[:len(body)-ed25519.SignatureSize], body[len(body)-ed25519.SignatureSize:]
	if !ed25519.Verify(pub, pae([]byte(tokenHeader), msg, f, nil), sig) {
		return nil, ErrTokenSignature
	}
	var c Claims
	if err := json.Unmarshal(msg, &c); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrTokenMalformed, err)
	}
	exp, err1 := time.Parse(time.RFC3339, c.Exp)
	iat, err2 := time.Parse(time.RFC3339, c.Iat)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("%w: bad iat/exp", ErrTokenMalformed)
	}
	if !now.Before(exp.Add(leeway)) {
		return nil, fmt.Errorf("%w: at %s", ErrTokenExpired, c.Exp)
	}
	if now.Add(leeway).Before(iat) {
		return nil, fmt.Errorf("%w: issued %s", ErrTokenNotYetValid, c.Iat)
	}
	return &c, nil
}
