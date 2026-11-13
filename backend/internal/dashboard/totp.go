package dashboard

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Time-based one-time passwords as authenticator apps implement them (RFC 6238 over
// RFC 4226): HMAC-SHA1, six digits, a new code every 30 seconds.
const (
	totpDigits    = 6
	totpPeriod    = 30
	totpSecretLen = 20
	// totpSkew is how many periods before and after the current one are accepted, to
	// allow for a phone clock that is a little off.
	totpSkew = 1
)

func totpStep(t time.Time) int64 { return t.Unix() / totpPeriod }

func totpCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	s := strconv.FormatUint(uint64(v%1_000_000), 10)
	return strings.Repeat("0", totpDigits-len(s)) + s
}

// totpVerify checks a typed code against the periods around now and returns the period it
// belongs to. Every candidate is compared, in constant time, whether or not one matched.
func totpVerify(secret []byte, code string, now time.Time) (int64, bool) {
	code = strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, code)
	if len(code) != totpDigits {
		code = strings.Repeat("x", totpDigits)
	}
	matched, ok := int64(0), 0
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		step := totpStep(now) + d
		eq := subtle.ConstantTimeCompare([]byte(totpCode(secret, step)), []byte(code))
		matched = int64(subtle.ConstantTimeSelect(eq, int(step), int(matched)))
		ok |= eq
	}
	return matched, ok == 1
}

func newTOTPSecret() ([]byte, error) {
	b := make([]byte, totpSecretLen)
	_, err := rand.Read(b)
	return b, err
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// otpauthURI is what the enrolment QR code holds. The defaults (SHA1, six digits, 30
// seconds) are left out: every authenticator app assumes them, and a shorter text makes a
// QR code that is easier to scan.
func otpauthURI(issuer, account string, secret []byte) string {
	esc := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
	return "otpauth://totp/" + esc(issuer) + ":" + esc(account) + "?secret=" + b32.EncodeToString(secret) + "&issuer=" + esc(issuer)
}

// secretBox seals what must be stored in a readable form (the two-factor secret) and keys
// the hashes of recovery codes. Its key comes from a file kept next to the database, so a
// copy of the database alone gives neither.
type secretBox struct {
	aead    cipher.AEAD
	codeKey []byte
}

func newSecretBox(key []byte) (*secretBox, error) {
	if len(key) < 32 {
		return nil, errors.New("dashboard secret key must be at least 32 bytes")
	}
	derive := func(label string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(label))
		return m.Sum(nil)
	}
	block, err := aes.NewCipher(derive("carthago dashboard seal v1"))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &secretBox{aead: aead, codeKey: derive("carthago dashboard recovery codes v1")}, nil
}

// seal encrypts plain; what names the row it belongs to, so a sealed value moved to another
// user or field does not open.
func (b *secretBox) seal(plain []byte, what string) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plain, []byte(what)), nil
}

func (b *secretBox) open(sealed []byte, what string) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("sealed value too short")
	}
	return b.aead.Open(nil, sealed[:n], sealed[n:], []byte(what))
}

func totpSealName(tenant string, userID int64) string {
	return "totp\x00" + tenant + "\x00" + strconv.FormatInt(userID, 10)
}

// Recovery codes: ten one-time codes of 80 random bits each, shown once at enrolment and
// stored as keyed hashes.
const (
	recoveryCodes   = 10
	recoveryCodeLen = 16
	// No i, l, o or u, so a code read aloud or copied by hand has no look-alikes.
	recoveryAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"
)

func newRecoveryCodes() ([]string, error) {
	out := make([]string, recoveryCodes)
	buf := make([]byte, recoveryCodeLen)
	for i := range out {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		var s strings.Builder
		for j, c := range buf {
			if j > 0 && j%4 == 0 {
				s.WriteByte('-')
			}
			s.WriteByte(recoveryAlphabet[c&31])
		}
		out[i] = s.String()
	}
	return out, nil
}

// normalizeRecoveryCode undoes what people do to a code when typing it.
func normalizeRecoveryCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch r {
		case ' ', '-', '\t':
			continue
		case 'o':
			r = '0'
		case 'i', 'l':
			r = '1'
		case 'u':
			r = 'v'
		}
		b.WriteRune(r)
	}
	return b.String()
}

func looksLikeRecoveryCode(s string) bool {
	return len(normalizeRecoveryCode(s)) == recoveryCodeLen
}

func (b *secretBox) recoveryHash(userID int64, code string) string {
	m := hmac.New(sha256.New, b.codeKey)
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], uint64(userID))
	m.Write(id[:])
	m.Write([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(m.Sum(nil))
}
