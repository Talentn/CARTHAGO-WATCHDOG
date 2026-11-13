package dashboard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// argonParams are the argon2id cost settings. Every stored hash names its own, so the
// default can be raised later and old hashes still verify (and are replaced at the next
// successful sign-in).
type argonParams struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// defaultArgon is the second recommended option of RFC 9106: 64 MiB, three passes, four
// lanes. One hash takes a few tens of milliseconds on a server core.
var defaultArgon = argonParams{MemoryKiB: 64 * 1024, Time: 3, Threads: 4}

const (
	argonSaltLen = 16
	argonKeyLen  = 32
	// maxPasswordBytes bounds what is fed to the hash, so a huge form field cannot be
	// used to burn CPU.
	maxPasswordBytes = 512
)

// hashPassword returns an argon2id hash in the PHC string format:
// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>, both in unpadded base64.
func hashPassword(pw string, p argonParams) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, p.Time, p.MemoryKiB, p.Threads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

var errBadHash = errors.New("not an argon2id hash this gateway accepts")

func parseHash(encoded string) (p argonParams, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return p, nil, nil, errBadHash
	}
	var m, t uint32
	var lanes uint8
	if n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &lanes); err != nil || n != 3 {
		return p, nil, nil, errBadHash
	}
	// A hash is only ever written by this gateway, but it is read from a database: refuse
	// settings that would make checking one a denial of service.
	if m < 8 || m > 1<<20 || t < 1 || t > 16 || lanes < 1 || lanes > 16 {
		return p, nil, nil, errBadHash
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(salt) < 8 || len(salt) > 64 {
		return p, nil, nil, errBadHash
	}
	if key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(key) < 16 || len(key) > 64 {
		return p, nil, nil, errBadHash
	}
	return argonParams{MemoryKiB: m, Time: t, Threads: lanes}, salt, key, nil
}

// verifyPassword reports whether pw matches the hash, comparing in constant time, and the
// settings the hash was made with.
func verifyPassword(encoded, pw string) (bool, argonParams) {
	p, salt, want, err := parseHash(encoded)
	if err != nil || len(pw) > maxPasswordBytes {
		return false, p
	}
	got := argon2.IDKey([]byte(pw), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, p
}

const (
	minPasswordLen = 12
	maxPasswordLen = 128
)

// commonPasswords are the widely used passwords that are long enough to pass the length
// rule. Shorter ones need no list.
var commonPasswords = map[string]bool{}

func init() {
	for _, p := range strings.Fields(`
		123456789012 1234567890123 12345678901234 123456789123 1234567891011 123123123123 112233445566
		111111111111 000000000000 121212121212 098765432109 987654321098 1q2w3e4r5t6y 1q2w3e4r5t6y7u
		qwertyuiop12 qwertyuiop123 qwertyuiopas qwertyuiopasdf 1qaz2wsx3edc 1qaz2wsx3edc4rfv zaq12wsxcde3
		qazwsxedcrfv q1w2e3r4t5y6 qwerty123456 qwerty1234567 asdfghjkl123 asdfghjklqwe zxcvbnm12345
		password1234 password12345 password123456 passwordpassword password1234! passw0rd1234 p@ssw0rd1234
		p@ssword1234 mypassword123 newpassword123 changeme1234 changemenow1 letmein12345 letmeinplease
		welcome12345 welcome123456 iloveyou1234 iloveyou12345 iloveyouiloveyou administrator admin1234567
		adminadminadmin administrator1 superman1234 football1234 baseball1234 basketball123 trustno1trustno1
		abc123abc123 abcd1234abcd abcdefghijkl abcdefghijklm abcdefgh1234 a1b2c3d4e5f6 monkey123456
		dragon123456 master123456 michael12345 sunshine1234 princess1234 starwars1234 whatever1234
		computer1234 internet1234 correcthorsebatterystaple thisisapassword thisismypassword
		iamtheadmin1 temporary1234 temppassword1 defaultpassword secretpassword qwertyqwerty qweasdzxc123
		counterstrike counter-strike counterstrike16 anticheat1234 summer202612 winter202612 spring202612`) {
		commonPasswords[p] = true
	}
}

// checkPassword applies the password policy and returns what to tell the user, or "".
// The rules follow NIST SP 800-63B: a minimum length, no composition rules, and a refusal
// of passwords that are common, repetitive or built from the account's own names.
func checkPassword(pw, user, tenant string) string {
	if !utf8.ValidString(pw) {
		return "That password contains characters that cannot be stored"
	}
	n := utf8.RuneCountInString(pw)
	switch {
	case n < minPasswordLen:
		return fmt.Sprintf("Use at least %d characters", minPasswordLen)
	case n > maxPasswordLen || len(pw) > maxPasswordBytes:
		return fmt.Sprintf("Use at most %d characters", maxPasswordLen)
	}
	low := strings.ToLower(pw)
	for _, own := range []string{user, tenant, "carthago", "watchdog"} {
		if own = strings.ToLower(own); len(own) >= 3 && strings.Contains(low, own) {
			return "Do not use your user name, the studio name or the product name in the password"
		}
	}
	if commonPasswords[low] || repetitive([]rune(low)) {
		return "That password is too easy to guess"
	}
	return ""
}

// repetitive: few distinct characters, a short block repeated, or one straight run up or
// down the alphabet or the digits.
func repetitive(r []rune) bool {
	distinct := map[rune]bool{}
	for _, c := range r {
		distinct[c] = true
	}
	if len(distinct) < 5 {
		return true
	}
	for period := 1; period <= len(r)/3; period++ {
		same := true
		for i := period; i < len(r) && same; i++ {
			same = r[i] == r[i-period]
		}
		if same {
			return true
		}
	}
	up, down := true, true
	for i := 1; i < len(r); i++ {
		d := r[i] - r[i-1]
		// Digits wrap around: 8, 9, 0, 1.
		if r[i-1] == '9' && r[i] == '0' {
			d = 1
		} else if r[i-1] == '0' && r[i] == '9' {
			d = -1
		}
		up, down = up && d == 1, down && d == -1
	}
	return up || down
}
