package dashboard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testArgon keeps tests fast; the cost settings travel with every hash.
var testArgon = argonParams{MemoryKiB: 64, Time: 1, Threads: 1}

func TestPasswordHash(t *testing.T) {
	h, err := hashPassword("a long enough secret", testArgon)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^\$argon2id\$v=19\$m=64,t=1,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`).MatchString(h) {
		t.Fatalf("hash format: %s", h)
	}
	if ok, p := verifyPassword(h, "a long enough secret"); !ok || p != testArgon {
		t.Fatalf("right password refused (%+v)", p)
	}
	for _, wrong := range []string{"a long enough secreT", "a long enough secret ", "", strings.Repeat("x", maxPasswordBytes+1)} {
		if ok, _ := verifyPassword(h, wrong); ok {
			t.Errorf("accepted %q", wrong)
		}
	}
	// The salt is random: the same password never gives the same hash.
	if h2, _ := hashPassword("a long enough secret", testArgon); h2 == h {
		t.Error("two hashes of one password are equal")
	}
	// A hash made with other settings still verifies and reports them, so it can be replaced.
	old, _ := hashPassword("pw", argonParams{MemoryKiB: 32, Time: 2, Threads: 1})
	if ok, p := verifyPassword(old, "pw"); !ok || p == testArgon || p.Time != 2 {
		t.Errorf("hash with older settings: %v %+v", ok, p)
	}
	for _, bad := range []string{
		"", "plain", "$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=16$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=4294967295,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", // absurd memory
		"$argon2id$v=19$m=64,t=999,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",       // absurd time
		"$argon2id$v=19$m=64,t=1,p=1$$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$",
	} {
		if ok, _ := verifyPassword(bad, ""); ok {
			t.Errorf("malformed hash %q verified", bad)
		}
		if ok, _ := verifyPassword(bad, "pw"); ok {
			t.Errorf("malformed hash %q verified", bad)
		}
	}
	if defaultArgon.MemoryKiB < 19*1024 || defaultArgon.Time < 2 {
		t.Errorf("default argon2id settings are below the OWASP minimum: %+v", defaultArgon)
	}
}

func TestPasswordPolicy(t *testing.T) {
	for _, ok := range []string{"plum-kettle-orbit-97", "Tr0ub4dor&3xtra!", "une phrase assez longue", "zZ9!kq0Lw#2mPv", "sept nuages verts au-dessus"} {
		if msg := checkPassword(ok, "ala", "demo"); msg != "" {
			t.Errorf("%q refused: %s", ok, msg)
		}
	}
	for pw, want := range map[string]string{
		"short":                       "at least 12",
		"elevenchars":                 "at least 12",
		strings.Repeat("a1B2", 40):    "at most 128",
		"aaaaaaaaaaaaaa":              "easy to guess",
		"abababababababab":            "easy to guess",
		"abcabcabcabcabc":             "easy to guess",
		"abcdefghijklmnop":            "easy to guess",
		"zyxwvutsrqpon":               "easy to guess",
		"1234567890123456":            "easy to guess",
		"aaaabbbbccccdddd":            "easy to guess",
		"passwordpassword":            "easy to guess",
		"Password123456":              "easy to guess",
		"qwertyuiop123":               "easy to guess",
		"my-name-is-ala-ok":           "user name",
		"DEMO-studio-secret":          "user name",
		"I-love-Carthago-99":          "product name",
		"watchdog-forever-1":          "product name",
		"bad\xffbytes-in-password-xx": "cannot be stored",
	} {
		if msg := checkPassword(pw, "ala", "demo"); !strings.Contains(msg, want) {
			t.Errorf("%q: got %q, want a message about %q", pw, msg, want)
		}
	}
	// Very short names are not searched for: "al" would refuse half of all passwords.
	if msg := checkPassword("total-eclipse-of-al", "al", "x"); msg != "" {
		t.Errorf("two-letter name blocked a password: %s", msg)
	}
	for _, msg := range []string{checkPassword("short", "", ""), checkPassword("aaaaaaaaaaaaaa", "", "")} {
		if strings.HasSuffix(msg, ".") {
			t.Errorf("short messages carry no closing period: %q", msg)
		}
	}
}

// The test values of RFC 6238 appendix B for SHA-1, cut to six digits.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{
		59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037", 20000000000: "353130",
	} {
		if got := totpCode(secret, unix/totpPeriod); got != want {
			t.Errorf("T=%d: %s, want %s", unix, got, want)
		}
	}
}

func TestTOTPVerify(t *testing.T) {
	secret, err := newTOTPSecret()
	if err != nil || len(secret) != 20 {
		t.Fatalf("secret: %d %v", len(secret), err)
	}
	now := time.Unix(1_800_000_015, 0)
	step := totpStep(now)
	for d, want := range map[int64]bool{-2: false, -1: true, 0: true, 1: true, 2: false} {
		got, ok := totpVerify(secret, totpCode(secret, step+d), now)
		if ok != want || ok && got != step+d {
			t.Errorf("code from %d periods away: accepted=%v step=%d", d, ok, got-step)
		}
	}
	code := totpCode(secret, step)
	if _, ok := totpVerify(secret, code[:3]+" "+code[3:], now); !ok {
		t.Error("a code typed with a space is refused")
	}
	other, _ := newTOTPSecret()
	for _, bad := range []string{"", "12345", "1234567", "abcdef", code + "0", totpCode(other, step)} {
		if bad == code {
			continue
		}
		if _, ok := totpVerify(secret, bad, now); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	uri := otpauthURI("Carthago Watchdog", "ala@demo studio", []byte("12345678901234567890"))
	if uri != "otpauth://totp/Carthago%20Watchdog:ala%40demo%20studio?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Carthago%20Watchdog" {
		t.Errorf("otpauth URI: %s", uri)
	}
}

func TestSecretBox(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	box, err := newSecretBox(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSecretBox(key[:16]); err == nil {
		t.Error("a short key was accepted")
	}
	sealed, err := box.seal([]byte("totp secret"), totpSealName("demo", 7))
	if err != nil || bytes.Contains(sealed, []byte("totp secret")) {
		t.Fatalf("seal: %v", err)
	}
	if got, err := box.open(sealed, totpSealName("demo", 7)); err != nil || string(got) != "totp secret" {
		t.Fatalf("open: %q %v", got, err)
	}
	// Moved to another user, another tenant, or changed by one bit: it does not open.
	for _, what := range []string{totpSealName("demo", 8), totpSealName("rival", 7)} {
		if _, err := box.open(sealed, what); err == nil {
			t.Errorf("opened under %q", what)
		}
	}
	flipped := append([]byte(nil), sealed...)
	flipped[len(flipped)-1] ^= 1
	if _, err := box.open(flipped, totpSealName("demo", 7)); err == nil {
		t.Error("a modified value opened")
	}
	if _, err := box.open(sealed[:5], totpSealName("demo", 7)); err == nil {
		t.Error("a truncated value opened")
	}
	otherBox, _ := newSecretBox(bytes.Repeat([]byte{8}, 32))
	if _, err := otherBox.open(sealed, totpSealName("demo", 7)); err == nil {
		t.Error("opened with another key")
	}
	if again, _ := box.seal([]byte("totp secret"), totpSealName("demo", 7)); bytes.Equal(again, sealed) {
		t.Error("sealing twice gives the same bytes (nonce reuse)")
	}

	codes, err := newRecoveryCodes()
	if err != nil || len(codes) != recoveryCodes {
		t.Fatalf("recovery codes: %v %v", codes, err)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if !regexp.MustCompile(`^[0-9a-hjkmnp-tv-z]{4}(-[0-9a-hjkmnp-tv-z]{4}){3}$`).MatchString(c) || seen[c] || !looksLikeRecoveryCode(c) {
			t.Errorf("recovery code %q", c)
		}
		seen[c] = true
	}
	h := box.recoveryHash(7, codes[0])
	typed := strings.ToUpper(strings.ReplaceAll(codes[0], "-", " "))
	if len(h) != 64 || box.recoveryHash(7, typed) != h {
		t.Error("a code typed in capitals with spaces hashes differently")
	}
	if box.recoveryHash(8, codes[0]) == h || otherBox.recoveryHash(7, codes[0]) == h || box.recoveryHash(7, codes[1]) == h {
		t.Error("recovery hash does not depend on the user, the key and the code")
	}
	if looksLikeRecoveryCode("123456") || looksLikeRecoveryCode("") {
		t.Error("a six-digit code is taken for a recovery code")
	}
}

// Each case was compared, module by module, with an independent encoder (python-qrcode,
// byte mode, level M, the same mask) and read back with zbar. The hash is over the rows
// written as 0 and 1 with a slash after each row.
func TestQRMatchesReferenceEncoder(t *testing.T) {
	base := strings.Repeat("otpauth://totp/Carthago%20Watchdog:ala%40demo?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Carthago%20Watchdog ", 4)
	for _, c := range []struct {
		n, mask, size int
		sha           string
	}{
		{1, 0, 21, "279bfe5da0ecbf9d5198b59ab09321904b93e8cfd328ee76325eb3eec9c99488"},
		{26, 3, 25, "9ca993fd9798c303d0ad41256f1cdfd3c9b9227e20aae0336b3692844514915f"},
		{107, 5, 45, "ee15e053441737db6ceb1750bbdc919ff5cbac5bad82afc0fc86ff94b804e426"},
		{123, 7, 49, "c9766487ce2fe9d99a93b886d240a779173a5e36b83a5552f920598fd8b5bc9a"},
		{181, 2, 57, "dc011278f242847d274fe1b21f2fe3ccb52e5edf9e0112dfb75b58fa2798dacf"},
		{214, 6, 61, "f8ea7041352a59517f0496b7451ef3b244a8ebabd1e6fa1fd7da962708732f2f"},
		{288, 1, 69, "1cdb5063cdcf6cf86e4b5158d8762d47d2a1e3627d75876378195a824d5b4050"},
		{331, 4, 69, "9233687db896fd0ddbd85ee00e3854fe0d8e006c83f084b14f3ad77185034304"},
	} {
		q, err := qrEncode(base[:c.n], c.mask)
		if err != nil {
			t.Fatalf("%d bytes: %v", c.n, err)
		}
		sum := sha256.Sum256([]byte(qrRows(q)))
		if q.size != c.size || hex.EncodeToString(sum[:]) != c.sha {
			t.Errorf("%d bytes, mask %d: size %d, modules differ from the reference", c.n, c.mask, q.size)
		}
	}
	if _, err := qrEncode(base[:332], -1); err != errQRTooLong {
		t.Errorf("332 bytes: %v, want errQRTooLong", err)
	}
}

func qrRows(q *qrCode) string {
	var b strings.Builder
	for _, row := range q.dark {
		for _, d := range row {
			if d {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		b.WriteByte('/')
	}
	return b.String()
}

func TestQRStructureAndSVG(t *testing.T) {
	uri := otpauthURI("Carthago Watchdog", "ala@demo", []byte("12345678901234567890"))
	q, err := qrEncode(uri, -1)
	if err != nil {
		t.Fatal(err)
	}
	if q.size != 45 { // 112 bytes: version 7
		t.Errorf("size %d for %d bytes", q.size, len(uri))
	}
	// The three finder patterns, and none in the fourth corner.
	finder := []string{"1111111", "1000001", "1011101", "1011101", "1011101", "1000001", "1111111"}
	at := func(x0, y0 int) bool {
		for y, row := range finder {
			for x, c := range row {
				if q.dark[y0+y][x0+x] != (c == '1') {
					return false
				}
			}
		}
		return true
	}
	if !at(0, 0) || !at(q.size-7, 0) || !at(0, q.size-7) || at(q.size-7, q.size-7) {
		t.Error("finder patterns misplaced")
	}
	if !q.dark[q.size-8][8] {
		t.Error("the always-dark module is light")
	}
	// The chosen mask is the best of the eight by the encoder's own score.
	best := 1 << 30
	for m := 0; m < 8; m++ {
		c, _ := qrEncode(uri, m)
		best = min(best, c.penalty())
	}
	if q.penalty() != best {
		t.Errorf("automatic mask scores %d, the best is %d", q.penalty(), best)
	}

	// The SVG path covers exactly the dark modules, inside the quiet zone.
	path, side := q.svgPath()
	if side != q.size+2*qrQuiet {
		t.Errorf("side %d", side)
	}
	covered := make([][]bool, q.size)
	for i := range covered {
		covered[i] = make([]bool, q.size)
	}
	runs := regexp.MustCompile(`M(\d+) (\d+)h(\d+)v1h-(\d+)z`).FindAllStringSubmatch(path, -1)
	total := 0
	for _, r := range runs {
		x, _ := strconv.Atoi(r[1])
		y, _ := strconv.Atoi(r[2])
		n, _ := strconv.Atoi(r[3])
		total += len(r[0])
		if r[3] != r[4] || x < qrQuiet || y < qrQuiet || x+n > q.size+qrQuiet || y >= q.size+qrQuiet {
			t.Fatalf("run %q leaves the symbol", r[0])
		}
		for i := 0; i < n; i++ {
			if covered[y-qrQuiet][x-qrQuiet+i] {
				t.Fatalf("module drawn twice at %d,%d", x+i, y)
			}
			covered[y-qrQuiet][x-qrQuiet+i] = true
		}
	}
	if total != len(path) {
		t.Error("the path holds something other than module runs")
	}
	for y := range covered {
		for x := range covered[y] {
			if covered[y][x] != q.dark[y][x] {
				t.Fatalf("module %d,%d: drawn=%v dark=%v", x, y, covered[y][x], q.dark[y][x])
			}
		}
	}
}
