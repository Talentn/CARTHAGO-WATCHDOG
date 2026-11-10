package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	paseto "aidanwoods.dev/go-paseto"
	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
)

const vectorDir = "../../../proto/testvectors"

func load[T any](t *testing.T, name string) *T {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatalf("read %s: %v (run go run ./cmd/gen-testvectors)", name, err)
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return &v
}

func sameJSON(t *testing.T, name string, a, b any) {
	t.Helper()
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Errorf("%s: checked-in vectors differ from the generator; regenerate only for an intentional wire change", name)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func TestTokenVectors(t *testing.T) {
	v := load[TokenVectors](t, "token.json")
	gen, err := BuildTokenVectors()
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, "token.json", v, gen)

	sk := ed25519.NewKeyFromSeed(v.SigningSeed)
	keys := map[string]ed25519.PublicKey{v.Kid: ed25519.PublicKey(v.PublicKey)}
	leeway := time.Duration(v.LeewaySecs) * time.Second
	for _, c := range v.Valid {
		tok, err := SignToken(sk, *c.Claims)
		if err != nil || tok != c.Token {
			t.Errorf("%s: sign mismatch (%v)", c.Name, err)
		}
		got, err := VerifyToken(keys, c.Token, mustTime(t, c.VerifyAt), leeway)
		if err != nil {
			t.Errorf("%s: verify: %v", c.Name, err)
		} else if *got != *c.Claims {
			t.Errorf("%s: claims %+v, want %+v", c.Name, got, c.Claims)
		}
	}
	classes := []error{ErrTokenMalformed, ErrTokenUnknownKey, ErrTokenSignature, ErrTokenExpired, ErrTokenNotYetValid}
	for _, c := range v.Invalid {
		_, err := VerifyToken(keys, c.Token, mustTime(t, c.VerifyAt), leeway)
		var class string
		for _, e := range classes {
			if errors.Is(err, e) {
				class = e.Error()
			}
		}
		if class != c.Error {
			t.Errorf("%s: got %v, want class %s", c.Name, err, c.Error)
		}
	}
}

// An independent PASETO implementation must accept our tokens and their footer.
func TestTokenInteropGoPaseto(t *testing.T) {
	v := load[TokenVectors](t, "token.json")
	pk, err := paseto.NewV4AsymmetricPublicKeyFromBytes(v.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p := paseto.NewParserWithoutExpiryCheck()
	for _, c := range v.Valid {
		tok, err := p.ParseV4Public(pk, c.Token, nil)
		if err != nil {
			t.Fatalf("%s: go-paseto rejects our token: %v", c.Name, err)
		}
		var got Claims
		if err := json.Unmarshal(tok.ClaimsJSON(), &got); err != nil || got != *c.Claims {
			t.Errorf("%s: go-paseto claims %+v (%v)", c.Name, got, err)
		}
		if string(tok.Footer()) != `{"kid":"`+v.Kid+`"}` {
			t.Errorf("%s: footer %q", c.Name, tok.Footer())
		}
	}
}

func TestHandshakeVectors(t *testing.T) {
	v := load[HandshakeVectors](t, "handshake.json")
	gen, err := BuildHandshakeVectors()
	if err != nil {
		t.Fatal(err)
	}
	gen.P256 = v.P256
	sameJSON(t, "handshake.json", v, gen)

	var hello pb.Hello
	if err := proto.Unmarshal(v.HelloBytes, &hello); err != nil || !proto.Equal(&hello, HelloFromJSON(&v.Hello)) {
		t.Errorf("hello_bytes does not decode to the hello fields (%v)", err)
	}
	var ch pb.Challenge
	if err := proto.Unmarshal(v.ChallengeBytes, &ch); err != nil || !bytes.Equal(ch.Body, v.ChallengeBodyBytes) {
		t.Fatalf("challenge_bytes: %v", err)
	}
	th := TranscriptHash(v.HelloBytes, ch.Body)
	if !ed25519.Verify(ed25519.PublicKey(v.ServerIdentityPub), ChallengeSigInput(th), ch.ServerSig) {
		t.Error("server_sig does not verify")
	}
	pd := ProveDigest(th)
	if !ed25519.Verify(ed25519.PublicKey(v.DevicePub), pd[:], v.DeviceSig) {
		t.Error("device_sig does not verify")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), v.P256.PublicSEC1)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if x == nil || !ecdsa.Verify(pub, pd[:], new(big.Int).SetBytes(v.P256.SignatureRS[:32]), new(big.Int).SetBytes(v.P256.SignatureRS[32:])) {
		t.Error("p256 signature does not verify")
	}
	if DeviceID(uint8(pb.DeviceKeyAlg_DEVICE_KEY_ALG_ECDSA_P256_TPM), v.P256.PublicSEC1) != v.P256.DeviceID {
		t.Error("p256 device id")
	}
}

func TestAEADVectors(t *testing.T) {
	v := load[AEADVectors](t, "aead.json")
	gen, err := BuildAEADVectors()
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, "aead.json", v, gen)
	for _, c := range v.Valid {
		pt, err := Open(v.Key, v.SessionID, c.Direction, c.Seq, c.Frame)
		if err != nil || !bytes.Equal(pt, c.Plaintext) {
			t.Errorf("%s: open: %v", c.Name, err)
		}
	}
	for _, c := range v.Invalid {
		_, err := Open(v.Key, v.SessionID, c.Direction, c.Seq, c.Frame)
		want := map[string]error{"seq": ErrFrameSeq, "auth": ErrFrameAuth, "malformed": ErrFrameMalformed}[c.Error]
		if !errors.Is(err, want) {
			t.Errorf("%s: got %v, want %v", c.Name, err, want)
		}
	}
}

func TestTrustLevel(t *testing.T) {
	for _, c := range []struct {
		flags uint64
		want  uint32
	}{
		{0, TrustSoftware},
		{FlagTPMDeviceKey, TrustTPMKey},
		{FlagTPMDeviceKey | FlagAKBoundToEK | FlagQuoteVerified, TrustTPMKey},
		{attestedMask, TrustAttested},
		{attestedMask | FlagSecureBoot | FlagHVCI, TrustAttested},
		{rankedMask, TrustRankedBoot},
		// Without a verified EK chain, everything else verified still caps at 1.
		{rankedMask &^ FlagEKChainVerified, TrustTPMKey},
		{rankedMask&^FlagEKChainVerified | FlagEKChainUnknownVendor, TrustTPMKey},
		{rankedMask &^ (FlagEKChainVerified | FlagEKCertMatches), TrustTPMKey},
		{rankedMask | FlagEKChainInvalid, TrustTPMKey},
		// A software key never rises above 0, whatever else is claimed.
		{rankedMask &^ FlagTPMDeviceKey, TrustSoftware},
	} {
		if got := TrustLevel(c.flags); got != c.want {
			t.Errorf("TrustLevel(%#x) = %d, want %d", c.flags, got, c.want)
		}
	}
}
