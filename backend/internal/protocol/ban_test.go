package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
)

func TestBanRefusal(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := &pb.BanRefusalBody{SessionId: bytes.Repeat([]byte{7}, SessionIDLen), TenantId: "t1", PlayerIdHash: "p1", IssuedAtMs: 1_700_000_000_000, BanRef: "CW-ABCD-2345"}
	r, err := SignBan(priv, KeyID(pub), body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyBan(pub, r)
	if err != nil || got.BanRef != "CW-ABCD-2345" || got.PlayerIdHash != "p1" || !bytes.Equal(got.SessionId, body.SessionId) {
		t.Fatalf("verify: %+v %v", got, err)
	}
	// A notice signature over the same bytes is not a ban refusal, and the reverse.
	if _, err := VerifyBan(pub, &pb.BanRefusal{Body: r.Body, ServerSig: ed25519.Sign(priv, NoticeSigInput(r.Body)), ServerKeyId: r.ServerKeyId}); err == nil {
		t.Error("a signature made for a notice was accepted")
	}
	changed := &pb.BanRefusal{Body: append([]byte{}, r.Body...), ServerSig: r.ServerSig, ServerKeyId: r.ServerKeyId}
	changed.Body[len(changed.Body)-1] ^= 1
	if _, err := VerifyBan(pub, changed); err == nil {
		t.Error("a changed body was accepted")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := VerifyBan(other, r); err == nil {
		t.Error("another key was accepted")
	}
	for _, bad := range []*pb.BanRefusalBody{{SessionId: []byte{1}, BanRef: "x"}, {SessionId: body.SessionId}} {
		if _, err := SignBan(priv, KeyID(pub), bad); err == nil {
			t.Errorf("signed %+v", bad)
		}
	}
}

// The same bytes are in the client's test (client/crates/carthago-core/src/ban.rs): what
// this gateway signs is what that client verifies.
const (
	banVectorPub = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
	banVectorRaw = "0a370a10000102030405060708090a0b0c0d0e0f120464656d6f1a08706c617965722d312080d095ffbc312a0c43572d414243442d32333435124085ca56c74123e3ace0cb7d2de75ba1e8f4096772f1312bfab56130ee4ff0d3812140947c5fbe06b73aee2a09b2da862d17b802be9f70d8444964fc61a5d4cb021a1033303937653264656532636234613334"
)

func TestBanRefusalVector(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
	pub := priv.Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != banVectorPub {
		t.Fatal("the vector's key changed")
	}
	sid, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	r, err := SignBan(priv, KeyID(pub), &pb.BanRefusalBody{SessionId: sid, TenantId: "demo", PlayerIdHash: "player-1", IssuedAtMs: 1700000000000, BanRef: "CW-ABCD-2345"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := proto.Marshal(r)
	if hex.EncodeToString(raw) != banVectorRaw {
		t.Fatalf("the encoding of a ban refusal changed:\n%x", raw)
	}
}
