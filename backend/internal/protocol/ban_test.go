package protocol

import (
	"bytes"
	"crypto/ed25519"
	"testing"

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
