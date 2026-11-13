package protocol

import (
	"crypto/ed25519"

	pb "carthago/backend/gen/carthago/v1"
)

type NoticeCase struct {
	Name         string `json:"name"`
	NoticeID     Hex    `json:"notice_id"`
	SessionID    Hex    `json:"session_id"`
	TenantID     string `json:"tenant_id"`
	PlayerIDHash string `json:"player_id_hash"`
	IssuedAtMs   uint64 `json:"issued_at_ms"`
	Category     uint32 `json:"category"`
	Severity     uint32 `json:"severity"`
	BodyBytes    Hex    `json:"body_bytes"`
	ServerSig    Hex    `json:"server_sig"`
	NoticeBytes  Hex    `json:"notice_bytes"`
}

type NoticeVectors struct {
	Description        string       `json:"description"`
	ServerIdentitySeed Hex          `json:"server_identity_seed"`
	ServerIdentityPub  Hex          `json:"server_identity_pub"`
	ServerKeyID        string       `json:"server_key_id"`
	Valid              []NoticeCase `json:"valid"`
	// Invalid notices are encoded EnforcementNotice messages that must be refused.
	Invalid []struct {
		Name        string `json:"name"`
		NoticeBytes Hex    `json:"notice_bytes"`
	} `json:"invalid"`
}

func BuildNoticeVectors() (*NoticeVectors, error) {
	priv := ed25519.NewKeyFromSeed(seed("server identity"))
	pub := priv.Public().(ed25519.PublicKey)
	v := &NoticeVectors{
		Description:        "EnforcementNotice. Encode the body from its fields and compare bytes; the signature is Ed25519 by the server identity key over \"carthago/v1/enforcement-notice\" || body_bytes.",
		ServerIdentitySeed: seed("server identity"), ServerIdentityPub: Hex(pub), ServerKeyID: KeyID(pub),
	}
	cases := []NoticeCase{
		{Name: "test_notice", NoticeID: seed("notice a")[:NoticeIDLen], SessionID: seed("session id")[:SessionIDLen], TenantID: "tenant-demo", PlayerIDHash: "9f2c1e7a55d04b3c",
			IssuedAtMs: 1794225700000, Category: uint32(pb.EnforcementCategory_ENFORCEMENT_CATEGORY_TEST), Severity: uint32(pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_NOTICE)},
		{Name: "aim_assistance_high", NoticeID: seed("notice b")[:NoticeIDLen], SessionID: seed("session id")[:SessionIDLen], TenantID: "tenant-demo", PlayerIDHash: "9f2c1e7a55d04b3c",
			IssuedAtMs: 1794225800000, Category: uint32(pb.EnforcementCategory_ENFORCEMENT_CATEGORY_AIM_ASSISTANCE), Severity: uint32(pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_HIGH)},
		{Name: "game_integrity_critical", NoticeID: seed("notice c")[:NoticeIDLen], SessionID: seed("session id")[:SessionIDLen], TenantID: "tenant-demo", PlayerIDHash: "",
			IssuedAtMs: 1794225900000, Category: uint32(pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY), Severity: uint32(pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_CRITICAL)},
	}
	encode := func(n *pb.EnforcementNotice) (Hex, error) { return deterministic.Marshal(n) }
	for _, c := range cases {
		n, err := SignNotice(priv, v.ServerKeyID, &pb.EnforcementNoticeBody{NoticeId: c.NoticeID, SessionId: c.SessionID, TenantId: c.TenantID,
			PlayerIdHash: c.PlayerIDHash, IssuedAtMs: c.IssuedAtMs, Category: c.Category, Severity: c.Severity})
		if err != nil {
			return nil, err
		}
		c.BodyBytes, c.ServerSig = n.Body, n.ServerSig
		if c.NoticeBytes, err = encode(n); err != nil {
			return nil, err
		}
		v.Valid = append(v.Valid, c)
	}
	invalid := func(name string, change func(n *pb.EnforcementNotice)) error {
		c := v.Valid[1]
		n := &pb.EnforcementNotice{Body: append([]byte(nil), c.BodyBytes...), ServerSig: append([]byte(nil), c.ServerSig...), ServerKeyId: v.ServerKeyID}
		change(n)
		b, err := encode(n)
		v.Invalid = append(v.Invalid, struct {
			Name        string `json:"name"`
			NoticeBytes Hex    `json:"notice_bytes"`
		}{name, b})
		return err
	}
	other := ed25519.NewKeyFromSeed(seed("another identity"))
	for _, e := range []error{
		// The category byte is the last but two of the body: a high notice turned into another category.
		invalid("body_changed", func(n *pb.EnforcementNotice) { n.Body[len(n.Body)-3] ^= 1 }),
		invalid("signature_changed", func(n *pb.EnforcementNotice) { n.ServerSig[0] ^= 1 }),
		invalid("signed_by_another_key", func(n *pb.EnforcementNotice) { n.ServerSig = ed25519.Sign(other, NoticeSigInput(n.Body)) }),
		invalid("another_key_id", func(n *pb.EnforcementNotice) { n.ServerKeyId = KeyID(other.Public().(ed25519.PublicKey)) }),
		invalid("signature_of_another_message", func(n *pb.EnforcementNotice) { n.ServerSig = ed25519.Sign(priv, n.Body) }),
	} {
		if e != nil {
			return nil, e
		}
	}
	return v, nil
}
