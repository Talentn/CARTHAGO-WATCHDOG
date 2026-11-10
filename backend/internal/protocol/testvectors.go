package protocol

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	pb "sentinel/backend/gen/sentinel/v1"
)

// Golden vectors for proto/testvectors/. Inputs are derived from fixed labels, so
// regeneration is reproducible except for the verify-only ECDSA signature.

type Hex []byte

func (h Hex) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(h)), nil }
func (h *Hex) UnmarshalText(b []byte) error {
	v, err := hex.DecodeString(string(b))
	*h = v
	return err
}

func seed(label string) Hex {
	s := sha256.Sum256([]byte("sentinel test vector: " + label))
	return s[:]
}

type TokenCase struct {
	Name     string  `json:"name"`
	Claims   *Claims `json:"claims,omitempty"`
	Token    string  `json:"token"`
	VerifyAt string  `json:"verify_at"`
	Error    string  `json:"error,omitempty"`
}

type TokenVectors struct {
	Description string      `json:"description"`
	SigningSeed Hex         `json:"signing_seed"`
	PublicKey   Hex         `json:"public_key"`
	Kid         string      `json:"kid"`
	LeewaySecs  int         `json:"leeway_secs"`
	Valid       []TokenCase `json:"valid"`
	Invalid     []TokenCase `json:"invalid"`
}

type HelloJSON struct {
	ProtocolVersion uint32 `json:"protocol_version"`
	SdkVersion      string `json:"sdk_version"`
	TenantID        string `json:"tenant_id"`
	BuildID         string `json:"build_id"`
	ClientEphPub    Hex    `json:"client_eph_pub"`
	DeviceKeyAlg    int32  `json:"device_key_alg"`
	DeviceKeyPublic Hex    `json:"device_key_public"`
	PlayerIDHash    string `json:"player_id_hash"`
	EnvOSBuild      string `json:"env_os_build"`
	EnvElevated     bool   `json:"env_elevated"`
	EnvTPMPresent   bool   `json:"env_tpm_present"`
	EnvTPMMfr       string `json:"env_tpm_manufacturer"`
	EKPublic        Hex    `json:"enroll_ek_public"`
	EKCerts         []Hex  `json:"enroll_ek_certs"`
	EKChainCerts    []Hex  `json:"enroll_ek_chain_certs"`
	AKPublic        Hex    `json:"enroll_ak_public"`
	AKCreateData    Hex    `json:"enroll_ak_create_data"`
	AKCreateAttest  Hex    `json:"enroll_ak_create_attestation"`
	AKCreateSig     Hex    `json:"enroll_ak_create_signature"`
	TPMMfr          string `json:"enroll_tpm_manufacturer"`
	TPMFirmware     string `json:"enroll_tpm_firmware"`
	TPMAvailable    bool   `json:"tpm_attestation_available"`
	ClientTsMs      uint64 `json:"client_ts_ms"`
}

type ChallengeBodyJSON struct {
	ServerNonce         Hex      `json:"server_nonce"`
	ServerEphPub        Hex      `json:"server_eph_pub"`
	SessionID           Hex      `json:"session_id"`
	ServerTsMs          uint64   `json:"server_ts_ms"`
	PCRs                []uint32 `json:"attest_pcrs"`
	EKObjectPublic      Hex      `json:"attest_ek_object_public"`
	EKDuplicate         Hex      `json:"attest_ek_duplicate"`
	EKInSymSeed         Hex      `json:"attest_ek_in_sym_seed"`
	CertifyDeviceKey    bool     `json:"attest_certify_device_key"`
	HeartbeatIntervalMs uint32   `json:"heartbeat_interval_ms"`
	HeartbeatTimeoutMs  uint32   `json:"heartbeat_timeout_ms"`
}

type P256Vector struct {
	PublicSEC1  Hex    `json:"public_sec1"`
	DeviceID    string `json:"device_id"`
	SignatureRS Hex    `json:"signature_rs"`
}

type HandshakeVectors struct {
	Description        string            `json:"description"`
	ClientEphSecret    Hex               `json:"client_eph_secret"`
	ClientEphPub       Hex               `json:"client_eph_pub"`
	ServerEphSecret    Hex               `json:"server_eph_secret"`
	ServerEphPub       Hex               `json:"server_eph_pub"`
	ServerIdentitySeed Hex               `json:"server_identity_seed"`
	ServerIdentityPub  Hex               `json:"server_identity_pub"`
	ServerKeyID        string            `json:"server_key_id"`
	DeviceSeed         Hex               `json:"device_ed25519_seed"`
	DevicePub          Hex               `json:"device_ed25519_pub"`
	DeviceID           string            `json:"device_id"`
	Hello              HelloJSON         `json:"hello"`
	HelloBytes         Hex               `json:"hello_bytes"`
	ChallengeBody      ChallengeBodyJSON `json:"challenge_body"`
	ChallengeBodyBytes Hex               `json:"challenge_body_bytes"`
	ChallengeBytes     Hex               `json:"challenge_bytes"`
	SharedSecret       Hex               `json:"shared_secret"`
	TranscriptHash     Hex               `json:"transcript_hash"`
	KeyC2S             Hex               `json:"key_c2s"`
	KeyS2C             Hex               `json:"key_s2c"`
	ServerSig          Hex               `json:"server_sig"`
	ProveDigest        Hex               `json:"prove_digest"`
	QuoteNonce         Hex               `json:"quote_nonce"`
	DeviceSig          Hex               `json:"device_sig"`
	P256               P256Vector        `json:"p256_verify_only"`
}

type AEADCase struct {
	Name        string    `json:"name"`
	Direction   Direction `json:"direction"`
	Seq         uint64    `json:"seq"`
	MessageType string    `json:"message_type,omitempty"`
	Plaintext   Hex       `json:"plaintext,omitempty"`
	Frame       Hex       `json:"frame"`
	Error       string    `json:"error,omitempty"`
}

type AEADVectors struct {
	Description string     `json:"description"`
	Key         Hex        `json:"key"`
	SessionID   Hex        `json:"session_id"`
	Valid       []AEADCase `json:"valid"`
	Invalid     []AEADCase `json:"invalid"`
}

var vectorEpoch = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func BuildTokenVectors() (*TokenVectors, error) {
	sk := ed25519.NewKeyFromSeed(seed("token signing key"))
	pub := sk.Public().(ed25519.PublicKey)
	v := &TokenVectors{
		Description: "PASETO v4.public session tokens. Sign `claims` with the seed and compare the token byte-for-byte; verify each case at verify_at with leeway_secs.",
		SigningSeed: sk.Seed(), PublicKey: Hex(pub), Kid: KeyID(pub), LeewaySecs: int(DefaultLeeway / time.Second),
	}
	claims := Claims{
		Iss: TokenIssuer, Tenant: "tenant-demo", PlayerHash: "9f2c1e7a55d04b3c", DeviceID: "0123456789abcdef0123456789abcdef",
		SessionID: "00112233445566778899aabbccddeeff", Iat: FormatTime(vectorEpoch), Exp: FormatTime(vectorEpoch.Add(15 * time.Minute)),
		TrustLevel: TrustRankedBoot, AttestFlags: rankedMask | FlagEKCertMatches,
	}
	tok, err := SignToken(sk, claims)
	if err != nil {
		return nil, err
	}
	soft := claims
	soft.TrustLevel, soft.AttestFlags, soft.PlayerHash = TrustSoftware, 0, "player <&> \"quoted\" é"
	softTok, err := SignToken(sk, soft)
	if err != nil {
		return nil, err
	}
	at := FormatTime(vectorEpoch.Add(time.Minute))
	v.Valid = []TokenCase{
		{Name: "ranked_device", Claims: &claims, Token: tok, VerifyAt: at},
		{Name: "software_device_unusual_chars", Claims: &soft, Token: softTok, VerifyAt: at},
		{Name: "within_exp_leeway", Claims: &claims, Token: tok, VerifyAt: FormatTime(vectorEpoch.Add(15*time.Minute + 29*time.Second))},
	}

	flip := func(s string, i int) string {
		b := []byte(s)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}
	other := ed25519.NewKeyFromSeed(seed("attacker key"))
	forged, _ := signWithKid(other, claims, v.Kid)
	foreign, _ := SignToken(other, claims)
	dot := len(tok) - len(b64.EncodeToString([]byte(`{"kid":"`+v.Kid+`"}`))) - 1
	v.Invalid = []TokenCase{
		{Name: "tampered_claims", Token: flip(tok, len("v4.public.")+20), VerifyAt: at, Error: ErrTokenSignature.Error()},
		{Name: "tampered_signature", Token: flip(tok, dot-5), VerifyAt: at, Error: ErrTokenSignature.Error()},
		{Name: "forged_with_trusted_kid", Token: forged, VerifyAt: at, Error: ErrTokenSignature.Error()},
		{Name: "unknown_kid", Token: foreign, VerifyAt: at, Error: ErrTokenUnknownKey.Error()},
		{Name: "expired", Token: tok, VerifyAt: FormatTime(vectorEpoch.Add(15*time.Minute + 30*time.Second)), Error: ErrTokenExpired.Error()},
		{Name: "not_yet_valid", Token: tok, VerifyAt: FormatTime(vectorEpoch.Add(-31 * time.Second)), Error: ErrTokenNotYetValid.Error()},
		{Name: "wrong_version", Token: "v3" + tok[2:], VerifyAt: at, Error: ErrTokenMalformed.Error()},
		{Name: "missing_footer", Token: tok[:dot], VerifyAt: at, Error: ErrTokenMalformed.Error()},
		{Name: "truncated", Token: tok[:len("v4.public.")+40] + tok[dot:], VerifyAt: at, Error: ErrTokenMalformed.Error()},
	}
	return v, nil
}

// signWithKid signs with priv but labels the token with another key's kid (forgery test).
func signWithKid(priv ed25519.PrivateKey, c Claims, kid string) (string, error) {
	msg, err := encodeJSON(c)
	if err != nil {
		return "", err
	}
	f, _ := encodeJSON(footer{Kid: kid})
	sig := ed25519.Sign(priv, pae([]byte(tokenHeader), msg, f, nil))
	return tokenHeader + b64.EncodeToString(append(msg, sig...)) + "." + b64.EncodeToString(f), nil
}

func HelloFromJSON(h *HelloJSON) *pb.Hello {
	certs := make([][]byte, len(h.EKCerts))
	for i, c := range h.EKCerts {
		certs[i] = c
	}
	chain := make([][]byte, len(h.EKChainCerts))
	for i, c := range h.EKChainCerts {
		chain[i] = c
	}
	return &pb.Hello{
		ProtocolVersion: h.ProtocolVersion, SdkVersion: h.SdkVersion, TenantId: h.TenantID, BuildId: h.BuildID,
		ClientEphPub: h.ClientEphPub,
		DeviceKey:    &pb.DeviceKey{Alg: pb.DeviceKeyAlg(h.DeviceKeyAlg), PublicKey: h.DeviceKeyPublic},
		PlayerIdHash: h.PlayerIDHash,
		Env:          &pb.EnvReport{OsBuild: h.EnvOSBuild, Elevated: h.EnvElevated, TpmPresent: h.EnvTPMPresent, TpmManufacturer: h.EnvTPMMfr},
		TpmEnrollment: &pb.TpmEnrollment{
			EkPublic: h.EKPublic, EkCerts: certs, AkPublic: h.AKPublic, AkCreateData: h.AKCreateData,
			AkCreateAttestation: h.AKCreateAttest, AkCreateSignature: h.AKCreateSig, TpmManufacturer: h.TPMMfr, TpmFirmware: h.TPMFirmware,
			EkChainCerts: chain,
		},
		TpmAttestationAvailable: h.TPMAvailable, ClientTsMs: h.ClientTsMs,
	}
}

func ChallengeBodyFromJSON(c *ChallengeBodyJSON) *pb.ChallengeBody {
	return &pb.ChallengeBody{
		ServerNonce: c.ServerNonce, ServerEphPub: c.ServerEphPub, SessionId: c.SessionID, ServerTsMs: c.ServerTsMs,
		Attest: &pb.AttestRequest{
			Pcrs:             c.PCRs,
			EkChallenge:      &pb.EkChallenge{ObjectPublic: c.EKObjectPublic, Duplicate: c.EKDuplicate, InSymSeed: c.EKInSymSeed},
			CertifyDeviceKey: c.CertifyDeviceKey,
		},
		HeartbeatIntervalMs: c.HeartbeatIntervalMs, HeartbeatTimeoutMs: c.HeartbeatTimeoutMs,
	}
}

var deterministic = proto.MarshalOptions{Deterministic: true}

func BuildHandshakeVectors() (*HandshakeVectors, error) {
	v := &HandshakeVectors{
		Description: "Hello/Challenge/Prove. Encode hello and challenge_body from their fields and compare bytes; recompute every derived value from the secrets.",
		ClientEphSecret: seed("client ephemeral"), ServerEphSecret: seed("server ephemeral"),
		ServerIdentitySeed: seed("server identity"), DeviceSeed: seed("device key ed25519"),
	}
	var err error
	if v.ClientEphPub, err = X25519Public(v.ClientEphSecret); err != nil {
		return nil, err
	}
	if v.ServerEphPub, err = X25519Public(v.ServerEphSecret); err != nil {
		return nil, err
	}
	ident := ed25519.NewKeyFromSeed(v.ServerIdentitySeed)
	v.ServerIdentityPub = Hex(ident.Public().(ed25519.PublicKey))
	v.ServerKeyID = KeyID(ident.Public().(ed25519.PublicKey))
	dev := ed25519.NewKeyFromSeed(v.DeviceSeed)
	v.DevicePub = Hex(dev.Public().(ed25519.PublicKey))
	v.DeviceID = DeviceID(uint8(pb.DeviceKeyAlg_DEVICE_KEY_ALG_ED25519_SOFTWARE), v.DevicePub)

	v.Hello = HelloJSON{
		ProtocolVersion: ProtocolVersion, SdkVersion: "0.1.0", TenantID: "tenant-demo", BuildID: "build-2026.11.09",
		ClientEphPub: v.ClientEphPub, DeviceKeyAlg: int32(pb.DeviceKeyAlg_DEVICE_KEY_ALG_ED25519_SOFTWARE), DeviceKeyPublic: v.DevicePub,
		PlayerIDHash: "9f2c1e7a55d04b3c", EnvOSBuild: "26200", EnvElevated: false, EnvTPMPresent: true, EnvTPMMfr: "INTC",
		EKPublic: seed("ek")[:12], EKCerts: []Hex{seed("cert1")[:5], seed("cert2")[:9]},
		EKChainCerts: []Hex{seed("chain1")[:7], seed("chain2")[:11], seed("chain3")[:3]}, AKPublic: seed("ak")[:10],
		AKCreateData: seed("cd")[:4], AKCreateAttest: seed("ca")[:6], AKCreateSig: seed("cs")[:8],
		TPMMfr: "INTC", TPMFirmware: "600.7.42.2235", TPMAvailable: true, ClientTsMs: uint64(vectorEpoch.UnixMilli()),
	}
	if v.HelloBytes, err = deterministic.Marshal(HelloFromJSON(&v.Hello)); err != nil {
		return nil, err
	}
	v.ChallengeBody = ChallengeBodyJSON{
		ServerNonce: seed("server nonce"), ServerEphPub: v.ServerEphPub, SessionID: seed("session id")[:SessionIDLen],
		ServerTsMs: uint64(vectorEpoch.UnixMilli()) + 7, PCRs: []uint32{0, 2, 4, 7, 11, 12, 13, 14},
		EKObjectPublic: seed("ek obj")[:7], EKDuplicate: seed("ek dup")[:11], EKInSymSeed: seed("ek seed")[:3],
		CertifyDeviceKey: true, HeartbeatIntervalMs: 15000, HeartbeatTimeoutMs: 45000,
	}
	if v.ChallengeBodyBytes, err = deterministic.Marshal(ChallengeBodyFromJSON(&v.ChallengeBody)); err != nil {
		return nil, err
	}
	th := TranscriptHash(v.HelloBytes, v.ChallengeBodyBytes)
	v.TranscriptHash = th[:]
	v.ServerSig = ed25519.Sign(ident, ChallengeSigInput(th))
	if v.ChallengeBytes, err = deterministic.Marshal(&pb.Challenge{Body: v.ChallengeBodyBytes, ServerSig: v.ServerSig, ServerKeyId: v.ServerKeyID}); err != nil {
		return nil, err
	}
	if v.SharedSecret, err = X25519(v.ClientEphSecret, v.ServerEphPub); err != nil {
		return nil, err
	}
	if v.KeyC2S, v.KeyS2C, err = DeriveKeys(v.SharedSecret, th); err != nil {
		return nil, err
	}
	pd, qn := ProveDigest(th), QuoteNonce(th)
	v.ProveDigest, v.QuoteNonce = pd[:], qn[:]
	v.DeviceSig = ed25519.Sign(dev, pd[:])

	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, ek, pd[:])
	if err != nil {
		return nil, err
	}
	sec1, err := ek.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	rs := make([]byte, 64)
	r.FillBytes(rs[:32])
	s.FillBytes(rs[32:])
	v.P256 = P256Vector{PublicSEC1: sec1, DeviceID: DeviceID(uint8(pb.DeviceKeyAlg_DEVICE_KEY_ALG_ECDSA_P256_TPM), sec1), SignatureRS: rs}
	return v, nil
}

func BuildAEADVectors() (*AEADVectors, error) {
	v := &AEADVectors{
		Description: "Sealed frames. Seal plaintext at (direction, seq) and compare the frame; decode plaintext as message_type and re-encode it byte-for-byte; invalid frames must fail with error.",
		Key:         seed("aead key"), SessionID: seed("session id")[:SessionIDLen],
	}
	sid := []byte(v.SessionID)
	msgs := []struct {
		name string
		dir  Direction
		seq  uint64
		m    proto.Message
	}{
		{"client_prove_seq0", ClientToServer, 0, &pb.ClientMsg{Seq: 0, SessionId: sid, ClientTsMs: 1794225600000, Body: &pb.ClientMsg_Prove{Prove: &pb.Prove{
			DeviceSig: append(seed("sig a"), seed("sig b")...), Attestation: &pb.TpmEvidence{Quote: seed("q")[:20], Pcrs: []*pb.Pcr{{Index: 0, Digest: seed("pcr0")}, {Index: 7, Digest: seed("pcr7")}}, Error: ""},
		}}}},
		{"client_heartbeat_seq1", ClientToServer, 1, &pb.ClientMsg{Seq: 1, SessionId: sid, ClientTsMs: 1794225615000, Body: &pb.ClientMsg_Heartbeat{Heartbeat: &pb.Heartbeat{
			Activity: 1, Sched: &pb.SchedSummary{WorkerCpuNs: 123456789, Slices: 42, SliceCpuMaxNs: 1020000, Frames: 9000, JobsQuarantined: 0, FindingsDropped: 3},
			Findings: []*pb.Finding{{Job: "memory_region_walk", Code: 3, A: 0x7ff612340000, B: 4096}},
		}}}},
		{"server_session_seq0", ServerToClient, 0, &pb.ServerMsg{Seq: 0, SessionId: sid, ServerTsMs: 1794225600100, Body: &pb.ServerMsg_Session{Session: &pb.Session{
			SessionToken: "v4.public.example", TrustLevel: 3, AttestFlags: 0x3ff, ExpiresAtMs: 1794226500000, Notes: []string{"ek chain not verified"},
		}}}},
		{"server_kicked_seq5", ServerToClient, 5, &pb.ServerMsg{Seq: 5, SessionId: sid, ServerTsMs: 1794225700000, Body: &pb.ServerMsg_Kicked{Kicked: &pb.Kicked{Reason: "heartbeat_timeout"}}}},
	}
	for _, m := range msgs {
		pt, err := deterministic.Marshal(m.m)
		if err != nil {
			return nil, err
		}
		fr, err := Seal(v.Key, sid, m.dir, m.seq, pt)
		if err != nil {
			return nil, err
		}
		v.Valid = append(v.Valid, AEADCase{Name: m.name, Direction: m.dir, Seq: m.seq, MessageType: fmt.Sprintf("%T", m.m)[len("*sentinelv1."):], Plaintext: pt, Frame: fr})
	}
	base := v.Valid[1].Frame
	mut := func(i int) Hex {
		b := append(Hex{}, base...)
		b[i] ^= 0x01
		return b
	}
	v.Invalid = []AEADCase{
		{Name: "replayed_seq", Direction: ClientToServer, Seq: 2, Frame: base, Error: "seq"},
		{Name: "flipped_ciphertext", Direction: ClientToServer, Seq: 1, Frame: mut(SealedHeaderLen + 3), Error: "auth"},
		{Name: "flipped_tag", Direction: ClientToServer, Seq: 1, Frame: mut(len(base) - 1), Error: "auth"},
		{Name: "wrong_direction", Direction: ServerToClient, Seq: 1, Frame: base, Error: "auth"},
		{Name: "seq_rewritten", Direction: ClientToServer, Seq: 0, Frame: append(append(Hex{FrameSealed}, make([]byte, 8)...), base[SealedHeaderLen:]...), Error: "auth"},
		{Name: "short", Direction: ClientToServer, Seq: 1, Frame: base[:SealedHeaderLen+10], Error: "malformed"},
		{Name: "wrong_type", Direction: ClientToServer, Seq: 1, Frame: append(Hex{FrameHello}, base[1:]...), Error: "malformed"},
	}
	return v, nil
}
