package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/attest/ekroots"
	"carthago/backend/internal/protocol"
	"carthago/backend/internal/store"
)

const serverKey = "test-server-key"

type env struct {
	gw   *Gateway
	srv  *httptest.Server
	keys *Keys
	st   *store.Memory
	dial *websocket.DialOptions
}

func newEnv(t *testing.T) *env {
	keys, err := LoadOrCreateKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	gw := New(Config{
		Tenants: map[string]string{"demo": serverKey}, HeartbeatInterval: 50 * time.Millisecond, HeartbeatTimeout: 300 * time.Millisecond,
		TokenTTL: time.Minute, RenewBefore: time.Minute,
	}, keys, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	return &env{gw: gw, srv: srv, keys: keys, st: st}
}

func (e *env) url(path string) string { return "ws" + strings.TrimPrefix(e.srv.URL, "http") + path }

// testClient is a minimal Go implementation of the client side of the handshake.
type testClient struct {
	t       *testing.T
	ws      *websocket.Conn
	sid     []byte
	c2s     []byte
	s2c     []byte
	sendSeq uint64
	recvSeq uint64
	session *pb.Session
	last    []byte
}

type deviceKey struct {
	alg  pb.DeviceKeyAlg
	pub  []byte
	sign func(digest [32]byte) []byte
}

func softwareKey() deviceKey {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return deviceKey{pb.DeviceKeyAlg_DEVICE_KEY_ALG_ED25519_SOFTWARE, pub, func(d [32]byte) []byte { return ed25519.Sign(priv, d[:]) }}
}

func p256Key() deviceKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1, _ := k.PublicKey.Bytes()
	return deviceKey{pb.DeviceKeyAlg_DEVICE_KEY_ALG_ECDSA_P256_TPM, sec1, func(d [32]byte) []byte {
		r, s, _ := ecdsa.Sign(rand.Reader, k, d[:])
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	}}
}

func handshake(t *testing.T, e *env, dk deviceKey, corruptSig bool) (*testClient, error) {
	return handshakeAs(t, e, dk, "player-1", corruptSig)
}

func handshakeAs(t *testing.T, e *env, dk deviceKey, player string, corruptSig bool) (*testClient, error) {
	ctx := context.Background()
	ws, _, err := websocket.Dial(ctx, e.url("/v1/client"), e.dial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.CloseNow() })
	eph := make([]byte, 32)
	rand.Read(eph)
	ephPub, _ := protocol.X25519Public(eph)
	hello, _ := proto.Marshal(&pb.Hello{
		ProtocolVersion: 1, SdkVersion: "test", TenantId: "demo", BuildId: "b1", ClientEphPub: ephPub,
		DeviceKey: &pb.DeviceKey{Alg: dk.alg, PublicKey: dk.pub}, PlayerIdHash: player, ClientTsMs: uint64(time.Now().UnixMilli()),
	})
	if err := ws.Write(ctx, websocket.MessageBinary, append([]byte{protocol.FrameHello}, hello...)); err != nil {
		t.Fatal(err)
	}
	_, data, err := ws.Read(ctx)
	if err != nil || data[0] != protocol.FrameChallenge {
		t.Fatalf("challenge: %v", err)
	}
	var ch pb.Challenge
	if err := proto.Unmarshal(data[1:], &ch); err != nil {
		t.Fatal(err)
	}
	th := protocol.TranscriptHash(hello, ch.Body)
	if !ed25519.Verify(e.keys.Identity.Public().(ed25519.PublicKey), protocol.ChallengeSigInput(th), ch.ServerSig) {
		t.Fatal("challenge signature does not verify under the pinned identity key")
	}
	var body pb.ChallengeBody
	proto.Unmarshal(ch.Body, &body)
	shared, _ := protocol.X25519(eph, body.ServerEphPub)
	c2s, s2c, _ := protocol.DeriveKeys(shared, th)
	c := &testClient{t: t, ws: ws, sid: body.SessionId, c2s: c2s, s2c: s2c}
	sig := dk.sign(protocol.ProveDigest(th))
	if corruptSig {
		sig[3] ^= 1
	}
	c.send(&pb.ClientMsg{Body: &pb.ClientMsg_Prove{Prove: &pb.Prove{DeviceSig: sig}}})
	m, err := c.recv()
	if err != nil {
		return c, err
	}
	if m.GetError() != nil {
		return c, &rejectError{code: m.GetError().Code, msg: m.GetError().Message}
	}
	if b := m.GetBanned(); b != nil {
		return c, &banRefused{refusal: b}
	}
	c.session = m.GetSession()
	if c.session == nil {
		t.Fatalf("expected Session, got %v", m)
	}
	return c, nil
}

func (c *testClient) send(m *pb.ClientMsg) {
	m.Seq, m.SessionId = c.sendSeq, c.sid
	pt, _ := proto.Marshal(m)
	f, _ := protocol.Seal(c.c2s, c.sid, protocol.ClientToServer, c.sendSeq, pt)
	c.sendSeq++
	c.last = f
	if err := c.ws.Write(context.Background(), websocket.MessageBinary, f); err != nil {
		c.t.Logf("write: %v", err)
	}
}

func (c *testClient) recv() (*pb.ServerMsg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := c.ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	pt, err := protocol.Open(c.s2c, c.sid, protocol.ServerToClient, c.recvSeq, data)
	if err != nil {
		return nil, err
	}
	c.recvSeq++
	var m pb.ServerMsg
	return &m, proto.Unmarshal(pt, &m)
}

func (c *testClient) heartbeat() *pb.ServerMsg {
	c.send(&pb.ClientMsg{Body: &pb.ClientMsg_Heartbeat{Heartbeat: &pb.Heartbeat{Sched: &pb.SchedSummary{Frames: 1}}}})
	m, err := c.recv()
	if err != nil {
		c.t.Fatalf("heartbeat ack: %v", err)
	}
	return m
}

func tokenKeys(e *env) map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{e.keys.TokenKID: e.keys.Token.Public().(ed25519.PublicKey)}
}

func TestHandshakeIssuesOfflineVerifiableToken(t *testing.T) {
	e := newEnv(t)
	dk := softwareKey()
	c, err := handshake(t, e, dk, false)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := protocol.VerifyToken(tokenKeys(e), c.session.SessionToken, time.Now(), protocol.DefaultLeeway)
	if err != nil {
		t.Fatal(err)
	}
	if claims.TrustLevel != protocol.TrustSoftware || claims.AttestFlags != 0 || claims.Tenant != "demo" || claims.PlayerHash != "player-1" ||
		claims.DeviceID != protocol.DeviceID(uint8(dk.alg), dk.pub) {
		t.Errorf("claims %+v", claims)
	}
	if _, err := e.st.GetDevice(context.Background(), claims.DeviceID); err != nil {
		t.Errorf("device not stored: %v", err)
	}
	if m := c.heartbeat(); m.GetHeartbeatAck() == nil || m.GetHeartbeatAck().RenewedToken == "" {
		t.Errorf("expected an ack with a renewed token (RenewBefore = TTL), got %v", m)
	} else if _, err := protocol.VerifyToken(tokenKeys(e), m.GetHeartbeatAck().RenewedToken, time.Now(), protocol.DefaultLeeway); err != nil {
		t.Errorf("renewed token: %v", err)
	}
}

func TestTPMKeyWithoutAttestationGetsTrustLevel1(t *testing.T) {
	e := newEnv(t)
	c, err := handshake(t, e, p256Key(), false)
	if err != nil {
		t.Fatal(err)
	}
	if c.session.TrustLevel != protocol.TrustTPMKey || c.session.AttestFlags != protocol.FlagTPMDeviceKey {
		t.Errorf("trust %d flags %#x", c.session.TrustLevel, c.session.AttestFlags)
	}
}

func TestBadDeviceSignatureRejected(t *testing.T) {
	e := newEnv(t)
	_, err := handshake(t, e, softwareKey(), true)
	if re, ok := err.(*rejectError); !ok || re.code != "bad_device_sig" {
		t.Fatalf("got %v", err)
	}
}

func watch(t *testing.T, e *env, sid string) *websocket.Conn {
	ctx := context.Background()
	gs, _, err := websocket.Dial(ctx, e.url("/v1/gs"), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + serverKey}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gs.CloseNow() })
	b, _ := proto.Marshal(&pb.GsClientMsg{Body: &pb.GsClientMsg_Watch{Watch: &pb.WatchSession{SessionId: sid}}})
	gs.Write(ctx, websocket.MessageBinary, b)
	if m := readGS(t, gs); m.GetWatchAck() == nil || !m.GetWatchAck().Known {
		t.Fatalf("watch ack: %v", m)
	}
	return gs
}

func readGS(t *testing.T, gs *websocket.Conn) *pb.GsServerMsg {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, data, err := gs.Read(ctx)
	if err != nil {
		t.Fatalf("game server read: %v", err)
	}
	var m pb.GsServerMsg
	proto.Unmarshal(data, &m)
	return &m
}

func TestHeartbeatTimeoutKicksWatchingGameServer(t *testing.T) {
	e := newEnv(t)
	c, err := handshake(t, e, softwareKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := protocol.VerifyToken(tokenKeys(e), c.session.SessionToken, time.Now(), protocol.DefaultLeeway)
	gs := watch(t, e, claims.SessionID)
	for range 5 { // heartbeats keep the session alive past the 300 ms deadline
		c.heartbeat()
		time.Sleep(100 * time.Millisecond)
	}
	if s, _ := e.gw.Sessions().Get(claims.SessionID); s.State != store.SessionActive {
		t.Fatalf("kicked despite heartbeats: %+v", s)
	}
	start := time.Now()
	kick := readGS(t, gs).GetKick()
	if kick == nil || kick.Reason != "heartbeat_timeout" || kick.SessionId != claims.SessionID {
		t.Fatalf("kick: %v", kick)
	}
	t.Logf("kick %v after the last heartbeat", time.Since(start).Round(time.Millisecond))
	if m, err := c.recv(); err != nil || m.GetKicked() == nil {
		t.Errorf("client should be told it was kicked: %v %v", m, err)
	}
	if s, _ := e.st.GetSession(context.Background(), claims.SessionID); s.State != store.SessionKicked || s.Heartbeats != 5 {
		t.Errorf("stored session %+v", s)
	}
	// A game server that starts watching after the kick still gets it.
	late, _, _ := websocket.Dial(context.Background(), e.url("/v1/gs"), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + serverKey}}})
	defer late.CloseNow()
	b, _ := proto.Marshal(&pb.GsClientMsg{Body: &pb.GsClientMsg_Watch{Watch: &pb.WatchSession{SessionId: claims.SessionID}}})
	late.Write(context.Background(), websocket.MessageBinary, b)
	readGS(t, late)
	if k := readGS(t, late).GetKick(); k == nil {
		t.Error("late watcher did not get the kick")
	}
}

func TestReplayedFrameKicks(t *testing.T) {
	e := newEnv(t)
	c, err := handshake(t, e, softwareKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := protocol.VerifyToken(tokenKeys(e), c.session.SessionToken, time.Now(), protocol.DefaultLeeway)
	gs := watch(t, e, claims.SessionID)
	c.heartbeat()
	c.ws.Write(context.Background(), websocket.MessageBinary, c.last)
	if k := readGS(t, gs).GetKick(); k == nil || k.Reason != "protocol_violation" {
		t.Fatalf("kick: %v", k)
	}
}

func TestGameServerAuth(t *testing.T) {
	e := newEnv(t)
	_, resp, err := websocket.Dial(context.Background(), e.url("/v1/gs"), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer wrong"}}})
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %v %v", resp, err)
	}
}

// Everything else verified, the EK chain outcome alone decides whether trust reaches 2/3.
func TestEKChainStatusCapsTrustLevel(t *testing.T) {
	verified := protocol.FlagTPMDeviceKey | protocol.FlagDeviceKeyCertified | protocol.FlagAKBoundToEK | protocol.FlagQuoteVerified |
		protocol.FlagSecureBoot | protocol.FlagHVCI | protocol.FlagTestSigningOff | protocol.FlagKernelDebugOff | protocol.FlagBootDebugOff | protocol.FlagCodeIntegrity
	for _, c := range []struct {
		dev  store.Device
		want uint32
	}{
		{store.Device{EKCertMatches: true, EKChain: string(ekroots.StatusVerified)}, protocol.TrustRankedBoot},
		{store.Device{EKCertMatches: true, EKChain: string(ekroots.StatusUnknownVendor)}, protocol.TrustTPMKey},
		{store.Device{EKCertMatches: true, EKChain: string(ekroots.StatusInvalid)}, protocol.TrustTPMKey},
		{store.Device{EKChain: string(ekroots.StatusInvalid)}, protocol.TrustTPMKey},
		{store.Device{EKChain: string(ekroots.StatusNoCert)}, protocol.TrustTPMKey},
		{store.Device{EKCertMatches: true}, protocol.TrustTPMKey}, // bound before chains were checked
		{store.Device{EKChain: string(ekroots.StatusVerified)}, protocol.TrustTPMKey},
	} {
		d := c.dev
		if got := protocol.TrustLevel(verified | ekChainFlags(&d)); got != c.want {
			t.Errorf("%+v: trust %d, want %d", c.dev, got, c.want)
		}
		if got := protocol.TrustLevel((verified &^ protocol.FlagTPMDeviceKey) | ekChainFlags(&d)); got != protocol.TrustSoftware {
			t.Errorf("software key with %+v: trust %d", c.dev, got)
		}
	}

	// A chain status stored at enrollment counts only when the EK was presented and verified
	// again in this handshake.
	stored := store.Device{EKCertMatches: true, EKChain: string(ekroots.StatusVerified)}
	all := verified | ekChainFlags(&stored)
	if f, notes := capUncheckedEK(all, nil, false); protocol.TrustLevel(f) != protocol.TrustTPMKey || len(notes) != 1 {
		t.Errorf("stored chain status without a re-check: trust %d, notes %v", protocol.TrustLevel(f), notes)
	}
	if f, notes := capUncheckedEK(all, nil, true); protocol.TrustLevel(f) != protocol.TrustRankedBoot || len(notes) != 0 {
		t.Errorf("re-checked chain: trust %d, notes %v", protocol.TrustLevel(f), notes)
	}
}
