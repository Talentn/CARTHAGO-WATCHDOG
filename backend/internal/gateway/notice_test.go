package gateway

import (
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/protocol"
	"carthago/backend/internal/store"
)

func newNoticeEnv(t *testing.T, testAfter time.Duration) *env {
	keys, err := LoadOrCreateKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var gw *Gateway
	pl := pipeline.New(pipeline.Config{Notices: true}, st, st, kickFunc(func(id, reason string) { gw.Sessions().Kick(id, reason) }), log)
	t.Cleanup(pl.Close)
	gw = New(Config{
		Tenants: map[string]string{"demo": serverKey}, HeartbeatInterval: time.Second, HeartbeatTimeout: 5 * time.Second,
		TokenTTL: time.Minute, RenewBefore: time.Second, Detections: pl, TestNoticeAfter: testAfter,
	}, keys, st, log)
	pl.SetNotifier(gw)
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	return &env{gw: gw, srv: srv, keys: keys, st: st}
}

// recvNotice reads until an EnforcementNotice arrives, skipping heartbeat acks.
func recvNotice(t *testing.T, c *testClient) *pb.EnforcementNotice {
	t.Helper()
	for range 4 {
		m, err := c.recv()
		if err != nil {
			t.Fatalf("waiting for a notice: %v", err)
		}
		if n := m.GetEnforcementNotice(); n != nil {
			return n
		}
		if m.GetKicked() != nil {
			t.Fatalf("kicked: %v", m)
		}
	}
	t.Fatal("no notice")
	return nil
}

func TestIntegrityEvidenceSendsASignedNoticeOnce(t *testing.T) {
	e := newNoticeEnv(t, 0)
	c, err := handshake(t, e, softwareKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := protocol.VerifyToken(tokenKeys(e), c.session.SessionToken, time.Now(), protocol.DefaultLeeway)
	patch := func(detail string) {
		c.send(&pb.ClientMsg{Body: &pb.ClientMsg_Heartbeat{Heartbeat: &pb.Heartbeat{Findings: []*pb.Finding{
			{Code: uint32(pb.FindingCode_FINDING_CODE_CODE_PATCH), A: 1, B: 2, Detail: detail},
		}}}})
	}
	patch("hw.dll>a")
	n := recvNotice(t, c)
	pub := e.keys.Identity.Public().(ed25519.PublicKey)
	body, err := protocol.VerifyNotice(pub, n)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(body.SessionId) != claims.SessionID || body.TenantId != "demo" || body.PlayerIdHash != "player-1" ||
		body.Category != uint32(pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY) || body.Severity != uint32(pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_HIGH) ||
		body.IssuedAtMs == 0 {
		t.Fatalf("notice body %v", body)
	}
	n.Body[len(n.Body)-1] ^= 1
	if _, err := protocol.VerifyNotice(pub, n); err == nil {
		t.Fatal("a changed notice verifies")
	}

	// More evidence of the same kind: no second notice, and the session is never ended.
	patch("hw.dll>b")
	if e.gw.Notice(claims.SessionID, pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY, pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_CRITICAL) {
		t.Fatal("a second notice of the same category was issued")
	}
	for range 3 {
		if m := c.heartbeat(); m.GetHeartbeatAck() == nil {
			t.Fatalf("after the notice the client got %v, want heartbeat acks only", m)
		}
	}
	if s, _ := e.gw.Sessions().Get(claims.SessionID); s.State != store.SessionActive {
		t.Fatal("a notice must leave the session active")
	}
}

func TestTestNoticeIsLabelledAsATest(t *testing.T) {
	e := newNoticeEnv(t, 30*time.Millisecond)
	c, err := handshake(t, e, softwareKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	body, err := protocol.VerifyNotice(e.keys.Identity.Public().(ed25519.PublicKey), recvNotice(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if body.Category != uint32(pb.EnforcementCategory_ENFORCEMENT_CATEGORY_TEST) || body.Severity != uint32(pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_NOTICE) {
		t.Fatalf("test notice body %v", body)
	}
}

func TestNoticeWaitsForTheClientConnection(t *testing.T) {
	e := newNoticeEnv(t, 0)
	m := e.gw.Sessions()
	id := "000102030405060708090a0b0c0d0e0f"
	if err := m.Start(store.Session{SessionID: id, TenantID: "demo", PlayerHash: "p"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	aim, dbg := pb.EnforcementCategory_ENFORCEMENT_CATEGORY_AIM_ASSISTANCE, pb.EnforcementCategory_ENFORCEMENT_CATEGORY_DEBUGGER
	high := pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_HIGH
	if !e.gw.Notice(id, aim, high) {
		t.Fatal("notice for an active session without a connection was not issued")
	}
	var got []*pb.EnforcementNotice
	m.AttachNotices(id, func(n *pb.EnforcementNotice) { got = append(got, n) })
	if len(got) != 1 {
		t.Fatalf("pending notices handed over: %d, want 1", len(got))
	}
	if e.gw.Notice(id, aim, high) || len(got) != 1 {
		t.Fatal("the same category was sent twice")
	}
	if !e.gw.Notice(id, dbg, high) || len(got) != 2 {
		t.Fatalf("another category: %d notices, want 2", len(got))
	}
	m.Detach(id)
	m.AttachNotices(id, func(n *pb.EnforcementNotice) { got = append(got, n) })
	if len(got) != 2 {
		t.Fatal("a notice was handed over twice after a reconnect")
	}
	m.Kick(id, "test")
	if e.gw.Notice(id, pb.EnforcementCategory_ENFORCEMENT_CATEGORY_TIME_MANIPULATION, high) {
		t.Fatal("notice issued for a session that has ended")
	}
	if e.gw.Notice("not-a-session", aim, high) || e.gw.Notice("ffffffffffffffffffffffffffffffff", aim, high) {
		t.Fatal("notice issued for an unknown session")
	}
}
