package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/bans"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/protocol"
	"carthago/backend/internal/store"
)

type banEnv struct {
	*env
	bans *bans.Service
}

// newBanEnv is a gateway with notices and bans wired as the gateway binary wires them.
func newBanEnv(t *testing.T, automatic bool) *banEnv {
	keys, err := LoadOrCreateKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := bans.New(st, log)
	var gw *Gateway
	pl := pipeline.New(pipeline.Config{Notices: true}, st, st, kickFunc(func(id, reason string) { gw.Sessions().Kick(id, reason) }), log)
	t.Cleanup(pl.Close)
	if automatic {
		pl.SetBanner(svc)
	}
	gw = New(Config{
		Tenants: map[string]string{"demo": serverKey}, HeartbeatInterval: time.Second, HeartbeatTimeout: 5 * time.Second,
		TokenTTL: time.Minute, RenewBefore: time.Second, Detections: pl, Bans: svc,
	}, keys, st, log)
	pl.SetNotifier(gw)
	svc.SetEnder(gw.Sessions())
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	return &banEnv{env: &env{gw: gw, srv: srv, keys: keys, st: st}, bans: svc}
}

// refusal checks that err is a signed ban refusal for this handshake and returns its body.
func refusal(t *testing.T, e *env, c *testClient, err error) *pb.BanRefusalBody {
	t.Helper()
	var banned *banRefused
	if !errors.As(err, &banned) {
		t.Fatalf("want a ban refusal, got %v", err)
	}
	body, err := protocol.VerifyBan(e.keys.Identity.Public().(ed25519.PublicKey), banned.refusal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body.SessionId, c.sid) || body.TenantId != "demo" || body.IssuedAtMs == 0 {
		t.Fatalf("refusal body %v", body)
	}
	return body
}

func sessionOf(t *testing.T, e *env, c *testClient) store.Session {
	t.Helper()
	claims, err := protocol.VerifyToken(tokenKeys(e), c.session.SessionToken, time.Now(), protocol.DefaultLeeway)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := e.gw.Sessions().Get(claims.SessionID)
	if !ok {
		t.Fatal("no live session")
	}
	return s
}

// recvKick reads until the session is ended, and returns the notices that came first.
func recvKick(t *testing.T, c *testClient) (reason string, notices []*pb.EnforcementNotice) {
	t.Helper()
	for range 6 {
		m, err := c.recv()
		if err != nil {
			t.Fatalf("waiting for the kick: %v", err)
		}
		if n := m.GetEnforcementNotice(); n != nil {
			notices = append(notices, n)
		}
		if k := m.GetKicked(); k != nil {
			return k.Reason, notices
		}
	}
	t.Fatal("the session was not ended")
	return "", nil
}

// A ban made from a session refuses the account on any device key and the device key
// under any account, ends the session that is running, and stops when it is lifted.
func TestBanRefusesAccountAndDeviceKey(t *testing.T) {
	e := newBanEnv(t, false)
	ctx := context.Background()
	keyA, keyB := p256Key(), softwareKey()
	c, err := handshake(t, e.env, keyA, false)
	if err != nil {
		t.Fatal(err)
	}
	sess := sessionOf(t, e.env, c)
	const reason = "seen through walls in three matches"
	b, created, err := e.bans.Ban(ctx, bans.Request{Session: sess, By: "ada", Reason: reason, Rule: "wallhack_information"})
	if err != nil || !created || b.PlayerHash != "player-1" || b.DeviceID != sess.DeviceID || !b.DeviceTPM || b.BannedBy != "ada" || b.SessionID != sess.SessionID {
		t.Fatalf("ban: %+v created=%v err=%v", b, created, err)
	}
	if got, notices := recvKick(t, c); got != bans.KickReason || len(notices) != 0 {
		t.Fatalf("the running session got %q and %d notices", got, len(notices))
	}
	if s, _ := e.gw.Sessions().Get(sess.SessionID); s.State != store.SessionKicked || s.KickReason != bans.KickReason {
		t.Fatalf("session after the ban: %+v", s)
	}
	if _, created, _ := e.bans.Ban(ctx, bans.Request{Session: sess, By: "rev"}); created {
		t.Fatal("a second ban was made for a player who is banned")
	}

	// The account, on another device key.
	c, err = handshake(t, e.env, keyB, false)
	body := refusal(t, e.env, c, err)
	if body.BanRef != b.Ref || body.PlayerIdHash != "player-1" {
		t.Fatalf("refusal by account: %v", body)
	}
	// The refusal says "banned" and the reference. Nothing of the reason or the rule.
	var banned *banRefused
	errors.As(err, &banned)
	raw, _ := proto.Marshal(banned.refusal)
	for _, secret := range []string{reason, "walls", "wallhack_information", "ada"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("the refusal carries %q", secret)
		}
	}
	// The device key, under a new account.
	c, err = handshakeAs(t, e.env, keyA, "player-2", false)
	if body := refusal(t, e.env, c, err); body.BanRef != b.Ref || body.PlayerIdHash != "player-2" {
		t.Fatalf("refusal by device key: %v", body)
	}
	// Somebody else is not affected, and no session was stored for the refused ones.
	if _, err := handshakeAs(t, e.env, softwareKey(), "player-3", false); err != nil {
		t.Fatalf("an unrelated player was refused: %v", err)
	}
	if _, err := e.st.GetSession(ctx, protocolHex(c.sid)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused handshake left a session: %v", err)
	}

	// Lifted: both get a session again.
	if _, err := e.bans.Lift(ctx, "demo", b.ID, "grace", "appeal"); err != nil {
		t.Fatal(err)
	}
	if _, err := handshake(t, e.env, keyB, false); err != nil {
		t.Fatalf("the account after the lift: %v", err)
	}
	if _, err := handshakeAs(t, e.env, keyA, "player-2", false); err != nil {
		t.Fatalf("the device key after the lift: %v", err)
	}
}

func protocolHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&15])
	}
	return string(out)
}

func rendererFinding() *pb.Finding {
	b := uint64(pb.ModuleSignature_MODULE_SIGNATURE_NONE) | uint64(pb.ModulePathClass_MODULE_PATH_CLASS_GAME_DIR)<<8 |
		uint64(pb.ObservedFlags_OBSERVED_FLAGS_AT_START|pb.ObservedFlags_OBSERVED_FLAGS_SHADOWS_SYSTEM)<<16
	return &pb.Finding{Code: uint32(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE), A: 1, B: b, Detail: "OPENGL32.dll"}
}

// A memory editor holding a write handle raises the alert and is of the suspicious tier.
func memoryToolFinding() *pb.Finding {
	about := uint64(pb.ModuleSignature_MODULE_SIGNATURE_VALID) | (uint64(pb.ModulePathClass_MODULE_PATH_CLASS_PROGRAM_FILES)+1)<<8 |
		uint64(pb.HolderFlags_HOLDER_FLAGS_KNOWN) | uint64(pb.ObservedFlags_OBSERVED_FLAGS_AFTER_START)<<24
	return &pb.Finding{Code: uint32(pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE), A: 4242, B: 0x1fffff | about<<32, Detail: "cheatengine-x86_64.exe"}
}

func sendFindings(c *testClient, f ...*pb.Finding) {
	c.send(&pb.ClientMsg{Body: &pb.ClientMsg_Heartbeat{Heartbeat: &pb.Heartbeat{Findings: f}}})
}

// Certain evidence bans by itself: the player's client gets the notice first, then the
// session ends, and the next handshake is refused. The ban is recorded and audited as
// automatic, with the rule.
func TestCertainEvidenceBansAutomatically(t *testing.T) {
	e := newBanEnv(t, true)
	ctx := context.Background()
	key := softwareKey()
	c, err := handshake(t, e.env, key, false)
	if err != nil {
		t.Fatal(err)
	}
	sess := sessionOf(t, e.env, c)
	sendFindings(c, rendererFinding())
	reason, notices := recvKick(t, c)
	if reason != bans.KickReason || len(notices) != 1 {
		t.Fatalf("got %q after %d notices; want the notice, then the end of the session", reason, len(notices))
	}
	if body, err := protocol.VerifyNotice(e.keys.Identity.Public().(ed25519.PublicKey), notices[0]); err != nil || body.Category != uint32(pb.EnforcementCategory_ENFORCEMENT_CATEGORY_VISIBILITY) {
		t.Fatalf("notice %v %v", body, err)
	}
	list, _ := e.st.ListBans(ctx, "demo", 0)
	if len(list) != 1 {
		t.Fatalf("bans: %+v", list)
	}
	b := list[0]
	if b.BannedBy != store.BanAutomatic || b.Rule != "renderer_replaced" || b.PlayerHash != "player-1" || b.DeviceID != sess.DeviceID || b.DeviceTPM ||
		b.SessionID != sess.SessionID || !strings.Contains(b.Reason, "OPENGL32.dll") || !b.Active(time.Now()) {
		t.Fatalf("automatic ban: %+v", b)
	}
	audit, _ := e.st.ListAudit(ctx, "demo", store.AuditFilter{Limit: 10})
	if len(audit) != 1 || audit[0].Action != "ban.add" || audit[0].Actor != store.BanAutomatic || audit[0].Target != "session "+sess.SessionID || !strings.Contains(audit[0].Detail, b.Ref) {
		t.Fatalf("audit: %+v", audit)
	}
	c, err = handshakeAs(t, e.env, key, "a-new-account", false)
	if body := refusal(t, e.env, c, err); body.BanRef != b.Ref {
		t.Fatalf("refusal: %v", body)
	}
}

// Evidence of the suspicious tier raises its notice and bans nobody, and with automatic
// bans off certain evidence does not either.
func TestOnlyCertainEvidenceBans(t *testing.T) {
	for name, tc := range map[string]struct {
		automatic bool
		finding   *pb.Finding
	}{
		"suspicious evidence, automatic bans on": {true, memoryToolFinding()},
		"certain evidence, automatic bans off":   {false, rendererFinding()},
	} {
		e := newBanEnv(t, tc.automatic)
		c, err := handshake(t, e.env, softwareKey(), false)
		if err != nil {
			t.Fatal(err)
		}
		sendFindings(c, tc.finding)
		recvNotice(t, c)
		for range 2 {
			if m := c.heartbeat(); m.GetHeartbeatAck() == nil {
				t.Fatalf("%s: after the notice the client got %v", name, m)
			}
		}
		if list, _ := e.st.ListBans(context.Background(), "demo", 0); len(list) != 0 {
			t.Fatalf("%s: banned: %+v", name, list)
		}
		if s := sessionOf(t, e.env, c); s.State != store.SessionActive {
			t.Fatalf("%s: session %+v", name, s)
		}
	}
}

// With a delay the automatic ban is pending: the session goes on and a new handshake is
// accepted until the ban is due.
func TestPendingBanRefusesNobodyUntilDue(t *testing.T) {
	e := newBanEnv(t, true)
	ctx := context.Background()
	if err := e.st.SetBanDelay(ctx, "demo", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	key := softwareKey()
	c, err := handshake(t, e.env, key, false)
	if err != nil {
		t.Fatal(err)
	}
	sendFindings(c, rendererFinding())
	recvNotice(t, c)
	if m := c.heartbeat(); m.GetHeartbeatAck() == nil {
		t.Fatalf("a pending ban ended the session: %v", m)
	}
	list, _ := e.st.ListBans(ctx, "demo", 0)
	if len(list) != 1 || !list[0].Pending(time.Now()) || list[0].EffectiveAt.Sub(list[0].BannedAt) != 30*time.Minute {
		t.Fatalf("bans: %+v", list)
	}
	if _, err := handshake(t, e.env, key, false); err != nil {
		t.Fatalf("refused while the ban is pending: %v", err)
	}
	e.bans.Now = func() time.Time { return time.Now().Add(31 * time.Minute) }
	c, err = handshake(t, e.env, key, false)
	if body := refusal(t, e.env, c, err); body.BanRef != list[0].Ref {
		t.Fatalf("refusal: %v", body)
	}
}
