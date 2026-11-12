package gateway

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/protocol"
	"carthago/backend/internal/store"
)

func validHello() *pb.Hello {
	eph := make([]byte, 32)
	rand.Read(eph)
	pub, _ := protocol.X25519Public(eph)
	dk := softwareKey()
	return &pb.Hello{ProtocolVersion: 1, SdkVersion: "test", TenantId: "demo", BuildId: "b1", ClientEphPub: pub,
		DeviceKey: &pb.DeviceKey{Alg: dk.alg, PublicKey: dk.pub}, PlayerIdHash: "player-1"}
}

// sendHello returns the close reason the gateway answers a Hello with ("" when it sends a
// Challenge instead).
func sendHello(t *testing.T, e *env, h *pb.Hello) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, e.url("/v1/client"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	ws.SetReadLimit(1 << 20)
	b, _ := proto.Marshal(h)
	if err := ws.Write(ctx, websocket.MessageBinary, append([]byte{protocol.FrameHello}, b...)); err != nil {
		t.Fatal(err)
	}
	_, data, err := ws.Read(ctx)
	if err != nil {
		var ce websocket.CloseError
		if errors.As(err, &ce) {
			return ce.Reason
		}
		return err.Error()
	}
	if len(data) == 0 || data[0] != protocol.FrameChallenge {
		t.Fatalf("unexpected frame %x", data[:1])
	}
	return ""
}

func TestHelloFieldBounds(t *testing.T) {
	e := newEnv(t)
	if r := sendHello(t, e, validHello()); r != "" {
		t.Fatalf("valid Hello rejected: %s", r)
	}
	big := strings.Repeat("x", 4096)
	cert := make([]byte, maxCertBytes+1)
	cases := map[string]func(*pb.Hello){
		"long build id":         func(h *pb.Hello) { h.BuildId = big },
		"long sdk version":      func(h *pb.Hello) { h.SdkVersion = big },
		"long player hash":      func(h *pb.Hello) { h.PlayerIdHash = big },
		"control chars in hash": func(h *pb.Hello) { h.PlayerIdHash = "p1\nlevel=ERROR forged" },
		"space in hash":         func(h *pb.Hello) { h.PlayerIdHash = "player 1" },
		"long env":              func(h *pb.Hello) { h.Env = &pb.EnvReport{OsBuild: big} },
		"huge AK blob":          func(h *pb.Hello) { h.TpmEnrollment = &pb.TpmEnrollment{AkPublic: make([]byte, maxTPMBlob+1)} },
		"huge EK blob":          func(h *pb.Hello) { h.TpmEnrollment = &pb.TpmEnrollment{EkPublic: make([]byte, maxTPMBlob+1)} },
		"huge certificate":      func(h *pb.Hello) { h.TpmEnrollment = &pb.TpmEnrollment{EkCerts: [][]byte{cert}} },
		"too many EK certs":     func(h *pb.Hello) { h.TpmEnrollment = &pb.TpmEnrollment{EkCerts: make([][]byte, maxEKCerts+1)} },
		"too many chain certs": func(h *pb.Hello) {
			h.TpmEnrollment = &pb.TpmEnrollment{EkChainCerts: make([][]byte, maxEKChainCerts+1)}
		},
		"long TPM manufacturer":  func(h *pb.Hello) { h.TpmEnrollment = &pb.TpmEnrollment{TpmManufacturer: big} },
		"long TPM firmware text": func(h *pb.Hello) { h.TpmEnrollment = &pb.TpmEnrollment{TpmFirmware: big} },
	}
	for name, mod := range cases {
		h := validHello()
		mod(h)
		if r := sendHello(t, e, h); !strings.HasPrefix(r, "bad_hello") {
			t.Errorf("%s: want bad_hello, got %q", name, r)
		}
	}
	// A Hello above the frame limit is refused by the reader, before it is decoded.
	h := validHello()
	h.TpmEnrollment = &pb.TpmEnrollment{EkChainCerts: [][]byte{make([]byte, helloReadLimit)}}
	if r := sendHello(t, e, h); r == "" || strings.HasPrefix(r, "bad_hello") {
		t.Errorf("oversized Hello frame: %q", r)
	}
}

func TestHandshakeGate(t *testing.T) {
	g := newHandshakeGate(3, 2)
	if !g.acquire("a") || !g.acquire("a") {
		t.Fatal("first two from one address refused")
	}
	if g.acquire("a") {
		t.Fatal("third concurrent handshake from one address allowed")
	}
	if !g.acquire("b") {
		t.Fatal("other address refused")
	}
	if g.acquire("c") {
		t.Fatal("total limit not enforced")
	}
	g.release("a")
	if !g.acquire("c") {
		t.Fatal("slot not released")
	}
	g.release("a")
	g.release("b")
	g.release("c")
	if g.total != 0 || len(g.perIP) != 0 {
		t.Fatalf("gate not empty: %d %v", g.total, g.perIP)
	}
	if remoteIP("203.0.113.9:4411") != "203.0.113.9" || remoteIP("[::ffff:203.0.113.9]:4411") != "203.0.113.9" {
		t.Fatal("remoteIP")
	}
	// One IPv6 subscriber owns a whole /64: all of its addresses share one budget.
	if a, b := remoteIP("[2001:db8:1:2:aaaa::1]:80"), remoteIP("[2001:db8:1:2:bbbb::9]:443"); a != b || a != "2001:db8:1:2::/64" {
		t.Fatalf("IPv6 addresses of one /64 counted separately: %q %q", a, b)
	}
	if remoteIP("[2001:db8:1:3::1]:80") == remoteIP("[2001:db8:1:2::1]:80") {
		t.Fatal("different /64s share a budget")
	}
}

// The start-rate table must not grow without bound when handshakes arrive from more
// addresses than it can hold.
func TestHandshakeGateTableIsBounded(t *testing.T) {
	g := newHandshakeGate(1<<30, 4)
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	for i := range maxStartBuckets + 5000 {
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16, i>>8&255, i&255)
		if !g.acquire(ip) {
			t.Fatalf("address %d refused", i)
		}
		g.release(ip)
	}
	if n := len(g.started); n > maxStartBuckets {
		t.Fatalf("start-rate table holds %d addresses (limit %d)", n, maxStartBuckets)
	}
}

// Connections that never finish the handshake must not be able to pile up without bound;
// the slot is returned when the handshake ends either way.
func TestStalledHandshakesAreBounded(t *testing.T) {
	e := newEnv(t)
	e.gw.handshakes = newHandshakeGate(100, 2)
	e.gw.handshakes.burst = 100
	ctx := context.Background()
	var stalled []*websocket.Conn
	for i := 0; i < 2; i++ {
		ws, _, err := websocket.Dial(ctx, e.url("/v1/client"), nil)
		if err != nil {
			t.Fatal(err)
		}
		stalled = append(stalled, ws)
	}
	_, resp, err := websocket.Dial(ctx, e.url("/v1/client"), nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("third stalled handshake: want 503, got %v %v", resp, err)
	}
	for _, ws := range stalled {
		ws.CloseNow()
	}
	waitFor(t, "slots released", func() bool {
		e.gw.handshakes.mu.Lock()
		defer e.gw.handshakes.mu.Unlock()
		return e.gw.handshakes.total == 0
	})
	// An established session no longer holds a slot.
	for i := 0; i < 4; i++ {
		if _, err := handshake(t, e, softwareKey(), false); err != nil {
			t.Fatal(err)
		}
	}
}

type countingDetections struct{ n atomic.Int32 }

func (c *countingDetections) Heartbeat(store.Session, *pb.Heartbeat) { c.n.Add(1) }
func (c *countingDetections) Gameplay(context.Context, string, *pb.GameplayBatch) (bool, error) {
	return true, nil
}

func TestOversizedHeartbeatKicks(t *testing.T) {
	for name, hb := range map[string]*pb.Heartbeat{
		"too many findings": {Findings: make([]*pb.Finding, maxHeartbeatFindings+1)},
		"long detail":       {Findings: []*pb.Finding{{Detail: strings.Repeat("d", maxFindingDetail+1)}}},
		"long job":          {Findings: []*pb.Finding{{Job: strings.Repeat("j", maxJobName+1)}}},
		"too much coverage": {Coverage: make([]*pb.JobCoverage, maxCoverageEntries+1)},
	} {
		det := &countingDetections{}
		e := newEnv(t)
		e.gw.cfg.Detections = det
		c, err := handshake(t, e, softwareKey(), false)
		if err != nil {
			t.Fatal(err)
		}
		claims, _ := protocol.VerifyToken(tokenKeys(e), c.session.SessionToken, time.Now(), protocol.DefaultLeeway)
		gs := watch(t, e, claims.SessionID)
		c.send(&pb.ClientMsg{Body: &pb.ClientMsg_Heartbeat{Heartbeat: hb}})
		if k := readGS(t, gs).GetKick(); k == nil || k.Reason != "protocol_violation" {
			t.Errorf("%s: kick %v", name, k)
		}
		if det.n.Load() != 0 {
			t.Errorf("%s: oversized heartbeat reached the pipeline", name)
		}
	}
	// The SDK's own maximum passes.
	det := &countingDetections{}
	e := newEnv(t)
	e.gw.cfg.Detections = det
	c, err := handshake(t, e, softwareKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	full := &pb.Heartbeat{}
	for i := 0; i < 96; i++ {
		full.Findings = append(full.Findings, &pb.Finding{Job: "memory_region_walk", Detail: strings.Repeat("d", 47)})
	}
	c.send(&pb.ClientMsg{Body: &pb.ClientMsg_Heartbeat{Heartbeat: full}})
	if m, err := c.recv(); err != nil || m.GetHeartbeatAck() == nil {
		t.Fatalf("full-size heartbeat: %v %v", m, err)
	}
	if det.n.Load() != 1 {
		t.Fatal("full-size heartbeat not analysed")
	}
}

func TestHeartbeatFloodIsNotAnalysed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newHeartbeatLimiter(2*time.Second, now)
	passed := 0
	for i := 0; i < 1000; i++ {
		if l.allow(now.Add(time.Duration(i) * time.Millisecond)) {
			passed++
		}
	}
	if passed > heartbeatBurst+1 {
		t.Fatalf("%d of 1000 heartbeats in one second passed the limiter", passed)
	}
	// The negotiated rate, and a burst after a network stall, pass in full.
	l = newHeartbeatLimiter(2*time.Second, now)
	for i := 1; i <= 50; i++ {
		if !l.allow(now.Add(time.Duration(i) * 2 * time.Second)) {
			t.Fatalf("heartbeat %d at the negotiated rate dropped", i)
		}
	}
	at := now.Add(200 * time.Second)
	for i := 0; i < 3; i++ {
		if !l.allow(at) {
			t.Fatalf("delayed heartbeat %d of a burst dropped", i)
		}
	}

	// End to end: every heartbeat is acknowledged and keeps the session alive, only a
	// bounded number reach the pipeline.
	det := &countingDetections{}
	e := newEnv(t)
	e.gw.cfg.HeartbeatInterval = time.Hour
	e.gw.cfg.Detections = det
	c, err := handshake(t, e, softwareKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		c.heartbeat()
	}
	if n := det.n.Load(); n != heartbeatBurst {
		t.Fatalf("%d of 50 flooded heartbeats analysed, want %d", n, heartbeatBurst)
	}
	claims, _ := protocol.VerifyToken(tokenKeys(e), c.session.SessionToken, time.Now(), protocol.DefaultLeeway)
	if s, _ := e.gw.Sessions().Get(claims.SessionID); s.Heartbeats != heartbeatBurst || s.State != store.SessionActive {
		t.Fatalf("session after the flood: %d heartbeats persisted, state %v", s.Heartbeats, s.State)
	}
}

func TestHandshakeStartRate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	g := newHandshakeGate(1000, 4)
	g.now = func() time.Time { return now }
	started := 0
	for i := 0; i < 100; i++ {
		if g.acquire("203.0.113.7") {
			g.release("203.0.113.7")
			started++
		}
	}
	if started != 8 {
		t.Fatalf("%d handshakes started at once from one address, want the burst of 8", started)
	}
	if !g.acquire("198.51.100.1") {
		t.Fatal("another address is throttled too")
	}
	now = now.Add(8 * time.Second) // 4/16 per second: two more
	started = 0
	for i := 0; i < 10; i++ {
		if g.acquire("203.0.113.7") {
			g.release("203.0.113.7")
			started++
		}
	}
	if started != 2 {
		t.Fatalf("%d handshakes after 8 s, want 2", started)
	}
}
