package gateway

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	pb "sentinel/backend/gen/sentinel/v1"
	"sentinel/backend/internal/pipeline"
	"sentinel/backend/internal/protocol"
	"sentinel/backend/internal/store"
)

func newDetectEnv(t *testing.T, autoKick bool) (*env, *pipeline.Pipeline) {
	keys, err := LoadOrCreateKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{
		Tenants: map[string]string{"demo": serverKey, "other": "other-key"}, HeartbeatInterval: time.Second, HeartbeatTimeout: 5 * time.Second,
		TokenTTL: time.Minute, RenewBefore: time.Second,
	}
	// The pipeline kicks through the gateway's manager, which only exists after New.
	var gw *Gateway
	pl := pipeline.New(pipeline.Config{AutoKick: autoKick}, st, st, kickFunc(func(id, reason string) { gw.Sessions().Kick(id, reason) }), log)
	t.Cleanup(pl.Close)
	cfg.Detections = pl
	gw = New(cfg, keys, st, log)
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	return &env{gw: gw, srv: srv, keys: keys, st: st}, pl
}

type kickFunc func(id, reason string)

func (f kickFunc) Kick(id, reason string) { f(id, reason) }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestHeartbeatFindingsBecomeEvidence(t *testing.T) {
	e, _ := newDetectEnv(t, false)
	c, err := handshake(t, e, softwareKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := protocol.VerifyToken(tokenKeys(e), c.session.SessionToken, time.Now(), protocol.DefaultLeeway)
	c.send(&pb.ClientMsg{Body: &pb.ClientMsg_Heartbeat{Heartbeat: &pb.Heartbeat{
		Sched: &pb.SchedSummary{WorkerCpuNs: 1e6, Frames: 10},
		Findings: []*pb.Finding{
			{Job: "api_hooks", Code: uint32(pb.FindingCode_FINDING_CODE_API_HOOK), A: 0x1000, B: 4, Detail: ""},
			{Job: "mitigations", Code: uint32(pb.FindingCode_FINDING_CODE_MITIGATIONS), A: 3},
		},
	}}})
	if m, err := c.recv(); err != nil || m.GetHeartbeatAck() == nil {
		t.Fatalf("ack: %v %v", m, err)
	}
	ctx := context.Background()
	var evs []store.Evidence
	waitFor(t, "evidence", func() bool {
		evs, _ = e.st.ListEvidence(ctx, "demo", store.EvidenceFilter{SessionID: claims.SessionID})
		return len(evs) == 1
	})
	if evs[0].Rule != "api_hook" || evs[0].PlayerHash != "player-1" {
		t.Fatalf("evidence %+v", evs[0])
	}
	waitFor(t, "telemetry", func() bool {
		tel, err := e.st.GetTelemetry(ctx, "demo", claims.SessionID)
		return err == nil && tel.MitigationsApplied == 3 && tel.WorkerCPUNs == 1e6
	})
	if s, _ := e.gw.Sessions().Get(claims.SessionID); s.State != store.SessionActive {
		t.Fatal("auto-kick is off: the session must stay active")
	}
}

func TestAutoKickReachesGameServer(t *testing.T) {
	e, _ := newDetectEnv(t, true)
	c, err := handshake(t, e, softwareKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := protocol.VerifyToken(tokenKeys(e), c.session.SessionToken, time.Now(), protocol.DefaultLeeway)
	gs := watch(t, e, claims.SessionID)
	c.send(&pb.ClientMsg{Body: &pb.ClientMsg_Heartbeat{Heartbeat: &pb.Heartbeat{Findings: []*pb.Finding{
		{Code: uint32(pb.FindingCode_FINDING_CODE_CODE_PATCH), A: 1, B: 2, Detail: "d3d11.dll>?"},
	}}}})
	if k := readGS(t, gs).GetKick(); k == nil || k.Reason != "integrity_violation: code_patch" {
		t.Fatalf("kick: %v", k)
	}
}

func dialIngest(t *testing.T, e *env, key string) *websocket.Conn {
	ws, _, err := websocket.Dial(context.Background(), e.url("/v1/ingest"), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.CloseNow() })
	return ws
}

func sendBatch(t *testing.T, ws *websocket.Conn, b *pb.GameplayBatch) *pb.IngestAck {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, _ := proto.Marshal(b)
	if err := ws.Write(ctx, websocket.MessageBinary, out); err != nil {
		t.Fatal(err)
	}
	_, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ack pb.IngestAck
	if err := proto.Unmarshal(data, &ack); err != nil {
		t.Fatal(err)
	}
	return &ack
}

func TestIngest(t *testing.T) {
	e, _ := newDetectEnv(t, false)
	_, resp, err := websocket.Dial(context.Background(), e.url("/v1/ingest"), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer wrong"}}})
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %v %v", resp, err)
	}
	ws := dialIngest(t, e, serverKey)
	var cw []*pb.CommandWindow
	for w := range uint32(5) {
		cw = append(cw, &pb.CommandWindow{Slot: 7, TickFrom: w * 64, TickTo: (w + 1) * 64, Commands: 90})
	}
	b := &pb.GameplayBatch{MatchId: "m-1", BatchSeq: 1, TickRate: 64, Players: []*pb.MatchPlayer{{Slot: 7, PlayerHash: "speedy"}}, Commands: cw}
	if ack := sendBatch(t, ws, b); !ack.Accepted || ack.Error != "" || ack.MatchId != "m-1" || ack.BatchSeq != 1 {
		t.Fatalf("ack %v", ack)
	}
	if ack := sendBatch(t, ws, b); ack.Accepted || ack.Error != "" {
		t.Fatalf("duplicate ack %v", ack)
	}
	evs, _ := e.st.ListEvidence(context.Background(), "demo", store.EvidenceFilter{PlayerHash: "speedy"})
	if len(evs) != 1 || evs[0].Rule != "command_rate" {
		t.Fatalf("evidence %+v", evs)
	}
	// The same match id under another tenant is a different match.
	other := dialIngest(t, e, "other-key")
	if ack := sendBatch(t, other, b); !ack.Accepted {
		t.Fatalf("other tenant ack %v", ack)
	}
	if ack := sendBatch(t, ws, &pb.GameplayBatch{BatchSeq: 1}); ack.Accepted || ack.Error == "" {
		t.Fatalf("missing match id ack %v", ack)
	}
}
