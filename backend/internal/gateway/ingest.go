package gateway

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
)

// ingestTimeout bounds how long one batch may wait for the analysis queue before the game
// server is told to retry.
const ingestTimeout = 5 * time.Second

// handleIngest is the game server's gameplay stream (proto/README.md, "Gameplay ingest"):
// binary GameplayBatch frames in, one IngestAck per batch out, authenticated with the tenant's
// server key like /v1/gs.
func (g *Gateway) handleIngest(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.tenantForServerKey(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "unknown server key", http.StatusUnauthorized)
		return
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(1 << 20)
	ctx := r.Context()
	g.log.Info("gameplay stream connected", "tenant", tenant, "remote", r.RemoteAddr)
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			g.log.Info("gameplay stream closed", "tenant", tenant, "err", err)
			return
		}
		var b pb.GameplayBatch
		if typ != websocket.MessageBinary || proto.Unmarshal(data, &b) != nil {
			ws.Close(websocket.StatusUnsupportedData, "expected a binary GameplayBatch")
			return
		}
		bctx, cancel := context.WithTimeout(ctx, ingestTimeout)
		accepted, warning, err := g.cfg.Detections.Gameplay(bctx, tenant, &b)
		cancel()
		ack := &pb.IngestAck{MatchId: b.MatchId, BatchSeq: b.BatchSeq, Accepted: accepted, Warning: warning}
		if err != nil {
			ack.Error = err.Error()
		}
		out, err := proto.Marshal(ack)
		if err != nil {
			return
		}
		if err := ws.Write(ctx, websocket.MessageBinary, out); err != nil {
			return
		}
	}
}
