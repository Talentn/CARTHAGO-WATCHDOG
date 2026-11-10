package gateway

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
)

// gsConn is one game server's control channel. Sends never block the session manager.
type gsConn struct {
	tenant string
	out    chan []byte
}

func (c *gsConn) send(m *pb.GsServerMsg) {
	b, err := proto.Marshal(m)
	if err != nil {
		return
	}
	select {
	case c.out <- b:
	default:
	}
}

func (g *Gateway) tenantForServerKey(auth string) (string, bool) {
	key, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok {
		return "", false
	}
	found := ""
	for tenant, k := range g.cfg.Tenants {
		if subtle.ConstantTimeCompare([]byte(k), []byte(key)) == 1 {
			found = tenant
		}
	}
	return found, found != ""
}

func (g *Gateway) handleGameServer(w http.ResponseWriter, r *http.Request) {
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
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	conn := &gsConn{tenant: tenant, out: make(chan []byte, 256)}
	defer g.sessions.DropConn(conn)
	g.log.Info("game server connected", "tenant", tenant, "remote", r.RemoteAddr)

	go func() {
		for {
			select {
			case b := <-conn.out:
				if ws.Write(ctx, websocket.MessageBinary, b) != nil {
					cancel()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		_, data, err := ws.Read(ctx)
		if err != nil {
			g.log.Info("game server disconnected", "tenant", tenant, "err", err)
			return
		}
		var m pb.GsClientMsg
		if proto.Unmarshal(data, &m) != nil {
			ws.Close(websocket.StatusUnsupportedData, "bad message")
			return
		}
		switch b := m.Body.(type) {
		case *pb.GsClientMsg_Watch:
			known, kick := g.sessions.Watch(conn, b.Watch.SessionId)
			conn.send(&pb.GsServerMsg{Body: &pb.GsServerMsg_WatchAck{WatchAck: &pb.WatchAck{SessionId: b.Watch.SessionId, Known: known}}})
			if kick != nil {
				conn.send(&pb.GsServerMsg{Body: &pb.GsServerMsg_Kick{Kick: kick}})
			}
		case *pb.GsClientMsg_Unwatch:
			g.sessions.Unwatch(conn, b.Unwatch.SessionId)
		}
	}
}
