package gateway

import (
	"context"
	"crypto/sha256"
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
	// drop closes the connection. A game server that is not reading must not silently
	// lose a Kick: closing makes it reconnect and watch again, and Watch on a session
	// that was kicked meanwhile answers with the Kick.
	drop func()
}

func (c *gsConn) send(m *pb.GsServerMsg) {
	b, err := proto.Marshal(m)
	if err != nil {
		return
	}
	select {
	case c.out <- b:
	default:
		if c.drop != nil {
			c.drop()
		}
	}
}

// reply answers a request from this game server. Unlike send it waits for room in the
// buffer: it runs on the connection's own read loop, so a burst of requests (a game server
// watching all its sessions again after a reconnect) slows that game server down instead of
// overflowing the buffer and closing the connection it has just opened.
func (c *gsConn) reply(ctx context.Context, m *pb.GsServerMsg) {
	b, err := proto.Marshal(m)
	if err != nil {
		return
	}
	select {
	case c.out <- b:
	case <-ctx.Done():
	}
}

// tenantForServerKey maps a server API key to its tenant. Keys are compared as SHA-256
// digests in constant time against every tenant, so neither a key's length nor which
// tenant matched shows in the timing. Two tenants must not share a key (the gateway
// refuses such a configuration at startup); if they do, no tenant matches.
func (g *Gateway) tenantForServerKey(auth string) (string, bool) {
	key, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || key == "" {
		return "", false
	}
	got := sha256.Sum256([]byte(key))
	found, matches := "", 0
	for tenant, k := range g.cfg.Tenants {
		want := sha256.Sum256([]byte(k))
		if subtle.ConstantTimeCompare(want[:], got[:]) == 1 && k != "" {
			found = tenant
			matches++
		}
	}
	return found, matches == 1
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
	conn := &gsConn{tenant: tenant, out: make(chan []byte, 256), drop: func() {
		g.log.Warn("game server is not reading its control channel; closing it so it reconnects", "tenant", tenant, "remote", r.RemoteAddr)
		cancel()
	}}
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
			conn.reply(ctx, &pb.GsServerMsg{Body: &pb.GsServerMsg_WatchAck{WatchAck: &pb.WatchAck{SessionId: b.Watch.SessionId, Known: known}}})
			if kick != nil {
				conn.reply(ctx, &pb.GsServerMsg{Body: &pb.GsServerMsg_Kick{Kick: kick}})
			}
		case *pb.GsClientMsg_Unwatch:
			g.sessions.Unwatch(conn, b.Unwatch.SessionId)
		}
	}
}
