package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
)

// A Kick must not be lost because a game server's send buffer is full.
func TestSlowGameServerIsDisconnectedNotSkipped(t *testing.T) {
	dropped := 0
	c := &gsConn{out: make(chan []byte, 2), drop: func() { dropped++ }}
	kick := &pb.GsServerMsg{Body: &pb.GsServerMsg_Kick{Kick: &pb.Kick{SessionId: "s"}}}
	c.send(kick)
	c.send(kick)
	if dropped != 0 {
		t.Fatal("dropped while there was room")
	}
	c.send(kick)
	if dropped != 1 {
		t.Fatalf("overflow closed the connection %d times, want once", dropped)
	}
}

// Answers to a game server's own requests wait for room: watching many sessions at once
// (as after a reconnect) must not close the connection.
func TestWatchAcksWaitForRoom(t *testing.T) {
	dropped := 0
	c := &gsConn{out: make(chan []byte, 1), drop: func() { dropped++ }}
	ack := &pb.GsServerMsg{Body: &pb.GsServerMsg_WatchAck{WatchAck: &pb.WatchAck{SessionId: "s"}}}
	done := make(chan struct{})
	go func() {
		for range 5 {
			c.reply(context.Background(), ack)
		}
		close(done)
	}()
	for range 5 {
		select {
		case <-c.out:
		case <-time.After(3 * time.Second):
			t.Fatal("reply did not arrive")
		}
	}
	<-done
	if dropped != 0 {
		t.Fatalf("connection closed %d times while answering", dropped)
	}
	// A closed connection releases a waiting reply.
	ctx, cancel := context.WithCancel(context.Background())
	c.out <- nil
	cancel()
	c.reply(ctx, ack)

	e := newEnv(t)
	gs, _, err := websocket.Dial(context.Background(), e.url("/v1/gs"), &websocket.DialOptions{HTTPHeader: map[string][]string{"Authorization": {"Bearer " + serverKey}}})
	if err != nil {
		t.Fatal(err)
	}
	defer gs.CloseNow()
	const n = 3000
	b, _ := proto.Marshal(&pb.GsClientMsg{Body: &pb.GsClientMsg_Watch{Watch: &pb.WatchSession{SessionId: "00112233445566778899aabbccddeeff"}}})
	go func() {
		for range n {
			if gs.Write(context.Background(), websocket.MessageBinary, b) != nil {
				return
			}
		}
	}()
	for i := range n {
		if m := readGS(t, gs); m.GetWatchAck() == nil {
			t.Fatalf("ack %d: %v", i, m)
		}
	}
}

func TestServerKeySelectsExactlyOneTenant(t *testing.T) {
	g := &Gateway{cfg: Config{Tenants: map[string]string{"a": "key-a", "b": "key-b", "dup1": "same", "dup2": "same", "empty": ""}}}
	for auth, want := range map[string]string{
		"Bearer key-a": "a", "Bearer key-b": "b", "Bearer key-": "", "Bearer key-aa": "", "key-a": "", "Bearer ": "", "": "",
		// A key shared by two tenants must not pick one of them at random.
		"Bearer same": "",
	} {
		got, ok := g.tenantForServerKey(auth)
		if got != want && ok || ok != (want != "") {
			t.Errorf("%q: tenant %q ok=%v, want %q", auth, got, ok, want)
		}
	}
}
