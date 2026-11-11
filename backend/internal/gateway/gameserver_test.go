package gateway

import (
	"testing"

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
