// Package simclient is a simulated game client for the simulators: the real client handshake
// and heartbeats over the gateway's client protocol, with a software device key. It reports
// what it is told to report; there is no game and no scanner behind it.
package simclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/protocol"
)

// A PC's device key. An account that signs in on the same PC presents the same key.
type DeviceKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func NewDeviceKey() DeviceKey {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return DeviceKey{pub, priv}
}

var ErrBanned = errors.New("refused: banned")

// Player is one simulated game client: a real session with the gateway that sends a
// heartbeat at the gateway's interval and keeps count of everything the gateway sends
// back, which is all a player's client can ever see.
type Player struct {
	Name string
	ws   *websocket.Conn
	SID  []byte
	c2s  []byte
	s2c  []byte

	mu      sync.Mutex
	sendSeq uint64
	// What the client has received since it signed in.
	acks, notices int
	kicked        string
	closed        bool
}

func (p *Player) Send(ctx context.Context, m *pb.ClientMsg) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	m.Seq, m.SessionId, m.ClientTsMs = p.sendSeq, p.SID, uint64(time.Now().UnixMilli())
	pt, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	f, err := protocol.Seal(p.c2s, p.SID, protocol.ClientToServer, p.sendSeq, pt)
	if err != nil {
		return err
	}
	p.sendSeq++
	return p.ws.Write(ctx, websocket.MessageBinary, f)
}

func (p *Player) recv(ctx context.Context, seq uint64) (*pb.ServerMsg, error) {
	_, data, err := p.ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	pt, err := protocol.Open(p.s2c, p.SID, protocol.ServerToClient, seq, data)
	if err != nil {
		return nil, err
	}
	var m pb.ServerMsg
	return &m, proto.Unmarshal(pt, &m)
}

// report sends one heartbeat with what the client's scans found.
func (p *Player) Report(ctx context.Context, findings ...*pb.Finding) error {
	return p.Send(ctx, &pb.ClientMsg{Body: &pb.ClientMsg_Heartbeat{Heartbeat: &pb.Heartbeat{Findings: findings}}})
}

// seen is what the client has received so far.
type Seen struct {
	Acks, Notices int
	Kicked        string
	Closed        bool
}

func (p *Player) Seen() Seen {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Seen{p.acks, p.notices, p.kicked, p.closed}
}

func (p *Player) Online() bool {
	s := p.Seen()
	return !s.Closed && s.Kicked == ""
}

// play keeps the session alive until the gateway ends it or ctx is done.
func (p *Player) Play(ctx context.Context, every time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if p.Report(ctx) != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer p.ws.CloseNow()
		for seq := uint64(1); ; seq++ {
			m, err := p.recv(ctx, seq)
			p.mu.Lock()
			switch {
			case err != nil:
				p.closed = true
			case m.GetHeartbeatAck() != nil:
				p.acks++
			case m.GetEnforcementNotice() != nil:
				p.notices++
			case m.GetKicked() != nil:
				p.kicked = m.GetKicked().Reason
			}
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
}

// SignIn runs the client handshake for an account on a PC. It returns ErrBanned when the
// gateway answers with a ban refusal instead of a session.
func SignIn(ctx context.Context, url, tenant, name string, identity ed25519.PublicKey, dk DeviceKey) (*Player, time.Duration, error) {
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return nil, 0, err
	}
	fail := func(err error) (*Player, time.Duration, error) {
		ws.CloseNow()
		return nil, 0, err
	}
	eph := make([]byte, 32)
	rand.Read(eph)
	ephPub, _ := protocol.X25519Public(eph)
	hello, _ := proto.Marshal(&pb.Hello{
		ProtocolVersion: protocol.ProtocolVersion, SdkVersion: SDKVersion, TenantId: tenant, BuildId: "sim", ClientEphPub: ephPub,
		DeviceKey: &pb.DeviceKey{Alg: pb.DeviceKeyAlg_DEVICE_KEY_ALG_ED25519_SOFTWARE, PublicKey: dk.pub}, PlayerIdHash: name, ClientTsMs: uint64(time.Now().UnixMilli()),
	})
	if err := ws.Write(ctx, websocket.MessageBinary, append([]byte{protocol.FrameHello}, hello...)); err != nil {
		return fail(err)
	}
	_, data, err := ws.Read(ctx)
	if err != nil {
		return fail(err)
	}
	if len(data) == 0 || data[0] != protocol.FrameChallenge {
		return fail(errors.New("expected a Challenge"))
	}
	var ch pb.Challenge
	if err := proto.Unmarshal(data[1:], &ch); err != nil {
		return fail(err)
	}
	th := protocol.TranscriptHash(hello, ch.Body)
	if !ed25519.Verify(identity, protocol.ChallengeSigInput(th), ch.ServerSig) {
		return fail(errors.New("challenge not signed by the gateway's identity key"))
	}
	var body pb.ChallengeBody
	if err := proto.Unmarshal(ch.Body, &body); err != nil {
		return fail(err)
	}
	shared, err := protocol.X25519(eph, body.ServerEphPub)
	if err != nil {
		return fail(err)
	}
	c2s, s2c, err := protocol.DeriveKeys(shared, th)
	if err != nil {
		return fail(err)
	}
	p := &Player{Name: name, ws: ws, SID: body.SessionId, c2s: c2s, s2c: s2c}
	digest := protocol.ProveDigest(th)
	if err := p.Send(ctx, &pb.ClientMsg{Body: &pb.ClientMsg_Prove{Prove: &pb.Prove{DeviceSig: ed25519.Sign(dk.priv, digest[:])}}}); err != nil {
		return fail(err)
	}
	m, err := p.recv(ctx, 0)
	switch {
	case err != nil:
		return fail(err)
	case m.GetBanned() != nil:
		var refusal pb.BanRefusalBody
		if err := proto.Unmarshal(m.GetBanned().Body, &refusal); err != nil || refusal.BanRef == "" {
			return fail(ErrBanned)
		}
		return fail(fmt.Errorf("%w (%s)", ErrBanned, refusal.BanRef))
	case m.GetError() != nil:
		return fail(fmt.Errorf("rejected: %s: %s", m.GetError().Code, m.GetError().Message))
	case m.GetSession() == nil:
		return fail(errors.New("expected a Session"))
	}
	return p, time.Duration(body.HeartbeatIntervalMs) * time.Millisecond, nil
}

// SDKVersion is what the simulated clients name as their SDK in the handshake.
var SDKVersion = "carthago-sim"

// Heartbeat sends one heartbeat as it is, for a simulator that fills in more than findings.
func (p *Player) Heartbeat(ctx context.Context, hb *pb.Heartbeat) error {
	return p.Send(ctx, &pb.ClientMsg{Body: &pb.ClientMsg_Heartbeat{Heartbeat: hb}})
}

// SessionID is the session's id as the gateway and the dashboard write it.
func (p *Player) SessionID() string { return hex.EncodeToString(p.SID) }
