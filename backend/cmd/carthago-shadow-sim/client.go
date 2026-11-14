package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
type deviceKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newDeviceKey() deviceKey {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return deviceKey{pub, priv}
}

var errBanned = errors.New("refused: banned")

// player is one simulated game client: a real session with the gateway that sends a
// heartbeat at the gateway's interval and keeps count of everything the gateway sends
// back, which is all a player's client can ever see.
type player struct {
	name string
	ws   *websocket.Conn
	sid  []byte
	c2s  []byte
	s2c  []byte

	mu      sync.Mutex
	sendSeq uint64
	// What the client has received since it signed in.
	acks, notices int
	kicked        string
	closed        bool
}

func (p *player) send(ctx context.Context, m *pb.ClientMsg) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	m.Seq, m.SessionId, m.ClientTsMs = p.sendSeq, p.sid, uint64(time.Now().UnixMilli())
	pt, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	f, err := protocol.Seal(p.c2s, p.sid, protocol.ClientToServer, p.sendSeq, pt)
	if err != nil {
		return err
	}
	p.sendSeq++
	return p.ws.Write(ctx, websocket.MessageBinary, f)
}

func (p *player) recv(ctx context.Context, seq uint64) (*pb.ServerMsg, error) {
	_, data, err := p.ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	pt, err := protocol.Open(p.s2c, p.sid, protocol.ServerToClient, seq, data)
	if err != nil {
		return nil, err
	}
	var m pb.ServerMsg
	return &m, proto.Unmarshal(pt, &m)
}

// report sends one heartbeat with what the client's scans found.
func (p *player) report(ctx context.Context, findings ...*pb.Finding) error {
	return p.send(ctx, &pb.ClientMsg{Body: &pb.ClientMsg_Heartbeat{Heartbeat: &pb.Heartbeat{Findings: findings}}})
}

// seen is what the client has received so far.
type seen struct {
	acks, notices int
	kicked        string
	closed        bool
}

func (p *player) seen() seen {
	p.mu.Lock()
	defer p.mu.Unlock()
	return seen{p.acks, p.notices, p.kicked, p.closed}
}

func (p *player) online() bool {
	s := p.seen()
	return !s.closed && s.kicked == ""
}

// play keeps the session alive until the gateway ends it or ctx is done.
func (p *player) play(ctx context.Context, every time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if p.report(ctx) != nil {
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

// signIn runs the client handshake for an account on a PC. It returns errBanned when the
// gateway answers with a ban refusal instead of a session.
func signIn(ctx context.Context, url, tenant, name string, identity ed25519.PublicKey, dk deviceKey) (*player, time.Duration, error) {
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return nil, 0, err
	}
	fail := func(err error) (*player, time.Duration, error) {
		ws.CloseNow()
		return nil, 0, err
	}
	eph := make([]byte, 32)
	rand.Read(eph)
	ephPub, _ := protocol.X25519Public(eph)
	hello, _ := proto.Marshal(&pb.Hello{
		ProtocolVersion: protocol.ProtocolVersion, SdkVersion: "carthago-shadow-sim", TenantId: tenant, BuildId: "sim", ClientEphPub: ephPub,
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
	p := &player{name: name, ws: ws, sid: body.SessionId, c2s: c2s, s2c: s2c}
	digest := protocol.ProveDigest(th)
	if err := p.send(ctx, &pb.ClientMsg{Body: &pb.ClientMsg_Prove{Prove: &pb.Prove{DeviceSig: ed25519.Sign(dk.priv, digest[:])}}}); err != nil {
		return fail(err)
	}
	m, err := p.recv(ctx, 0)
	switch {
	case err != nil:
		return fail(err)
	case m.GetBanned() != nil:
		var refusal pb.BanRefusalBody
		if err := proto.Unmarshal(m.GetBanned().Body, &refusal); err != nil || refusal.BanRef == "" {
			return fail(errBanned)
		}
		return fail(fmt.Errorf("%w (%s)", errBanned, refusal.BanRef))
	case m.GetError() != nil:
		return fail(fmt.Errorf("rejected: %s: %s", m.GetError().Code, m.GetError().Message))
	case m.GetSession() == nil:
		return fail(errors.New("expected a Session"))
	}
	return p, time.Duration(body.HeartbeatIntervalMs) * time.Millisecond, nil
}
