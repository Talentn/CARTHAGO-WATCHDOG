package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/attest"
	"carthago/backend/internal/attest/ekroots"
	"carthago/backend/internal/protocol"
	"carthago/backend/internal/store"
)

// windowsPCRs is the PCR set requested from the client; the verifier accepts no other set.
var windowsPCRs = func() []uint32 {
	out := make([]uint32, len(attest.WindowsPCRs))
	for i, p := range attest.WindowsPCRs {
		out[i] = uint32(p)
	}
	return out
}()

// rejectError is a handshake failure the client is told about.
type rejectError struct {
	code string
	msg  string
}

func (e *rejectError) Error() string { return e.code + ": " + e.msg }

func reject(code, format string, a ...any) error {
	return &rejectError{code: code, msg: fmt.Sprintf(format, a...)}
}

// sealedConn is the post-Challenge AEAD channel (server side).
type sealedConn struct {
	ws        *websocket.Conn
	sid       []byte
	sendKey   []byte
	recvKey   []byte
	sendSeq   uint64
	recvSeq   uint64
	g         *Gateway
	sessionID string
}

func (s *sealedConn) send(ctx context.Context, m *pb.ServerMsg) error {
	m.Seq, m.SessionId, m.ServerTsMs = s.sendSeq, s.sid, uint64(s.g.cfg.Now().UnixMilli())
	pt, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	frame, err := protocol.Seal(s.sendKey, s.sid, protocol.ServerToClient, s.sendSeq, pt)
	if err != nil {
		return err
	}
	s.sendSeq++
	return s.ws.Write(ctx, websocket.MessageBinary, frame)
}

func (s *sealedConn) open(frame []byte) (*pb.ClientMsg, error) {
	pt, err := protocol.Open(s.recvKey, s.sid, protocol.ClientToServer, s.recvSeq, frame)
	if err != nil {
		return nil, err
	}
	var m pb.ClientMsg
	if err := proto.Unmarshal(pt, &m); err != nil {
		return nil, fmt.Errorf("decode ClientMsg: %w", err)
	}
	if m.Seq != s.recvSeq || !bytes.Equal(m.SessionId, s.sid) {
		return nil, errors.New("ClientMsg seq/session_id do not match the frame")
	}
	s.recvSeq++
	return &m, nil
}

func readFrame(ctx context.Context, ws *websocket.Conn, timeout time.Duration, want byte) ([]byte, error) {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	typ, data, err := ws.Read(rctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary || len(data) == 0 || data[0] != want {
		return nil, reject("bad_frame", "expected frame type 0x%02x", want)
	}
	return data, nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func (g *Gateway) handleClient(w http.ResponseWriter, r *http.Request) {
	// Refuse before the upgrade when too many handshakes are already in progress.
	ip := remoteIP(r.RemoteAddr)
	if !g.handshakes.acquire(ip) {
		g.log.Warn("handshake refused: too many in progress", "remote", r.RemoteAddr)
		http.Error(w, "too many handshakes in progress", http.StatusServiceUnavailable)
		return
	}
	release := sync.OnceFunc(func() { g.handshakes.release(ip) })
	defer release()
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(helloReadLimit)
	ctx := r.Context()
	sc, hb, err := g.handshake(ctx, ws)
	if err != nil {
		var re *rejectError
		code, msg := "internal", "handshake failed"
		if errors.As(err, &re) {
			code, msg = re.code, re.msg
		}
		g.log.Warn("handshake rejected", "remote", r.RemoteAddr, "code", code, "err", err)
		if sc != nil {
			_ = sc.send(ctx, &pb.ServerMsg{Body: &pb.ServerMsg_Error{Error: &pb.Error{Code: code, Message: msg}}})
		}
		reason := code + ": " + msg
		if len(reason) > 120 {
			reason = reason[:120]
		}
		ws.Close(websocket.StatusPolicyViolation, reason)
		return
	}
	release()
	ws.SetReadLimit(sessionReadLimit)
	g.serve(ctx, ws, sc, hb)
}

type sessionCtx struct {
	claims protocol.Claims
	expiry time.Time
}

func validateDeviceKey(k *pb.DeviceKey) (any, error) {
	if k == nil {
		return nil, reject("bad_hello", "missing device key")
	}
	switch k.Alg {
	case pb.DeviceKeyAlg_DEVICE_KEY_ALG_ED25519_SOFTWARE:
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, reject("bad_hello", "Ed25519 device key must be 32 bytes")
		}
		return ed25519.PublicKey(k.PublicKey), nil
	case pb.DeviceKeyAlg_DEVICE_KEY_ALG_ECDSA_P256_TPM:
		x, y := elliptic.Unmarshal(elliptic.P256(), k.PublicKey)
		if x == nil {
			return nil, reject("bad_hello", "P-256 device key must be an uncompressed point on the curve")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	}
	return nil, reject("bad_hello", "unsupported device key algorithm %v", k.Alg)
}

func verifyDeviceSig(pub any, digest [32]byte, sig []byte) bool {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(k, digest[:], sig)
	case *ecdsa.PublicKey:
		return len(sig) == 64 && ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	}
	return false
}

// handshake runs Hello -> Challenge -> Prove -> Session. sc is non-nil once the AEAD channel
// exists, so failures after that point can be reported to the client in a sealed Error.
func (g *Gateway) handshake(ctx context.Context, ws *websocket.Conn) (sc *sealedConn, hb *sessionCtx, err error) {
	now := g.cfg.Now()
	helloFrame, err := readFrame(ctx, ws, g.cfg.HelloTimeout, protocol.FrameHello)
	if err != nil {
		return nil, nil, err
	}
	helloBytes := helloFrame[1:]
	var hello pb.Hello
	if err := proto.Unmarshal(helloBytes, &hello); err != nil {
		return nil, nil, reject("bad_hello", "decode: %v", err)
	}
	if hello.ProtocolVersion != protocol.ProtocolVersion {
		return nil, nil, reject("bad_version", "protocol %d not supported", hello.ProtocolVersion)
	}
	if _, ok := g.cfg.Tenants[hello.TenantId]; !ok {
		return nil, nil, reject("unknown_tenant", "tenant %.64q", hello.TenantId)
	}
	if err := validateHello(&hello); err != nil {
		return nil, nil, err
	}
	if len(hello.ClientEphPub) != 32 {
		return nil, nil, reject("bad_hello", "client_eph_pub must be 32 bytes")
	}
	devicePub, err := validateDeviceKey(hello.DeviceKey)
	if err != nil {
		return nil, nil, err
	}
	deviceID := protocol.DeviceID(uint8(hello.DeviceKey.Alg), hello.DeviceKey.PublicKey)
	isTPM := hello.DeviceKey.Alg == pb.DeviceKeyAlg_DEVICE_KEY_ALG_ECDSA_P256_TPM

	dev, err := g.store.GetDevice(ctx, deviceID)
	if errors.Is(err, store.ErrNotFound) {
		dev = &store.Device{DeviceID: deviceID, TenantID: hello.TenantId, KeyAlg: int32(hello.DeviceKey.Alg), PublicKey: hello.DeviceKey.PublicKey, FirstSeen: now}
	} else if err != nil {
		return nil, nil, err
	} else if dev.TenantID != hello.TenantId {
		return nil, nil, reject("bad_hello", "device key registered to another tenant")
	}

	// Attestation plan: reuse a bound AK, or enroll the presented one via the EK challenge.
	var attestReq *pb.AttestRequest
	var pending *attest.Enrollment
	var notes []string
	// ekChecked: the EK certificate chain was verified in this handshake. The status stored
	// with the device is from an earlier day and an earlier root bundle; on its own it does
	// not count towards trust 2 and 3.
	ekChecked := false
	if isTPM && hello.TpmAttestationAvailable {
		attestReq = &pb.AttestRequest{Pcrs: windowsPCRs, CertifyDeviceKey: true}
		enr := hello.TpmEnrollment
		switch {
		case enr != nil && len(dev.AKPublic) > 0 && bytes.Equal(enr.AkPublic, dev.AKPublic):
			if rep, err := attest.RecheckEK(enr.EkPublic, enr.EkCerts, enr.EkChainCerts, enr.TpmManufacturer, g.cfg.FetchEKCerts, g.cfg.EKRoots, now, dev.EKPublicSHA256); err != nil {
				notes = append(notes, "EK recheck: "+err.Error())
				dev.EKChain, dev.EKChainRoot = string(ekroots.StatusInvalid), ""
			} else {
				dev.EKCertMatches, dev.EKChain, dev.EKChainRoot = rep.CertMatchesEK, string(rep.ChainStatus), rep.Root
				notes = append(notes, rep.Notes...)
			}
			ekChecked = true
		case enr != nil:
			pending, err = attest.PrepareEnrollment(enr.EkPublic, enr.EkCerts, enr.EkChainCerts, attest.AKParams{
				Public: enr.AkPublic, CreateData: enr.AkCreateData, CreateAttestation: enr.AkCreateAttestation, CreateSignature: enr.AkCreateSignature,
			}, enr.TpmManufacturer, g.cfg.FetchEKCerts, g.cfg.EKRoots, now)
			if err != nil {
				notes = append(notes, "AK enrollment rejected: "+err.Error())
				attestReq = nil
			} else {
				attestReq.EkChallenge = &pb.EkChallenge{ObjectPublic: pending.Challenge.ObjectPublic, Duplicate: pending.Challenge.Duplicate, InSymSeed: pending.Challenge.InSymSeed}
				ekChecked = true
			}
		case len(dev.AKPublic) == 0:
			notes = append(notes, "TPM available but no AK enrollment presented")
			attestReq = nil
		}
	} else if isTPM {
		notes = append(notes, "client reported TPM attestation unavailable")
	}

	ephSecret := randBytes(32)
	ephPub, err := protocol.X25519Public(ephSecret)
	if err != nil {
		return nil, nil, err
	}
	sid := randBytes(protocol.SessionIDLen)
	body := &pb.ChallengeBody{
		ServerNonce: randBytes(protocol.NonceLen), ServerEphPub: ephPub, SessionId: sid, ServerTsMs: uint64(now.UnixMilli()),
		Attest:              attestReq,
		HeartbeatIntervalMs: uint32(g.cfg.HeartbeatInterval.Milliseconds()), HeartbeatTimeoutMs: uint32(g.cfg.HeartbeatTimeout.Milliseconds()),
	}
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	th := protocol.TranscriptHash(helloBytes, bodyBytes)
	ch, err := proto.Marshal(&pb.Challenge{Body: bodyBytes, ServerSig: ed25519.Sign(g.keys.Identity, protocol.ChallengeSigInput(th)), ServerKeyId: g.keys.IdentityKID})
	if err != nil {
		return nil, nil, err
	}
	if err := ws.Write(ctx, websocket.MessageBinary, append([]byte{protocol.FrameChallenge}, ch...)); err != nil {
		return nil, nil, err
	}
	shared, err := protocol.X25519(ephSecret, hello.ClientEphPub)
	if err != nil {
		return nil, nil, reject("bad_hello", "client ephemeral key: %v", err)
	}
	c2s, s2c, err := protocol.DeriveKeys(shared, th)
	if err != nil {
		return nil, nil, err
	}
	sc = &sealedConn{ws: ws, sid: sid, sendKey: s2c, recvKey: c2s, g: g, sessionID: hex.EncodeToString(sid)}

	if attestReq != nil {
		ws.SetReadLimit(proveReadLimit)
	}
	proveFrame, err := readFrame(ctx, ws, g.cfg.ProveTimeout, protocol.FrameSealed)
	if err != nil {
		return sc, nil, err
	}
	msg, err := sc.open(proveFrame)
	if err != nil {
		return sc, nil, reject("bad_prove", "%v", err)
	}
	prove := msg.GetProve()
	if prove == nil {
		return sc, nil, reject("bad_prove", "first sealed message must be Prove")
	}
	if !verifyDeviceSig(devicePub, protocol.ProveDigest(th), prove.DeviceSig) {
		return sc, nil, reject("bad_device_sig", "device key signature over the transcript is invalid")
	}

	flags := uint64(0)
	if isTPM {
		flags |= protocol.FlagTPMDeviceKey
	}
	var boot *attest.BootResult
	if attestReq != nil {
		f, b, n := g.verifyAttestation(ctx, dev, pending, prove.Attestation, hello.DeviceKey.PublicKey, protocol.QuoteNonce(th))
		f, n = capUncheckedEK(f, n, ekChecked)
		flags |= f
		boot = b
		notes = append(notes, n...)
	}
	dev.LastSeen = now
	if err := g.store.UpsertDevice(ctx, dev); err != nil {
		return sc, nil, err
	}

	trust := protocol.TrustLevel(flags)
	expiry := now.Add(g.cfg.TokenTTL)
	claims := protocol.Claims{
		Iss: protocol.TokenIssuer, Tenant: hello.TenantId, PlayerHash: hello.PlayerIdHash, DeviceID: deviceID, SessionID: sc.sessionID,
		Iat: protocol.FormatTime(now), Exp: protocol.FormatTime(expiry), TrustLevel: trust, AttestFlags: flags,
	}
	token, err := protocol.SignToken(g.keys.Token, claims)
	if err != nil {
		return sc, nil, err
	}
	rec := store.Session{
		SessionID: sc.sessionID, TenantID: hello.TenantId, PlayerHash: hello.PlayerIdHash, DeviceID: deviceID,
		TrustLevel: trust, AttestFlags: flags, CreatedAt: now, ExpiresAt: expiry, LastHeartbeat: now,
	}
	hb = &sessionCtx{claims: claims, expiry: expiry}
	if err := g.sessions.Start(rec, g.cfg.HeartbeatTimeout); err != nil {
		return sc, nil, err
	}
	if boot != nil {
		a := &store.Attestation{SessionID: rec.SessionID, DeviceID: deviceID, VerifiedAt: now, QuoteOK: boot.QuoteOK, RankedPolicy: boot.Policy.Ranked,
			Failures: strings.Join(boot.Policy.RankedFailures, "; ")}
		if s := boot.Security; s != nil {
			a.SecureBoot, a.HVCI, a.TestSigning, a.KernelDebug, a.BootDebug, a.CodeIntegrity = s.SecureBoot, s.HVCI, s.TestSigning, s.KernelDebug, s.BootDebug, s.CodeIntegrity
		}
		if err := g.store.AddAttestation(ctx, a); err != nil {
			g.log.Warn("persist attestation", "err", err)
		}
	}
	if err := sc.send(ctx, &pb.ServerMsg{Body: &pb.ServerMsg_Session{Session: &pb.Session{
		SessionToken: token, TrustLevel: trust, AttestFlags: flags, ExpiresAtMs: uint64(expiry.UnixMilli()), Notes: notes,
	}}}); err != nil {
		return sc, nil, err
	}
	g.log.Info("session issued", "session", sc.sessionID, "tenant", hello.TenantId, "player", hello.PlayerIdHash, "device", deviceID,
		"trust_level", trust, "attest_flags", fmt.Sprintf("%#x", flags), "ak_enrolled_now", pending != nil && flags&protocol.FlagAKBoundToEK != 0,
		"notes", notes, "handshake_ms", g.cfg.Now().Sub(now).Milliseconds())
	return sc, hb, nil
}

// verifyAttestation turns TPM evidence into attest_flags. A failure lowers trust; it never
// fails the handshake (plan §5.4: graceful fallback trust levels).
func (g *Gateway) verifyAttestation(ctx context.Context, dev *store.Device, pending *attest.Enrollment, ev *pb.TpmEvidence, deviceSEC1 []byte, nonce [32]byte) (uint64, *attest.BootResult, []string) {
	var notes []string
	if ev == nil {
		return 0, nil, []string{"no TPM evidence in Prove"}
	}
	if ev.Error != "" {
		notes = append(notes, "client: "+ev.Error)
	}
	akPub := dev.AKPublic
	if pending != nil {
		if err := pending.VerifyEKCertify(ev.EkCertifyAttest, ev.EkCertifySignature); err != nil {
			return 0, nil, append(notes, "AK-to-EK binding failed: "+err.Error())
		}
		akPub = pending.AKPublic
		dev.AKPublic, dev.BoundVia, dev.EKPublicSHA256, dev.EKCertMatches = pending.AKPublic, "ek-certify", pending.EKPublicSHA256, pending.EK.CertMatchesEK
		dev.EKChain, dev.EKChainRoot = string(pending.EK.ChainStatus), pending.EK.Root
		notes = append(notes, pending.EK.Notes...)
	}
	if len(akPub) == 0 {
		return 0, nil, append(notes, "no bound AK")
	}
	flags := protocol.FlagAKBoundToEK | ekChainFlags(dev)
	switch ekroots.Status(dev.EKChain) {
	case ekroots.StatusVerified:
		notes = append(notes, "EK certificate chain verified to "+dev.EKChainRoot)
	case ekroots.StatusUnknownVendor:
		notes = append(notes, "EK certificate does not chain to a bundled manufacturer root; trust capped at 1")
	case ekroots.StatusInvalid:
		notes = append(notes, "EK certificate chain invalid; trust capped at 1")
	case ekroots.StatusNoCert:
		notes = append(notes, "no EK certificate for this EK; trust capped at 1")
	default:
		notes = append(notes, "EK certificate chain not checked for this device yet; trust capped at 1")
	}
	if err := attest.VerifyDeviceKeyCertify(akPub, ev.DeviceKeyPublicArea, deviceSEC1, ev.DeviceKeyCertifyAttest, ev.DeviceKeyCertifySignature, nonce[:]); err != nil {
		notes = append(notes, "device key not certified: "+err.Error())
	} else {
		flags |= protocol.FlagDeviceKeyCertified
	}
	pcrs := make([]attest.PCRValue, 0, len(ev.Pcrs))
	for _, p := range ev.Pcrs {
		pcrs = append(pcrs, attest.PCRValue{Index: int(p.Index), Digest: p.Digest})
	}
	boot := attest.VerifyBootEvidence(akPub, nonce[:], ev.Quote, ev.QuoteSignature, pcrs, ev.EventLog)
	for _, c := range boot.Checks {
		if !c.OK {
			notes = append(notes, c.Name+": "+c.Detail)
		}
	}
	if boot.QuoteOK {
		flags |= protocol.FlagQuoteVerified
		if s := boot.Security; s != nil {
			set := func(cond bool, f uint64) {
				if cond {
					flags |= f
				}
			}
			set(s.SecureBoot, protocol.FlagSecureBoot)
			set(s.HVCI, protocol.FlagHVCI)
			set(!s.TestSigning, protocol.FlagTestSigningOff)
			set(!s.KernelDebug, protocol.FlagKernelDebugOff)
			set(!s.BootDebug, protocol.FlagBootDebugOff)
			set(s.CodeIntegrity == "enabled", protocol.FlagCodeIntegrity)
		}
	}
	notes = append(notes, boot.Policy.RankedFailures...)
	return flags, boot, notes
}

// capUncheckedEK removes the verified-chain flag when the EK certificate chain was not
// verified in this handshake (a bound device that presented no EK).
func capUncheckedEK(flags uint64, notes []string, ekChecked bool) (uint64, []string) {
	if ekChecked || flags&protocol.FlagEKChainVerified == 0 {
		return flags, notes
	}
	return flags &^ protocol.FlagEKChainVerified, append(notes, "EK not presented in this handshake: the stored EK certificate chain status was not re-checked; trust capped at 1")
}

// ekChainFlags maps a device's stored EK chain status to attest_flags.
func ekChainFlags(dev *store.Device) uint64 {
	var f uint64
	if dev.EKCertMatches {
		f |= protocol.FlagEKCertMatches
	}
	switch ekroots.Status(dev.EKChain) {
	case ekroots.StatusVerified:
		if dev.EKCertMatches {
			f |= protocol.FlagEKChainVerified
		}
	case ekroots.StatusUnknownVendor:
		f |= protocol.FlagEKChainUnknownVendor
	case ekroots.StatusInvalid:
		f |= protocol.FlagEKChainInvalid
	}
	return f
}

// serve handles heartbeats until the client leaves or the session is kicked.
func (g *Gateway) serve(ctx context.Context, ws *websocket.Conn, sc *sealedConn, sess *sessionCtx) {
	id := sc.sessionID
	kicked := make(chan string, 1)
	if !g.sessions.Attach(id, func(reason string) { kicked <- reason }) {
		kicked <- "kicked"
	}
	defer g.sessions.Detach(id)

	limiter := newHeartbeatLimiter(g.cfg.HeartbeatInterval, g.cfg.Now())
	skipped := 0
	frames := make(chan []byte)
	readErr := make(chan error, 1)
	go func() {
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				readErr <- err
				return
			}
			if typ != websocket.MessageBinary {
				continue
			}
			select {
			case frames <- data:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case reason := <-kicked:
			_ = sc.send(ctx, &pb.ServerMsg{Body: &pb.ServerMsg_Kicked{Kicked: &pb.Kicked{Reason: reason}}})
			ws.Close(websocket.StatusPolicyViolation, "kicked: "+reason)
			return
		case err := <-readErr:
			g.log.Info("client disconnected; heartbeat deadline still running", "session", id, "err", err)
			return
		case frame := <-frames:
			m, err := sc.open(frame)
			if err != nil {
				g.log.Warn("bad client frame", "session", id, "err", err)
				g.sessions.Kick(id, "protocol_violation")
				ws.Close(websocket.StatusPolicyViolation, "protocol violation")
				return
			}
			hbm := m.GetHeartbeat()
			if hbm == nil {
				continue
			}
			if err := validateHeartbeat(hbm); err != nil {
				g.log.Warn("oversized heartbeat", "session", id, "err", err)
				g.sessions.Kick(id, "protocol_violation")
				ws.Close(websocket.StatusPolicyViolation, "protocol violation")
				return
			}
			// A heartbeat within the allowed rate refreshed the deadline moments ago, so an
			// excess one is acknowledged and otherwise ignored: no store write, no token
			// signature, no analysis.
			if !limiter.allow(g.cfg.Now()) {
				if skipped++; skipped == 1 {
					g.log.Warn("heartbeats arriving faster than negotiated; extra ones are ignored", "session", id)
				}
				if err := sc.send(ctx, &pb.ServerMsg{Body: &pb.ServerMsg_HeartbeatAck{HeartbeatAck: &pb.HeartbeatAck{}}}); err != nil {
					return
				}
				continue
			}
			ack := &pb.HeartbeatAck{}
			var newExpiry time.Time
			now := g.cfg.Now()
			if sess.expiry.Sub(now) < g.cfg.RenewBefore {
				c := sess.claims
				newExpiry = now.Add(g.cfg.TokenTTL)
				c.Iat, c.Exp = protocol.FormatTime(now), protocol.FormatTime(newExpiry)
				if tok, err := protocol.SignToken(g.keys.Token, c); err == nil {
					ack.RenewedToken, ack.RenewedExpiresAtMs = tok, uint64(newExpiry.UnixMilli())
					sess.claims, sess.expiry = c, newExpiry
				}
			}
			if !g.sessions.Heartbeat(id, newExpiry) {
				continue // already kicked; the kicked channel delivers the notice
			}
			if d := g.cfg.Detections; d != nil {
				if rec, ok := g.sessions.Get(id); ok {
					d.Heartbeat(rec, hbm)
				}
			}
			if s := hbm.Sched; s != nil {
				g.log.Debug("heartbeat", "session", id, "activity", hbm.Activity, "worker_cpu_ms", float64(s.WorkerCpuNs)/1e6,
					"slices", s.Slices, "frames", s.Frames, "findings", len(hbm.Findings))
			}
			if err := sc.send(ctx, &pb.ServerMsg{Body: &pb.ServerMsg_HeartbeatAck{HeartbeatAck: ack}}); err != nil {
				return
			}
		}
	}
}
