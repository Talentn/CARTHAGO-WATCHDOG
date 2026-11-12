// Command carthago-sim drives the Carthago Watchdog gateway with simulated game clients for
// the Phase 1 demo and end-to-end test. Each simulated client runs the real handshake (a
// software or a TPM-claimed P-256 device key, no attestation) and then sends heartbeats whose
// telemetry is synthetic: scheduler counters, per-job coverage, time samples, input counters
// and mocked finding codes chosen by a profile. No client code runs; it only produces the
// numbers a client would report, so the server-side rules and the dashboard have data.
//
// Profiles:
//
//	clean      nothing unusual
//	tpm        clean, with a TPM-claimed device key (trust level 1 without attestation)
//	overlay    reports allowlisted overlay and handle findings (should stay info)
//	integrity  reports code-integrity finding codes (should be flagged critical)
//	clock      reports a QPC that runs faster than the interrupt time
//	input      reports mostly injected mouse events
//	legit, prefire, sound, teamcall, informed, subtle
//	           clean heartbeats; the name is the slot's simulated gameplay role in a
//	           telemetry v2 scenario (see below)
//
// It writes `slot session_id player_hash mmr` lines for gs-stub simulate --sessions.
//
// Two offline modes need no gateway:
//
//	-scenario-out FILE  writes a telemetry v2 match on the carthago-yard test map for
//	                    gs-stub simulate --scenario: -mode, -roles (one per slot from
//	                    -first-slot), -match, -match-seconds, -seed. Roles: legit, prefire
//	                    (prefires common angles), sound (tracks footsteps), teamcall (follows
//	                    team spots), informed (acts on true enemy positions, which only the
//	                    simulator knows), subtle (does so rarely and noisily).
//	-calibrate N        simulates N matches per mode and prints, per segment, the honest
//	                    false-flag rate and the recall on informed and subtle players.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge"
	"carthago/backend/internal/knowledge/synth"
	"carthago/backend/internal/protocol"
	"carthago/backend/internal/store"
)

var jobs = []string{"module_inventory", "memory_region_walk", "thread_audit", "api_hooks", "text_integrity", "external_handles", "overlay_windows", "debugger_signals", "vulnerable_drivers"}

type client struct {
	ws       *websocket.Conn
	sid      []byte
	c2s, s2c []byte
	sendSeq  uint64
	recvSeq  uint64
	interval time.Duration
	session  *pb.Session
}

func (c *client) send(ctx context.Context, m *pb.ClientMsg) error {
	m.Seq, m.SessionId = c.sendSeq, c.sid
	pt, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	f, err := protocol.Seal(c.c2s, c.sid, protocol.ClientToServer, c.sendSeq, pt)
	if err != nil {
		return err
	}
	c.sendSeq++
	return c.ws.Write(ctx, websocket.MessageBinary, f)
}

func (c *client) recv(ctx context.Context) (*pb.ServerMsg, error) {
	_, data, err := c.ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	pt, err := protocol.Open(c.s2c, c.sid, protocol.ServerToClient, c.recvSeq, data)
	if err != nil {
		return nil, err
	}
	c.recvSeq++
	var m pb.ServerMsg
	return &m, proto.Unmarshal(pt, &m)
}

type deviceKey struct {
	alg  pb.DeviceKeyAlg
	pub  []byte
	sign func([32]byte) []byte
}

func newKey(tpmClaim bool) deviceKey {
	if !tpmClaim {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		return deviceKey{pb.DeviceKeyAlg_DEVICE_KEY_ALG_ED25519_SOFTWARE, pub, func(d [32]byte) []byte { return ed25519.Sign(priv, d[:]) }}
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1, _ := k.PublicKey.Bytes()
	return deviceKey{pb.DeviceKeyAlg_DEVICE_KEY_ALG_ECDSA_P256_TPM, sec1, func(d [32]byte) []byte {
		r, s, _ := ecdsa.Sign(rand.Reader, k, d[:])
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	}}
}

func handshake(ctx context.Context, url, tenant, player string, identity ed25519.PublicKey, dk deviceKey) (*client, error) {
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	eph := make([]byte, 32)
	rand.Read(eph)
	ephPub, _ := protocol.X25519Public(eph)
	hello, _ := proto.Marshal(&pb.Hello{
		ProtocolVersion: protocol.ProtocolVersion, SdkVersion: "carthago-sim", TenantId: tenant, BuildId: "sim", ClientEphPub: ephPub,
		DeviceKey: &pb.DeviceKey{Alg: dk.alg, PublicKey: dk.pub}, PlayerIdHash: player, ClientTsMs: uint64(time.Now().UnixMilli()),
	})
	if err := ws.Write(ctx, websocket.MessageBinary, append([]byte{protocol.FrameHello}, hello...)); err != nil {
		return nil, err
	}
	_, data, err := ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || data[0] != protocol.FrameChallenge {
		return nil, errors.New("expected a Challenge")
	}
	var ch pb.Challenge
	if err := proto.Unmarshal(data[1:], &ch); err != nil {
		return nil, err
	}
	th := protocol.TranscriptHash(hello, ch.Body)
	if !ed25519.Verify(identity, protocol.ChallengeSigInput(th), ch.ServerSig) {
		return nil, errors.New("challenge not signed by the pinned gateway identity")
	}
	var body pb.ChallengeBody
	if err := proto.Unmarshal(ch.Body, &body); err != nil {
		return nil, err
	}
	shared, err := protocol.X25519(eph, body.ServerEphPub)
	if err != nil {
		return nil, err
	}
	c2s, s2c, err := protocol.DeriveKeys(shared, th)
	if err != nil {
		return nil, err
	}
	c := &client{ws: ws, sid: body.SessionId, c2s: c2s, s2c: s2c, interval: time.Duration(body.HeartbeatIntervalMs) * time.Millisecond}
	if err := c.send(ctx, &pb.ClientMsg{Body: &pb.ClientMsg_Prove{Prove: &pb.Prove{DeviceSig: dk.sign(protocol.ProveDigest(th))}}}); err != nil {
		return nil, err
	}
	m, err := c.recv(ctx)
	if err != nil {
		return nil, err
	}
	if e := m.GetError(); e != nil {
		return nil, fmt.Errorf("rejected: %s: %s", e.Code, e.Message)
	}
	if c.session = m.GetSession(); c.session == nil {
		return nil, errors.New("expected a Session")
	}
	return c, nil
}

func finding(code pb.FindingCode, job string, a, b uint64, detail string) *pb.Finding {
	return &pb.Finding{Job: job, Code: uint32(code), A: a, B: b, Detail: detail}
}

// heartbeat builds beat n's synthetic telemetry for a profile, elapsed after the session began.
func heartbeat(profile string, n int, elapsed time.Duration) *pb.Heartbeat {
	const boot = 3 * time.Hour
	qpc := boot + elapsed
	if profile == "clock" {
		qpc = boot + elapsed*13/10
	}
	hb := &pb.Heartbeat{
		Activity: 0,
		Time:     &pb.TimeSample{QpcNs: uint64(qpc), TickCountMs: uint64((boot + elapsed).Milliseconds()), InterruptTime_100Ns: uint64((boot + elapsed) / 100)},
		Sched: &pb.SchedSummary{
			WorkerCpuNs: uint64(float64(elapsed) * 0.0035), Slices: uint64(elapsed / (100 * time.Millisecond)), SliceCpuMaxNs: 410_000,
			Frames: uint64(elapsed / (7 * time.Millisecond)), InputThreadCpuNs: uint64(float64(elapsed) * 0.0002),
		},
	}
	for i, j := range jobs {
		hb.Coverage = append(hb.Coverage, &pb.JobCoverage{Job: j, RunsCompleted: uint64(elapsed/time.Second) / uint64(2+i)})
	}
	events := uint64(elapsed / (8 * time.Millisecond))
	hb.Input = &pb.InputStats{MouseEvents: events, Injected: events / 500, FocusedMs: uint64(elapsed.Milliseconds())}
	if profile == "input" {
		hb.Input.Injected = events * 8 / 10
	}
	if n == 0 {
		hb.Findings = append(hb.Findings,
			finding(pb.FindingCode_FINDING_CODE_MITIGATIONS, "mitigations", 3, 0, ""),
			finding(pb.FindingCode_FINDING_CODE_MODULE_LOADED, "module_inventory", 0x7ff6_1000_0000, uint64(pb.ModulePathClass_MODULE_PATH_CLASS_GAME_DIR), "game_audio.dll"))
	}
	switch {
	case profile == "overlay" && n == 1:
		hb.Findings = append(hb.Findings,
			finding(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, "overlay_windows", 4120, 0x80020, "steam.exe"),
			finding(pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE, "external_handles", 5032, 0x1410, "discordhook64.dll"))
	case profile == "integrity" && n == 2:
		hb.Findings = append(hb.Findings,
			finding(pb.FindingCode_FINDING_CODE_CODE_PATCH, "text_integrity", 0x7ffb_2000_1a40, 0, "d3d11.dll>?"),
			finding(pb.FindingCode_FINDING_CODE_UNBACKED_EXEC, "memory_region_walk", 0x1f0_0000, 0x2000|uint64(pb.UnbackedFlags_UNBACKED_FLAGS_PRIVATE)<<48, ""))
	}
	return hb
}

type player struct {
	slot    int
	profile string
	hash    string
	mmr     int
}

type ready struct {
	p         player
	sessionID string
}

func run(ctx context.Context, url, tenant string, identity ed25519.PublicKey, p player, done chan<- ready) {
	c, err := handshake(ctx, url, tenant, p.hash, identity, newKey(p.profile == "tpm"))
	if err != nil {
		log.Printf("slot %d (%s): %v", p.slot, p.profile, err)
		done <- ready{p: p}
		return
	}
	defer c.ws.CloseNow()
	sessionID := hex.EncodeToString(c.sid)
	log.Printf("slot %d %-9s player %s session %s trust_level %d", p.slot, p.profile, p.hash, sessionID, c.session.TrustLevel)
	done <- ready{p, sessionID}

	acks := make(chan error, 1)
	go func() {
		for {
			m, err := c.recv(ctx)
			if err != nil {
				acks <- err
				return
			}
			if k := m.GetKicked(); k != nil {
				acks <- fmt.Errorf("kicked: %s", k.Reason)
				return
			}
		}
	}()
	start := time.Now()
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for n := 0; ; n++ {
		if err := c.send(ctx, &pb.ClientMsg{Body: &pb.ClientMsg_Heartbeat{Heartbeat: heartbeat(p.profile, n, time.Since(start))}}); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			c.ws.Close(websocket.StatusNormalClosure, "simulation over")
			return
		case err := <-acks:
			log.Printf("slot %d (%s): %v", p.slot, p.profile, err)
			return
		case <-t.C:
		}
	}
}

func main() {
	url := flag.String("gateway", "ws://127.0.0.1:8750/v1/client", "gateway client endpoint")
	keysPath := flag.String("keys", "gateway-data/public-keys.json", "gateway public-keys.json (pins the identity key)")
	tenant := flag.String("tenant", "demo", "tenant id")
	profiles := flag.String("profiles", "clean,tpm,overlay,integrity,clock,input,clean,tpm", "comma-separated profile per slot")
	duration := flag.Duration("duration", 90*time.Second, "how long to keep the sessions heartbeating")
	sessionsOut := flag.String("sessions-out", "", "write slot/session lines here for gs-stub simulate --sessions")
	seedDB := flag.String("seed-db", "", "also insert synthetic past sessions at trust levels 2 and 3 into this gateway SQLite file (demo only)")
	seedN := flag.Int("seed-attested", 6, "number of synthetic attested sessions for -seed-db")
	scenarioOut := flag.String("scenario-out", "", "write a telemetry v2 scenario for gs-stub simulate --scenario and exit")
	mode := flag.String("mode", "shooter", "scenario game mode: shooter or extraction")
	roles := flag.String("roles", "legit,informed,prefire,sound,teamcall,legit,legit,prefire,sound,teamcall", "scenario gameplay role per slot (10 players)")
	firstSlot := flag.Int("first-slot", 1, "slot of the first scenario player")
	matchID := flag.String("match", "", "scenario match id (default: derived from mode and seed)")
	matchSeconds := flag.Int("match-seconds", 1800, "simulated match length for -scenario-out and -calibrate")
	seed := flag.Uint64("seed", 11, "simulation seed")
	calibrate := flag.Int("calibrate", 0, "simulate this many matches per mode, print the per-segment calibration and exit")
	flag.Parse()

	if *calibrate > 0 {
		rows := synth.Calibrate([]pb.GameMode{pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, pb.GameMode_GAME_MODE_EXTRACTION}, *calibrate, *matchSeconds, *seed, knowledge.DefaultConfig())
		if err := synth.WriteCalibration(os.Stdout, rows); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *scenarioOut != "" {
		if err := writeScenario(*scenarioOut, *mode, *roles, *firstSlot, *matchID, *matchSeconds, *seed); err != nil {
			log.Fatalf("scenario: %v", err)
		}
		return
	}

	raw, err := os.ReadFile(*keysPath)
	if err != nil {
		log.Fatal(err)
	}
	var keys struct {
		ServerIdentity struct {
			PublicKey string `json:"public_key"`
		} `json:"server_identity"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		log.Fatal(err)
	}
	identity, err := hex.DecodeString(keys.ServerIdentity.PublicKey)
	if err != nil || len(identity) != ed25519.PublicKeySize {
		log.Fatalf("%s: bad server_identity key", *keysPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	var players []player
	for i, prof := range strings.Split(*profiles, ",") {
		prof = strings.TrimSpace(prof)
		h := sha256.Sum256([]byte(fmt.Sprintf("carthago-sim/%d/%s", i+1, prof)))
		players = append(players, player{slot: i + 1, profile: prof, hash: "p-" + hex.EncodeToString(h[:6]), mmr: slotMMR(i + 1)})
	}
	if *seedDB != "" {
		if err := seedAttested(*seedDB, *tenant, *seedN); err != nil {
			log.Fatalf("seed: %v", err)
		}
	}
	var wg sync.WaitGroup
	done := make(chan ready)
	for _, p := range players {
		wg.Add(1)
		go func() {
			defer wg.Done()
			run(ctx, *url, *tenant, identity, p, done)
		}()
	}
	var lines []string
	failed := 0
	for range players {
		r := <-done
		if r.sessionID == "" {
			failed++
			continue
		}
		lines = append(lines, fmt.Sprintf("%d %s %s %d", r.p.slot, r.sessionID, r.p.hash, r.p.mmr))
	}
	if *sessionsOut != "" {
		if err := os.WriteFile(*sessionsOut, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			log.Fatal(err)
		}
	}
	if failed > 0 {
		log.Printf("%d of %d handshakes failed", failed, len(players))
	}
	wg.Wait()
	if failed > 0 {
		os.Exit(1)
	}
}

// seedAttested writes ended sessions at trust levels 2 and 3 straight into the store. The
// simulator cannot produce real TPM evidence, so these rows exist only to show the dashboard's
// trust distribution; their device ids are marked synthetic.
func seedAttested(path, tenant string, n int) error {
	st, err := store.OpenSQLite(path)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now()
	for i := range n {
		id := make([]byte, 16)
		rand.Read(id)
		h := sha256.Sum256([]byte(fmt.Sprintf("carthago-sim/attested/%d", i)))
		dev := "synthetic-demo-" + hex.EncodeToString(h[:6])
		at := now.Add(-time.Duration(20+i*7) * time.Minute)
		if err := st.UpsertDevice(ctx, &store.Device{DeviceID: dev, TenantID: tenant, KeyAlg: int32(pb.DeviceKeyAlg_DEVICE_KEY_ALG_ECDSA_P256_TPM), PublicKey: []byte{0}, FirstSeen: at, LastSeen: at}); err != nil {
			return err
		}
		trust, flags := protocol.TrustAttested, protocol.FlagTPMDeviceKey|protocol.FlagDeviceKeyCertified|protocol.FlagAKBoundToEK|protocol.FlagQuoteVerified|protocol.FlagEKCertMatches
		if i%3 != 0 {
			trust = protocol.TrustRankedBoot
			flags |= protocol.FlagSecureBoot | protocol.FlagHVCI | protocol.FlagTestSigningOff | protocol.FlagKernelDebugOff | protocol.FlagBootDebugOff | protocol.FlagCodeIntegrity
		}
		s := store.Session{SessionID: hex.EncodeToString(id), TenantID: tenant, PlayerHash: "p-" + hex.EncodeToString(h[6:12]), DeviceID: dev,
			TrustLevel: trust, AttestFlags: flags, State: store.SessionClosed, CreatedAt: at, ExpiresAt: at.Add(15 * time.Minute),
			LastHeartbeat: at.Add(12 * time.Minute), Heartbeats: 48}
		if err := st.PutSession(ctx, &s); err != nil {
			return err
		}
	}
	return nil
}

// slotMMR is the skill rating a slot's session reports. Scenario players must be simulated at
// the same rating, or the server's MMR-relative headshot test sees a mismatched baseline.
func slotMMR(slot int) int { return 1300 + 100*((slot-1)%5) }

func writeScenario(path, modeName, roleList string, firstSlot int, matchID string, seconds int, seed uint64) error {
	mode, err := synth.ParseMode(modeName)
	if err != nil {
		return err
	}
	var roles []synth.Role
	for _, r := range strings.Split(roleList, ",") {
		role, ok := synth.ParseRole(strings.TrimSpace(r))
		if !ok {
			return fmt.Errorf("unknown role %q (legit, prefire, sound, teamcall, informed, subtle)", r)
		}
		roles = append(roles, role)
	}
	if len(roles) != 10 {
		return fmt.Errorf("-roles needs 10 players, got %d", len(roles))
	}
	if firstSlot < 1 || seconds < 10 {
		return errors.New("-first-slot must be at least 1 and -match-seconds at least 10")
	}
	if matchID == "" {
		matchID = fmt.Sprintf("v2-%s-%d", modeName, seed)
	}
	players := synth.DefaultPlayers(mode, uint32(firstSlot), roles)
	for i := range players {
		players[i].MMR = int32(slotMMR(int(players[i].Slot)))
	}
	spec := synth.Spec{MatchID: matchID, Mode: mode, TickRate: 64, Seconds: seconds, Seed: seed, Players: players}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := synth.WriteScenario(f, spec); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	log.Printf("scenario %s: %s, %d s, slots %d-%d, roles %s -> %s", matchID, modeName, seconds, firstSlot, firstSlot+9, roleList, path)
	return nil
}
