package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/bans"
	"carthago/backend/internal/economy"
	"carthago/backend/internal/knowledge/synth"
	"carthago/backend/internal/oracle/train"
	"carthago/backend/internal/sim/econsim"
	"carthago/backend/internal/sim/localgw"
	"carthago/backend/internal/sim/simclient"
	"carthago/backend/internal/store"
)

// shadowPeriod is what the studio of the story sets for its shadow pool.
const shadowPeriod = 48 * time.Hour

type pc = simclient.DeviceKey

type story struct {
	ctx     context.Context
	out     io.Writer
	gw      *localgw.Gateway
	history []train.Row

	// pcs is the PC of each account; players is every client that signed in.
	pcs     map[string]pc
	players map[string]*actor

	// What the chapters leave for the dashboard check.
	bannedRef, pooled string
	outside           []string
	// shotBySami: the first two players sami shot in the match, and the tick.
	shotBySami []hit
	// teamKilled: the teammate walid killed in the spoiled match.
	teamKilled string
}

// actor is one simulated client with the telemetry of a healthy scanner.
type actor struct {
	*simclient.Player
	start time.Time
}

var scanJobs = []string{"module_inventory", "memory_region_walk", "thread_audit", "api_hooks", "text_integrity", "external_handles", "overlay_windows", "debugger_signals", "vulnerable_drivers"}

// beat is the heartbeat of a client whose scanner is running and finds nothing.
func beat(n int, elapsed time.Duration) *pb.Heartbeat {
	const boot = 3 * time.Hour
	at := boot + elapsed
	hb := &pb.Heartbeat{
		Time: &pb.TimeSample{QpcNs: uint64(at), TickCountMs: uint64(at.Milliseconds()), InterruptTime_100Ns: uint64(at / 100)},
		Sched: &pb.SchedSummary{WorkerCpuNs: uint64(float64(elapsed) * 0.0035), Slices: uint64(elapsed / (100 * time.Millisecond)), SliceCpuMaxNs: 410_000,
			Frames: uint64(elapsed / (7 * time.Millisecond)), InputThreadCpuNs: uint64(float64(elapsed) * 0.0002)},
	}
	for i, j := range scanJobs {
		hb.Coverage = append(hb.Coverage, &pb.JobCoverage{Job: j, RunsCompleted: uint64(elapsed/time.Second) / uint64(2+i)})
	}
	events := uint64(elapsed / (8 * time.Millisecond))
	hb.Input = &pb.InputStats{MouseEvents: events, Injected: events / 500, FocusedMs: uint64(elapsed.Milliseconds())}
	if n == 0 {
		hb.Findings = append(hb.Findings,
			&pb.Finding{Job: "mitigations", Code: uint32(pb.FindingCode_FINDING_CODE_MITIGATIONS), A: 3},
			&pb.Finding{Job: "module_inventory", Code: uint32(pb.FindingCode_FINDING_CODE_MODULE_LOADED), A: 0x7ff6_1000_0000, B: uint64(pb.ModulePathClass_MODULE_PATH_CLASS_GAME_DIR), Detail: "game_audio.dll"})
	}
	return hb
}

// report sends what the client's scanner found, with the same telemetry as any heartbeat.
func (a *actor) report(ctx context.Context, findings ...*pb.Finding) error {
	hb := beat(1, time.Since(a.start))
	hb.Findings = findings
	return a.Heartbeat(ctx, hb)
}

// signIn starts a client for an account on a PC; an empty pc is a PC of its own.
func (s *story) signIn(name, onPC string) (*actor, error) {
	if onPC == "" {
		onPC = name
	}
	dk, ok := s.pcs[onPC]
	if !ok {
		dk = simclient.NewDeviceKey()
		s.pcs[onPC] = dk
	}
	p, every, err := simclient.SignIn(s.ctx, s.gw.ClientURL(), localgw.Tenant, name, s.gw.Identity, dk)
	if err != nil {
		return nil, err
	}
	a := &actor{Player: p, start: time.Now()}
	p.Beat = beat
	p.Play(s.ctx, every)
	s.pcs[name] = dk
	if s.players == nil {
		s.players = map[string]*actor{}
	}
	s.players[name] = a
	return a, nil
}

// call is the studio's backend calling the game-server API under its server key.
func (s *story) call(path string, into any) error {
	req, err := http.NewRequestWithContext(s.ctx, "GET", s.gw.API+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+localgw.ServerKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d %s", path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return json.Unmarshal(raw, into)
}

// shadowStatus is what the studio's matchmaking is told about a player.
func (s *story) shadowStatus(name string) (string, error) {
	var out struct{ Status string }
	err := s.call("/v1/shadow/status?player="+url.QueryEscape(name), &out)
	return out.Status, err
}

// ban is the standing ban of an account, nil when it has none.
func (s *story) ban(name string) *store.Ban {
	all, err := s.gw.Store.ListBans(s.ctx, localgw.Tenant, 200)
	if err != nil {
		return nil
	}
	for i := range all {
		if all[i].PlayerHash == name && all[i].LiftedAt.IsZero() {
			return &all[i]
		}
	}
	return nil
}

// flagged counts an account's evidence a reviewer would look at: medium or above.
func (s *story) flagged(name string) int {
	ev, err := s.gw.Store.ListEvidence(s.ctx, localgw.Tenant, store.EvidenceFilter{PlayerHash: name, Limit: 500})
	if err != nil {
		return -1
	}
	n := 0
	for i := range ev {
		if ev[i].Severity >= int(analyzer.SeverityMedium) {
			n++
		}
	}
	return n
}

func fileHash(what string) []byte {
	sum := sha256.Sum256([]byte("carthago-demo: " + what))
	return sum[:]
}

// rendererReport is what a client reports when the game loaded an unsigned OPENGL32.dll
// from its own folder in place of the system's, with the file's hash. The demo sends the
// report; no such file exists.
func rendererReport(file string) *pb.Finding {
	b := uint64(pb.ModuleSignature_MODULE_SIGNATURE_NONE) | uint64(pb.ModulePathClass_MODULE_PATH_CLASS_GAME_DIR)<<8 |
		uint64(pb.ObservedFlags_OBSERVED_FLAGS_AT_START|pb.ObservedFlags_OBSERVED_FLAGS_SHADOWS_SYSTEM)<<16
	return &pb.Finding{Job: "module_inventory", Code: uint32(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE), A: 1, B: b, Detail: "OPENGL32.dll", FileSha256: fileHash(file)}
}

// moduleReport is the hash of a file the game loaded, as every client reports it.
func moduleReport(name, file string) *pb.Finding {
	return &pb.Finding{Job: "module_inventory", Code: uint32(pb.FindingCode_FINDING_CODE_MODULE_FILE), A: 0x7ffb_4000_0000, Detail: name, FileSha256: fileHash(file)}
}

func (s *story) play() (passed, total int) {
	for i, ch := range []struct {
		title string
		run   func() error
	}{
		{"Honest players are left alone", s.honest},
		{"A match is analysed on the server: a wallhack suspect goes to review, not to a ban", s.match},
		{"A cheater is caught on certain evidence and banned", s.certain},
		{"A known cheat file is matched by its hash", s.knownCheat},
		{"An in-game money exploit is caught by the ledger", s.ledger},
		{"A caught player is held in the shadow pool", s.shadow},
		{"The Oracle puts the players outside the studio's normal play first", s.oracle},
		{"A player who spoils matches is noted for the community team, and nothing more", s.toxic},
		{"Players report what they saw: a queue for the reviewer, and nothing more", s.reports},
	} {
		total++
		fmt.Fprintf(s.out, "\n%d. %s\n", i+1, ch.title)
		err := ch.run()
		if err == nil && s.ctx.Err() != nil {
			err = errors.New("interrupted")
		}
		if err != nil {
			s.say("FAIL: %v", err)
			continue
		}
		passed++
	}
	return passed, total
}

var cast = []string{"amira", "bilel", "chiraz", "dali", "emna", "fares", "ghofrane", "hatem"}

func (s *story) honest() error {
	for _, n := range cast {
		if _, err := s.signIn(n, ""); err != nil {
			return fmt.Errorf("%s signs in: %w", n, err)
		}
	}
	// One of them runs an overlay and a voice chat, as players do.
	if err := s.players["dali"].report(s.ctx,
		&pb.Finding{Job: "overlay_windows", Code: uint32(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW), A: 4120, B: 0x80020, Detail: "steam.exe"},
		&pb.Finding{Job: "external_handles", Code: uint32(pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE), A: 5032, B: 0x1410, Detail: "discordhook64.dll"}); err != nil {
		return err
	}
	if !s.wait(8*time.Second, func() bool {
		for _, n := range cast {
			if s.players[n].Seen().Acks < 3 {
				return false
			}
		}
		return true
	}) {
		return errors.New("the gateway did not acknowledge the heartbeats of every player")
	}
	for _, n := range cast {
		got := s.players[n].Seen()
		if !s.players[n].Online() || got.Notices != 0 || s.flagged(n) != 0 || s.ban(n) != nil {
			return fmt.Errorf("%s, an honest player, was flagged, told or banned", n)
		}
	}
	s.say("%d players sign in with the real handshake and play: %s.", len(cast), list(cast))
	s.say("dali runs the Steam overlay and Discord. The gateway knows both and records them as information.")
	s.say("Nobody is flagged, nobody gets a notice, nobody is banned.")
	return nil
}

// ingest is the studio's game server streaming a match to the gateway: /v1/ingest, one
// binary GameplayBatch per second of play, each answered with an acknowledgement.
func (s *story) ingest(batches []*pb.GameplayBatch) error {
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Minute)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(s.gw.API, "http")+"/v1/ingest",
		&websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + localgw.ServerKey}}})
	if err != nil {
		return err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(1 << 20)
	for _, b := range batches {
		raw, err := proto.Marshal(b)
		if err != nil {
			return err
		}
		if err := ws.Write(ctx, websocket.MessageBinary, raw); err != nil {
			return err
		}
		_, data, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		var ack pb.IngestAck
		if err := proto.Unmarshal(data, &ack); err != nil || ack.Error != "" || !ack.Accepted {
			return fmt.Errorf("batch %d of the match was not accepted: %s %v", b.BatchSeq, ack.Error, err)
		}
	}
	return ws.Close(websocket.StatusNormalClosure, "match over")
}

// matchSeconds is the length of the simulated match: a full competitive match.
const matchSeconds = 1500

const demoMatch = "ranked-yard-0001"

func (s *story) match() error {
	// Ten players in one match: the eight honest ones, ilyes, and sami, whose simulated
	// play acts on where enemies really are, also when his team could not know.
	for _, n := range []string{"ilyes", "sami"} {
		if _, err := s.signIn(n, ""); err != nil {
			return fmt.Errorf("%s signs in: %w", n, err)
		}
	}
	names := append(append([]string{}, cast...), "ilyes", "sami")
	roles := make([]synth.Role, len(names))
	for i := range roles {
		roles[i] = synth.RoleLegit
	}
	roles[len(roles)-1] = synth.RoleInformed
	players := synth.DefaultPlayers(pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, 1, roles)
	for i := range players {
		players[i].SessionID, players[i].PlayerHash = s.players[names[i]].SessionID(), names[i]
	}
	batches := synth.Batches(synth.Spec{MatchID: demoMatch, Mode: pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, TickRate: 64, Seconds: matchSeconds, Seed: seed, Players: players})
	if err := s.ingest(batches); err != nil {
		return err
	}
	s.shotBySami = firstHits(batches, players[len(players)-1].Slot, players, 2)
	leak := func(name string) *store.Evidence {
		ev, _ := s.gw.Store.ListEvidence(s.ctx, localgw.Tenant, store.EvidenceFilter{PlayerHash: name, Limit: 100})
		for i := range ev {
			if ev[i].Rule == "information_leak" {
				return &ev[i]
			}
		}
		return nil
	}
	if !s.wait(20*time.Second, func() bool { return leak("sami") != nil }) {
		return errors.New("the information-leak rule did not flag sami's match")
	}
	for _, n := range names[:len(names)-1] {
		if s.flagged(n) != 0 {
			return fmt.Errorf("%s, an honest player of the match, was flagged", n)
		}
	}
	sami := s.players["sami"]
	if s.ban("sami") != nil || !sami.Online() || sami.Seen().Notices != 0 {
		return errors.New("sami was banned, ended or told on statistical evidence")
	}
	s.say("The game server streams a %d-minute match of ten players to the gateway (positions, view, shots, sounds).", matchSeconds/60)
	s.say("The gateway works out what each team could see and hear. sami keeps aiming at enemies his team could not")
	s.say("have known about: rule information_leak, %s severity, with the moments and a top-down replay for the reviewer.", analyzer.Severity(leak("sami").Severity))
	s.say("It is statistics, so it goes to review. sami is not banned and not told. The nine honest players are clean.")
	rec, err := s.gw.Store.GetMatchReplay(s.ctx, localgw.Tenant, demoMatch)
	if err != nil || rec.Samples == 0 || len(rec.Players) != len(names) {
		return fmt.Errorf("the match was not recorded for replay: %v", err)
	}
	s.say("The positions also make a replay of the whole match (%d KB stored): %s/matches/%s?player=sami", (len(rec.Data)+1023)/1024, s.gw.Dashboard, demoMatch)
	s.say("plays it from above, with sami's flagged moments on the timeline.")
	walls, err := s.registerMap()
	if err != nil {
		return fmt.Errorf("the map outline was not registered: %w", err)
	}
	s.say("The game server also registers the outline of the map %s (%d wall lines), so the replay shows the", synth.YardID, walls)
	s.say("walls and points out shots whose line crosses one: an aid for the reviewer, not a finding.")
	return nil
}

func (s *story) certain() error {
	for _, n := range []string{"zied", "yosra"} {
		a, err := s.signIn(n, "")
		if err != nil {
			return fmt.Errorf("%s signs in: %w", n, err)
		}
		if err := a.report(s.ctx, rendererReport("opengl32-wallhack")); err != nil {
			return err
		}
	}
	if !s.wait(8*time.Second, func() bool {
		return s.ban("zied") != nil && s.ban("yosra") != nil && s.players["zied"].Seen().Kicked != "" && s.players["yosra"].Seen().Kicked != ""
	}) {
		return errors.New("the report of a replaced renderer did not ban and end the session")
	}
	b := s.ban("zied")
	if b.Rule != "renderer_replaced" || b.BannedBy != store.BanAutomatic || s.players["zied"].Seen().Notices == 0 {
		return fmt.Errorf("zied's ban is by %q on rule %q, want the automatic ban on renderer_replaced with a notice to the client", b.BannedBy, b.Rule)
	}
	s.bannedRef = b.Ref
	s.say("The clients of zied and yosra report that the game loaded an unsigned OPENGL32.dll in place of Windows' own:")
	s.say("the way a wallhack is delivered. That is certain evidence, so no reviewer is needed.")
	s.say("zied: the client is told (category \"visibility\"), the session is ended, the account and the PC are banned: %s.", b.Ref)
	// The ban holds: the account is refused, and so is a new account on the same PC.
	for _, try := range []struct{ name, pc string }{{"zied", "zied"}, {"zied2", "zied"}} {
		if _, _, err := simclient.SignIn(s.ctx, s.gw.ClientURL(), localgw.Tenant, try.name, s.gw.Identity, s.pcs[try.pc]); !errors.Is(err, simclient.ErrBanned) {
			return fmt.Errorf("%s signed in on the banned PC (%v)", try.name, err)
		}
	}
	s.say("zied starts the game again: refused, and all the client is given is the reference. A new account on")
	s.say("zied's PC, zied2, is refused too. Both banned accounts loaded the same file, so the Known cheats page")
	s.say("now proposes it for the studio's list.")
	return nil
}

func (s *story) knownCheat() error {
	const cheatName = "aimhelper-loader (demo entry)"
	sum := hex.EncodeToString(fileHash("aimhelper-loader"))
	now := time.Now()
	if err := s.gw.Store.AddKnownCheat(s.ctx, &store.KnownCheat{TenantID: localgw.Tenant, SHA256: sum, Name: cheatName,
		Note: "added by the demo: the hash of a file that does not exist", AddedBy: "demo", AddedAt: now}); err != nil {
		return err
	}
	_ = s.gw.Store.AppendAudit(s.ctx, &store.AuditEntry{TenantID: localgw.Tenant, At: now, Actor: "demo", Action: "cheats.add", Target: cheatName, Detail: "SHA-256 " + sum})
	a, err := s.signIn("wissem", "")
	if err != nil {
		return fmt.Errorf("wissem signs in: %w", err)
	}
	// Every client reports the hashes of the files the game loads. This one is on the list,
	// under a harmless name.
	if err := a.report(s.ctx, moduleReport("d3dx9_helper.dll", "aimhelper-loader"), moduleReport("game_audio.dll", "game-audio")); err != nil {
		return err
	}
	if !s.wait(8*time.Second, func() bool { return s.ban("wissem") != nil && a.Seen().Kicked != "" }) {
		return errors.New("a file on the list of known cheats did not ban")
	}
	b := s.ban("wissem")
	if b.Rule != analyzer.RuleKnownCheat {
		return fmt.Errorf("wissem was banned on rule %q, want %s", b.Rule, analyzer.RuleKnownCheat)
	}
	s.say("The studio has one file on its list of known cheats, by SHA-256: %s...", sum[:16])
	s.say("wissem's game loads a file called d3dx9_helper.dll with that hash. The name does not matter, the hash")
	s.say("decides: banned at once, %s.", b.Ref)
	return nil
}

func (s *story) ledger() error {
	if err := s.gw.Store.SetEconomyLimit(s.ctx, store.EconomyLimit{TenantID: localgw.Tenant, Source: "robbery", Currency: economy.DefaultCurrency,
		PerHour: econsim.RobberyPerHour, PerDay: econsim.RobberyPerDay}); err != nil {
		return err
	}
	// The economy simulator's four scenarios, against this gateway.
	g := econsim.NewGameServer(s.gw.API, localgw.ServerKey)
	var full bytes.Buffer
	passed, total := econsim.Scenarios(g, &full)
	s.say("The game server reports every change of a player's money; the gateway keeps its own ledger.")
	for _, line := range strings.Split(full.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PASS: ") || strings.HasPrefix(line, "FAIL: ") {
			s.say("- %s", strings.TrimPrefix(line, "PASS: "))
		}
	}
	max := s.ban("max-" + g.Run)
	if passed != total || max == nil {
		return fmt.Errorf("%d of %d ledger scenarios passed", passed, total)
	}
	s.say("max-%s gave himself a million: the balance the game server reported is above what the ledger can", g.Run)
	s.say("explain, so the account is banned (%s) and what he passed on is marked dirty for removal.", max.Ref)
	return nil
}

func (s *story) shadow() error {
	if err := s.gw.Store.SetShadowPeriod(s.ctx, localgw.Tenant, shadowPeriod); err != nil {
		return err
	}
	_ = s.gw.Store.AppendAudit(s.ctx, &store.AuditEntry{TenantID: localgw.Tenant, At: time.Now(), Actor: "demo", Action: "shadow.period", Target: "shadow pool", Detail: "period set to " + shadowPeriod.String()})
	a, err := s.signIn("tarek", "")
	if err != nil {
		return fmt.Errorf("tarek signs in: %w", err)
	}
	if !s.wait(5*time.Second, func() bool { return a.Seen().Acks >= 1 }) {
		return errors.New("tarek's heartbeats are not acknowledged")
	}
	before := a.Seen()
	if err := a.report(s.ctx, rendererReport("opengl32-wallhack")); err != nil {
		return err
	}
	status := ""
	if !s.wait(8*time.Second, func() bool {
		status, err = s.shadowStatus("tarek")
		return err == nil && status == bans.StatusShadow && a.Seen().Acks >= before.Acks+2
	}) {
		return fmt.Errorf("tarek is %q for the matchmaking, want %q (%v)", status, bans.StatusShadow, err)
	}
	honest, err := s.shadowStatus("amira")
	if err != nil {
		return err
	}
	got := a.Seen()
	if !a.Online() || got.Notices != 0 || honest != bans.StatusNormal {
		return fmt.Errorf("tarek was told or ended (notices %d, online %v), or amira is %q", got.Notices, a.Online(), honest)
	}
	s.pooled = "tarek"
	s.say("The studio now sets a shadow period of %d hours. tarek's client reports the same replaced renderer.", int(shadowPeriod.Hours()))
	s.say("This time nothing reaches the client: no notice, no kick, the heartbeats are answered as before.")
	s.say("The studio's matchmaking asks GET /v1/shadow/status: tarek is \"shadow\", amira is \"normal\". It can now")
	s.say("match tarek with other caught players only, while his sessions and files are collected. In %d hours the", int(shadowPeriod.Hours()))
	s.say("ban takes effect by itself. A reviewer can ban now or release on the Shadow pool page.")
	return nil
}
