package synth

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge"
)

var csRoles = []Role{RoleInformed, RoleLegit, RolePrefire, RoleSound, RoleTeamCall, RoleLegit, RoleSubtle, RoleLegit, RoleSound, RolePrefire}

func feature(r knowledge.Result, name string) knowledge.FeatureResult {
	for _, f := range r.Features {
		if f.Name == name {
			return f
		}
	}
	return knowledge.FeatureResult{}
}

// Rounds start from known spawns, so walking towards hidden enemies is what honest
// players do: in the round-based mode the route feature is shown but takes no part in the
// score. Elsewhere it does.
func TestRoundModeDoesNotScoreRoutes(t *testing.T) {
	for _, mode := range []pb.GameMode{pb.GameMode_GAME_MODE_ROUND_SHOOTER, pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER} {
		spec := Spec{MatchID: "t", Mode: mode, TickRate: 64, Seconds: 900, Seed: 5, Players: DefaultPlayers(mode, 1, calibrationRoles[0])}
		routes, scored := 0, 0
		for _, r := range Score(spec, knowledge.DefaultConfig()) {
			f := feature(r, "hidden_route")
			if f.Eligible {
				routes++
			}
			if f.Scored {
				scored++
			}
			if !feature(r, "hidden_aim").Scored && feature(r, "hidden_aim").Eligible {
				t.Errorf("%s: aim must stay scored", ModeName(mode))
			}
		}
		round := mode == pb.GameMode_GAME_MODE_ROUND_SHOOTER
		if routes == 0 || (round && scored != 0) || (!round && scored != routes) {
			t.Errorf("%s: %d players with routes, %d scored", ModeName(mode), routes, scored)
		}
	}
	if knowledge.ModeName(pb.GameMode_GAME_MODE_ROUND_SHOOTER) != "round_shooter" {
		t.Error("mode name")
	}
	cfg := knowledge.DefaultConfig()
	if !cfg.Calibrated(knowledge.Segment{Mode: pb.GameMode_GAME_MODE_ROUND_SHOOTER, Device: pb.InputDevice_INPUT_DEVICE_MOUSE_KEYBOARD}) {
		t.Error("the round-based mode has no calibrated threshold")
	}
}

// Windows share no sample, do not disturb the match score, and add up to the match.
func TestWindowsLeaveTheMatchScoreAlone(t *testing.T) {
	spec := Spec{MatchID: "t", Mode: pb.GameMode_GAME_MODE_ROUND_SHOOTER, TickRate: 64, Seconds: 900, Seed: 9, Players: DefaultPlayers(pb.GameMode_GAME_MODE_ROUND_SHOOTER, 1, calibrationRoles[0])}
	want := Score(spec, knowledge.DefaultConfig())

	var sc *knowledge.Scorer
	blocks, samples := map[uint32]int{}, map[uint32]int{}
	windows := 0
	from := 0.0
	for _, b := range Batches(spec) {
		if sc == nil {
			sc = knowledge.NewScorer(knowledge.DefaultConfig(), YardMap(), b.Mode, b.TickRate)
		}
		sc.Add(b)
		if sc.Analysed()-from >= 120 {
			from = sc.Analysed()
			windows++
			for _, r := range sc.Window() {
				f := feature(r, "hidden_aim")
				blocks[r.Slot] += f.Blocks
				samples[r.Slot] += f.Samples
				if r.Flagged {
					t.Errorf("a window is never a flag: slot %d", r.Slot)
				}
			}
		}
	}
	got := sc.Finish()
	if !reflect.DeepEqual(got, want) {
		t.Fatal("taking windows changed the match result")
	}
	if windows < 6 {
		t.Fatalf("%d windows in a 15 minute match", windows)
	}
	for _, r := range got {
		f := feature(r, "hidden_aim")
		if blocks[r.Slot] > f.Blocks || samples[r.Slot] > f.Samples || blocks[r.Slot] < f.Blocks*3/4 {
			t.Errorf("slot %d: windows hold %d blocks and %d samples, the match %d and %d", r.Slot, blocks[r.Slot], samples[r.Slot], f.Blocks, f.Samples)
		}
	}
}

func TestAlerterNeedsRepeatedStrongWindows(t *testing.T) {
	spec := Spec{MatchID: "t", Mode: pb.GameMode_GAME_MODE_ROUND_SHOOTER, TickRate: 64, Seconds: 1800, Seed: 11, Players: DefaultPlayers(pb.GameMode_GAME_MODE_ROUND_SHOOTER, 1, calibrationRoles[0])}
	run := func(cfg knowledge.AlertConfig) (map[uint32]int, *knowledge.Alerter) {
		var sc *knowledge.Scorer
		var al *knowledge.Alerter
		hits := map[uint32]int{}
		for _, b := range Batches(spec) {
			if sc == nil {
				sc = knowledge.NewScorer(knowledge.DefaultConfig(), YardMap(), b.Mode, b.TickRate)
				al = knowledge.NewAlerter(cfg, sc)
			}
			sc.Add(b)
			for _, h := range al.Step() {
				hits[h.Slot]++
				if h.Strong != cfg.Windows || len(h.Scores) != cfg.Windows || h.Windows < cfg.Windows {
					t.Errorf("hit %+v under %+v", h, cfg)
				}
				for _, s := range h.Scores {
					if s < cfg.Z {
						t.Errorf("a window of score %.2f counted as strong at %.2f", s, cfg.Z)
					}
				}
			}
		}
		return hits, al
	}
	cfg := knowledge.DefaultAlert()
	hits, al := run(cfg)
	if al.Windows() != int(1800/cfg.WindowSec) && al.Windows() != int(1800/cfg.WindowSec)-1 {
		t.Errorf("%d windows of %.0f s in 30 minutes", al.Windows(), cfg.WindowSec)
	}
	for _, p := range spec.Players {
		switch n := hits[p.Slot]; {
		case p.Role == RoleInformed && n != 1:
			t.Errorf("informed slot %d: %d hits, want exactly one (strong windows %d, best %.2f)", p.Slot, n, al.Strong(p.Slot), al.Best[p.Slot])
		case p.Role != RoleInformed && p.Role != RoleSubtle && n != 0:
			t.Errorf("%s slot %d reached the live rule", p.Role, p.Slot)
		}
	}
	// Out of reach: nobody.
	cfg.Windows = 100
	if hits, _ := run(cfg); len(hits) != 0 {
		t.Errorf("hits with 100 windows required: %v", hits)
	}
}

func TestCSStreamIsWhatThePluginSends(t *testing.T) {
	spec := Spec{MatchID: "cs-t", Seconds: 60, Seed: 3, Players: CSPlayers(csRoles, true)}
	var a, b bytes.Buffer
	if err := WriteCS16Stream(&a, spec); err != nil {
		t.Fatal(err)
	}
	if err := WriteCS16Stream(&b, spec); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("the same seed gave two different matches")
	}
	kinds := map[byte]int{}
	size := 0
	for _, line := range strings.Split(strings.TrimSuffix(a.String(), "\n"), "\n") {
		if line == "" || !strings.Contains("DHPTCVSE", line[:1]) || (len(line) > 1 && line[1] != ' ') {
			t.Fatalf("line %q", line)
		}
		if line[0] == 'D' {
			size = 0
		}
		if size += len(line) + 1; size > csDatagram {
			t.Fatalf("a datagram of more than %d bytes", csDatagram)
		}
		kinds[line[0]]++
	}
	for _, k := range []byte("DHPTCVS") {
		if kinds[k] == 0 {
			t.Errorf("no %c line", k)
		}
	}
	if kinds['E'] != 1 || !strings.HasSuffix(a.String(), "E\n") {
		t.Errorf("%d end lines", kinds['E'])
	}
	if !strings.Contains(a.String(), "P 1 4 1 Informed-1\n") || !strings.Contains(a.String(), "P 2 1 2 [BOT] legit-2\n") {
		t.Error("slot 1 must be the person on the server's machine and the others bots")
	}

	var bsp bytes.Buffer
	if err := WriteCSYardBSP(&bsp); err != nil {
		t.Fatal(err)
	}
	if raw := bsp.Bytes(); len(raw) < 1000 || raw[0] != 30 || raw[1] != 0 {
		t.Fatalf("map file: %d bytes, version %d", len(raw), raw[0])
	}
}

// The whole path the kit uses: stream and map file through the real bridge, then the
// gateway's scorer. It needs the bridge binary: CARTHAGO_CS16_BRIDGE=path.
func TestCSMatchesThroughTheBridge(t *testing.T) {
	bridge := os.Getenv("CARTHAGO_CS16_BRIDGE")
	if bridge == "" {
		t.Skip("CARTHAGO_CS16_BRIDGE is not set")
	}
	dir := t.TempDir()
	spec := Spec{MatchID: "cs-bridge", Seconds: 1200, Seed: 13, Players: CSPlayers(csRoles, true)}
	batches, err := CSBatches(bridge, dir, spec)
	if err != nil {
		t.Fatal(err)
	}
	g := batches[0].MapGeometry
	if g == nil || g.MapId != CSYardID || g.Solid == nil || len(g.SourceSha256) != 32 || batches[0].Mode != pb.GameMode_GAME_MODE_ROUND_SHOOTER {
		t.Fatalf("first batch: map %v, mode %v", g.GetMapId(), batches[0].Mode)
	}
	if !batches[len(batches)-1].MatchOver {
		t.Error("the last batch does not end the match")
	}
	run, err := CSScore(batches, knowledge.DefaultConfig(), knowledge.DefaultAlert())
	if err != nil {
		t.Fatal(err)
	}
	if run.InSolid > 0.005 {
		t.Errorf("%.2f %% of the positions are inside the map's walls: the map file and the match disagree", 100*run.InSolid)
	}
	res := bySlot(run.Results)
	for _, p := range spec.Players {
		r, ok := res[p.Slot]
		if !ok {
			t.Fatalf("slot %d not scored", p.Slot)
		}
		if r.Segment.String() != "round_shooter/mouse_keyboard" || !r.Calibrated {
			t.Fatalf("slot %d scored as %s, calibrated %v", p.Slot, r.Segment, r.Calibrated)
		}
		switch p.Role {
		case RoleInformed:
			if !r.Flagged {
				t.Errorf("informed slot %d not flagged: %s", p.Slot, r.Summary())
			}
			if _, ok := run.Alerts[p.Slot]; !ok {
				t.Errorf("informed slot %d did not reach the live rule: %d strong windows of %d, best %.2f", p.Slot, run.Strong[p.Slot], run.Windows, run.Best[p.Slot])
			}
		case RoleSubtle:
		default:
			if _, alerted := run.Alerts[p.Slot]; r.Flagged || alerted || r.Score > 3.6 {
				t.Errorf("%s slot %d: flagged=%v alerted=%v score %.2f", p.Role, p.Slot, r.Flagged, alerted, r.Score)
			}
		}
	}

	// The same match with the wrong map file: the positions give it away.
	other := t.TempDir()
	if err := os.MkdirAll(other+"/maps", 0o755); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../../../../client/cs16/bridge/tests/data/cs_fixture.bsp")
	if err != nil {
		t.Skip("the bridge's fixture map is not here")
	}
	if err := os.WriteFile(other+"/maps/"+CSYardID+".bsp", fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	spec.Seconds = 120
	batches, err = CSBatches(bridge, other, spec)
	if err != nil {
		t.Fatal(err)
	}
	run, err = CSScore(batches, knowledge.DefaultConfig(), knowledge.DefaultAlert())
	if err != nil {
		t.Fatal(err)
	}
	if run.InSolid < 0.02 {
		t.Errorf("only %.2f %% of the positions are inside the walls of a different map", 100*run.InSolid)
	}
}
