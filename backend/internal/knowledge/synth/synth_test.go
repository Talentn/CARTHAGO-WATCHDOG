package synth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge"
)

var modes = []pb.GameMode{pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, pb.GameMode_GAME_MODE_EXTRACTION}

func bySlot(rs []knowledge.Result) map[uint32]knowledge.Result {
	out := map[uint32]knowledge.Result{}
	for _, r := range rs {
		out[r.Slot] = r
	}
	return out
}

// honestCeiling is well under every calibrated threshold: an honest player
// scoring above it in a fixed-seed match means the null model has drifted.
const honestCeiling = 3.0

func TestInformedFlagsLegitStaysQuiet(t *testing.T) {
	for _, mode := range modes {
		t.Run(ModeName(mode), func(t *testing.T) {
			t.Parallel()
			spec := Spec{MatchID: "t", Mode: mode, TickRate: 64, Seconds: 1800, Seed: 11, Players: DefaultPlayers(mode, 1, calibrationRoles[0])}
			res := bySlot(Score(spec, knowledge.DefaultConfig()))
			for _, p := range spec.Players {
				r, ok := res[p.Slot]
				if !ok {
					t.Fatalf("slot %d not scored", p.Slot)
				}
				switch p.Role {
				case RoleInformed:
					if !r.Flagged {
						t.Errorf("informed slot %d not flagged: %s", p.Slot, r.Summary())
					}
				case RoleSubtle:
					// Recall on subtle players is reported by the calibration run, not asserted.
				default:
					if r.Flagged || r.Score > honestCeiling {
						t.Errorf("%s slot %d: flagged=%v score %.2f: %s", p.Role, p.Slot, r.Flagged, r.Score, r.Summary())
					}
				}
			}
		})
	}
}

// Noisy legit play only: prefiring common angles, tracking footsteps and
// following team callouts all line up with enemies, but no better with where
// they are than with where they were or will be.
func TestNoisyLegitMatchHasNoFlags(t *testing.T) {
	noisy := []Role{RolePrefire, RoleSound, RoleTeamCall, RolePrefire, RoleSound, RoleTeamCall, RolePrefire, RoleSound, RoleTeamCall, RoleSound}
	for _, mode := range modes {
		t.Run(ModeName(mode), func(t *testing.T) {
			t.Parallel()
			ps := DefaultPlayers(mode, 1, noisy)
			for i := range ps {
				if i%2 == 1 {
					ps[i].Device, ps[i].AimAssist = pb.InputDevice_INPUT_DEVICE_CONTROLLER, true
				}
			}
			spec := Spec{MatchID: "t", Mode: mode, TickRate: 64, Seconds: 1800, Seed: 23, Players: ps}
			for _, r := range Score(spec, knowledge.DefaultConfig()) {
				if r.Flagged || r.Score > honestCeiling {
					t.Errorf("slot %d (%s): flagged=%v score %.2f: %s", r.Slot, r.Segment, r.Flagged, r.Score, r.Summary())
				}
			}
		})
	}
}

func TestExplanation(t *testing.T) {
	mode := pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER
	spec := Spec{MatchID: "t", Mode: mode, TickRate: 64, Seconds: 1800, Seed: 11, Players: DefaultPlayers(mode, 1, calibrationRoles[0])}
	res := bySlot(Score(spec, knowledge.DefaultConfig()))
	r := res[2]
	if !r.Flagged {
		t.Fatalf("slot 2 not flagged: %s", r.Summary())
	}
	before := r.Features[0].Z
	ex := r.Explain(YardMap(), func(s uint32) string { return fmt.Sprintf("slot %d", s) })
	if r.Features[0].Z != before {
		t.Error("Explain changed the result")
	}
	if len(ex.Moments) == 0 || ex.Replay == nil || len(ex.Replay.Viewer) == 0 || len(ex.Replay.Occluders) == 0 {
		t.Fatalf("explanation lacks moments or replay: %+v", ex)
	}
	if !strings.Contains(ex.Policy, "never triggers an automatic kick") {
		t.Errorf("policy: %q", ex.Policy)
	}
	for _, m := range ex.Moments {
		if m.Text == "" || m.Known == "" || m.At == "" {
			t.Errorf("moment missing text: %+v", m)
		}
	}
	for _, f := range ex.Features {
		if f.Name == "hidden_loot" && f.Scored {
			t.Error("hidden_loot must not be scored")
		}
	}
	if _, err := json.Marshal(ex); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary(), "z=") {
		t.Errorf("summary: %q", r.Summary())
	}
}

func TestScorerMemoryIsBounded(t *testing.T) {
	mode := pb.GameMode_GAME_MODE_EXTRACTION
	spec := Spec{MatchID: "t", Mode: mode, TickRate: 64, Seconds: 900, Seed: 5, Players: DefaultPlayers(mode, 1, calibrationRoles[1])}
	bs := Batches(spec)
	sc := knowledge.NewScorer(knowledge.DefaultConfig(), YardMap(), mode, 64)
	peakEarly, peakLate := 0, 0
	for i, b := range bs {
		sc.Add(b)
		if i < len(bs)/3 {
			peakEarly = max(peakEarly, sc.Buffered())
		} else {
			peakLate = max(peakLate, sc.Buffered())
		}
	}
	if peakLate > peakEarly*11/10 {
		t.Fatalf("buffer grows with match length: %d early, %d late", peakEarly, peakLate)
	}
	// 10 players, aim and motion samples, over the 12 s control window plus slack, at 64 Hz.
	if limit := 10 * 2 * 64 * 30; peakLate > limit {
		t.Fatalf("buffered %d samples, limit %d", peakLate, limit)
	}
}

func TestBatchesAreDeterministicAndVersioned(t *testing.T) {
	mode := pb.GameMode_GAME_MODE_EXTRACTION
	spec := Spec{MatchID: "t", Mode: mode, TickRate: 64, Seconds: 20, Seed: 3, Players: DefaultPlayers(mode, 1, nil)}
	a, b := Batches(spec), Batches(spec)
	if len(a) != len(b) || len(a) < 19 {
		t.Fatalf("%d vs %d batches", len(a), len(b))
	}
	for i := range a {
		if !proto.Equal(a[i], b[i]) {
			t.Fatalf("batch %d differs between runs", i)
		}
		if a[i].SchemaVersion != 2 || a[i].Map.GetMapId() != "carthago-yard" {
			t.Fatalf("batch %d: schema %d map %v", i, a[i].SchemaVersion, a[i].Map)
		}
	}
	if a[0].MapGeometry == nil || len(a[0].Players) != 10 || a[1].MapGeometry != nil {
		t.Fatal("geometry and players belong in the first batch only")
	}
	if !a[len(a)-1].MatchOver {
		t.Fatal("last batch is not match_over")
	}
	var sounds, items, team int
	for _, x := range a {
		sounds += len(x.Sounds)
		items += len(x.Items)
		team += len(x.TeamInfo)
	}
	if sounds == 0 || items == 0 || team == 0 {
		t.Fatalf("sounds %d items %d team info %d", sounds, items, team)
	}
}

func TestScenarioFile(t *testing.T) {
	spec := Spec{MatchID: "scn", Mode: pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, TickRate: 64, Seconds: 3, Seed: 1,
		Players: DefaultPlayers(pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, 1, []Role{RoleInformed})}
	var buf bytes.Buffer
	if err := WriteScenario(&buf, spec); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if lines[0] != "carthago-scenario 1" {
		t.Fatalf("header %q", lines[0])
	}
	kinds := map[string]int{}
	for _, l := range lines {
		kinds[strings.Fields(l)[0]]++
	}
	for _, k := range []string{"match", "map", "occluder", "zone", "player", "t", "p"} {
		if kinds[k] == 0 {
			t.Errorf("no %q lines", k)
		}
	}
	if kinds["player"] != 10 || kinds["t"] != 3*64 {
		t.Errorf("players %d ticks %d", kinds["player"], kinds["t"])
	}
}

func TestCalibrateSmall(t *testing.T) {
	rows := Calibrate(modes[:1], 2, 900, 77, knowledge.DefaultConfig())
	if len(rows) == 0 {
		t.Fatal("no rows")
	}
	honest := 0
	for _, r := range rows {
		honest += r.Honest
		if r.FalsePos != 0 {
			t.Errorf("%s: %d false positives", r.Segment, r.FalsePos)
		}
	}
	if honest != 2*8 {
		t.Errorf("honest player-matches %d", honest)
	}
	var buf bytes.Buffer
	if err := WriteCalibration(&buf, rows); err != nil || !strings.Contains(buf.String(), "competitive_shooter/") {
		t.Fatalf("table: %v\n%s", err, buf.String())
	}
}
