package synth

import (
	"reflect"
	"testing"

	pb "carthago/backend/gen/carthago/v1"
)

// A seed must always play the same match, whatever the roles: the end-to-end script and the
// calibration compare runs, and a rule that fires in one run out of several cannot be
// investigated if the match cannot be replayed.
func TestSeedReplaysTheSameMatch(t *testing.T) {
	roles := []Role{RoleInformed, RoleLegit, RoleSound, RolePrefire, RoleTeamCall, RoleSubtle, RoleLegit, RoleSound, RolePrefire, RoleTeamCall}
	for _, mode := range []pb.GameMode{pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, pb.GameMode_GAME_MODE_EXTRACTION} {
		spec := Spec{MatchID: "t", Mode: mode, TickRate: 64, Seconds: 120, Seed: 12, Players: DefaultPlayers(mode, 1, roles)}
		var first []*Frame
		Run(spec, func(f *Frame) { first = append(first, f) })
		for run := range 3 {
			i := 0
			Run(spec, func(f *Frame) {
				if i >= 0 && !reflect.DeepEqual(first[i], f) {
					t.Errorf("%v, run %d: tick %d differs from the first run", mode, run+2, f.Tick)
					i = -1
				}
				if i >= 0 {
					i++
				}
			})
		}
	}
}
