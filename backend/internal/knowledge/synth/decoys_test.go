package synth

import (
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge"
)

// frameKey is everything a frame says about the real match, decoys left out.
func frameKey(f *Frame) string {
	var b strings.Builder
	fmt.Fprint(&b, f.Tick, f.Players)
	for _, ms := range [][]proto.Message{msgs(f.Sounds), msgs(f.Team), msgs(f.Items), msgs(f.Vis), msgs(f.Shots)} {
		for _, m := range ms {
			fmt.Fprint(&b, prototext.Format(m))
		}
		b.WriteByte('|')
	}
	return b.String()
}

func msgs[T proto.Message](xs []T) []proto.Message {
	out := make([]proto.Message, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// Decoys run on their own random stream and honest roles never perceive them, so an honest
// match plays out identically with or without decoys, and its leak scores do not move.
func TestDecoysNeverChangeHonestPlay(t *testing.T) {
	noisy := []Role{RolePrefire, RoleSound, RoleTeamCall, RoleLegit, RoleSound, RoleTeamCall, RolePrefire, RoleLegit, RoleTeamCall, RoleSound}
	for _, mode := range modes {
		t.Run(ModeName(mode), func(t *testing.T) {
			t.Parallel()
			spec := Spec{MatchID: "t", Mode: mode, TickRate: 64, Seconds: 900, Seed: 29, Players: DefaultPlayers(mode, 1, noisy)}
			var off []string
			Run(spec, func(f *Frame) { off = append(off, frameKey(f)) })
			with := spec
			with.Decoys = true
			i, decoys := 0, 0
			Run(with, func(f *Frame) {
				decoys += len(f.Decoys)
				if i < len(off) && frameKey(f) != off[i] {
					t.Fatalf("tick %d differs with decoys on", f.Tick)
				}
				i++
			})
			if i != len(off) || decoys == 0 {
				t.Fatalf("frames %d vs %d, decoy frames %d", i, len(off), decoys)
			}

			a, b := bySlot(Score(spec, knowledge.DefaultConfig())), bySlot(Score(with, knowledge.DefaultConfig()))
			for slot, r := range a {
				d := b[slot]
				if r.Score != d.Score || r.Flagged != d.Flagged {
					t.Errorf("slot %d leak score %.3f -> %.3f with decoys", slot, r.Score, d.Score)
				}
				if r.Decoy != nil {
					t.Errorf("slot %d has decoy results without decoys", slot)
				}
				if d.Decoy == nil || d.Decoy.Received == 0 || d.Decoy.Flagged || d.Decoy.Score > honestCeiling || d.Decoy.Exposed != 0 {
					t.Errorf("slot %d decoys: %+v", slot, d.Decoy)
				}
			}
		})
	}
}

// The leak scorer ignores decoys: the same batches with their decoy tracks stripped give the
// same leak results, cheaters included.
func TestStrippingDecoysLeavesLeakResults(t *testing.T) {
	spec := Spec{MatchID: "t", Mode: pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, TickRate: 64, Seconds: 900, Seed: 31, Decoys: true,
		Players: DefaultPlayers(pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, 1, calibrationRoles[0])}
	m := YardMap()
	score := func(strip bool) map[uint32]knowledge.Result {
		var sc *knowledge.Scorer
		for _, b := range Batches(spec) {
			if strip {
				b = proto.Clone(b).(*pb.GameplayBatch)
				b.Decoys = nil
			}
			if sc == nil {
				sc = knowledge.NewScorer(knowledge.DefaultConfig(), m, b.Mode, b.TickRate)
			}
			sc.Add(b)
		}
		return bySlot(sc.Finish())
	}
	with, without := score(false), score(true)
	for slot, r := range without {
		d := with[slot]
		if r.Score != d.Score || r.Flagged != d.Flagged || len(r.Moments) != len(d.Moments) {
			t.Errorf("slot %d leak %.3f/%v -> %.3f/%v with decoys", slot, r.Score, r.Flagged, d.Score, d.Flagged)
		}
	}
}
