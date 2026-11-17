package synth

import (
	"slices"
	"sort"

	pb "carthago/backend/gen/carthago/v1"
)

// Spoil rewrites what the simulated game server reports about one slot of a match, so the
// slot plays the way a player who spoils matches does: it runs into the enemy and dies
// eleven times without a kill (0:30 to 3:00), hits teammates eight times and kills two
// (3:10 to 3:40), stands idle (3:45 to 5:30) and then leaves. The match should last at
// least seven and a half minutes for the leaving to count as early. Only the reported
// events change. Nothing here is a cheat or touches a client.
func Spoil(batches []*pb.GameplayBatch, rate, slot uint32, mates, enemies []uint32) {
	sec := func(s uint32) uint32 { return s * rate }
	idleFrom, idleTo, leave := sec(225), sec(330), sec(330)
	var extra []*pb.ShotEvent
	// Eleven deaths between 0:30 and 3:00, one enemy after another.
	for i := range uint32(11) {
		extra = append(extra, &pb.ShotEvent{Slot: enemies[int(i)%len(enemies)], Tick: sec(30 + i*14), TargetSlot: int32(slot), Hit: true, Kill: true, Weapon: "rifle", DistanceM: 9})
	}
	// Eight hits on teammates between 3:10 and 3:40, two of them kills.
	for i := range uint32(8) {
		extra = append(extra, &pb.ShotEvent{Slot: slot, Tick: sec(190 + i*4), TargetSlot: int32(mates[int(i)%len(mates)]), Hit: true, Kill: i == 3 || i == 7, Weapon: "rifle", DistanceM: 4})
	}
	var still struct {
		have    bool
		x, y, z int32
		yaw     float32
		pitch   float32
	}
	for _, b := range batches {
		var from, to uint32 = ^uint32(0), 0
		for _, m := range b.Motion {
			from, to = min(from, m.FirstTick), max(to, m.FirstTick+uint32(len(m.XCm))*max(m.Stride, 1))
		}
		for _, a := range b.Aim {
			from, to = min(from, a.FirstTick), max(to, a.FirstTick+uint32(len(a.Yaw)))
		}
		gone := from >= leave
		idle := !gone && from >= idleFrom && from < idleTo
		// The slot's own shots are dropped for the whole match: it never fights back.
		b.Shots = slices.DeleteFunc(b.Shots, func(e *pb.ShotEvent) bool {
			return e.Slot == slot || (gone && e.TargetSlot == int32(slot))
		})
		for _, e := range extra {
			if e.Tick >= from && e.Tick < to {
				b.Shots = append(b.Shots, e)
			}
		}
		sort.SliceStable(b.Shots, func(i, j int) bool { return b.Shots[i].Tick < b.Shots[j].Tick })
		if gone {
			b.Motion = slices.DeleteFunc(b.Motion, func(m *pb.MotionTrack) bool { return m.Slot == slot })
			b.Aim = slices.DeleteFunc(b.Aim, func(a *pb.AimTrack) bool { return a.Slot == slot })
			b.Sounds = slices.DeleteFunc(b.Sounds, func(e *pb.SoundEvent) bool { return e.SourceSlot == int32(slot) })
			b.Commands = slices.DeleteFunc(b.Commands, func(c *pb.CommandWindow) bool { return c.Slot == slot })
			continue
		}
		for _, m := range b.Motion {
			if m.Slot != slot || len(m.XCm) == 0 {
				continue
			}
			if !idle {
				// Where the slot stands at the end of this batch is where it will stand idle.
				still.x, still.y, still.z = sum(m.XCm), sum(m.YCm), sum(m.ZCm)
				still.have = true
				continue
			}
			for _, list := range [][]int32{m.XCm, m.YCm, m.ZCm, m.VxCmS, m.VyCmS, m.VzCmS} {
				clear(list)
			}
			m.XCm[0], m.YCm[0] = still.x, still.y
			if len(m.ZCm) > 0 {
				m.ZCm[0] = still.z
			}
		}
		for _, a := range b.Aim {
			if a.Slot != slot || len(a.Yaw) == 0 {
				continue
			}
			if !idle {
				still.yaw, still.pitch = a.Yaw[len(a.Yaw)-1], a.Pitch[len(a.Pitch)-1]
				continue
			}
			for i := range a.Yaw {
				a.Yaw[i], a.Pitch[i] = still.yaw, still.pitch
			}
		}
		if idle {
			b.Sounds = slices.DeleteFunc(b.Sounds, func(e *pb.SoundEvent) bool { return e.SourceSlot == int32(slot) })
		}
	}
}

func sum(deltas []int32) int32 {
	var v int32
	for _, d := range deltas {
		v += d
	}
	return v
}
