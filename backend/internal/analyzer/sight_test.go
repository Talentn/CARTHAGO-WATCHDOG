package analyzer

import (
	"testing"

	pb "carthago/backend/gen/carthago/v1"
)

// sightBatch is 20 seconds at 64 ticks a second. Slot 0 (team 1) stands at the origin and
// looks along yaw. Slot 1 (team 2) stands 10 m away along the x axis behind a wall and
// comes into view after 10 seconds. Slot 2 is slot 0's teammate, far to the side.
func sightBatch(yaw float32, with func(b *pb.GameplayBatch)) *pb.GameplayBatch {
	const ticks = 64 * 20
	still := func(slot uint32, xCm, yCm int32) *pb.MotionTrack {
		t := &pb.MotionTrack{Slot: slot, XCm: make([]int32, ticks), YCm: make([]int32, ticks), ZCm: make([]int32, ticks)}
		t.XCm[0], t.YCm[0] = xCm, yCm
		return t
	}
	look := func(slot uint32, yaw float32) *pb.AimTrack {
		t := &pb.AimTrack{Slot: slot, Yaw: make([]float32, ticks), Pitch: make([]float32, ticks)}
		for i := range t.Yaw {
			t.Yaw[i] = yaw
		}
		return t
	}
	b := &pb.GameplayBatch{MatchId: "m", TickRate: 64,
		Players: []*pb.MatchPlayer{{Slot: 0, Team: 1}, {Slot: 1, Team: 2}, {Slot: 2, Team: 1}},
		Motion:  []*pb.MotionTrack{still(0, 0, 0), still(1, 1000, 0), still(2, 0, 30000)},
		Aim:     []*pb.AimTrack{look(0, yaw), look(1, 90), look(2, 90)},
		Visibility: []*pb.VisibilityEvent{
			{ObserverSlot: 0, TargetSlot: 1, Tick: 0, Visible: false},
			{ObserverSlot: 0, TargetSlot: 1, Tick: 64 * 10, Visible: true},
		}}
	if with != nil {
		with(b)
	}
	return b
}

func TestSight(t *testing.T) {
	run := func(b *pb.GameplayBatch) *Player {
		m := NewMatch(Defaults())
		m.Add(b)
		return m.Players[0]
	}
	// The crosshair stays on an opponent behind a wall nobody told the player about, and
	// is there when the opponent comes out. The first two seconds do not count: the
	// player has just seen where the opponent went.
	p := run(sightBatch(0, nil))
	if p.HiddenSamples != 8*8-1 || p.HiddenTracked != p.HiddenSamples-1 || p.Appearances != 1 || p.PreAimed != 1 {
		t.Fatalf("through the wall: %d hidden samples, %d tracked, %d appearances, %d pre-aimed", p.HiddenSamples, p.HiddenTracked, p.Appearances, p.PreAimed)
	}
	// The same player looking somewhere else.
	p = run(sightBatch(90, nil))
	if p.HiddenSamples != 8*8-1 || p.HiddenTracked != 0 || p.Appearances != 1 || p.PreAimed != 0 {
		t.Fatalf("looking away: %d hidden samples, %d tracked, %d appearances, %d pre-aimed", p.HiddenSamples, p.HiddenTracked, p.Appearances, p.PreAimed)
	}
	// Honest ways to know where the opponent is: footsteps the game says the player can
	// hear, a teammate who sees the opponent, the game's own marker for the team.
	for name, with := range map[string]func(b *pb.GameplayBatch){
		"footsteps": func(b *pb.GameplayBatch) {
			for tick := uint32(32); tick < 64*20; tick += 64 {
				b.Sounds = append(b.Sounds, &pb.SoundEvent{Tick: tick, SourceSlot: 1, Kind: pb.SoundKind_SOUND_KIND_FOOTSTEP, XCm: 1000, RadiusCm: 1500})
			}
		},
		"a teammate sees the opponent": func(b *pb.GameplayBatch) {
			b.Visibility = append(b.Visibility, &pb.VisibilityEvent{ObserverSlot: 2, TargetSlot: 1, Tick: 1, Visible: true})
		},
		"marked for the team": func(b *pb.GameplayBatch) {
			for tick := uint32(0); tick < 64*20; tick += 64 {
				b.TeamInfo = append(b.TeamInfo, &pb.TeamInfo{Tick: tick, Team: 1, Kind: pb.TeamInfoKind_TEAM_INFO_KIND_SPOTTED, SourceSlot: -1, TargetSlot: 1, DurationMs: 2000})
			}
		},
	} {
		if p = run(sightBatch(0, with)); p.HiddenSamples != 0 || p.HiddenTracked != 0 || p.Appearances != 0 || p.PreAimed != 0 {
			t.Errorf("%s: %d hidden samples, %d tracked, %d appearances, %d pre-aimed", name, p.HiddenSamples, p.HiddenTracked, p.Appearances, p.PreAimed)
		}
	}
	// Footsteps too far away to hear explain nothing.
	p = run(sightBatch(0, func(b *pb.GameplayBatch) {
		b.Sounds = append(b.Sounds, &pb.SoundEvent{Tick: 64 * 5, SourceSlot: 1, Kind: pb.SoundKind_SOUND_KIND_FOOTSTEP, XCm: 1000, RadiusCm: 500})
	}))
	if p.HiddenSamples != 8*8-1 || p.PreAimed != 1 {
		t.Fatalf("a sound out of earshot: %d hidden samples, %d pre-aimed", p.HiddenSamples, p.PreAimed)
	}
	// A game server that reports no visibility, or no positions, gives nothing, and the
	// rest of the summary is as it was.
	for name, with := range map[string]func(b *pb.GameplayBatch){
		"no visibility": func(b *pb.GameplayBatch) { b.Visibility = nil },
		"no positions":  func(b *pb.GameplayBatch) { b.Motion = nil },
	} {
		m := NewMatch(Defaults())
		m.Add(sightBatch(0, with))
		p = m.Players[0]
		if s, _ := m.Summary(0); p.HiddenSamples != 0 || p.Appearances != 0 || s.HiddenSamples != 0 || s.AimSamples != 64*20 {
			t.Errorf("%s: %d hidden samples, %d appearances, %d aim samples", name, p.HiddenSamples, p.Appearances, s.AimSamples)
		}
	}
}
