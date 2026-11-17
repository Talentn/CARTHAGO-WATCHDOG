package analyzer

import (
	"math"
	"math/rand/v2"
	"testing"

	pb "carthago/backend/gen/carthago/v1"
)

// Slot 1 is a person: fires 150 to 400 ms after the crosshair arrives, now and then at
// once. Slot 2 is a trigger bot: 2 or 3 ticks after, every time. Slot 3 sprays, so the
// crosshair arriving again while it fires gives no sample.
func TestFireTiming(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	m := NewMatch(Defaults())
	var cross []*pb.CrosshairEvent
	var shots []*pb.ShotEvent
	tick := uint32(1000)
	for i := range 40 {
		person := uint32(10 + rng.IntN(16))
		if i%8 == 0 {
			person = uint32(rng.IntN(6))
		}
		cross = append(cross,
			&pb.CrosshairEvent{Slot: 1, TargetSlot: 4, Tick: tick},
			&pb.CrosshairEvent{Slot: 2, TargetSlot: 4, Tick: tick},
			&pb.CrosshairEvent{Slot: 3, TargetSlot: 4, Tick: tick})
		shots = append(shots,
			&pb.ShotEvent{Slot: 1, Tick: tick + person, TargetSlot: 4, Hit: true},
			// A second shot in the same arrival is not a second sample.
			&pb.ShotEvent{Slot: 1, Tick: tick + person + 6, TargetSlot: 4, Hit: true},
			// The bot's shot counts whether it hits or not.
			&pb.ShotEvent{Slot: 2, Tick: tick + 2 + uint32(rng.IntN(2)), TargetSlot: -1},
			&pb.ShotEvent{Slot: 3, Tick: tick - 10, TargetSlot: -1},
			&pb.ShotEvent{Slot: 3, Tick: tick + 1, TargetSlot: 4, Hit: true})
		// An arrival nobody fires on within a second is dropped.
		cross = append(cross, &pb.CrosshairEvent{Slot: 1, TargetSlot: 5, Tick: tick + 100})
		tick += 300
	}
	if err := CheckBatch(&pb.GameplayBatch{TickRate: 64, Crosshair: []*pb.CrosshairEvent{{Slot: 1, TargetSlot: MaxSlots}}}); err == nil {
		t.Error("a crosshair event with a slot out of range was accepted")
	}
	m.Add(&pb.GameplayBatch{TickRate: 64, Crosshair: cross, Shots: shots})
	person, _ := m.Summary(1)
	bot, _ := m.Summary(2)
	spray, _ := m.Summary(3)
	if person.FireDelays != 40 || person.FireTimed > 0.15 {
		t.Errorf("person: %d delays, timed %.2f", person.FireDelays, person.FireTimed)
	}
	if bot.FireDelays != 40 || bot.FireTimed != 1 {
		t.Errorf("trigger bot: %d delays, timed %.2f", bot.FireDelays, bot.FireTimed)
	}
	if spray.FireDelays != 0 || spray.FireTimed != 0 {
		t.Errorf("spray: %d delays, timed %.2f", spray.FireDelays, spray.FireTimed)
	}
	// Fast but spread over more than the window is a person's flicks, not a bot.
	if got := fireTimed([]float64{0, 16, 31, 47, 62, 78, 94, 200, 250, 300}); math.Abs(got-0.3) > 1e-9 {
		t.Errorf("spread fast delays: %.2f, want 0.30", got)
	}
	if got := fireTimed([]float64{150, 160, 170}); got != 0 {
		t.Errorf("even but slow delays: %.2f, want 0", got)
	}
}
