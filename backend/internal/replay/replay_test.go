package replay

import (
	"testing"
	"time"

	pb "carthago/backend/gen/carthago/v1"
)

// walk is one second (64 ticks) of a player moving 2 cm a tick along +X from x0.
func walk(slot, firstTick uint32, x0 int32) *pb.MotionTrack {
	m := &pb.MotionTrack{Slot: slot, FirstTick: firstTick}
	for i := range 64 {
		dx := int32(2)
		if i == 0 {
			dx = x0
		}
		m.XCm, m.YCm = append(m.XCm, dx), append(m.YCm, 0)
	}
	return m
}

func aim(slot, firstTick uint32, yaw float32) *pb.AimTrack {
	a := &pb.AimTrack{Slot: slot, FirstTick: firstTick}
	for range 64 {
		a.Yaw, a.Pitch = append(a.Yaw, yaw), append(a.Pitch, 0)
	}
	return a
}

func TestRecorderKeepsFourPositionsASecond(t *testing.T) {
	at := time.UnixMilli(1_800_000_000_000)
	r := NewRecorder("m1")
	r.Add(&pb.GameplayBatch{MatchId: "m1", BatchSeq: 1, TickRate: 64,
		Motion: []*pb.MotionTrack{walk(1, 0, 100), walk(2, 0, -500)},
		Aim:    []*pb.AimTrack{aim(1, 0, 90), aim(2, 0, -45)},
		Shots:  []*pb.ShotEvent{{Slot: 1, Tick: 32, TargetSlot: 2, Hit: true, Kill: true}, {Slot: 2, Tick: 40, TargetSlot: -1}},
	}, at)
	r.Add(&pb.GameplayBatch{MatchId: "m1", BatchSeq: 2, TickRate: 64,
		Motion: []*pb.MotionTrack{walk(1, 64, 100+2*63+2)},
		Aim:    []*pb.AimTrack{aim(1, 64, 180)},
	}, at.Add(time.Second))
	r.SetPlayer(1, "alice", "sess-a", 1, false)
	r.SetPlayer(2, "bot:Hawk", "", 2, true)
	if r.Samples() != 12 {
		t.Fatalf("samples = %d, want 4 a second for 2 s of slot 1 and 1 s of slot 2", r.Samples())
	}
	enc, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if d.Match != "m1" || d.StepMs != StepMs || len(d.Players) != 2 || d.Truncated {
		t.Fatalf("recording: %+v", d)
	}
	a := d.Players[0]
	if a.Name != "alice" || a.Session != "sess-a" || a.Team != 1 || len(a.T) != 8 || a.T[0] != 0 || a.T[7] != 7 {
		t.Fatalf("slot 1: %+v", a)
	}
	// Each kept position is the last one of its quarter second: tick 15, 31, 47, 63, ...
	if a.X[0] != 100+2*15 || a.X[3] != 100+2*63 || a.X[7] != 100+2*127 || a.Y[0] != 0 {
		t.Fatalf("slot 1 positions: %v", a.X)
	}
	if a.Yaw[0] != 90 || a.Yaw[3] != 90 || a.Yaw[4] != 180 || a.Yaw[7] != 180 {
		t.Fatalf("slot 1 view: %v", a.Yaw)
	}
	if b := d.Players[1]; !b.Bot || b.X[0] != -500+2*15 || b.Yaw[0] != -45 {
		t.Fatalf("slot 2: %+v", b)
	}
	if d.Bounds != [4]int32{-500 + 2*15, 0, 100 + 2*127, 0} {
		t.Fatalf("bounds: %v", d.Bounds)
	}
	if len(d.Shots) != 2 || d.Shots[0] != (Shot{500, 1, 2, 1, 1}) || d.Shots[1] != (Shot{625, 2, -1, 0, 0}) {
		t.Fatalf("shots: %v", d.Shots)
	}
	if ms, ok := d.BatchMs(2); !ok || ms != 127*1000/64 {
		t.Fatalf("batch 2 ends at %d %v", ms, ok)
	}
	if _, ok := d.BatchMs(3); ok {
		t.Fatal("a batch that was never received has a time")
	}
	if ms, ok := d.WallMs(at.Add(500 * time.Millisecond)); !ok || ms != 63*1000/64 {
		t.Fatalf("wall clock between the batches: %d %v", ms, ok)
	}
	if _, ok := d.WallMs(at.Add(-time.Second)); ok {
		t.Fatal("a time before the match maps into it")
	}
	if _, ok := d.WallMs(at.Add(5 * time.Minute)); ok {
		t.Fatal("a time long after the match maps into it")
	}
	if d.TickMs(128) != 2000 || d.DurationMs != 127*1000/64 {
		t.Fatalf("clock: %d %d", d.TickMs(128), d.DurationMs)
	}
}

func TestRecorderStopsAtItsCaps(t *testing.T) {
	r := NewRecorder("big")
	at := time.UnixMilli(1_800_000_000_000)
	// One slot, one position a tick at one tick a quarter second: every position is kept.
	const n = 50_000
	for batch := range MaxSamples/n + 1 {
		m := &pb.MotionTrack{Slot: 1, FirstTick: uint32(batch * n), XCm: make([]int32, n), YCm: make([]int32, n)}
		r.Add(&pb.GameplayBatch{MatchId: "big", BatchSeq: uint64(batch + 1), TickRate: 4, Motion: []*pb.MotionTrack{m}}, at)
	}
	if r.Samples() != MaxSamples || !r.Truncated() {
		t.Fatalf("samples = %d truncated = %v, want the cap", r.Samples(), r.Truncated())
	}
	for slot := range uint32(MaxPlayers + 10) {
		r.Add(&pb.GameplayBatch{MatchId: "big", BatchSeq: 100 + uint64(slot), TickRate: 4, Motion: []*pb.MotionTrack{{Slot: slot + 2, XCm: []int32{1}, YCm: []int32{1}}}}, at)
	}
	enc, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) > MaxBytes {
		t.Fatalf("encoded size %d is over the cap", len(enc))
	}
	d, err := Decode(enc)
	if err != nil || !d.Truncated || len(d.Players) != 1 {
		t.Fatalf("decoded: players %d truncated %v err %v", len(d.Players), d.Truncated, err)
	}
}

func TestDecodeRefusesGarbage(t *testing.T) {
	if _, err := Decode([]byte("not gzip")); err == nil {
		t.Fatal("garbage decoded")
	}
}
