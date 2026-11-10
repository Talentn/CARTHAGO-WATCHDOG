package synth

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"strings"

	pb "carthago/backend/gen/carthago/v1"
)

// Encoder packs frames into GameplayBatches the way carthago-server's MatchRecorder does:
// delta-encoded motion every MotionStride ticks, one aim track per player per batch.
type Encoder struct {
	spec    Spec
	seq     uint64
	sentMap bool
	sentPl  bool
	from    uint32
	tick    uint32
	motion  map[uint32]*motionTrack
	order   []uint32
	aim     map[uint32]*pb.AimTrack
	cmds    map[uint32]uint32
	b       pb.GameplayBatch
}

type motionTrack struct {
	t    *pb.MotionTrack
	last [6]int32
}

func NewEncoder(spec Spec) *Encoder {
	if spec.MotionStride == 0 {
		spec.MotionStride = 1
	}
	return &Encoder{spec: spec, motion: map[uint32]*motionTrack{}, aim: map[uint32]*pb.AimTrack{}, cmds: map[uint32]uint32{}}
}

func round(v float64) int32 { return int32(math.Round(v)) }

func (e *Encoder) Frame(f *Frame) {
	if e.from == 0 {
		e.from = f.Tick
	}
	e.tick = f.Tick
	for _, p := range f.Players {
		if f.Tick%e.spec.MotionStride == 0 {
			vals := [6]int32{round(p.Pos.X * 100), round(p.Pos.Y * 100), round(p.Pos.Z * 100), round(p.Vel.X * 100), round(p.Vel.Y * 100), round(p.Vel.Z * 100)}
			mt := e.motion[p.Slot]
			if mt == nil {
				mt = &motionTrack{t: &pb.MotionTrack{Slot: p.Slot, FirstTick: f.Tick, Stride: e.spec.MotionStride}}
				e.motion[p.Slot] = mt
				e.order = append(e.order, p.Slot)
			}
			d := vals
			if len(mt.t.XCm) > 0 {
				for i := range d {
					d[i] = vals[i] - mt.last[i]
				}
			}
			mt.last = vals
			t := mt.t
			t.XCm, t.YCm, t.ZCm = append(t.XCm, d[0]), append(t.YCm, d[1]), append(t.ZCm, d[2])
			t.VxCmS, t.VyCmS, t.VzCmS = append(t.VxCmS, d[3]), append(t.VyCmS, d[4]), append(t.VzCmS, d[5])
		}
		a := e.aim[p.Slot]
		if a == nil {
			a = &pb.AimTrack{Slot: p.Slot, FirstTick: f.Tick}
			e.aim[p.Slot] = a
		}
		a.Yaw = append(a.Yaw, float32(math.Mod(p.Yaw+360, 360)))
		a.Pitch = append(a.Pitch, float32(p.Pitch))
		e.cmds[p.Slot] += p.Commands
	}
	e.b.Sounds = append(e.b.Sounds, f.Sounds...)
	e.b.TeamInfo = append(e.b.TeamInfo, f.Team...)
	e.b.Items = append(e.b.Items, f.Items...)
	e.b.Visibility = append(e.b.Visibility, f.Vis...)
	e.b.Shots = append(e.b.Shots, f.Shots...)
}

func (e *Encoder) Flush(over bool) *pb.GameplayBatch {
	e.seq++
	b := &pb.GameplayBatch{
		MatchId: e.spec.MatchID, BatchSeq: e.seq, TickRate: e.spec.TickRate, MatchOver: over, SchemaVersion: 2, Mode: e.spec.Mode,
		Map:    &pb.MapRef{MapId: YardID, Version: YardVersion},
		Sounds: e.b.Sounds, TeamInfo: e.b.TeamInfo, Items: e.b.Items, Visibility: e.b.Visibility, Shots: e.b.Shots,
	}
	e.b = pb.GameplayBatch{}
	if !e.sentMap {
		b.MapGeometry, e.sentMap = YardGeometry(), true
	}
	if !e.sentPl {
		e.sentPl = true
		for _, p := range e.spec.Players {
			b.Players = append(b.Players, &pb.MatchPlayer{Slot: p.Slot, SessionId: p.SessionID, PlayerHash: p.PlayerHash, Mmr: p.MMR,
				Team: p.Team, InputDevice: p.Device, AimAssist: p.AimAssist})
		}
	}
	for _, slot := range e.order {
		mt := e.motion[slot]
		if len(mt.t.XCm) > 0 {
			b.Motion = append(b.Motion, mt.t)
		}
		mt.t = &pb.MotionTrack{Slot: slot, Stride: e.spec.MotionStride}
		mt.t.FirstTick = 0
		if a := e.aim[slot]; a != nil {
			b.Aim = append(b.Aim, a)
		}
		if n := e.cmds[slot]; n > 0 && e.tick > e.from {
			b.Commands = append(b.Commands, &pb.CommandWindow{Slot: slot, TickFrom: e.from, TickTo: e.tick, Commands: n})
		}
	}
	// A new batch's tracks start absolute again.
	for slot := range e.motion {
		delete(e.motion, slot)
	}
	e.order = e.order[:0]
	e.aim = map[uint32]*pb.AimTrack{}
	e.cmds = map[uint32]uint32{}
	e.from = e.tick
	return b
}

// Batches simulates a whole match, flushing once per second of game time.
func Batches(spec Spec) []*pb.GameplayBatch {
	if spec.TickRate == 0 {
		spec.TickRate = 64
	}
	enc := NewEncoder(spec)
	var out []*pb.GameplayBatch
	last := uint32(spec.Seconds) * spec.TickRate
	Run(spec, func(f *Frame) {
		enc.Frame(f)
		if f.Tick%spec.TickRate == 0 || f.Tick == last {
			out = append(out, enc.Flush(f.Tick == last))
		}
	})
	return out
}

func deviceWord(d pb.InputDevice) string {
	switch d {
	case pb.InputDevice_INPUT_DEVICE_MOUSE_KEYBOARD:
		return "mouse"
	case pb.InputDevice_INPUT_DEVICE_CONTROLLER:
		return "controller"
	case pb.InputDevice_INPUT_DEVICE_TOUCH:
		return "touch"
	}
	return "unspecified"
}

func ParseDevice(s string) (pb.InputDevice, error) {
	switch s {
	case "mouse":
		return pb.InputDevice_INPUT_DEVICE_MOUSE_KEYBOARD, nil
	case "controller":
		return pb.InputDevice_INPUT_DEVICE_CONTROLLER, nil
	case "touch":
		return pb.InputDevice_INPUT_DEVICE_TOUCH, nil
	case "unspecified":
		return pb.InputDevice_INPUT_DEVICE_UNSPECIFIED, nil
	}
	return 0, fmt.Errorf("unknown input device %q", s)
}

var soundWords = map[pb.SoundKind]string{
	pb.SoundKind_SOUND_KIND_FOOTSTEP: "footstep", pb.SoundKind_SOUND_KIND_GUNSHOT: "gunshot", pb.SoundKind_SOUND_KIND_RELOAD: "reload",
	pb.SoundKind_SOUND_KIND_ABILITY: "ability", pb.SoundKind_SOUND_KIND_INTERACT: "interact",
}

var teamWords = map[pb.TeamInfoKind]string{
	pb.TeamInfoKind_TEAM_INFO_KIND_PING: "ping", pb.TeamInfoKind_TEAM_INFO_KIND_SPOTTED: "spotted", pb.TeamInfoKind_TEAM_INFO_KIND_RADAR: "radar",
}

func b01(b bool) int {
	if b {
		return 1
	}
	return 0
}

func ints(xs []int32) string {
	var sb strings.Builder
	for i, x := range xs {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprint(&sb, x)
	}
	return sb.String()
}

// WriteScenario writes the match as a scenario file for gs-stub simulate --scenario, which
// replays it through the game-server SDK. Format (one record per line, integers in cm,
// cm/s and hundredths of a degree):
//
//	carthago-scenario 1
//	match <id> <shooter|extraction> <tick_rate> <ticks>
//	map <map_id> <version>
//	occluder <z_min> <z_max> <x0> <y0> <x1> <y1> ...
//	zone <name, spaces as _> <x0> <y0> ...
//	loot <spawn_id> <x> <y> <z>
//	player <slot> <team> <mouse|controller|touch|unspecified> <aim_assist 0|1> <role>
//	t <tick>
//	p <slot> <x> <y> <z> <vx> <vy> <vz> <yaw> <pitch>
//	s <source_slot> <footstep|gunshot|reload|ability|interact> <x> <y> <z> <radius>
//	i <team> <ping|spotted|radar> <source_slot> <target_slot> <item_id> <x> <y> <z> <duration_ms>
//	o <item_id> <x> <y> <z> <tier> <removed 0|1>
//	v <observer> <target> <visible 0|1>
//	f <slot> <target_slot> <hit 0|1> <headshot 0|1> <distance>
//
// The role is for the operator's log only; gs-stub never sends it.
func WriteScenario(w io.Writer, spec Spec) error {
	if spec.TickRate == 0 {
		spec.TickRate = 64
	}
	bw := bufio.NewWriterSize(w, 1<<16)
	g := YardGeometry()
	fmt.Fprintln(bw, "carthago-scenario 1")
	fmt.Fprintf(bw, "match %s %s %d %d\n", spec.MatchID, ModeName(spec.Mode), spec.TickRate, uint32(spec.Seconds)*spec.TickRate)
	fmt.Fprintf(bw, "map %s %d\n", g.MapId, g.Version)
	for _, o := range g.Occluders {
		fmt.Fprintf(bw, "occluder %d %d %s\n", o.ZMinCm, o.ZMaxCm, ints(o.XyCm))
	}
	for _, z := range g.Zones {
		fmt.Fprintf(bw, "zone %s %s\n", strings.ReplaceAll(z.Name, " ", "_"), ints(z.XyCm))
	}
	for _, l := range g.LootSpawns {
		fmt.Fprintf(bw, "loot %d %d %d %d\n", l.SpawnId, l.XCm, l.YCm, l.ZCm)
	}
	for _, p := range spec.Players {
		fmt.Fprintf(bw, "player %d %d %s %d %s\n", p.Slot, p.Team, deviceWord(p.Device), b01(p.AimAssist), p.Role)
	}
	Run(spec, func(f *Frame) {
		fmt.Fprintf(bw, "t %d\n", f.Tick)
		for _, p := range f.Players {
			fmt.Fprintf(bw, "p %d %d %d %d %d %d %d %d %d\n", p.Slot, round(p.Pos.X*100), round(p.Pos.Y*100), round(p.Pos.Z*100),
				round(p.Vel.X*100), round(p.Vel.Y*100), round(p.Vel.Z*100), round(math.Mod(p.Yaw+360, 360)*100), round(p.Pitch*100))
		}
		for _, s := range f.Sounds {
			fmt.Fprintf(bw, "s %d %s %d %d %d %d\n", s.SourceSlot, soundWords[s.Kind], s.XCm, s.YCm, s.ZCm, s.RadiusCm)
		}
		for _, t := range f.Team {
			fmt.Fprintf(bw, "i %d %s %d %d %d %d %d %d %d\n", t.Team, teamWords[t.Kind], t.SourceSlot, t.TargetSlot, t.ItemId, t.XCm, t.YCm, t.ZCm, t.DurationMs)
		}
		for _, it := range f.Items {
			fmt.Fprintf(bw, "o %d %d %d %d %d %d\n", it.ItemId, it.XCm, it.YCm, it.ZCm, it.Tier, b01(it.Removed))
		}
		for _, v := range f.Vis {
			fmt.Fprintf(bw, "v %d %d %d\n", v.ObserverSlot, v.TargetSlot, b01(v.Visible))
		}
		for _, s := range f.Shots {
			fmt.Fprintf(bw, "f %d %d %d %d %d\n", s.Slot, s.TargetSlot, b01(s.Hit), b01(s.Headshot), round(float64(s.DistanceM)*100))
		}
	})
	return bw.Flush()
}
