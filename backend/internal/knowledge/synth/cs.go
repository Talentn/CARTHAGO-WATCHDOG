package synth

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"strings"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge"
	"carthago/backend/internal/knowledge/bsptree"
)

// The Counter-Strike 1.6 build of the yard: the same walls as a GoldSrc map (a solid tree
// in game units) and matches played by the game's rules, written as the stream the server
// plugin sends. The bridge turns that stream and the map file into telemetry exactly as it
// does for the real game, so a calibration on these matches goes through the same code.
const (
	CSYardID   = "cs_carthago_yard"
	CSTickRate = 32
	// Metres per GoldSrc unit.
	csUnit = 0.0254
	// The game's distances, metres: sounds at normal attenuation (footsteps, pain) fade to
	// nothing at 1250 units and a rifle at 2500; running is 250 units a second.
	csNormalRadius  = 1250 * csUnit
	csGunshotRadius = 2500 * csUnit
	csRunSpeed      = 250 * csUnit
	// The body centre the plugin's sight traces also try is 17 units below the eyes.
	csEyeToCentre = 17 * csUnit
	csDatagram    = 1200
)

// CSYardBrushes are the yard's walls and floor in game units.
func CSYardBrushes() []bsptree.Brush {
	u := func(m float64) float64 { return math.Round(m / csUnit) }
	out := []bsptree.Brush{bsptree.Box(u(-2), u(-2), -64, u(62), u(42), 0)}
	for _, b := range yardBoxes {
		out = append(out, bsptree.Box(u(b.x0), u(b.y0), 0, u(b.x1), u(b.y1), u(b.h)))
	}
	return out
}

var csYardTree = func() *bsptree.Tree {
	t, err := bsptree.Build(CSYardBrushes())
	if err != nil {
		panic(err)
	}
	return t
}()

var csYardMap = func() *knowledge.Map {
	m, err := knowledge.Compile(&pb.MapGeometry{MapId: CSYardID, Version: 1, Mode: pb.GameMode_GAME_MODE_ROUND_SHOOTER, Solid: csYardTree.Proto(2.54)})
	if err != nil {
		panic(err)
	}
	return m
}()

// CSYardMap is the map as the simulation traces it.
func CSYardMap() *knowledge.Map { return csYardMap }

// WriteCSYardBSP writes the map as a GoldSrc map file (BSP version 30) for the bridge.
func WriteCSYardBSP(w io.Writer) error {
	return csYardTree.WriteBSP30(w, [3]float32{-80, -80, -64}, [3]float32{2450, 1660, 160})
}

// round runs the round clock: a round ends when a team is dead or its time is up, and
// everyone is back at their spawn a few seconds later.
func (s *sim) round() {
	if s.restartAt > 0 {
		if s.now < s.restartAt {
			return
		}
		s.restartAt, s.roundEnd = 0, s.now+float64(s.spec.RoundSec)
		for k := range s.spots {
			delete(s.spots, k)
		}
		for i, p := range s.ps {
			p.dead, p.hp = false, 100
			p.at = s.spawnNode(p.spec, i)
			p.pos, p.vel = v3(nodes[p.at], EyeHeight), knowledge.Vec3{}
			p.path, p.look, p.engaged, p.burst, p.prefire = nil, nil, -1, 0, 0
			p.hold = s.r.between(1, 3)
			p.yaw = s.r.between(-180, 180)
			p.visible, p.heard, p.cooldown = map[uint32]bool{}, map[uint32]heard{}, map[uint32]float64{}
		}
		return
	}
	alive := map[uint32]int{}
	for _, p := range s.ps {
		if !p.dead {
			alive[p.spec.Team]++
		}
	}
	teams := map[uint32]bool{}
	over := s.now >= s.roundEnd
	for _, p := range s.ps {
		if !teams[p.spec.Team] {
			teams[p.spec.Team] = true
			over = over || alive[p.spec.Team] == 0
		}
	}
	if over {
		s.restartAt = s.now + 4
	}
	// A dead human watches the round and tells the team where the enemies are. Bots do not.
	for _, d := range s.ps {
		if !d.dead || d.spec.Bot {
			continue
		}
		for _, e := range s.enemies(d) {
			s.spots[[2]uint32{d.spec.Team, e.spec.Slot}] = heard{e.pos, s.now}
		}
	}
}

func (s *sim) kill(e *simPlayer) {
	e.dead, e.vel = true, knowledge.Vec3{}
	for _, p := range s.ps {
		delete(p.visible, e.spec.Slot)
		if p.engaged == int(e.spec.Slot) {
			p.engaged = -1
		}
	}
}

// csSight is the plugin's sight sweep: a pair of living opponents is in sight when either
// one's eyes see the other's eyes or body centre through the world. The plugin gets round
// to each pair every few samples, which the stagger stands for.
func (s *sim) csSight() {
	centre := func(p *simPlayer) knowledge.Vec3 {
		return knowledge.Vec3{X: p.pos.X, Y: p.pos.Y, Z: p.pos.Z - csEyeToCentre}
	}
	for i, a := range s.ps {
		for j := i + 1; j < len(s.ps); j++ {
			b := s.ps[j]
			if a.spec.Team == b.spec.Team {
				continue
			}
			key := [2]uint32{a.spec.Slot, b.spec.Slot}
			if a.dead || b.dead {
				if s.sight[key] {
					delete(s.sight, key)
					s.frame.Sight = append(s.frame.Sight, [3]uint32{key[0], key[1], 0})
				}
				continue
			}
			if (s.tick+uint32(i*7+j))%4 != 0 {
				continue
			}
			vis := s.m.LineOfSight(a.pos, b.pos) || s.m.LineOfSight(a.pos, centre(b)) || s.m.LineOfSight(b.pos, centre(a))
			if vis != s.sight[key] {
				s.sight[key] = vis
				s.frame.Sight = append(s.frame.Sight, [3]uint32{key[0], key[1], uint32(b01(vis))})
			}
		}
	}
}

// CSPlayers is a 5v5 for a Counter-Strike match. With bots set, slot 1 is the human on
// the server's machine and every other player is a bot of the game, which is how one
// person tests on their own server; otherwise all ten are people.
func CSPlayers(roles []Role, bots bool) []PlayerSpec {
	ps := DefaultPlayers(pb.GameMode_GAME_MODE_ROUND_SHOOTER, 1, roles)
	for i := range ps {
		ps[i].Local = i == 0
		ps[i].Bot = bots && i != 0
	}
	return ps
}

// WriteCS16Stream plays the match and writes what the Counter-Strike server plugin would
// send (client/cs16/plugin/carthago_cs16.sma lists the lines), split into datagrams the
// way the plugin splits them.
func WriteCS16Stream(w io.Writer, spec Spec) error {
	spec.CS, spec.Mode = true, pb.GameMode_GAME_MODE_ROUND_SHOOTER
	if spec.TickRate == 0 {
		spec.TickRate = CSTickRate
	}
	bw := bufio.NewWriterSize(w, 1<<16)
	seq, used := 0, 0
	var tick uint32
	put := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		if used == 0 || used+len(line) > csDatagram {
			head := fmt.Sprintf("D %d %d\n", seq, tick)
			bw.WriteString(head)
			seq++
			used = len(head)
		}
		bw.WriteString(line)
		used += len(line)
	}
	units := func(m float64) int { return int(math.Round(m / csUnit)) }
	msec := 16000 / int(spec.TickRate)
	last := uint32(spec.Seconds) * spec.TickRate
	Run(spec, func(f *Frame) {
		tick, used = f.Tick, 0
		if f.Tick == 1 || f.Tick%64 == 0 {
			put("H %s %s %d %d 0\n", spec.MatchID, CSYardID, spec.TickRate, 32)
			for _, p := range spec.Players {
				flags := 0
				if p.Bot {
					flags |= 1
				}
				if p.Local {
					flags |= 4
				}
				put("P %d %d %d %s\n", p.Slot, flags, p.Team, csName(p))
			}
		}
		if f.Tick%16 == 0 {
			for _, p := range spec.Players {
				put("C %d %d %d\n", p.Slot, msec/10, msec)
			}
		}
		for _, p := range f.Players {
			// The engine's pitch is positive looking down.
			put("T %d %d %d %d %d %d %d %d %d 1\n", p.Slot, int(math.Round(p.Yaw*100)), int(math.Round(-p.Pitch*100)),
				units(p.Pos.X), units(p.Pos.Y), units(p.Pos.Z), units(p.Vel.X), units(p.Vel.Y), units(p.Vel.Z))
		}
		for _, v := range f.Sight {
			put("V %d %d %d\n", v[0], v[1], v[2])
		}
		for _, sh := range f.Shots {
			target, group := -1, 0
			if sh.Hit {
				target, group = int(sh.TargetSlot), 2
				if sh.Headshot {
					group = 1
				}
			}
			put("S %d %s %d %d %d %d\n", sh.Slot, sh.Weapon, target, group, b01(sh.Kill), units(float64(sh.DistanceM)))
		}
		if f.Tick == last {
			used = 0
			put("E\n")
		}
	})
	return bw.Flush()
}

func csName(p PlayerSpec) string {
	name := fmt.Sprintf("%s-%d", p.Role, p.Slot)
	if p.Bot {
		return "[BOT] " + name
	}
	return strings.ToUpper(name[:1]) + name[1:]
}
