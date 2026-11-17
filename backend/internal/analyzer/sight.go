package analyzer

import (
	"math"
	"sort"

	pb "carthago/backend/gen/carthago/v1"
)

// Sight is what a player's aim had to do with opponents the player could not see.
//
// The game server already says who can see whom (VisibilityEvent: its own trace between
// two players went clear or blocked) and, with telemetry v2, where everybody is
// (MotionTrack). Together with the aim tracks that is enough to ask two things, without
// the map and without any geometry of the gateway's own:
//
//   - Hidden aim. While an opponent is close and not visible, does the crosshair stay on
//     that opponent? A wallhack shows where the opponent is, and the hand follows.
//   - Pre-aim. At the moment an opponent comes into view, was the crosshair already on
//     the spot?
//
// A player has honest ways to know where a hidden opponent is, and those moments are left
// out: the player saw the opponent a moment ago, a teammate sees the opponent or did a
// moment ago (and says so, by voice or by the game's own marker), or the opponent made a
// sound the game says the player could hear (SoundEvent, optional). What is left is aim on
// opponents the player had no word of. An honest player still gets some of it by holding
// the angles opponents come from, so these are numbers for the Oracle to compare with the
// studio's other players. No rule is built on them and they are no evidence.
//
// A game server that reports no visibility or no positions gives no samples, and
// everything else is as before. One that reports no sounds gives samples in which a
// player who follows footsteps looks like one who sees through walls.

const (
	// sightPerSecond is how often a second the aim is compared with the hidden opponents.
	sightPerSecond = 8
	// sightRangeM bounds the opponents looked at: further away an opponent is a few pixels
	// and the crosshair passes over it by chance.
	sightRangeM = 40
	// sightAlignDeg is how close to an opponent the crosshair counts as on it.
	sightAlignDeg = 4
	// sightKnownSec is how long a player still knows where an opponent is after seeing
	// or hearing it or being told.
	sightKnownSec = 2
)

type sightPair struct {
	visible bool
	// seen: the tick the opponent went out of this player's view; known: the latest tick
	// at which the player heard the opponent or was told where it is.
	seen, known         uint32
	haveSeen, haveKnown bool

	// The latest sample in which the opponent was hidden and the player had no word of it.
	have    bool
	tick    uint32
	aligned bool
}

type sightState struct {
	team  map[uint32]uint32
	pairs map[uint64]*sightPair
	at    map[uint32]sightPos // where each player was at the latest sample
}

type sightPos struct{ x, y, z float64 }

func (a sightPos) dist(b sightPos) float64 {
	return math.Sqrt((a.x-b.x)*(a.x-b.x) + (a.y-b.y)*(a.y-b.y) + (a.z-b.z)*(a.z-b.z))
}

// sightEvent is something that tells a player where an opponent is, in tick order.
type sightEvent struct {
	tick uint32
	vis  *pb.VisibilityEvent
	snd  *pb.SoundEvent
	info *pb.TeamInfo
}

// addSight folds a batch's positions, aim, visibility and sounds into the sight counters.
func (m *Match) addSight(b *pb.GameplayBatch) {
	if m.sight == nil {
		if len(b.Visibility) == 0 {
			return // nothing to tell hidden from seen yet
		}
		m.sight = &sightState{team: map[uint32]uint32{}, pairs: map[uint64]*sightPair{}, at: map[uint32]sightPos{}}
	}
	st := m.sight
	for _, p := range b.Players {
		if p.Slot < MaxSlots {
			st.team[p.Slot] = p.Team
		}
	}
	rate := m.rate()
	gap := uint32(math.Max(1, math.Round(rate/sightPerSecond)))
	knownFor := uint32(sightKnownSec * rate)

	// Positions and aim at the ticks compared in this batch.
	pos := map[uint32]map[uint32]sightPos{}
	for _, t := range b.Motion {
		if t.Slot >= MaxSlots {
			continue
		}
		stride := max(t.Stride, 1)
		var x, y, z int64
		for i := range min(len(t.XCm), len(t.YCm), len(t.ZCm)) {
			x, y, z = x+int64(t.XCm[i]), y+int64(t.YCm[i]), z+int64(t.ZCm[i])
			tick := t.FirstTick + uint32(i)*stride
			if tick%gap != 0 {
				continue
			}
			if pos[tick] == nil {
				pos[tick] = map[uint32]sightPos{}
			}
			pos[tick][t.Slot] = sightPos{float64(x) / 100, float64(y) / 100, float64(z) / 100}
		}
	}
	aim := map[uint32]map[uint32][2]float64{}
	for _, t := range b.Aim {
		if t.Slot >= MaxSlots {
			continue
		}
		for i := range min(len(t.Yaw), len(t.Pitch)) {
			if tick := t.FirstTick + uint32(i); pos[tick] != nil {
				if aim[tick] == nil {
					aim[tick] = map[uint32][2]float64{}
				}
				aim[tick][t.Slot] = [2]float64{float64(t.Yaw[i]), float64(t.Pitch[i])}
			}
		}
	}
	order := make([]uint32, 0, len(pos))
	for t := range pos {
		order = append(order, t)
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })

	evs := make([]sightEvent, 0, len(b.Visibility)+len(b.Sounds)+len(b.TeamInfo))
	for _, v := range b.Visibility {
		if v.ObserverSlot < MaxSlots && v.TargetSlot < MaxSlots {
			evs = append(evs, sightEvent{tick: v.Tick, vis: v})
		}
	}
	for _, s := range b.Sounds {
		if s.SourceSlot >= 0 && s.SourceSlot < MaxSlots {
			evs = append(evs, sightEvent{tick: s.Tick, snd: s})
		}
	}
	for _, t := range b.TeamInfo {
		if t.TargetSlot >= 0 && t.TargetSlot < MaxSlots {
			evs = append(evs, sightEvent{tick: t.Tick, info: t})
		}
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].tick < evs[j].tick })

	pair := func(o, t uint32) *sightPair {
		k := uint64(o)<<32 | uint64(t)
		p := st.pairs[k]
		if p == nil {
			p = &sightPair{}
			st.pairs[k] = p
		}
		return p
	}
	opponents := func(a, b uint32) bool { return a != b && (st.team[a] == 0 || st.team[a] != st.team[b]) }
	told := func(p *sightPair, tick uint32) {
		if !p.haveKnown || tick > p.known {
			p.known, p.haveKnown = tick, true
		}
	}
	next := 0
	events := func(upTo uint32) {
		for ; next < len(evs) && evs[next].tick <= upTo; next++ {
			switch e := evs[next]; {
			case e.vis != nil:
				v := e.vis
				p := pair(v.ObserverSlot, v.TargetSlot)
				if v.Visible && !p.visible && p.have && v.Tick >= p.tick && v.Tick-p.tick <= 2*gap {
					if pl := m.player(v.ObserverSlot); pl != nil {
						pl.Appearances++
						if p.aligned {
							pl.PreAimed++
						}
					}
				}
				if !v.Visible {
					p.seen, p.haveSeen = v.Tick, true
				}
				p.visible, p.have = v.Visible, false
			case e.snd != nil:
				// Everybody within the sound's radius heard where its maker is.
				src := uint32(e.snd.SourceSlot)
				at := sightPos{float64(e.snd.XCm) / 100, float64(e.snd.YCm) / 100, float64(e.snd.ZCm) / 100}
				for o, op := range st.at {
					if opponents(o, src) && op.dist(at) <= float64(e.snd.RadiusCm)/100 {
						told(pair(o, src), e.tick)
					}
				}
			default:
				// The game marked an opponent for a team, for as long as the marker shows.
				until := e.tick + uint32(float64(e.info.DurationMs)*rate/1000)
				for o, team := range st.team {
					if team != 0 && team == e.info.Team {
						told(pair(o, uint32(e.info.TargetSlot)), until)
					}
				}
			}
		}
	}
	// teamSaw is the latest tick at which anybody on a team saw a player: what a team
	// tells each other.
	type teamTarget struct{ team, target uint32 }
	for _, tick := range order {
		events(tick)
		at := pos[tick]
		for slot, p := range at {
			st.at[slot] = p
		}
		teamSaw := map[teamTarget]uint32{}
		for k, p := range st.pairs {
			o, t := uint32(k>>32), uint32(k)
			if team := st.team[o]; team != 0 && (p.visible || p.haveSeen) {
				when := p.seen
				if p.visible {
					when = tick
				}
				if key := (teamTarget{team, t}); when >= teamSaw[key] {
					teamSaw[key] = when + 1 // +1: zero means never
				}
			}
		}
		for o, op := range at {
			view, ok := aim[tick][o]
			if !ok {
				continue
			}
			yaw, pitch := view[0]*math.Pi/180, view[1]*math.Pi/180
			dx, dy, dz := math.Cos(pitch)*math.Cos(yaw), math.Cos(pitch)*math.Sin(yaw), math.Sin(pitch)
			hidden, tracked := false, false
			for t, tp := range at {
				if !opponents(o, t) {
					continue
				}
				p := pair(o, t)
				dist := op.dist(tp)
				recent := func(have bool, when uint32) bool { return have && (when >= tick || tick-when <= knownFor) }
				saw := teamSaw[teamTarget{st.team[o], t}]
				if p.visible || dist > sightRangeM || dist < 1e-6 ||
					recent(p.haveSeen, p.seen) || recent(p.haveKnown, p.known) || recent(saw > 0, saw-1) {
					p.have = false
					continue
				}
				aligned := math.Acos(math.Max(-1, math.Min(1, (dx*(tp.x-op.x)+dy*(tp.y-op.y)+dz*(tp.z-op.z))/dist)))*180/math.Pi <= sightAlignDeg
				// Tracking is the crosshair on the opponent in two samples running; one
				// alone is a crosshair passing by.
				if aligned && p.have && p.aligned && tick-p.tick <= 2*gap {
					tracked = true
				}
				p.have, p.tick, p.aligned = true, tick, aligned
				hidden = true
			}
			if pl := m.player(o); pl != nil && hidden {
				pl.HiddenSamples++
				if tracked {
					pl.HiddenTracked++
				}
			}
		}
	}
	events(math.MaxUint32)
}
