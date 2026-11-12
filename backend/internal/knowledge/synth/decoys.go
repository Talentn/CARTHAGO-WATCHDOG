package synth

import (
	"math"

	"carthago/backend/internal/knowledge"
)

// The simulated game server's decoys follow the integration rules carthago-server's
// DecoyPlanner enforces. Every player gets its own decoys, a few at a time. A decoy is created
// unreplicated and walks the lanes like a player for a pre-roll; it is replicated to its
// recipient only once it stands where the recipient has no line of sight to it (in any
// direction, whatever they are looking at), farther than a footstep carries, away from
// real enemies and from anything the team was just told about. Replication stops the moment
// it would become visible, audible or come close to a real enemy, or when its lifetime
// ends; it then walks on, unreplicated, for a post-roll and is removed. The pre- and
// post-roll positions are reported but never sent to any client: they give the scorer the
// decoy's positions at the control offsets.
//
// Decoys use their own random stream and honest roles never look at them, so honest
// behaviour is the same with decoys on or off.

const (
	decoyMinDist     = 20.0 // metres from the recipient, beyond the 18 m footstep radius
	decoyPeekM       = 1.5  // hidden from this far either side of the recipient's eye too
	decoyMaxDist     = 40.0
	decoyEnemyClear  = 10.0 // from any real enemy when replication starts
	decoyKeepClear   = 7.0  // from any real enemy while replicated
	decoySpotClear   = 10.0 // from any spot shared with the team in the last decoySpotSec
	decoySpotSec     = 8.0
	decoyRollSec     = 12.5 // pre- and post-roll, longer than the largest control offset
	decoyWaitSec     = 30.0 // a pre-roll that finds no valid moment by then is dropped
	decoyMinLifetime = 15.0
	decoyMaxLifetime = 30.0
	decoysPerPlayer  = 12
)

type decoyPhase int

const (
	decoyPreRoll decoyPhase = iota
	decoyLive
	decoyPostRoll
)

type simDecoy struct {
	id      uint32
	team    uint32
	cloned  int32
	phase   decoyPhase
	created float64
	pos     knowledge.Vec3
	vel     knowledge.Vec3
	at      int
	path    []int
	hold    float64
	running bool
	until   float64 // end of the live phase, then of the post-roll
}

// Replicated reports whether the recipient's client is being sent the decoy right now.
func (d *simDecoy) Replicated() bool { return d != nil && d.phase == decoyLive }

// cmRound is a position as the telemetry carries it, so the simulated game server tests
// exactly what the gateway will see.
func cmRound(v knowledge.Vec3) knowledge.Vec3 {
	return knowledge.Vec3{X: math.Round(v.X*100) / 100, Y: math.Round(v.Y*100) / 100, Z: math.Round(v.Z*100) / 100}
}

// hiddenFromRecipient: far enough not to be heard and out of the recipient's line of sight,
// eye and chest, in any direction, even after a half-step peek; so a decoy never waits just
// behind the corner the recipient is holding.
func (s *sim) hiddenFromRecipient(p *simPlayer, pos knowledge.Vec3) bool {
	eye, pos := cmRound(p.pos), cmRound(pos)
	return eye.Dist(pos) >= decoyMinDist && s.m.HiddenWithMargin(eye, pos, 0.3, decoyPeekM)
}

// decoyOK is the replication rule. Only the recipient is sent the decoy, so only the
// recipient's sight and hearing matter: a teammate looking at the spot sees nothing there.
func (s *sim) decoyOK(p *simPlayer, pos knowledge.Vec3, enemyClear float64) bool {
	if !s.hiddenFromRecipient(p, pos) {
		return false
	}
	for _, m := range s.ps {
		if m.spec.Team != p.spec.Team && m.pos.Dist(pos) < enemyClear {
			return false
		}
	}
	return true
}

func (s *sim) canReplicate(p *simPlayer, pos knowledge.Vec3) bool {
	if pos.Dist(p.pos) > decoyMaxDist || !s.decoyOK(p, pos, decoyEnemyClear) {
		return false
	}
	for k, h := range s.spots {
		if k[0] == p.spec.Team && s.now-h.at < decoySpotSec && h.pos.Dist(pos) < decoySpotClear {
			return false
		}
	}
	return true
}

func (s *sim) stepDecoys() {
	for _, p := range s.ps {
		kept := p.decoys[:0]
		for _, d := range p.decoys {
			if s.stepDecoy(p, d) {
				kept = append(kept, d)
			}
		}
		p.decoys = kept
		if len(p.decoys) < decoysPerPlayer {
			if p.decoyIn -= s.dt; p.decoyIn <= 0 {
				d := s.createDecoy(p)
				p.decoys = append(p.decoys, d)
				p.decoyIn = s.dr.between(1, 4)
				s.frame.Decoys = append(s.frame.Decoys, s.decoyFrame(p, d, DecoyFrame{Created: true}))
			}
		}
	}
}

// stepDecoy moves one decoy through its phases and reports whether it still exists.
func (s *sim) stepDecoy(p *simPlayer, d *simDecoy) bool {
	s.moveDecoy(d)
	f := DecoyFrame{}
	switch d.phase {
	case decoyPreRoll:
		if s.now-d.created >= decoyRollSec && s.canReplicate(p, d.pos) {
			d.phase, d.until, f.Replicated = decoyLive, s.now+s.dr.between(decoyMinLifetime, decoyMaxLifetime), true
		} else if s.now-d.created > decoyWaitSec {
			s.frame.Decoys = append(s.frame.Decoys, s.decoyFrame(p, d, DecoyFrame{Ended: true}))
			return false
		}
	case decoyLive:
		if s.now >= d.until || !s.decoyOK(p, d.pos, decoyKeepClear) {
			d.phase, d.until, f.Unreplicated = decoyPostRoll, s.now+decoyRollSec, true
		}
	case decoyPostRoll:
		if s.now >= d.until {
			s.frame.Decoys = append(s.frame.Decoys, s.decoyFrame(p, d, DecoyFrame{Ended: true}))
			return false
		}
	}
	s.frame.Decoys = append(s.frame.Decoys, s.decoyFrame(p, d, f))
	return true
}

func (s *sim) decoyFrame(p *simPlayer, d *simDecoy, f DecoyFrame) DecoyFrame {
	f.ID, f.Team, f.Recipients, f.Cloned, f.Pos, f.Vel = d.id, d.team, []uint32{p.spec.Slot}, d.cloned, d.pos, d.vel
	return f
}

// createDecoy starts an unreplicated decoy on a lane node out of the recipient's sight; it
// imitates a random real enemy's speeds and pauses.
func (s *sim) createDecoy(p *simPlayer) *simDecoy {
	var cands []int
	for _, n := range laneNodes {
		pos := v3(nodes[n], EyeHeight)
		if d := pos.Dist(p.pos); d >= decoyMinDist && d <= decoyMaxDist+15 && !s.m.LineOfSight(p.pos, pos) {
			cands = append(cands, n)
		}
	}
	if len(cands) == 0 {
		cands = laneNodes
	}
	enemies := s.enemies(p)
	src := enemies[s.dr.intn(len(enemies))]
	at := cands[s.dr.intn(len(cands))]
	s.nextID++
	return &simDecoy{id: s.nextID, team: src.spec.Team, cloned: int32(src.spec.Slot), created: s.now, pos: v3(nodes[at], EyeHeight), at: at,
		hold: s.dr.between(0, 1.5)}
}

// moveDecoy walks the lanes with a player's speeds and pauses, the way the game's own bot
// navigation would. Its route never depends on its recipient: replication alone keeps it
// out of their sight. A decoy that steered by its recipient would be placed by what the
// recipient is doing, and its positions at other times would stop being a fair control.
func (s *sim) moveDecoy(d *simDecoy) {
	if d.hold > 0 {
		d.hold -= s.dt
		d.vel = knowledge.Vec3{}
		return
	}
	if len(d.path) == 0 {
		goal := laneNodes[s.dr.intn(len(laneNodes))]
		for goal == d.at {
			goal = laneNodes[s.dr.intn(len(laneNodes))]
		}
		d.path = route(d.at, goal)
		d.running = s.dr.unit() < 0.5
	}
	speed := 2.2
	if d.running {
		speed = 5
	}
	tgt := v3(nodes[d.path[0]], EyeHeight)
	delta := tgt.Sub(d.pos)
	l := delta.Len()
	next, vel := tgt, delta.Scale(1/s.dt)
	if l > speed*s.dt {
		vel = delta.Scale(speed / math.Max(l, 1e-9))
		next = d.pos.Add(vel.Scale(s.dt))
	}
	d.pos, d.vel = next, vel
	if next == tgt {
		d.at, d.path = d.path[0], d.path[1:]
		if len(d.path) == 0 || s.dr.unit() < 0.15 {
			d.hold = s.dr.between(1, 5)
		}
	}
}
