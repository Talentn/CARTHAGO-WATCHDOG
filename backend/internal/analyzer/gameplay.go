package analyzer

import (
	"fmt"
	"math"
	"sort"

	pb "sentinel/backend/gen/sentinel/v1"
)

// Match accumulates one match's gameplay telemetry across batches and evaluates the
// behavioural rules over it. Aim samples are folded in incrementally (only counters and the
// last sample are kept), so memory per player is bounded no matter how long the match runs.
type Match struct {
	cfg      Config
	TickRate uint32
	Players  map[uint32]*Player
	// open exposures: observer<<32|target -> tick the target became visible
	visible map[uint64]uint32
}

// Player is the per-slot accumulator.
type Player struct {
	Slot       uint32
	SessionID  string
	PlayerHash string
	MMR        int32

	lastTick           uint32
	lastYaw, lastPitch float64
	haveLast           bool
	pendingSnap        bool
	AimSamples         int
	SnapLocks          int

	Hits, Headshots int
	TTDms           []float64

	CmdTicks, Cmds uint64

	triggerUs []uint64
}

const maxTriggerSamples = 512

func NewMatch(c Config) *Match {
	return &Match{cfg: c, Players: map[uint32]*Player{}, visible: map[uint64]uint32{}}
}

func (m *Match) player(slot uint32) *Player {
	p := m.Players[slot]
	if p == nil {
		p = &Player{Slot: slot}
		m.Players[slot] = p
	}
	return p
}

// Add folds one batch into the match. Batches must arrive in batch_seq order (the pipeline
// rejects duplicates before calling Add).
func (m *Match) Add(b *pb.GameplayBatch) {
	if b.TickRate != 0 {
		m.TickRate = b.TickRate
	}
	for _, mp := range b.Players {
		p := m.player(mp.Slot)
		p.SessionID, p.PlayerHash, p.MMR = mp.SessionId, mp.PlayerHash, mp.Mmr
	}
	for _, t := range b.Aim {
		m.player(t.Slot).addAim(t, m.cfg.SnapDeg, m.cfg.SnapSettleDeg)
	}
	m.addCombat(b.Shots, b.Visibility)
	for _, c := range b.Commands {
		if c.TickTo > c.TickFrom {
			p := m.player(c.Slot)
			p.CmdTicks += uint64(c.TickTo - c.TickFrom)
			p.Cmds += uint64(c.Commands)
		}
	}
	for _, t := range b.Triggers {
		p := m.player(t.Slot)
		p.triggerUs = append(p.triggerUs, t.ClientTimeUs...)
		if n := len(p.triggerUs); n > maxTriggerSamples {
			p.triggerUs = append(p.triggerUs[:0], p.triggerUs[n-maxTriggerSamples:]...)
		}
	}
}

// angleStep is the angular distance between two view angles in degrees, with yaw wrapped so a
// turn across 0/360 is not mistaken for a full-circle snap.
func angleStep(y0, p0, y1, p1 float64) float64 {
	dy := math.Mod(y1-y0+540, 360) - 180
	dp := p1 - p0
	return math.Hypot(dy, dp)
}

// addAim folds samples in as they arrive (snap thresholds are applied here, not at Evaluate),
// keeping only the last sample so a long match costs constant memory.
func (p *Player) addAim(t *pb.AimTrack, snapDeg, snapSettle float64) {
	n := min(len(t.Yaw), len(t.Pitch))
	for i := range n {
		tick := t.FirstTick + uint32(i)
		y, pt := float64(t.Yaw[i]), float64(t.Pitch[i])
		p.AimSamples++
		if p.haveLast && tick == p.lastTick+1 {
			step := angleStep(p.lastYaw, p.lastPitch, y, pt)
			if p.pendingSnap && step < snapSettle {
				p.SnapLocks++
			}
			p.pendingSnap = step > snapDeg
		} else {
			p.pendingSnap = false
		}
		p.lastTick, p.lastYaw, p.lastPitch, p.haveLast = tick, y, pt, true
	}
}

// consumed marks an exposure whose reaction sample was already taken.
const consumed = math.MaxUint32

type combatEvent struct {
	tick uint32
	vis  *pb.VisibilityEvent
	shot *pb.ShotEvent
}

func (m *Match) addCombat(shots []*pb.ShotEvent, vis []*pb.VisibilityEvent) {
	evs := make([]combatEvent, 0, len(shots)+len(vis))
	for _, v := range vis {
		evs = append(evs, combatEvent{tick: v.Tick, vis: v})
	}
	for _, s := range shots {
		evs = append(evs, combatEvent{tick: s.Tick, shot: s})
	}
	// Visibility before shots on the same tick: a target that appears and is hit on one tick
	// is a 0 ms reaction, which is exactly what the TTD rule should see.
	sort.SliceStable(evs, func(i, j int) bool {
		if evs[i].tick != evs[j].tick {
			return evs[i].tick < evs[j].tick
		}
		return evs[i].vis != nil && evs[j].vis == nil
	})
	rate := float64(m.TickRate)
	if rate == 0 {
		rate = 64
	}
	for _, e := range evs {
		if v := e.vis; v != nil {
			key := uint64(v.ObserverSlot)<<32 | uint64(v.TargetSlot)
			if v.Visible {
				if _, open := m.visible[key]; !open {
					m.visible[key] = v.Tick
				}
			} else {
				delete(m.visible, key)
			}
			continue
		}
		s := e.shot
		if !s.Hit {
			continue
		}
		p := m.player(s.Slot)
		p.Hits++
		if s.Headshot {
			p.Headshots++
		}
		if s.TargetSlot >= 0 {
			key := uint64(s.Slot)<<32 | uint64(uint32(s.TargetSlot))
			if since, open := m.visible[key]; open && since != consumed {
				p.TTDms = append(p.TTDms, float64(s.Tick-since)*1000/rate)
				// One reaction sample per exposure: follow-up hits are tracking, not reaction.
				m.visible[key] = consumed
			}
		}
	}
}

// expectedHeadshotRate is the baseline headshot fraction of hits for a skill rating. Higher
// MMR players legitimately land more headshots, so the test is against their peers, not the
// population. 0 means unknown and uses the overall average.
func expectedHeadshotRate(mmr int32) float64 {
	if mmr <= 0 {
		return 0.25
	}
	r := 0.18 + 0.12*float64(mmr-1500)/1000
	return math.Max(0.08, math.Min(0.45, r))
}

// score maps how far a statistic is past its threshold onto 0.5..0.99.
func score(over, threshold float64) float64 {
	if threshold <= 0 {
		return 0.5
	}
	return math.Max(0.5, math.Min(0.99, 0.5+(over-threshold)/(2*threshold)))
}

// Evaluate runs every behavioural rule and returns evidence by slot. It is idempotent over the
// accumulated state; the pipeline dedupes on (match, slot, rule).
func (m *Match) Evaluate() map[uint32][]Evidence {
	c := m.cfg
	out := map[uint32][]Evidence{}
	add := func(slot uint32, e Evidence) { out[slot] = append(out[slot], e) }

	// Population of reaction times for the TTD rule, per slot so each player is compared to
	// everyone else.
	var all []float64
	for _, p := range m.Players {
		all = append(all, p.TTDms...)
	}

	for slot, p := range m.Players {
		if p.SnapLocks >= c.SnapMin {
			add(slot, Evidence{Rule: "angle_snap", Severity: SeverityHigh, Score: score(float64(p.SnapLocks), float64(c.SnapMin)),
				Summary: fmt.Sprintf("%d snap-and-lock aim movements (>%.0f° in one tick, then <%.1f°)", p.SnapLocks, c.SnapDeg, c.SnapSettleDeg)})
		}
		if p.Hits >= c.HeadshotMinShots {
			exp := expectedHeadshotRate(p.MMR)
			if z := binomialZ(p.Headshots, p.Hits, exp); z > c.HeadshotZ {
				add(slot, Evidence{Rule: "headshot_rate", Severity: SeverityMedium, Score: score(z, c.HeadshotZ),
					Summary: fmt.Sprintf("headshot rate %.0f%% over %d hits vs %.0f%% expected at MMR %d (z=%.1f)",
						100*float64(p.Headshots)/float64(p.Hits), p.Hits, 100*exp, p.MMR, z)})
			}
		}
		if len(p.TTDms) >= 5 && len(all)-len(p.TTDms) >= c.TTDMinSamples {
			others := othersTTD(m, slot)
			med := median(p.TTDms)
			if z := robustZ(med, others); z < -c.TTDZ && med < 180 {
				add(slot, Evidence{Rule: "time_to_damage", Severity: SeverityMedium, Score: score(-z, c.TTDZ),
					Summary: fmt.Sprintf("median reaction %.0f ms vs %.0f ms for the lobby (robust z=%.1f, %d samples)", med, median(others), z, len(p.TTDms))})
			}
		}
		if p.CmdTicks >= uint64(c.CmdMinTicks) {
			if r := float64(p.Cmds) / float64(p.CmdTicks); r > c.CmdRatio {
				add(slot, Evidence{Rule: "command_rate", Severity: SeverityHigh, Score: score(r-1, c.CmdRatio-1),
					Summary: fmt.Sprintf("%.3f commands per tick over %d ticks (speedhack threshold %.2f)", r, p.CmdTicks, c.CmdRatio)})
			}
		}
		if cv, n, ok := triggerCV(p.triggerUs); ok && n >= c.TriggerMinPresses && cv < c.TriggerMaxCV {
			add(slot, Evidence{Rule: "macro_interval", Severity: SeverityMedium, Score: score(c.TriggerMaxCV, cv+1e-9) * 0.9,
				Summary: fmt.Sprintf("trigger presses %d with interval CV %.4f (scripted below %.2f)", n, cv, c.TriggerMaxCV)})
		}
	}
	return out
}

func othersTTD(m *Match, slot uint32) []float64 {
	var o []float64
	for s, p := range m.Players {
		if s != slot {
			o = append(o, p.TTDms...)
		}
	}
	return o
}

// triggerCV is the coefficient of variation of inter-press intervals, over intervals shorter
// than a second (presses separated by longer gaps are distinct engagements, not a burst).
func triggerCV(us []uint64) (cv float64, presses int, ok bool) {
	var iv []float64
	for i := 1; i < len(us); i++ {
		if us[i] > us[i-1] {
			if d := float64(us[i] - us[i-1]); d < 1e6 {
				iv = append(iv, d)
			}
		}
	}
	if len(iv) < 2 {
		return 0, len(iv) + 1, false
	}
	m := mean(iv)
	if m == 0 {
		return 0, len(iv) + 1, false
	}
	return stddev(iv) / m, len(iv) + 1, true
}
