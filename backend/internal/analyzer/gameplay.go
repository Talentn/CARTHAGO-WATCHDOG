package analyzer

import (
	"errors"
	"fmt"
	"math"
	"sort"

	pb "carthago/backend/gen/carthago/v1"
)

// Match accumulates one match's gameplay telemetry across batches and evaluates the
// behavioural rules over it. Aim samples are folded in incrementally (only counters and the
// last sample are kept), reaction and trigger samples are capped, and slots are limited to
// MaxSlots, so memory per match is bounded no matter how long it runs or what a game server
// sends.
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
	lastShot        uint32 // tick of the player's latest shot, hit or miss
	haveShot        bool

	CmdTicks, Cmds uint64
	cmdTo          uint32 // end of the latest command window
	haveCmd        bool

	triggerUs []uint64
}

const (
	maxTriggerSamples = 512
	maxTTDSamples     = 2048
	// MaxSlots bounds the slot numbers a match may use.
	MaxSlots = 256
	// refTickRate is the tick rate the per-tick thresholds are written for.
	refTickRate = 64
)

// CheckBatch rejects a batch the analyzer cannot hold in bounded memory or that would be
// stored and shown as is: slot numbers, identifier lengths and track shapes.
func CheckBatch(b *pb.GameplayBatch) error {
	if b.TickRate > 1000 {
		return errors.New("tick_rate above 1000")
	}
	slot := func(s uint32) bool { return s < MaxSlots }
	for _, p := range b.Players {
		if !slot(p.Slot) {
			return fmt.Errorf("player slot %d: slots are 0-%d", p.Slot, MaxSlots-1)
		}
		if len(p.SessionId) > 128 || !printable(p.PlayerHash, 128) {
			return fmt.Errorf("player slot %d: session_id and player_hash are at most 128 printable ASCII bytes", p.Slot)
		}
	}
	for _, t := range b.Aim {
		if !slot(t.Slot) || len(t.Yaw) != len(t.Pitch) {
			return fmt.Errorf("aim track for slot %d: bad slot, or yaw and pitch differ in length", t.Slot)
		}
	}
	for _, s := range b.Shots {
		if !slot(s.Slot) || s.TargetSlot < -1 || s.TargetSlot >= MaxSlots {
			return fmt.Errorf("shot by slot %d at target %d: slots are 0-%d", s.Slot, s.TargetSlot, MaxSlots-1)
		}
	}
	for _, v := range b.Visibility {
		if !slot(v.ObserverSlot) || !slot(v.TargetSlot) {
			return fmt.Errorf("visibility %d->%d: slots are 0-%d", v.ObserverSlot, v.TargetSlot, MaxSlots-1)
		}
	}
	for _, c := range b.Commands {
		if !slot(c.Slot) || c.TickTo < c.TickFrom {
			return fmt.Errorf("command window for slot %d: bad slot, or it ends before it starts", c.Slot)
		}
	}
	for _, t := range b.Triggers {
		if !slot(t.Slot) {
			return fmt.Errorf("trigger presses for slot %d: slots are 0-%d", t.Slot, MaxSlots-1)
		}
	}
	return nil
}

func printable(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

func NewMatch(c Config) *Match {
	return &Match{cfg: c, Players: map[uint32]*Player{}, visible: map[uint64]uint32{}}
}

// player returns the accumulator for a slot, or nil for a slot outside 0..MaxSlots-1.
func (m *Match) player(slot uint32) *Player {
	p := m.Players[slot]
	if p == nil {
		if slot >= MaxSlots {
			return nil
		}
		p = &Player{Slot: slot}
		m.Players[slot] = p
	}
	return p
}

func (m *Match) rate() float64 {
	if m.TickRate == 0 {
		return refTickRate
	}
	return float64(m.TickRate)
}

// Add folds one batch into the match. Batches must arrive in batch_seq order (the pipeline
// rejects duplicates before calling Add). Records naming a slot outside 0..MaxSlots-1 are
// ignored; CheckBatch reports them to the sender.
func (m *Match) Add(b *pb.GameplayBatch) {
	if b.TickRate != 0 {
		m.TickRate = b.TickRate
	}
	for _, mp := range b.Players {
		if p := m.player(mp.Slot); p != nil {
			p.SessionID, p.PlayerHash, p.MMR = mp.SessionId, mp.PlayerHash, mp.Mmr
		}
	}
	// The snap threshold is an angular speed: at a lower tick rate the same hand movement
	// covers more degrees per tick, so the per-tick step is scaled up. It is never scaled
	// down, which keeps the rule at least as strict as written for faster servers.
	snapDeg := m.cfg.SnapDeg * math.Max(1, refTickRate/m.rate())
	for _, t := range b.Aim {
		if p := m.player(t.Slot); p != nil {
			p.addAim(t, snapDeg, m.cfg.SnapSettleDeg)
		}
	}
	m.addCombat(b.Shots, b.Visibility)
	// A stalled client sends nothing and then catches up; the SDK reports no window for the
	// silent stretch. Those ticks still passed, so a short gap between two windows counts as
	// ticks without commands. A long gap is an absence, not a stall.
	maxGap := uint32(4 * m.rate())
	for _, c := range b.Commands {
		p := m.player(c.Slot)
		if p == nil || c.TickTo <= c.TickFrom {
			continue
		}
		if p.haveCmd && c.TickFrom < p.cmdTo {
			continue // overlaps a window already counted
		}
		if p.haveCmd && c.TickFrom-p.cmdTo <= maxGap {
			p.CmdTicks += uint64(c.TickFrom - p.cmdTo)
		}
		p.cmdTo, p.haveCmd = c.TickTo, true
		p.CmdTicks += uint64(c.TickTo - c.TickFrom)
		p.Cmds += uint64(c.Commands)
	}
	for _, t := range b.Triggers {
		p := m.player(t.Slot)
		if p == nil {
			continue
		}
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
	rate := m.rate()
	// A player already shooting when the target came into view is spraying or pre-firing a
	// known angle, not reacting: that exposure gives no reaction sample.
	prefire := uint32(rate / 2)
	for _, e := range evs {
		if v := e.vis; v != nil {
			if v.ObserverSlot >= MaxSlots || v.TargetSlot >= MaxSlots {
				continue
			}
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
		p := m.player(s.Slot)
		if p == nil {
			continue
		}
		before, hadShot := p.lastShot, p.haveShot
		if !p.haveShot || s.Tick > p.lastShot {
			p.lastShot, p.haveShot = s.Tick, true
		}
		if !s.Hit {
			continue
		}
		p.Hits++
		if s.Headshot {
			p.Headshots++
		}
		if s.TargetSlot >= 0 && s.TargetSlot < MaxSlots {
			key := uint64(s.Slot)<<32 | uint64(uint32(s.TargetSlot))
			// A shot stamped before the exposure began (events from different batches arriving
			// out of order) says nothing about the reaction and must not be subtracted.
			if since, open := m.visible[key]; open && since != consumed && s.Tick >= since {
				if !(hadShot && before <= since && since-before <= prefire) && len(p.TTDms) < maxTTDSamples {
					p.TTDms = append(p.TTDms, float64(s.Tick-since)*1000/rate)
				}
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

// headshotOutlier is the headshot test at one moment of a match: the chance of at least this
// many headshots among the hits at the baseline for the rating, and whether that is evidence.
//
// The chance is the exact binomial tail, not its normal approximation: at a low baseline and
// a few dozen hits the approximation understates the chance of a lucky streak several times
// over. The margin keeps a large sample from flagging a small real difference between a
// player and the baseline for their rating.
func (c Config) headshotOutlier(headshots, hits int, mmr int32) (tail float64, ok bool) {
	if hits < c.HeadshotMinShots {
		return 1, false
	}
	exp := expectedHeadshotRate(mmr)
	if float64(headshots)/float64(hits)-exp < c.HeadshotMinExcess {
		return 1, false
	}
	tail = binomialTail(headshots, hits, exp)
	return tail, tail < normalTail(c.HeadshotZ)
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

	for slot, p := range m.Players {
		if p.SnapLocks >= c.SnapMin {
			add(slot, Evidence{Rule: "angle_snap", Severity: SeverityHigh, Score: score(float64(p.SnapLocks), float64(c.SnapMin)),
				Summary: fmt.Sprintf("%d snap-and-lock aim movements (>%.0f° in one tick, then <%.1f°)", p.SnapLocks, c.SnapDeg, c.SnapSettleDeg)})
		}
		if tail, ok := c.headshotOutlier(p.Headshots, p.Hits, p.MMR); ok {
			exp, rate := expectedHeadshotRate(p.MMR), float64(p.Headshots)/float64(p.Hits)
			z := binomialZ(p.Headshots, p.Hits, exp)
			add(slot, Evidence{Rule: "headshot_rate", Severity: SeverityMedium, Score: score(z, c.HeadshotZ),
				Summary: fmt.Sprintf("headshot rate %.0f%% over %d hits vs %.0f%% expected at MMR %d (chance %.1e)",
					100*rate, p.Hits, 100*exp, p.MMR, tail)})
		}
		if others, players := othersTTD(m, slot); len(p.TTDms) >= c.TTDMinOwn && len(others) >= c.TTDMinSamples && players >= c.TTDMinPlayers {
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
		if cv, n, ok := triggerCV(p.triggerUs, c.TriggerMaxCV); ok && n >= c.TriggerMinPresses && cv < c.TriggerMaxCV {
			add(slot, Evidence{Rule: "macro_interval", Severity: SeverityMedium, Score: score(c.TriggerMaxCV, cv+1e-9) * 0.9,
				Summary: fmt.Sprintf("trigger presses %d with interval CV %.4f (scripted below %.2f)", n, cv, c.TriggerMaxCV)})
		}
	}
	return out
}

// othersTTD is every other player's reaction samples and how many players they come from.
func othersTTD(m *Match, slot uint32) (samples []float64, players int) {
	for s, p := range m.Players {
		if s != slot && len(p.TTDms) > 0 {
			samples = append(samples, p.TTDms...)
			players++
		}
	}
	return samples, players
}

// triggerCV is the coefficient of variation of inter-press intervals, over intervals shorter
// than a second (presses separated by longer gaps are distinct engagements, not a burst).
//
// ok is false when the timestamps cannot support the verdict: if every gap between presses is
// a multiple of one step (the game stamps presses with tick or frame times), a steady human
// rhythm lands on the same few values and looks as regular as a script. The step must be
// small against the spread the rule tests for.
func triggerCV(us []uint64, maxCV float64) (cv float64, presses int, ok bool) {
	var iv []float64
	var step uint64
	for i := 1; i < len(us); i++ {
		if us[i] > us[i-1] {
			d := us[i] - us[i-1]
			step = gcd(step, d)
			if d < 1e6 {
				iv = append(iv, float64(d))
			}
		}
	}
	if len(iv) < 2 {
		return 0, len(iv) + 1, false
	}
	m := mean(iv)
	if m == 0 || float64(step) > maxCV*m {
		return 0, len(iv) + 1, false
	}
	return stddev(iv) / m, len(iv) + 1, true
}

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
