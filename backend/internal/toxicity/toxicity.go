// Package toxicity reads behaviour that spoils a match for the other players from what a
// game server already reports: shots at teammates, standing idle, leaving before the end,
// and dying over and over without fighting back. It uses server events only: no chat, no
// voice, no text and no model.
//
// What it finds is advice for a studio's community team, kept apart from the anti-cheat
// evidence: it is not stored with it, adds nothing to a player's risk, and can neither
// kick, ban nor put anyone in the shadow pool. A studio sets its own limits; a limit of
// zero turns that kind off.
package toxicity

import (
	"encoding/json"
	"fmt"
	"sort"

	pb "carthago/backend/gen/carthago/v1"
)

// The kinds of finding.
const (
	KindTeamDamage = "team_damage"
	KindTeamKill   = "team_kill"
	KindAFK        = "afk"
	KindLeftEarly  = "left_early"
	KindFeeding    = "feeding"
)

// Kinds lists the kinds in the order they are shown.
var Kinds = []string{KindTeamDamage, KindTeamKill, KindAFK, KindLeftEarly, KindFeeding}

// Limits are a studio's thresholds. Zero turns a kind off.
type Limits struct {
	// TeamDamageHits is the number of hits on teammates in one match that makes a finding.
	TeamDamageHits int `json:"team_damage_hits"`
	// TeamKills is the number of teammates killed in one match that makes a finding.
	TeamKills int `json:"team_kills"`
	// AFKSeconds is how long a player in play neither moves nor turns before a finding.
	AFKSeconds int `json:"afk_seconds"`
	// LeftEarlyPercent: a player whose data stops with more than this share of the match
	// still to play has left early. A match shorter than MinMatchSeconds is not judged.
	LeftEarlyPercent int `json:"left_early_percent"`
	// FeedingDeaths is the number of deaths in one match from which feeding is considered:
	// the player must also have at most one kill per FeedingDeathsPerKill deaths and at
	// least twice the deaths of the lobby's median player.
	FeedingDeaths int `json:"feeding_deaths"`
}

// Fixed parts of the rules, the same for every studio.
const (
	MinMatchSeconds      = 120
	FeedingDeathsPerKill = 5
	afkMoveCm            = 100 // moving less than this from where the idle spell began is not moving
	afkTurnDeg           = 2.0
	gapSeconds           = 2 // no data for this long ends an idle spell: the player is not in play
)

// Defaults are the limits of a studio that has set none.
func Defaults() Limits {
	return Limits{TeamDamageHits: 6, TeamKills: 2, AFKSeconds: 90, LeftEarlyPercent: 25, FeedingDeaths: 10}
}

// Valid says whether the limits are ones a studio may set.
func (l Limits) Valid() error {
	for name, v := range map[string]int{"team damage hits": l.TeamDamageHits, "team kills": l.TeamKills, "AFK seconds": l.AFKSeconds, "feeding deaths": l.FeedingDeaths} {
		if v < 0 || v > 100_000 {
			return fmt.Errorf("%s: %d is not between 0 and 100000", name, v)
		}
	}
	if l.LeftEarlyPercent < 0 || l.LeftEarlyPercent > 99 {
		return fmt.Errorf("left early percent: %d is not between 0 and 99", l.LeftEarlyPercent)
	}
	return nil
}

// Parse reads limits as a studio stored them. Empty input gives the defaults.
func Parse(stored string) (Limits, error) {
	if stored == "" {
		return Defaults(), nil
	}
	l := Defaults()
	if err := json.Unmarshal([]byte(stored), &l); err != nil {
		return Defaults(), err
	}
	return l, l.Valid()
}

// Describe writes the limits out for a person.
func (l Limits) Describe() string {
	part := func(n int, text string) string {
		if n <= 0 {
			return "off"
		}
		return fmt.Sprintf(text, n)
	}
	return "team damage " + part(l.TeamDamageHits, "from %d hits") + ", team kills " + part(l.TeamKills, "from %d") +
		", idle " + part(l.AFKSeconds, "from %d s") + ", left early " + part(l.LeftEarlyPercent, "with more than %d%% to play") +
		", feeding " + part(l.FeedingDeaths, "from %d deaths")
}

// Encode is the stored form of the limits.
func (l Limits) Encode() string {
	b, _ := json.Marshal(l)
	return string(b)
}

// Finding is one kind of behaviour by one slot in one match.
type Finding struct {
	Slot    uint32
	Kind    string
	Count   int    // hits, kills, idle seconds, percent of the match missed, or deaths
	Tick    uint32 // the moment to look at
	Summary string
}

type slot struct {
	team      uint32
	seen      bool // sent a position or a view angle
	lastTick  uint32
	teamHits  int
	teamKills int
	kills     int
	deaths    int
	lastDeath uint32
	raised    map[string]bool

	// The idle spell: when it began, and where the player stood and looked then.
	idleFrom uint32
	x, y     int32
	havePos  bool
	yaw      float32
	haveYaw  bool
}

// maxSlots bounds the per-match state.
const maxSlots = 256

// Match follows one match. It is not safe for concurrent use.
type Match struct {
	lim      Limits
	tickRate uint32
	slots    map[uint32]*slot
	endTick  uint32
}

func NewMatch(l Limits) *Match { return &Match{lim: l, slots: map[uint32]*slot{}} }

func (m *Match) slot(id uint32) *slot {
	s := m.slots[id]
	if s == nil {
		if len(m.slots) >= maxSlots {
			return nil
		}
		s = &slot{raised: map[string]bool{}}
		m.slots[id] = s
	}
	return s
}

func (m *Match) clock(tick uint32) string {
	s := tick / m.tickRate
	return fmt.Sprintf("%02d:%02d", s/60, s%60)
}

func (m *Match) raise(out *[]Finding, id uint32, s *slot, kind string, count int, tick uint32, summary string) {
	if s.raised[kind] {
		return
	}
	s.raised[kind] = true
	*out = append(*out, Finding{Slot: id, Kind: kind, Count: count, Tick: tick, Summary: summary})
}

// span is what one batch says about one slot: the ticks it has data for, and the last tick
// at which the player moved or turned.
type span struct {
	first, last uint32
	active      uint32
	wasActive   bool
	any         bool
}

func (sp *span) add(tick uint32, active bool) {
	if !sp.any || tick < sp.first {
		sp.first = tick
	}
	if !sp.any || tick > sp.last {
		sp.last = tick
	}
	sp.any = true
	if active && (!sp.wasActive || tick > sp.active) {
		sp.active, sp.wasActive = tick, true
	}
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}

// Add takes one batch and returns the findings it completes. A kind is raised once per
// slot and match, at the moment its limit is reached.
func (m *Match) Add(b *pb.GameplayBatch) []Finding {
	if m.tickRate == 0 {
		if m.tickRate = b.TickRate; m.tickRate == 0 {
			m.tickRate = 64
		}
	}
	var out []Finding
	for _, p := range b.Players {
		if s := m.slot(p.Slot); s != nil {
			s.team = p.Team
		}
	}
	spans := map[uint32]*span{}
	note := func(id uint32, tick uint32, active bool) {
		sp := spans[id]
		if sp == nil {
			sp = &span{}
			spans[id] = sp
		}
		sp.add(tick, active)
	}
	for _, t := range b.Motion {
		s := m.slot(t.Slot)
		if s == nil {
			continue
		}
		stride := max(t.Stride, 1)
		var x, y int32
		for i := 0; i < len(t.XCm) && i < len(t.YCm); i++ {
			x, y = x+t.XCm[i], y+t.YCm[i]
			moved := !s.havePos || abs32(x-s.x) > afkMoveCm || abs32(y-s.y) > afkMoveCm
			if moved {
				s.x, s.y, s.havePos = x, y, true
			}
			note(t.Slot, t.FirstTick+uint32(i)*stride, moved)
		}
	}
	for _, a := range b.Aim {
		s := m.slot(a.Slot)
		if s == nil {
			continue
		}
		for i, yaw := range a.Yaw {
			d := yaw - s.yaw
			turned := !s.haveYaw || d > afkTurnDeg || d < -afkTurnDeg
			if turned {
				s.yaw, s.haveYaw = yaw, true
			}
			note(a.Slot, a.FirstTick+uint32(i), turned)
		}
	}
	ids := make([]uint32, 0, len(spans))
	for id := range spans {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		sp, s := spans[id], m.slots[id]
		// Data that stopped for a while (dead, not spawned) is not standing idle: the idle
		// spell starts again when the data does.
		if !s.seen || sp.first < s.lastTick || sp.first-s.lastTick > gapSeconds*m.tickRate {
			s.idleFrom = sp.first
		}
		if sp.wasActive {
			s.idleFrom = sp.active
		}
		s.seen = true
		s.lastTick = max(s.lastTick, sp.last)
		m.endTick = max(m.endTick, sp.last)
		if idle := int((s.lastTick - s.idleFrom) / m.tickRate); m.lim.AFKSeconds > 0 && s.lastTick > s.idleFrom && idle >= m.lim.AFKSeconds {
			m.raise(&out, id, s, KindAFK, idle, s.idleFrom, fmt.Sprintf("Stood still without moving or turning for %d s from %s, while in play (limit %d s)", idle, m.clock(s.idleFrom), m.lim.AFKSeconds))
		}
	}
	for _, e := range b.Shots {
		if e.Tick > m.endTick {
			m.endTick = e.Tick
		}
		s := m.slot(e.Slot)
		if s == nil || !e.Hit || e.TargetSlot < 0 || uint32(e.TargetSlot) == e.Slot {
			continue
		}
		target := m.slot(uint32(e.TargetSlot))
		if target == nil {
			continue
		}
		team := s.team != 0 && s.team == target.team
		if !team {
			// Being killed by a teammate is not counted against the one who died.
			if e.Kill {
				s.kills++
				target.deaths++
				target.lastDeath = e.Tick
			}
			continue
		}
		s.teamHits++
		if m.lim.TeamDamageHits > 0 && s.teamHits >= m.lim.TeamDamageHits {
			m.raise(&out, e.Slot, s, KindTeamDamage, s.teamHits, e.Tick, fmt.Sprintf("Hit teammates %d times in this match (limit %d)", s.teamHits, m.lim.TeamDamageHits))
		}
		if e.Kill {
			s.teamKills++
			if m.lim.TeamKills > 0 && s.teamKills >= m.lim.TeamKills {
				m.raise(&out, e.Slot, s, KindTeamKill, s.teamKills, e.Tick, fmt.Sprintf("Killed %d teammates in this match (limit %d)", s.teamKills, m.lim.TeamKills))
			}
		}
	}
	return out
}

// Finish judges what can only be told once the match is over: who left early and who fed.
func (m *Match) Finish() []Finding {
	var out []Finding
	if m.tickRate == 0 || m.endTick < MinMatchSeconds*m.tickRate {
		return nil
	}
	ids := make([]uint32, 0, len(m.slots))
	var deaths []int
	for id, s := range m.slots {
		ids = append(ids, id)
		if s.seen {
			deaths = append(deaths, s.deaths)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	sort.Ints(deaths)
	median := 0
	if len(deaths) > 0 {
		median = deaths[len(deaths)/2]
	}
	for _, id := range ids {
		s := m.slots[id]
		if !s.seen {
			continue
		}
		if missed := int(uint64(m.endTick-s.lastTick) * 100 / uint64(m.endTick)); m.lim.LeftEarlyPercent > 0 && missed > m.lim.LeftEarlyPercent {
			m.raise(&out, id, s, KindLeftEarly, missed, s.lastTick, fmt.Sprintf("Left at %s with %d%% of the match still to play (limit %d%%)", m.clock(s.lastTick), missed, m.lim.LeftEarlyPercent))
		}
		if m.lim.FeedingDeaths > 0 && s.deaths >= m.lim.FeedingDeaths && s.kills*FeedingDeathsPerKill <= s.deaths && s.deaths >= 2*median && len(deaths) >= 4 {
			m.raise(&out, id, s, KindFeeding, s.deaths, s.lastDeath, fmt.Sprintf("Died %d times with %d kills; the lobby's median player died %d times (limit %d deaths)", s.deaths, s.kills, median, m.lim.FeedingDeaths))
		}
	}
	return out
}

// TickRate is the match's tick rate, known after the first batch.
func (m *Match) TickRate() uint32 { return m.tickRate }
