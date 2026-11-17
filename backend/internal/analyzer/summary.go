package analyzer

import "sort"

// PlayerSummary is what a match has accumulated about one player, as numbers rather than
// verdicts: the statistics the behavioural rules test, before any threshold is applied.
// The Carthago Oracle behaviour model scores a session from these.
type PlayerSummary struct {
	TickRate   float64
	AimSamples int
	SnapLocks  int

	Hits      int
	Headshots int
	// HeadshotZ is the headshot count's distance from the baseline for the player's rating,
	// in binomial standard deviations. Zero without hits.
	HeadshotZ float64

	// Reactions is the number of reaction samples; the median is in milliseconds.
	Reactions        int
	ReactionMedianMs float64
	// LobbyOK reports whether the rest of the lobby gave enough samples to compare against
	// (the same test the time_to_damage rule applies). ReactionZ is the robust z of the
	// player's median against the lobby; negative is faster.
	LobbyOK   bool
	ReactionZ float64

	CmdTicks uint64
	Cmds     uint64

	// TriggerOK reports whether the press timestamps can support a regularity statement.
	TriggerOK      bool
	TriggerPresses int
	TriggerCV      float64

	// FireDelays is the number of times a shot followed the crosshair arriving on an enemy
	// (CrosshairEvent). FireTimed is the largest share of them that are both fast and alike:
	// under fireFastMs and within fireWindowMs of each other.
	FireDelays int
	FireTimed  float64

	// Sight (sight.go), as counts: the Oracle turns them into shares.
	HiddenSamples, HiddenTracked int
	Appearances, PreAimed        int
}

// A person cannot keep answering the sight of an enemy under the crosshair in less than a
// tenth of a second, and a person's delays spread over far more than two ticks at 64 Hz.
const (
	fireFastMs   = 100
	fireWindowMs = 32
)

// fireTimed is the largest share of the delays that lie under fireFastMs and inside one
// window of fireWindowMs.
func fireTimed(delays []float64) float64 {
	var fast []float64
	for _, d := range delays {
		if d < fireFastMs {
			fast = append(fast, d)
		}
	}
	sort.Float64s(fast)
	best := 0
	for i, j := 0, 0; j < len(fast); j++ {
		for fast[j]-fast[i] > fireWindowMs {
			i++
		}
		best = max(best, j-i+1)
	}
	if best == 0 {
		return 0
	}
	return float64(best) / float64(len(delays))
}

// Summary returns the accumulated statistics for a slot. ok is false for a slot the match
// has not seen.
func (m *Match) Summary(slot uint32) (s PlayerSummary, ok bool) {
	p := m.Players[slot]
	if p == nil {
		return s, false
	}
	c := m.cfg
	s = PlayerSummary{
		TickRate: m.rate(), AimSamples: p.AimSamples, SnapLocks: p.SnapLocks,
		Hits: p.Hits, Headshots: p.Headshots, Reactions: len(p.TTDms), CmdTicks: p.CmdTicks, Cmds: p.Cmds,
	}
	if p.Hits > 0 {
		s.HeadshotZ = binomialZ(p.Headshots, p.Hits, expectedHeadshotRate(p.MMR))
	}
	if len(p.TTDms) > 0 {
		s.ReactionMedianMs = median(p.TTDms)
		if others, players := othersTTD(m, slot); len(others) >= c.TTDMinSamples && players >= c.TTDMinPlayers {
			s.LobbyOK, s.ReactionZ = true, robustZ(s.ReactionMedianMs, others)
		}
	}
	s.TriggerCV, s.TriggerPresses, s.TriggerOK = triggerCV(p.triggerUs, c.TriggerMaxCV)
	s.FireDelays, s.FireTimed = len(p.FireDelayMs), fireTimed(p.FireDelayMs)
	s.HiddenSamples, s.HiddenTracked, s.Appearances, s.PreAimed = p.HiddenSamples, p.HiddenTracked, p.Appearances, p.PreAimed
	return s, true
}
