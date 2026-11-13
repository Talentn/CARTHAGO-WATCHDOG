package knowledge

// AlertConfig is the opt-in live rule: a player's score is taken over consecutive windows
// of match time that share no sample, and the rule fires when enough of them are strong.
// It exists for an operator who wants a wallhack score to tell the player during the
// match (a test on one's own server); the review flag at the end of a match does not
// depend on it.
type AlertConfig struct {
	WindowSec float64 // match time per window
	Z         float64 // a window is strong at this combined score
	MinExcess float64 // and with at least this excess alignment in a scored feature
	Windows   int     // strong windows needed, anywhere in the match
}

// DefaultAlert was set on the synthetic Counter-Strike matches (carthago-sim -cs-calibrate):
// two four-minute windows, each strong on its own. One window holds few blocks, so its
// score is bounded well below a match score and the bar per window is lower than a match
// threshold; what keeps honest players out is the repetition and the large excess. In the
// corpus about 1 honest player-match in 600 had one strong window and none had two; with
// the excess lowered to 0.15 still none, at 0.10 two in 28,000.
func DefaultAlert() AlertConfig {
	return AlertConfig{WindowSec: 240, Z: 2.5, MinExcess: 0.20, Windows: 2}
}

// AlertHit is one player reaching the rule.
type AlertHit struct {
	Slot    uint32
	Strong  int       // strong windows so far
	Windows int       // windows scored so far
	Scores  []float64 // the strong windows' scores
	Last    Result    // the window that completed the rule
}

// Alerter applies an AlertConfig to a Scorer as its match runs.
type Alerter struct {
	cfg     AlertConfig
	s       *Scorer
	from    float64
	windows int
	strong  map[uint32][]float64
	fired   map[uint32]bool
	// Best is each player's highest window score, for calibration and display.
	Best map[uint32]float64
}

func NewAlerter(cfg AlertConfig, s *Scorer) *Alerter {
	return &Alerter{cfg: cfg, s: s, strong: map[uint32][]float64{}, fired: map[uint32]bool{}, Best: map[uint32]float64{}}
}

// Step is called after each batch. It returns the players who reached the rule with the
// window that just closed, each at most once per match.
func (a *Alerter) Step() []AlertHit {
	if a.s.Analysed()-a.from < a.cfg.WindowSec {
		return nil
	}
	a.from = a.s.Analysed()
	a.windows++
	var out []AlertHit
	for _, r := range a.s.Window() {
		if r.Score > a.Best[r.Slot] {
			a.Best[r.Slot] = r.Score
		}
		if !a.strongWindow(r) {
			continue
		}
		a.strong[r.Slot] = append(a.strong[r.Slot], r.Score)
		if len(a.strong[r.Slot]) >= a.cfg.Windows && !a.fired[r.Slot] {
			a.fired[r.Slot] = true
			out = append(out, AlertHit{Slot: r.Slot, Strong: len(a.strong[r.Slot]), Windows: a.windows, Scores: a.strong[r.Slot], Last: r})
		}
	}
	return out
}

func (a *Alerter) strongWindow(r Result) bool {
	if r.Score < a.cfg.Z {
		return false
	}
	for _, f := range r.Features {
		if f.Scored && f.Z > 0 && f.RateTrue-f.RateNull >= a.cfg.MinExcess {
			return true
		}
	}
	return false
}

// Strong is how many strong windows a player has had.
func (a *Alerter) Strong(slot uint32) int { return len(a.strong[slot]) }

// Windows is how many windows have been scored.
func (a *Alerter) Windows() int { return a.windows }
