package oracle

import (
	"encoding/json"
	"math"
	"sort"
	"time"

	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/store"
)

// The baseline is the Oracle's second opinion, learned from a studio's own players.
//
// The behaviour model is trained before it ships, on simulated play. The baseline is not
// trained at all: it looks at the sessions one tenant has already scored, takes for every
// gameplay signal where the middle of that tenant's players sits and where their outer
// edge is, and then says how far past the edge a session lies. It needs no labels, and one
// tenant's baseline never uses another tenant's sessions.
//
// Cheaters play in every studio, and a baseline that learns from everybody learns their
// play as normal. So it learns in two passes. The first finds, signal by signal, where the
// middle half of the sessions lie, and leaves out every session far from that in any
// signal. The second learns the edges from the sessions that are left. Sessions that carry
// a certain finding, and sessions of banned players, are never learned from at all.
//
// A studio that has too few sessions of its own is compared with a fixed starting baseline
// (baselineStart) until it has enough.
//
// Like the rest of the Oracle it is advice for a reviewer. Nothing here is stored, nothing
// is sent to a client, and no code path leads from it to a kick or a ban.

const (
	// BaselineMinSessions is how many sessions with gameplay a tenant must have before
	// its baseline is learned from them. Below it the starting baseline is used.
	BaselineMinSessions = 200
	// baselineTrim is how far from the middle a session may lie in the first pass before
	// it is left out of the second, in quartile distances (from the median to the quartile
	// on the suspicious side). 4.45 of them are three standard deviations of a bell curve.
	baselineTrim = 4.45
	// baselineMinValues is the same for one signal: a signal too few sessions report is
	// left out of the baseline.
	baselineMinValues = 100
	// baselinePerPlayer bounds how many sessions of one player the baseline learns from,
	// so that one account playing all day cannot move what is normal.
	baselinePerPlayer = 5
	// baselineEdge is the share of the tenant's sessions that lie inside the edge.
	baselineEdge = 0.95
	// baselineCap bounds what one signal can add to a session's distance.
	baselineCap = 10.0
	// BaselineWindow is how far back a player's sessions count toward the player's score.
	BaselineWindow = 30 * 24 * time.Hour
	// baselineTop is how many of a player's sessions make the player's score: the most
	// suspicious ones in the window.
	baselineTop = 3
	// minFireDelays is how many fire delays a match must give before its fire timing is
	// used; minHiddenSamples (30 s of them) and minAppearances are the same for the two
	// sight signals.
	minFireDelays    = 12
	minHiddenSamples = 240
	minAppearances   = 8

	// A distance is counted in spreads: the distance between the middle and the edge of
	// the tenant's own players. From baselineOutside spreads past the edge a session or
	// a player is outside normal, from baselineFar far outside.
	baselineOutside = 3.0
	baselineFar     = 8.0
)

// Baseline bands.
const (
	BaselineLearning = "learning"
	BaselineNormal   = "normal"
	BaselineOutside  = "outside"
	BaselineFar      = "far_outside"
)

// The baseline's signals. The first NumGameplay are the behaviour model's gameplay features.
// The rest are the baseline's own: the model does not know them, because a new model
// feature means a new feature version and a new model for every deployment.
const (
	BFireTiming = NumGameplay + iota
	BHiddenAim
	BPreAim
	NumBaseline
)

// NumOwn is the number of signals only the baseline has.
const NumOwn = NumBaseline - NumGameplay

var baselineSignals = func() (f [NumBaseline]Feature) {
	copy(f[:], Features[:NumGameplay])
	f[BFireTiming] = Feature{"fire_timing", "Fire timing on target", +1, "aim"}
	f[BHiddenAim] = Feature{"hidden_aim", "Aim on opponents out of sight", +1, "information"}
	f[BPreAim] = Feature{"pre_aim", "Aim ready where opponents appear", +1, "information"}
	return f
}()

// certainKey marks, in a stored feature vector, a session that carries a certain finding.
const certainKey = "certain_finding"

// BaselineVector is one session's values of the baseline's signals; NaN is unknown.
type BaselineVector [NumBaseline]float64

// BaselineOwn are the values of the baseline's own signals, in their order after the
// gameplay features.
type BaselineOwn [NumOwn]float64

// NoOwnSignals has every own signal unknown.
func NoOwnSignals() BaselineOwn {
	var o BaselineOwn
	for i := range o {
		o[i] = math.NaN()
	}
	return o
}

// OwnSignals computes the baseline's own signals from one player's finished match. Each
// is unknown when the game server does not report what it needs or the match gave too
// little of it.
//
//   - Fire timing: the largest share of the times the player fired after the crosshair
//     came onto an enemy that were both faster than a person answers and nearly the same.
//     A trigger bot fires for the player at a set delay; a person's delays are longer and
//     spread out. Needs crosshair events.
//   - Hidden aim: the share of the moments with a close opponent out of sight in which
//     the crosshair stayed on such an opponent. Needs visibility events and positions.
//   - Pre-aim: the share of the opponents who came into view with the crosshair already
//     on them. Needs the same.
func OwnSignals(p *pipeline.MatchPlayer) BaselineOwn {
	o, s := NoOwnSignals(), &p.Stats
	if s.FireDelays >= minFireDelays {
		o[BFireTiming-NumGameplay] = s.FireTimed
	}
	if s.HiddenSamples >= minHiddenSamples {
		o[BHiddenAim-NumGameplay] = float64(s.HiddenTracked) / float64(s.HiddenSamples)
	}
	if s.Appearances >= minAppearances {
		o[BPreAim-NumGameplay] = float64(s.PreAimed) / float64(s.Appearances)
	}
	return o
}

// BaselineOf is the baseline's view of a session: the gameplay part of its feature vector
// and the baseline's own signals.
func BaselineOf(v Vector, own BaselineOwn) BaselineVector {
	var b BaselineVector
	copy(b[:], v[:NumGameplay])
	copy(b[NumGameplay:], own[:])
	return b
}

// CertainFinding reports whether a session's evidence holds a finding of the certain
// tier: the kind the rules ban on. Such a session is scored and never learned from. The
// stored evidence does not keep everything a ban asks for, so this takes a little more
// than a ban would, which errs on the side of learning from less.
func CertainFinding(evidence []store.Evidence) bool {
	for i := range evidence {
		e := &evidence[i]
		if !e.Bot && e.Integrity && e.Severity >= int(analyzer.SeverityHigh) && analyzer.TierOf(e.Rule) == analyzer.TierCertain {
			return true
		}
	}
	return false
}

// WithBaseline adds what the baseline needs to a stored feature vector (a score row's
// Features), where it reads it back: its own signals, and whether the session carries a
// certain finding.
func WithBaseline(features string, own BaselineOwn, certain bool) string {
	m := map[string]float64{}
	if json.Unmarshal([]byte(features), &m) != nil {
		return features
	}
	for i, x := range own {
		if !math.IsNaN(x) && !math.IsInf(x, 0) {
			m[baselineSignals[NumGameplay+i].Key] = x
		}
	}
	if certain {
		m[certainKey] = 1
	}
	out, err := json.Marshal(m)
	if err != nil {
		return features
	}
	return string(out)
}

// ParseBaseline reads the baseline's signals from a stored feature vector, and whether the
// session carries a certain finding.
func ParseBaseline(features string) (b BaselineVector, certain bool, err error) {
	m := map[string]float64{}
	if err := json.Unmarshal([]byte(features), &m); err != nil {
		return b, false, err
	}
	for i := range b {
		b[i] = math.NaN()
		if x, ok := m[baselineSignals[i].Key]; ok {
			b[i] = x
		}
	}
	return b, m[certainKey] > 0, nil
}

// Own returns the baseline's own signals of a vector.
func (b BaselineVector) Own() BaselineOwn {
	var o BaselineOwn
	copy(o[:], b[NumGameplay:])
	return o
}

// baselineFloor is the smallest spread a signal can have, in the signal's own unit. It
// only matters where nearly all of a tenant's players share one value (no aim snaps at
// all, say) and the measured spread would be zero. The values are set by hand from what
// each number means; they are not fitted on any data.
var baselineFloor = [NumBaseline]float64{
	FAimSnapRate:    0.25, // snaps per minute
	FHeadshotZ:      0.5,  // standard deviations
	FReactionMs:     20,   // milliseconds
	FReactionLobbyZ: 0.5,  // standard deviations
	FCommandRatio:   0.02, // commands per tick
	FTriggerCV:      0.05, // coefficient of variation
	FLeakRatio:      0.1,  // share of the rule's threshold
	FDecoyRatio:     0.1,  // share of the rule's threshold
	BFireTiming:     0.05, // share of the player's fire delays
	BHiddenAim:      0.01, // share of the moments with an opponent out of sight
	BPreAim:         0.05, // share of the opponents who came into view
}

// baselineStart is the starting baseline: for each signal the edge and the spread a new
// studio is measured with until it has BaselineMinSessions sessions of its own. It is set
// by hand from what each number means and learned from nothing. A session is outside
// normal at the edge plus three spreads, and that point is put near where the analyzer's
// own rules stand or where a person should not get: five standard deviations for the two
// values counted in them, a reaction of 30 ms, a command rate of 1.09 a tick, two thirds
// of the fire delays quick and alike. It is wider than what a studio's own players will
// show, so it finds less. The two sight signals depend on the game's maps and have no
// starting value: they begin with the studio's own baseline.
//
// It is not free of false flags. The headshot rate against rating has a long honest tail:
// on the simulator about 3% of honest sessions lie past its line here, and one player in
// seventy has two such sessions and is called outside normal. A studio's own baseline
// measures that tail and does not have the problem.
var baselineStart = [NumBaseline]struct{ edge, spread float64 }{
	FAimSnapRate:    {0.4, 0.4},
	FHeadshotZ:      {2, 1},
	FReactionMs:     {150, 40},
	FReactionLobbyZ: {-2, 1},
	FCommandRatio:   {1.03, 0.02},
	FTriggerCV:      {0.08, 0.02},
	FLeakRatio:      {0.6, 0.2},
	FDecoyRatio:     {0.6, 0.2},
	BFireTiming:     {0.35, 0.1},
}

// BaselineSample is one scored session of a tenant.
type BaselineSample struct {
	PlayerHash string
	Vector     BaselineVector
	At         time.Time
	// Excluded: the session carries a certain finding or its player is banned. It is
	// scored like any other and never learned from.
	Excluded bool
}

// Baseline is what is normal for one tenant.
type Baseline struct {
	// Sessions is the number of the tenant's sessions it could learn from: with gameplay,
	// without a certain finding or a ban.
	Sessions int
	// Starting: the tenant has too few sessions and this is the starting baseline.
	Starting bool
	// LeftOut is how many sessions the first pass left out of the second.
	LeftOut int
	// Ready is false when no signal can be judged.
	Ready bool

	used         [NumBaseline]bool
	edge, spread [NumBaseline]float64
}

// StartingBaseline is the baseline of a studio without enough sessions of its own.
func StartingBaseline() *Baseline {
	b := &Baseline{Starting: true}
	for f, s := range baselineStart {
		if s.spread > 0 {
			b.used[f], b.edge[f], b.spread[f], b.Ready = true, s.edge, s.spread, true
		}
	}
	return b
}

// LearnBaseline builds a tenant's baseline from its scored sessions, newest first.
func LearnBaseline(samples []BaselineSample) *Baseline {
	var learn []*BaselineVector
	perPlayer := map[string]int{}
	sessions := 0
	for i := range samples {
		s := &samples[i]
		if s.Excluded || !hasGameplay(&s.Vector) {
			continue
		}
		sessions++
		if s.PlayerHash != "" {
			if perPlayer[s.PlayerHash] >= baselinePerPlayer {
				continue
			}
			perPlayer[s.PlayerHash]++
		}
		learn = append(learn, &s.Vector)
	}
	if sessions < BaselineMinSessions {
		b := StartingBaseline()
		b.Sessions = sessions
		return b
	}
	// First pass: the middle and the quartile on the suspicious side. Both stay where the
	// honest sessions put them while fewer than a quarter of the sessions cheat in the
	// same signal; an edge at 95% moves as soon as a twentieth do.
	side := func(f int, q float64) float64 {
		if baselineSignals[f].Direction < 0 {
			return 1 - q
		}
		return q
	}
	values := func(from []*BaselineVector, f int) []float64 {
		var v []float64
		for _, s := range from {
			if x := s[f]; !math.IsNaN(x) {
				v = append(v, x)
			}
		}
		sort.Float64s(v)
		return v
	}
	var cut [NumBaseline]float64
	var cuts [NumBaseline]bool
	for f := range cut {
		if v := values(learn, f); len(v) >= baselineMinValues {
			mid := quantile(v, 0.5)
			reach := baselineTrim * math.Max(math.Abs(quantile(v, side(f, 0.75))-mid), baselineFloor[f])
			cut[f], cuts[f] = mid+float64(baselineSignals[f].Direction)*reach, true
		}
	}
	var clean []*BaselineVector
	for _, s := range learn {
		in := true
		for f := range cut {
			if x := s[f]; cuts[f] && !math.IsNaN(x) && float64(baselineSignals[f].Direction)*(x-cut[f]) > 0 {
				in = false
				break
			}
		}
		if in {
			clean = append(clean, s)
		}
	}
	// Second pass: the edges, from the sessions that are left.
	b := &Baseline{Sessions: sessions, LeftOut: len(learn) - len(clean)}
	for f := range cut {
		v := values(clean, f)
		if len(v) < baselineMinValues {
			continue
		}
		mid, edge := quantile(v, 0.5), quantile(v, side(f, baselineEdge))
		b.used[f], b.edge[f], b.spread[f] = true, edge, math.Max(math.Abs(edge-mid), baselineFloor[f])
		b.Ready = true
	}
	return b
}

func hasGameplay(v *BaselineVector) bool {
	for f := range v {
		if !math.IsNaN(v[f]) {
			return true
		}
	}
	return false
}

// quantile of sorted values, interpolated.
func quantile(sorted []float64, q float64) float64 {
	pos := q * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := min(lo+1, len(sorted)-1)
	return sorted[lo] + (sorted[hi]-sorted[lo])*(pos-float64(lo))
}

// BaselineSignal is one signal in which a session lies past the tenant's edge.
type BaselineSignal struct {
	Key, Label string
	// Spreads is how far past the edge, in spreads.
	Spreads float64
}

// Distance is how far outside the tenant's normal play a session lies: for every signal
// the number of spreads past the edge on the suspicious side, added up. Zero is inside.
// ok is false when the baseline is not ready or the session has no gameplay it can judge.
func (b *Baseline) Distance(v BaselineVector) (d float64, signals []BaselineSignal, ok bool) {
	if b == nil || !b.Ready {
		return 0, nil, false
	}
	for f := range v {
		x := v[f]
		if !b.used[f] || math.IsNaN(x) {
			continue
		}
		ok = true
		past := (x - b.edge[f]) / b.spread[f]
		if baselineSignals[f].Direction < 0 {
			past = -past
		}
		if past <= 0 {
			continue
		}
		past = math.Min(past, baselineCap)
		d += past
		signals = append(signals, BaselineSignal{baselineSignals[f].Key, baselineSignals[f].Label, past})
	}
	sort.SliceStable(signals, func(i, j int) bool { return signals[i].Spreads > signals[j].Spreads })
	return d, signals, ok
}

// BaselineScore turns a player's distance into a 0..1 score; 1 is far outside.
func BaselineScore(d float64) float64 { return math.Min(1, d/baselineFar) }

// BaselineBand names a distance.
func BaselineBand(d float64) string {
	switch {
	case d >= baselineFar:
		return BaselineFar
	case d >= baselineOutside:
		return BaselineOutside
	}
	return BaselineNormal
}

// PlayerDistance combines the distances of one player's sessions in the window into one:
// the mean of the player's baselineTop most suspicious sessions.
//
// The ordinary sessions of somebody who cheats now and then do not pull the score down, as
// they would in a mean over everything. One session counts for no more than the far line
// and a session the player has not played counts as zero, so one extraordinary match
// leaves a player inside normal: it takes two sessions outside to be outside, and three
// far outside to be far outside.
func PlayerDistance(sessions []float64) float64 {
	top := append([]float64(nil), sessions...)
	sort.Sort(sort.Reverse(sort.Float64Slice(top)))
	sum := 0.0
	for i := 0; i < len(top) && i < baselineTop; i++ {
		sum += math.Min(top[i], baselineFar)
	}
	return sum / baselineTop
}

// PlayerBaseline is one player against the tenant's baseline.
type PlayerBaseline struct {
	Sessions int
	Distance float64
	Score    float64
	Band     string
	// Outside is how many of the sessions were outside normal on their own.
	Outside int
	// Signals are the signals the player's sessions were past the edge in, most first.
	Signals []BaselineSignal
}

// Players scores every player with a session in the window ending at now.
func (b *Baseline) Players(samples []BaselineSample, now time.Time) map[string]PlayerBaseline {
	if b == nil || !b.Ready {
		return nil
	}
	type acc struct {
		ds      []float64
		outside int
		signals map[string]*BaselineSignal
	}
	accs := map[string]*acc{}
	for i := range samples {
		s := &samples[i]
		if s.PlayerHash == "" || now.Sub(s.At) > BaselineWindow {
			continue
		}
		d, sigs, ok := b.Distance(s.Vector)
		if !ok {
			continue
		}
		a := accs[s.PlayerHash]
		if a == nil {
			a = &acc{signals: map[string]*BaselineSignal{}}
			accs[s.PlayerHash] = a
		}
		a.ds = append(a.ds, d)
		if d >= baselineOutside {
			a.outside++
		}
		for _, sg := range sigs {
			if have := a.signals[sg.Key]; have != nil {
				have.Spreads += sg.Spreads
			} else {
				sg := sg
				a.signals[sg.Key] = &sg
			}
		}
	}
	out := make(map[string]PlayerBaseline, len(accs))
	for hash, a := range accs {
		d := PlayerDistance(a.ds)
		p := PlayerBaseline{Sessions: len(a.ds), Distance: d, Score: BaselineScore(d), Band: BaselineBand(d), Outside: a.outside}
		for _, sg := range a.signals {
			p.Signals = append(p.Signals, *sg)
		}
		sort.Slice(p.Signals, func(i, j int) bool {
			if p.Signals[i].Spreads != p.Signals[j].Spreads {
				return p.Signals[i].Spreads > p.Signals[j].Spreads
			}
			return p.Signals[i].Key < p.Signals[j].Key
		})
		out[hash] = p
	}
	return out
}
