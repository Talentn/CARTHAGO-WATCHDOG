package oracle

import (
	"encoding/json"
	"math"
	"sort"
	"time"

	"carthago/backend/internal/pipeline"
)

// The baseline is the Oracle's second opinion, learned from a studio's own players.
//
// The behaviour model is trained before it ships, on simulated play. The baseline is not
// trained at all: it looks at the sessions one tenant has already scored, takes for every
// gameplay signal where the middle of that tenant's players sits and where their outer
// edge is, and then says how far past the edge a session lies. It needs no labels, and one
// tenant's baseline never uses another tenant's sessions.
//
// Like the rest of the Oracle it is advice for a reviewer. Nothing here is stored, nothing
// is sent to a client, and no code path leads from it to a kick or a ban.

const (
	// BaselineMinSessions is how many sessions with gameplay a tenant must have before
	// its baseline says anything. Below it the baseline only watches.
	BaselineMinSessions = 200
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
	// minFireDelays is how many fire delays a match must give before its fire timing is used.
	minFireDelays = 12

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
	NumBaseline
)

var baselineSignals = func() (f [NumBaseline]Feature) {
	copy(f[:], Features[:NumGameplay])
	f[BFireTiming] = Feature{"fire_timing", "Fire timing on target", +1, "aim"}
	return f
}()

// BaselineVector is one session's values of the baseline's signals; NaN is unknown.
type BaselineVector [NumBaseline]float64

// FireTiming is the fire-timing signal of one player's finished match: the largest share
// of the times the player fired after the crosshair came onto an enemy that were both
// faster than a person answers and nearly the same. A trigger bot fires for the player at
// a set delay; a person's delays are longer and spread out. Unknown when the game server
// does not report crosshair events or the match gave too few.
func FireTiming(p *pipeline.MatchPlayer) float64 {
	if p.Stats.FireDelays < minFireDelays {
		return math.NaN()
	}
	return p.Stats.FireTimed
}

// BaselineOf is the baseline's view of a session: the gameplay part of its feature vector
// and its fire timing.
func BaselineOf(v Vector, fireTiming float64) BaselineVector {
	var b BaselineVector
	copy(b[:], v[:NumGameplay])
	b[BFireTiming] = fireTiming
	return b
}

// WithFireTiming adds the fire timing to a stored feature vector (a score row's Features),
// where the baseline reads it back.
func WithFireTiming(features string, fireTiming float64) string {
	m := map[string]float64{}
	if math.IsNaN(fireTiming) || math.IsInf(fireTiming, 0) || json.Unmarshal([]byte(features), &m) != nil {
		return features
	}
	m[baselineSignals[BFireTiming].Key] = fireTiming
	out, err := json.Marshal(m)
	if err != nil {
		return features
	}
	return string(out)
}

// ParseBaselineVector reads the baseline's signals from a stored feature vector.
func ParseBaselineVector(features string) (BaselineVector, error) {
	var b BaselineVector
	m := map[string]float64{}
	if err := json.Unmarshal([]byte(features), &m); err != nil {
		return b, err
	}
	for i := range b {
		b[i] = math.NaN()
		if x, ok := m[baselineSignals[i].Key]; ok {
			b[i] = x
		}
	}
	return b, nil
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
}

// BaselineSample is one scored session of a tenant.
type BaselineSample struct {
	PlayerHash string
	Vector     BaselineVector
	At         time.Time
}

// Baseline is what is normal for one tenant.
type Baseline struct {
	// Sessions is the number of sessions with gameplay it has seen.
	Sessions int
	// Ready is false while the baseline only watches.
	Ready bool

	used         [NumBaseline]bool
	edge, spread [NumBaseline]float64
}

// LearnBaseline builds a tenant's baseline from its scored sessions, newest first.
func LearnBaseline(samples []BaselineSample) *Baseline {
	b := &Baseline{}
	var values [NumBaseline][]float64
	perPlayer := map[string]int{}
	for i := range samples {
		s := &samples[i]
		if !hasGameplay(&s.Vector) {
			continue
		}
		b.Sessions++
		if s.PlayerHash != "" {
			if perPlayer[s.PlayerHash] >= baselinePerPlayer {
				continue
			}
			perPlayer[s.PlayerHash]++
		}
		for f := range values {
			if x := s.Vector[f]; !math.IsNaN(x) {
				values[f] = append(values[f], x)
			}
		}
	}
	if b.Sessions < BaselineMinSessions {
		return b
	}
	for f := range values {
		v := values[f]
		if len(v) < baselineMinValues {
			continue
		}
		sort.Float64s(v)
		q := baselineEdge
		if baselineSignals[f].Direction < 0 {
			q = 1 - baselineEdge
		}
		mid, edge := quantile(v, 0.5), quantile(v, q)
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
