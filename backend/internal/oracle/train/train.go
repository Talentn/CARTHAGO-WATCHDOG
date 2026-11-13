package train

import (
	"errors"
	"math"
	"sort"

	"carthago/backend/internal/oracle"
)

// Params are the trainer's settings.
type Params struct {
	Rounds       int
	LearningRate float64
	// L2 regularises a leaf's value; MinLeaf is the least number of rows on each side of
	// a cut.
	L2      float64
	MinLeaf int
	// Bins is the number of candidate cuts per feature.
	Bins int
	// Cap bounds how far one feature's curve may move a score, in log-odds either way;
	// 0 leaves it free.
	Cap [oracle.NumFeatures]float64
}

// ContextCap is the default bound on the features that describe a player's PC rather
// than what the player did: the trust level, findings about other software, injected
// input and scanner gaps. They are common among honest players (no TPM, an overlay, a
// remapper), and how common is an assumption of the synthetic data, so they may shade a
// score and never decide it: together they move the odds by less than a factor of four.
const ContextCap = 0.3

func DefaultParams() Params {
	p := Params{Rounds: 300, LearningRate: 0.1, L2: 2, MinLeaf: 25, Bins: 24}
	for _, f := range []int{oracle.FTrustLevel, oracle.FClientFindings, oracle.FInjectedRatio, oracle.FScannerGaps} {
		p.Cap[f] = ContextCap
	}
	return p
}

// Fit learns a behaviour model by gradient boosting of one-cut trees on the logistic
// loss. Each tree looks at one feature, so the sum over trees is one curve per feature:
// the additive model oracle.Model evaluates. Two constraints keep the curves honest:
//
//   - a cut is only taken if it moves the score in the feature's declared direction, so
//     every curve is monotone and more of a suspicious signal can never lower a score;
//   - a value that is unknown gets a leaf of its own, learned like any other, so the
//     model does not have to pretend a session without a match played an average one.
func Fit(rows []Row, p Params) (*oracle.Model, error) {
	n := len(rows)
	pos := 0
	for i := range rows {
		if rows[i].Cheating {
			pos++
		}
	}
	if pos == 0 || pos == n {
		return nil, errors.New("training data needs both honest and cheating sessions")
	}

	// Candidate cuts: quantiles of each feature's known values.
	cuts := make([][]float64, oracle.NumFeatures)
	for f := range cuts {
		var xs []float64
		for i := range rows {
			if x := rows[i].Vector[f]; !math.IsNaN(x) {
				xs = append(xs, x)
			}
		}
		sort.Float64s(xs)
		for b := 1; b < p.Bins && len(xs) > 1; b++ {
			i := b * len(xs) / p.Bins
			if i == 0 || xs[i] == xs[i-1] {
				// Step to the next change in value so heavy ties still get a cut.
				j := sort.SearchFloat64s(xs, math.Nextafter(xs[i], math.Inf(1)))
				if j >= len(xs) {
					continue
				}
				i = j
			}
			c := (xs[i] + xs[i-1]) / 2
			c = math.Round(c*1e4) / 1e4
			if !(c > xs[i-1] && c <= xs[i]) {
				c = xs[i]
			}
			if k := len(cuts[f]); k == 0 || cuts[f][k-1] < c {
				cuts[f] = append(cuts[f], c)
			}
		}
	}
	// bin[f][i] is the number of cuts at or below row i's value, or -1 when unknown.
	bin := make([][]int16, oracle.NumFeatures)
	for f := range bin {
		bin[f] = make([]int16, n)
		for i := range rows {
			x := rows[i].Vector[f]
			if math.IsNaN(x) {
				bin[f][i] = -1
				continue
			}
			bin[f][i] = int16(sort.Search(len(cuts[f]), func(k int) bool { return cuts[f][k] > x }))
		}
	}

	bias := math.Log(float64(pos) / float64(n-pos))
	shape := make([][]float64, oracle.NumFeatures) // value per bin
	missing := make([]float64, oracle.NumFeatures)
	for f := range shape {
		shape[f] = make([]float64, len(cuts[f])+1)
	}
	z := make([]float64, n)
	for i := range z {
		z[i] = bias
	}
	g, h := make([]float64, n), make([]float64, n)
	var capped [oracle.NumFeatures]bool
	leaf := func(G, H float64) float64 { return -G / (H + p.L2) }
	gain := func(G, H float64) float64 { return G * G / (H + p.L2) }

	for range p.Rounds {
		for i := range rows {
			pr := 1 / (1 + math.Exp(-z[i]))
			y := 0.0
			if rows[i].Cheating {
				y = 1
			}
			g[i], h[i] = pr-y, math.Max(pr*(1-pr), 1e-6)
		}
		best := struct {
			gain           float64
			f, cut         int
			left, right, m float64
		}{f: -1}
		for f := range oracle.NumFeatures {
			if capped[f] {
				continue
			}
			nb := len(cuts[f]) + 1
			G, H, N := make([]float64, nb), make([]float64, nb), make([]int, nb)
			var GM, HM float64
			NM := 0
			for i := range rows {
				if b := bin[f][i]; b < 0 {
					GM, HM, NM = GM+g[i], HM+h[i], NM+1
				} else {
					G[b], H[b], N[b] = G[b]+g[i], H[b]+h[i], N[b]+1
				}
			}
			var GT, HT float64
			NT := 0
			for b := range nb {
				GT, HT, NT = GT+G[b], HT+H[b], NT+N[b]
			}
			mv, mg := 0.0, 0.0
			if NM >= p.MinLeaf {
				mv, mg = leaf(GM, HM), gain(GM, HM)
			}
			// A feature can also be used for its unknown leaf alone.
			if mg > best.gain {
				best.gain, best.f, best.cut, best.left, best.right, best.m = mg, f, -1, 0, 0, mv
			}
			var GL, HL float64
			NL := 0
			for c := 0; c < nb-1; c++ { // cut c separates bins <= c from bins > c
				GL, HL, NL = GL+G[c], HL+H[c], NL+N[c]
				if NL < p.MinLeaf || NT-NL < p.MinLeaf {
					continue
				}
				l, r := leaf(GL, HL), leaf(GT-GL, HT-HL)
				if d := oracle.Features[f].Direction; d != 0 && float64(d)*(r-l) <= 0 {
					continue
				}
				if gn := gain(GL, HL) + gain(GT-GL, HT-HL) - gain(GT, HT) + mg; gn > best.gain {
					best.gain, best.f, best.cut, best.left, best.right, best.m = gn, f, c, l, r, mv
				}
			}
		}
		if best.f < 0 || best.gain < 1e-9 {
			break
		}
		f, lr := best.f, p.LearningRate
		before, beforeM := append([]float64(nil), shape[f]...), missing[f]
		bound := func(x float64) float64 {
			if c := p.Cap[f]; c > 0 {
				return math.Max(-c, math.Min(c, x))
			}
			return x
		}
		moved := 0.0
		for b := range shape[f] {
			if best.cut >= 0 {
				if b <= best.cut {
					shape[f][b] = bound(shape[f][b] + lr*best.left)
				} else {
					shape[f][b] = bound(shape[f][b] + lr*best.right)
				}
				moved = math.Max(moved, math.Abs(shape[f][b]-before[b]))
			}
		}
		missing[f] = bound(missing[f] + lr*best.m)
		moved = math.Max(moved, math.Abs(missing[f]-beforeM))
		if moved < 1e-9 {
			// The curve is at its cap wherever the data wants to move it: leave it there
			// and let the other features have the remaining rounds.
			capped[f] = true
			continue
		}
		for i := range rows {
			if b := int(bin[f][i]); b < 0 {
				z[i] += missing[f] - beforeM
			} else {
				z[i] += shape[f][b] - before[b]
			}
		}
	}

	round := func(x float64) float64 { return math.Round(x*1e4) / 1e4 }
	m := &oracle.Model{Kind: oracle.ModelKind, FormatVersion: 1, FeatureVersion: oracle.FeatureVersion, Bias: round(bias)}
	for f := range oracle.NumFeatures {
		s := oracle.Shape{Key: oracle.Features[f].Key, Missing: round(missing[f])}
		// Keep only the cuts where the curve changes.
		s.Values = []float64{round(shape[f][0])}
		for c := range cuts[f] {
			if v := round(shape[f][c+1]); v != s.Values[len(s.Values)-1] {
				s.Cuts, s.Values = append(s.Cuts, cuts[f][c]), append(s.Values, v)
			}
		}
		if s.Cuts == nil {
			s.Cuts = []float64{}
		}
		m.Shapes = append(m.Shapes, s)
	}
	// The baseline of each curve: its mean over the honest training sessions.
	honest := 0
	sums := make([]float64, oracle.NumFeatures)
	for i := range rows {
		if rows[i].Cheating {
			continue
		}
		honest++
		for f := range oracle.NumFeatures {
			sums[f] += shapeAt(&m.Shapes[f], rows[i].Vector[f])
		}
	}
	for f := range m.Shapes {
		m.Shapes[f].Baseline = round(sums[f] / float64(honest))
	}
	return m, m.Validate()
}

func shapeAt(s *oracle.Shape, x float64) float64 {
	if math.IsNaN(x) {
		return s.Missing
	}
	return s.Values[sort.Search(len(s.Cuts), func(i int) bool { return s.Cuts[i] > x })]
}

// Split divides sessions by match, so one match's players are never on both sides: three
// fifths to train on, one fifth to choose thresholds on and one fifth to test on.
func Split(rows []Row) (train, calib, test []Row) {
	for _, r := range rows {
		switch r.Match % 5 {
		case 3:
			calib = append(calib, r)
		case 4:
			test = append(test, r)
		default:
			train = append(train, r)
		}
	}
	return
}

// Thresholds picks the watch and review thresholds from held-out honest sessions: the
// lowest scores at which no more than the target share of them is at or above.
func Thresholds(m *oracle.Model, calib []Row, watchFPR, reviewFPR float64) oracle.Thresholds {
	var honest []float64
	for i := range calib {
		if !calib[i].Cheating {
			s, _ := m.Score(calib[i].Vector)
			honest = append(honest, s)
		}
	}
	sort.Float64s(honest)
	at := func(fpr float64) float64 {
		if len(honest) == 0 {
			return 0.5
		}
		allowed := int(math.Floor(fpr * float64(len(honest))))
		// The threshold sits just above the highest honest score that must stay below it.
		i := len(honest) - 1 - allowed
		t := math.Ceil(honest[i]*1000+1e-9) / 1000
		if t <= honest[i] {
			t += 0.001
		}
		return math.Min(0.999, math.Max(0.02, t))
	}
	t := oracle.Thresholds{Watch: at(watchFPR), Review: at(reviewFPR)}
	// A threshold on a handful of sessions can land anywhere; keep review at or above
	// even odds so a "review" always means the model leans towards cheating.
	t.Review = math.Max(t.Review, 0.5)
	t.Watch = math.Min(t.Watch, t.Review)
	return t
}
