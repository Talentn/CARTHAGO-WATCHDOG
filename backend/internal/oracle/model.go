package oracle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
)

// ModelKind identifies a behaviour model file.
const ModelKind = "carthago-oracle-behaviour"

// Model is the behaviour model: a bias plus one learned curve per feature, summed and
// passed through a logistic function. Each curve is piecewise constant, so a score is a
// handful of table lookups and every feature's share of it is exact.
//
// The score is a number between 0 and 1 that orders sessions by how much they resemble
// the cheating profiles the model was trained on. It is not the probability that a player
// cheats: the training data fixes the share of cheaters, the real world does not.
type Model struct {
	Kind           string  `json:"kind"`
	FormatVersion  int     `json:"format_version"`
	FeatureVersion int     `json:"feature_version"`
	Bias           float64 `json:"bias"`
	Shapes         []Shape `json:"shapes"`
	// Training describes how the file was produced. It carries no timestamp, so the same
	// tool with the same options writes the same bytes.
	Training Training `json:"training"`
}

// Shape is one feature's curve. Values[i] applies to a value x with exactly i cuts at or
// below it; Missing applies when the value is unknown. Baseline is the curve's mean over
// the honest training sessions, the point a contribution is measured from.
type Shape struct {
	Key      string    `json:"key"`
	Cuts     []float64 `json:"cuts"`
	Values   []float64 `json:"values"`
	Missing  float64   `json:"missing"`
	Baseline float64   `json:"baseline"`
}

type Training struct {
	Tool         string  `json:"tool"`
	Data         string  `json:"data"`
	Seed         uint64  `json:"seed"`
	Matches      int     `json:"matches"`
	MatchSeconds int     `json:"match_seconds"`
	Rows         int     `json:"rows"`
	Honest       int     `json:"honest"`
	Cheating     int     `json:"cheating"`
	Rounds       int     `json:"rounds"`
	LearningRate float64 `json:"learning_rate"`
}

func (s *Shape) at(x float64) float64 {
	if math.IsNaN(x) {
		return s.Missing
	}
	// The number of cuts <= x.
	return s.Values[sort.Search(len(s.Cuts), func(i int) bool { return s.Cuts[i] > x })]
}

// Score returns the session's score and each feature's contribution to it in log-odds,
// measured from what the feature gives a typical honest session.
func (m *Model) Score(v Vector) (score float64, contrib [NumFeatures]float64) {
	z := m.Bias
	for i := range m.Shapes {
		f := m.Shapes[i].at(v[i])
		z += f
		contrib[i] = f - m.Shapes[i].Baseline
	}
	return 1 / (1 + math.Exp(-z)), contrib
}

// Validate checks a model read from disk: its shape, and that every curve respects the
// direction its feature is declared with.
func (m *Model) Validate() error {
	if m.Kind != ModelKind || m.FormatVersion != 1 {
		return fmt.Errorf("not a behaviour model this engine reads (kind %q, format %d)", m.Kind, m.FormatVersion)
	}
	if m.FeatureVersion != FeatureVersion {
		return fmt.Errorf("model was trained on feature version %d, this engine computes version %d: train a new model", m.FeatureVersion, FeatureVersion)
	}
	if len(m.Shapes) != NumFeatures {
		return fmt.Errorf("model has %d curves, want %d", len(m.Shapes), NumFeatures)
	}
	finite := func(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) }
	if !finite(m.Bias) {
		return errors.New("model bias is not a number")
	}
	for i := range m.Shapes {
		s, f := &m.Shapes[i], Features[i]
		if s.Key != f.Key {
			return fmt.Errorf("curve %d is for %q, want %q", i, s.Key, f.Key)
		}
		if len(s.Values) != len(s.Cuts)+1 || !sort.Float64sAreSorted(s.Cuts) || !finite(s.Missing) || !finite(s.Baseline) {
			return fmt.Errorf("curve %q is malformed", s.Key)
		}
		for j, x := range s.Values {
			if !finite(x) {
				return fmt.Errorf("curve %q is malformed", s.Key)
			}
			if j > 0 && f.Direction != 0 && float64(f.Direction)*(x-s.Values[j-1]) < -1e-9 {
				return fmt.Errorf("curve %q goes against its direction", s.Key)
			}
		}
	}
	return nil
}

// ParseModel reads and validates a model file. The id names its exact bytes.
func ParseModel(data []byte) (*Model, string, error) {
	var m Model
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, "", fmt.Errorf("behaviour model: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, "", err
	}
	return &m, ModelID(data), nil
}

// ModelID is the short name of a model file: "cob-" and the start of its SHA-256.
func ModelID(data []byte) string {
	sum := sha256.Sum256(data)
	return "cob-" + hex.EncodeToString(sum[:6])
}

// Encode writes the model in its canonical form.
func (m *Model) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Signal is one feature's part in a score, as stored for and shown on the dashboard. It
// names the signal and the direction and size of its effect; it carries neither the
// feature's value nor anything of the model's curve.
type Signal struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Family string  `json:"family"`
	Effect float64 `json:"effect"` // log-odds against a typical honest session; positive raises the score
}

// TopSignals returns the n features that moved the score most, strongest first, leaving
// out those with next to no effect.
func TopSignals(contrib [NumFeatures]float64, n int) []Signal {
	out := make([]Signal, 0, NumFeatures)
	for i, c := range contrib {
		if math.Abs(c) >= 0.05 {
			out = append(out, Signal{Features[i].Key, Features[i].Label, Features[i].Family, math.Round(c*100) / 100})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return math.Abs(out[i].Effect) > math.Abs(out[j].Effect) })
	if len(out) > n {
		out = out[:n]
	}
	return out
}
