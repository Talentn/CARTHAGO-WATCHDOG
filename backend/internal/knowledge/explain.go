package knowledge

import (
	"fmt"
	"math"
	"strings"
)

// Result is one player's leak score for a match.
type Result struct {
	Slot       uint32
	Segment    Segment
	Calibrated bool
	Threshold  Threshold
	AimAssist  bool
	Score      float64 // eligible feature z values combined (Stouffer)
	Flagged    bool
	Features   []FeatureResult
	Moments    []Moment
	cfg        Config
}

type FeatureResult struct {
	Name     string  `json:"name"`
	Label    string  `json:"label"`
	Z        float64 `json:"z"`
	Samples  int     `json:"samples"`
	Blocks   int     `json:"blocks"`
	RateTrue float64 `json:"rate_true"` // mean alignment with the true hidden state
	RateNull float64 `json:"rate_null"` // mean alignment with the control offsets
	Eligible bool    `json:"eligible"`  // enough samples to count
	Scored   bool    `json:"scored"`    // part of the combined score
}

// Moment is one concrete episode for a reviewer.
type Moment struct {
	Kind       string  `json:"kind"` // tracked_hidden | shot_hidden | approached_hidden | approached_unseen_loot
	At         string  `json:"at"`   // mm:ss into the match
	Tick       uint32  `json:"tick"`
	End        uint32  `json:"end_tick"`
	DurationS  float64 `json:"duration_s,omitempty"`
	TargetSlot uint32  `json:"target_slot,omitempty"`
	ItemID     uint32  `json:"item_id,omitempty"`
	SweepDeg   float64 `json:"sweep_deg,omitempty"`
	MeanErrDeg float64 `json:"mean_err_deg,omitempty"`
	DistanceM  float64 `json:"distance_m,omitempty"`
	ClosedM    float64 `json:"closed_m,omitempty"`
	Hit        bool    `json:"hit,omitempty"`
	ViewerZone string  `json:"viewer_zone,omitempty"`
	TargetZone string  `json:"target_zone,omitempty"`
	Known      string  `json:"known"` // what the knowledge model says the team knew
	Weight     float64 `json:"-"`
	Replay     *Replay `json:"-"`
}

// Replay is the top-down picture of a moment, in map metres.
type Replay struct {
	Viewer       []Vec2    `json:"viewer"`
	Target       []Vec2    `json:"target"`
	TargetIsItem bool      `json:"target_is_item,omitempty"`
	Rays         [][2]Vec2 `json:"rays"`
	Occluders    [][]Vec2  `json:"occluders"`
	Min          Vec2      `json:"min"`
	Max          Vec2      `json:"max"`
}

// Explanation is what the dashboard shows a reviewer, stored as the evidence's raw JSON.
type Explanation struct {
	Segment    string          `json:"segment"`
	Calibrated bool            `json:"calibrated"`
	Threshold  float64         `json:"threshold_z"`
	MinExcess  float64         `json:"min_excess"`
	TargetFPR  float64         `json:"target_fpr"`
	Score      float64         `json:"score_z"`
	AimAssist  bool            `json:"aim_assist,omitempty"`
	Map        string          `json:"map"`
	Features   []FeatureResult `json:"features"`
	Moments    []MomentText    `json:"moments"`
	Replay     *Replay         `json:"replay,omitempty"`
	ReplayNote string          `json:"replay_note,omitempty"`
	Knowledge  string          `json:"knowledge_model"`
	Policy     string          `json:"policy"`
}

type MomentText struct {
	Moment
	Target string `json:"target,omitempty"`
	Text   string `json:"text"`
}

// Explain words a result for review. name resolves a slot to the player label shown.
func (r *Result) Explain(m *Map, name func(slot uint32) string) Explanation {
	ex := Explanation{
		Segment: r.Segment.String(), Calibrated: r.Calibrated, Threshold: r.Threshold.Z, MinExcess: r.Threshold.MinExcess,
		TargetFPR: r.Threshold.TargetFPR, Score: round2(r.Score), AimAssist: r.AimAssist,
		Map:      fmt.Sprintf("%s v%d", m.ID, m.Version),
		Features: append([]FeatureResult(nil), r.Features...),
		Knowledge: fmt.Sprintf("Per tick, the player's team is credited with everything any teammate could see through the %d occluders of %s v%d "+
			"(%.0f° cone, %.0f m), every sound within the game's audible radius, every spot, radar reveal and ping, and each enemy's last-known "+
			"position (an enemy within %.0f m of it, or reported in the last %.1f s, counts as known; %.0f s for movement). Scores compare the "+
			"player's aim, shots and movement against the true hidden positions and against the same enemies %s seconds away in time, which is "+
			"how often common angles and routes line up by habit. The combined score is the eligible scored features' z values added and "+
			"divided by the square root of their count.",
			len(m.occ), m.ID, m.Version, r.cfg.FOVDeg, r.cfg.ViewRange, r.cfg.KnownRadius, r.cfg.FreshSec, r.cfg.RouteFreshSec, shiftsText(r.cfg.ShiftsSec)),
		Policy: "Flag-only evidence for human review. It never triggers an automatic kick and counts as one evidence family (information use); a ban needs a second, independent family.",
	}
	for i := range ex.Features {
		f := &ex.Features[i]
		f.Z, f.RateTrue, f.RateNull = round2(f.Z), round3(f.RateTrue), round3(f.RateNull)
	}
	for _, mo := range r.Moments {
		mt := MomentText{Moment: mo}
		if mo.Kind != "approached_unseen_loot" {
			mt.Target = name(mo.TargetSlot)
		}
		mt.Text = momentText(mo, mt.Target)
		ex.Moments = append(ex.Moments, mt)
	}
	if len(r.Moments) > 0 && r.Moments[0].Replay != nil {
		rp := *r.Moments[0].Replay
		rp.Min, rp.Max, rp.Occluders = frame(m, rp)
		ex.Replay = &rp
		ex.ReplayNote = fmt.Sprintf("Top-down view of the first moment (%s): the player's path, the hidden %s, and where the crosshair pointed.",
			r.Moments[0].At, map[bool]string{true: "loot", false: "enemy's path"}[rp.TargetIsItem])
	}
	return ex
}

func shiftsText(s []float64) string {
	var parts []string
	for _, v := range s {
		if v > 0 {
			parts = append(parts, fmt.Sprintf("%g", v))
		}
	}
	return "±" + strings.Join(parts, ", ±")
}

func zoneOr(z, fallback string) string {
	if z == "" {
		return fallback
	}
	return "‘" + z + "’"
}

func momentText(m Moment, target string) string {
	where := zoneOr(m.TargetZone, "behind cover")
	from := zoneOr(m.ViewerZone, "their position")
	switch m.Kind {
	case "tracked_hidden":
		return fmt.Sprintf("From %s the crosshair stayed on %s, hidden %s %.0f m away, for %.1f s while they moved through %.0f° of bearing (mean error %.1f°). The team could not see them; %s.",
			from, target, where, m.DistanceM, m.DurationS, m.SweepDeg, m.MeanErrDeg, m.Known)
	case "shot_hidden":
		hit := "missed"
		if m.Hit {
			hit = "hit"
		}
		return fmt.Sprintf("From %s fired at %s, hidden %s %.0f m away, %.1f° off their position (%s). The team could not see them; %s.",
			from, target, where, m.DistanceM, m.MeanErrDeg, hit, m.Known)
	case "approached_hidden":
		return fmt.Sprintf("Moved straight toward %s, hidden %s, closing %.0f of %.0f m in %.1f s. The team could not see them; %s.",
			target, where, m.ClosedM, m.DistanceM, m.DurationS, m.Known)
	case "approached_unseen_loot":
		return fmt.Sprintf("Headed straight for high-tier loot item %d %s, closing %.0f of %.0f m in %.1f s; it was %s.",
			m.ItemID, where, m.ClosedM, m.DistanceM, m.DurationS, m.Known)
	}
	return m.Kind
}

// frame picks the area to draw and the occluders inside it.
func frame(m *Map, r Replay) (Vec2, Vec2, [][]Vec2) {
	lo, hi := Vec2{math.Inf(1), math.Inf(1)}, Vec2{math.Inf(-1), math.Inf(-1)}
	add := func(p Vec2) {
		lo.X, lo.Y = math.Min(lo.X, p.X), math.Min(lo.Y, p.Y)
		hi.X, hi.Y = math.Max(hi.X, p.X), math.Max(hi.Y, p.Y)
	}
	for _, p := range r.Viewer {
		add(p)
	}
	for _, p := range r.Target {
		add(p)
	}
	if math.IsInf(lo.X, 0) {
		return m.Min, m.Max, m.Occluders()
	}
	const pad = 12.0
	lo, hi = Vec2{lo.X - pad, lo.Y - pad}, Vec2{hi.X + pad, hi.Y + pad}
	// Small maps are drawn whole, which reads better than a crop.
	if m.Max.X-m.Min.X < 120 && m.Max.Y-m.Min.Y < 120 {
		lo, hi = Vec2{math.Min(lo.X, m.Min.X), math.Min(lo.Y, m.Min.Y)}, Vec2{math.Max(hi.X, m.Max.X), math.Max(hi.Y, m.Max.Y)}
	}
	var occ [][]Vec2
	for i, poly := range m.Occluders() {
		if len(occ) >= 256 || !m.TallOccluder(i, 1.2) {
			continue
		}
		for _, p := range poly {
			if p.X >= lo.X && p.X <= hi.X && p.Y >= lo.Y && p.Y <= hi.Y {
				occ = append(occ, poly)
				break
			}
		}
	}
	return lo, hi, occ
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
func round3(v float64) float64 { return math.Round(v*1000) / 1000 }

// Summary is the one-line evidence summary.
func (r *Result) Summary() string {
	best := FeatureResult{}
	for _, f := range r.Features {
		if f.Eligible && f.Z >= best.Z {
			best = f
		}
	}
	return fmt.Sprintf("behaviour tracks hidden enemies or loot: %s z=%.1f (%.0f%% aligned vs %.0f%% by habit, %d samples), threshold %.1f for %s",
		best.Name, best.Z, 100*best.RateTrue, 100*best.RateNull, best.Samples, r.Threshold.Z, r.Segment)
}
