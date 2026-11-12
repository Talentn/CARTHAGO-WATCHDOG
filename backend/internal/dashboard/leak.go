package dashboard

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"

	"carthago/backend/internal/knowledge"
	"carthago/backend/internal/store"
)

// leakView is an information_leak evidence's explanation laid out for the page.
type leakView struct {
	Slot uint32
	knowledge.Explanation
	SVG *replaySVG
}

type svgPoint struct{ X, Y float64 }

type svgLine struct{ A, B svgPoint }

// replaySVG is the top-down replay in SVG user units: the map frame is scaled
// to replayWidth and Y is flipped so north is up. Everything is attributes, so
// it renders under the dashboard's style-src 'self' policy.
type replaySVG struct {
	W, H         float64
	Occluders    []string
	Viewer       string
	Target       string
	TargetIsItem bool
	Start, End   svgPoint
	TargetEnd    svgPoint
	Rays         []svgLine
	Scale        float64 // SVG units per metre
	ScaleBar     float64 // 10 m in SVG units
}

const replayWidth = 640.0

func parseLeak(e *store.Evidence) *leakView {
	if e == nil || e.Rule != "information_leak" || e.Raw == "" {
		return nil
	}
	var v leakView
	if err := json.Unmarshal([]byte(e.Raw), &struct {
		Slot *uint32 `json:"slot"`
		*knowledge.Explanation
	}{&v.Slot, &v.Explanation}); err != nil {
		return nil
	}
	if r := v.Replay; r != nil {
		v.SVG = layoutReplay(r)
	}
	return &v
}

func layoutReplay(r *knowledge.Replay) *replaySVG {
	w, h := r.Max.X-r.Min.X, r.Max.Y-r.Min.Y
	if w <= 0 || h <= 0 || math.IsInf(w, 0) || math.IsInf(h, 0) {
		return nil
	}
	k := replayWidth / w
	if h*k > 480 {
		k = 480 / h
	}
	pt := func(p knowledge.Vec2) svgPoint {
		return svgPoint{round1((p.X - r.Min.X) * k), round1((r.Max.Y - p.Y) * k)}
	}
	poly := func(ps []knowledge.Vec2) string {
		var b strings.Builder
		for i, p := range ps {
			if i > 0 {
				b.WriteByte(' ')
			}
			q := pt(p)
			b.WriteString(strconv.FormatFloat(q.X, 'f', 1, 64))
			b.WriteByte(',')
			b.WriteString(strconv.FormatFloat(q.Y, 'f', 1, 64))
		}
		return b.String()
	}
	s := &replaySVG{W: round1(w * k), H: round1(h * k), TargetIsItem: r.TargetIsItem, Scale: k, ScaleBar: round1(10 * k)}
	for _, o := range r.Occluders {
		s.Occluders = append(s.Occluders, poly(o))
	}
	s.Viewer, s.Target = poly(r.Viewer), poly(r.Target)
	if n := len(r.Viewer); n > 0 {
		s.Start, s.End = pt(r.Viewer[0]), pt(r.Viewer[n-1])
	}
	if n := len(r.Target); n > 0 {
		s.TargetEnd = pt(r.Target[n-1])
	}
	for _, ray := range r.Rays {
		s.Rays = append(s.Rays, svgLine{pt(ray[0]), pt(ray[1])})
	}
	return s
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

func leakOf(evs []store.Evidence) []*leakView {
	var out []*leakView
	for i := range evs {
		if v := parseLeak(&evs[i]); v != nil {
			out = append(out, v)
		}
	}
	return out
}

func fixed(digits int, f float64) string { return strconv.FormatFloat(f, 'f', digits, 64) }
