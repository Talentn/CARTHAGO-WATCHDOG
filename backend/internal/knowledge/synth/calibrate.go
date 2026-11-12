package synth

import (
	"fmt"
	"io"
	"math"
	"runtime"
	"sort"
	"sync"
	"text/tabwriter"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge"
)

// Score runs one simulated match through a scorer on the yard map.
func Score(spec Spec, cfg knowledge.Config) []knowledge.Result {
	m := YardMap()
	var sc *knowledge.Scorer
	for _, b := range Batches(spec) {
		if sc == nil {
			sc = knowledge.NewScorer(cfg, m, b.Mode, b.TickRate)
		}
		sc.Add(b)
	}
	if sc == nil {
		return nil
	}
	return sc.Finish()
}

// CalibrationRow is one segment of a calibration run.
type CalibrationRow struct {
	Segment   knowledge.Segment
	Threshold knowledge.Threshold
	Honest    int // legit, prefire, sound and teamcall player-matches
	FalsePos  int
	Informed  int
	Caught    int
	Subtle    int
	SubtleHit int
	HonestP50 float64
	HonestP99 float64
	HonestMax float64
	InfP10    float64 // tenth percentile of informed scores

	// Decoy rule, filled when the run had decoys on. Every player is sent decoys, so
	// every honest player-match is a decoy trial.
	Decoy DecoyRow
}

// DecoyRow is the decoy rule's half of a calibration row.
type DecoyRow struct {
	Threshold knowledge.Threshold
	Honest    int
	FalsePos  int
	Informed  int
	Caught    int
	Subtle    int
	SubtleHit int
	HonestP99 float64
	HonestMax float64
	InfP10    float64
	Received  float64 // mean decoys sent per player-match
	Exposed   int     // decoy samples a recipient could have seen; 0 when placement is right
}

func (r DecoyRow) Recall() float64       { return ratio(r.Caught, r.Informed) }
func (r DecoyRow) SubtleRecall() float64 { return ratio(r.SubtleHit, r.Subtle) }

// FPRBound is the 95% one-sided upper bound on a false-flag rate after falsePos flags in
// honest trials (Poisson): with no flags it is about 3/honest, so showing a 1e-3 rate takes
// about 3,000 honest player-matches per segment.
func FPRBound(falsePos, honest int) float64 {
	if honest == 0 {
		return 1
	}
	cdf := func(lambda float64) float64 {
		term, sum := math.Exp(-lambda), 0.0
		for i := 0; i <= falsePos; i++ {
			if i > 0 {
				term *= lambda / float64(i)
			}
			sum += term
		}
		return sum
	}
	lo, hi := 0.0, float64(falsePos)+50
	for range 100 {
		mid := (lo + hi) / 2
		if cdf(mid) > 0.05 {
			lo = mid
		} else {
			hi = mid
		}
	}
	return math.Min(1, hi/float64(honest))
}

func (r CalibrationRow) FPR() float64 { return ratio(r.FalsePos, r.Honest) }

func (r CalibrationRow) Recall() float64 { return ratio(r.Caught, r.Informed) }

func (r CalibrationRow) SubtleRecall() float64 { return ratio(r.SubtleHit, r.Subtle) }

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// calibrationRoles puts one informed and one subtle player in every match and
// fills the rest with honest roles, including the noisy ones.
var calibrationRoles = [][]Role{
	{RoleLegit, RoleInformed, RolePrefire, RoleSound, RoleTeamCall, RoleSubtle, RoleLegit, RolePrefire, RoleSound, RoleTeamCall},
	{RoleInformed, RoleLegit, RoleSound, RolePrefire, RoleSubtle, RoleTeamCall, RoleLegit, RoleSound, RolePrefire, RoleLegit},
}

// Calibrate simulates matches per mode and reports, per segment, how often
// honest players flag and how often informed ones do. Every third player uses
// a controller with aim assist.
func Calibrate(modes []pb.GameMode, matches, seconds int, seed uint64, cfg knowledge.Config, decoys bool) []CalibrationRow {
	type job struct {
		mode pb.GameMode
		i    int
	}
	type out struct {
		spec Spec
		res  []knowledge.Result
	}
	jobs := make(chan job)
	results := make(chan out)
	var wg sync.WaitGroup
	for range max(1, runtime.GOMAXPROCS(0)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				ps := DefaultPlayers(j.mode, 1, calibrationRoles[j.i%len(calibrationRoles)])
				for k := range ps {
					if (k+j.i)%3 == 2 {
						ps[k].Device, ps[k].AimAssist = pb.InputDevice_INPUT_DEVICE_CONTROLLER, true
					}
				}
				spec := Spec{MatchID: fmt.Sprintf("cal-%d-%d", j.mode, j.i), Mode: j.mode, TickRate: 64, Seconds: seconds,
					Seed: seed + uint64(j.i)*7919 + uint64(j.mode)*104729, Players: ps, Decoys: decoys}
				results <- out{spec, Score(spec, cfg)}
			}
		}()
	}
	go func() {
		for _, mode := range modes {
			for i := range matches {
				jobs <- job{mode, i}
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	rows := map[knowledge.Segment]*CalibrationRow{}
	honest := map[knowledge.Segment][]float64{}
	informed := map[knowledge.Segment][]float64{}
	dHonest := map[knowledge.Segment][]float64{}
	dInformed := map[knowledge.Segment][]float64{}
	dReceived := map[knowledge.Segment]int{}
	dTrials := map[knowledge.Segment]int{}
	for o := range results {
		roles := map[uint32]Role{}
		for _, p := range o.spec.Players {
			roles[p.Slot] = p.Role
		}
		for _, r := range o.res {
			row := rows[r.Segment]
			if row == nil {
				row = &CalibrationRow{Segment: r.Segment, Threshold: r.Threshold}
				rows[r.Segment] = row
			}
			if d := r.Decoy; d != nil {
				row.Decoy.Threshold = d.Threshold
				row.Decoy.Exposed += d.Exposed
				dReceived[r.Segment] += d.Received
				dTrials[r.Segment]++
				switch roles[r.Slot] {
				case RoleInformed:
					row.Decoy.Informed++
					row.Decoy.Caught += b2i(d.Flagged)
					dInformed[r.Segment] = append(dInformed[r.Segment], d.Score)
				case RoleSubtle:
					row.Decoy.Subtle++
					row.Decoy.SubtleHit += b2i(d.Flagged)
				default:
					row.Decoy.Honest++
					row.Decoy.FalsePos += b2i(d.Flagged)
					dHonest[r.Segment] = append(dHonest[r.Segment], d.Score)
				}
			}
			switch roles[r.Slot] {
			case RoleInformed:
				row.Informed++
				row.Caught += b2i(r.Flagged)
				informed[r.Segment] = append(informed[r.Segment], r.Score)
			case RoleSubtle:
				row.Subtle++
				row.SubtleHit += b2i(r.Flagged)
			default:
				row.Honest++
				row.FalsePos += b2i(r.Flagged)
				honest[r.Segment] = append(honest[r.Segment], r.Score)
			}
		}
	}
	var list []CalibrationRow
	for seg, row := range rows {
		row.HonestP50, row.HonestP99, row.HonestMax = quantile(honest[seg], 0.5), quantile(honest[seg], 0.99), quantile(honest[seg], 1)
		row.InfP10 = quantile(informed[seg], 0.1)
		if n := dTrials[seg]; n > 0 {
			row.Decoy.HonestP99, row.Decoy.HonestMax = quantile(dHonest[seg], 0.99), quantile(dHonest[seg], 1)
			row.Decoy.InfP10 = quantile(dInformed[seg], 0.1)
			row.Decoy.Received = float64(dReceived[seg]) / float64(n)
		}
		list = append(list, *row)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Segment.String() < list[j].Segment.String() })
	return list
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func quantile(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	return s[int(math.Round(q*float64(len(s)-1)))]
}

// WriteCalibration prints a calibration run as a table.
func WriteCalibration(w io.Writer, rows []CalibrationRow) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "segment\tz\tmin_excess\ttarget_fpr\thonest\tfalse_pos\tfpr\thonest_p50\thonest_p99\thonest_max\tinformed\trecall\tinformed_p10\tsubtle_recall")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%.1f\t%.2f\t%.0e\t%d\t%d\t%.4f\t%.2f\t%.2f\t%.2f\t%d\t%.2f\t%.2f\t%.2f\n",
			r.Segment, r.Threshold.Z, r.Threshold.MinExcess, r.Threshold.TargetFPR, r.Honest, r.FalsePos, r.FPR(),
			r.HonestP50, r.HonestP99, r.HonestMax, r.Informed, r.Recall(), r.InfP10, r.SubtleRecall())
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(rows) == 0 || rows[0].Decoy.Honest == 0 {
		return nil
	}
	fmt.Fprintln(w, "\ndecoy_reaction")
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "segment\tz\tdecoys_per_player\thonest\tfalse_pos\tfpr_95_bound\thonest_needed\thonest_p99\thonest_max\tinformed\trecall\tinformed_p10\tsubtle_recall\texposed_samples")
	for _, r := range rows {
		d := r.Decoy
		fmt.Fprintf(tw, "%s\t%.1f\t%.1f\t%d\t%d\t%.4f\t%.0f\t%.2f\t%.2f\t%d\t%.2f\t%.2f\t%.2f\t%d\n",
			r.Segment, d.Threshold.Z, d.Received, d.Honest, d.FalsePos, FPRBound(d.FalsePos, d.Honest), math.Ceil(3/d.Threshold.TargetFPR),
			d.HonestP99, d.HonestMax, d.Informed, d.Recall(), d.InfP10, d.SubtleRecall(), d.Exposed)
	}
	return tw.Flush()
}
