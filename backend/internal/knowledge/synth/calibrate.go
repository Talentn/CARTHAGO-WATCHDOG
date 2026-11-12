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
func Calibrate(modes []pb.GameMode, matches, seconds int, seed uint64, cfg knowledge.Config) []CalibrationRow {
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
					Seed: seed + uint64(j.i)*7919 + uint64(j.mode)*104729, Players: ps}
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
	return tw.Flush()
}
