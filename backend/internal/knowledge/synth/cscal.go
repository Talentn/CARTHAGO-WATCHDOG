package synth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge"
)

// CSBatches plays a Counter-Strike match and converts it with the real bridge
// (carthago-cs16-bridge convert), which reads the map file from dir/maps. dir is scratch.
func CSBatches(bridge, dir string, spec Spec) ([]*pb.GameplayBatch, error) {
	maps := filepath.Join(dir, "maps")
	if err := os.MkdirAll(maps, 0o755); err != nil {
		return nil, err
	}
	bsp := filepath.Join(maps, CSYardID+".bsp")
	if _, err := os.Stat(bsp); err != nil {
		tmp, err := os.CreateTemp(maps, "bsp-*")
		if err != nil {
			return nil, err
		}
		if err := errors.Join(WriteCSYardBSP(tmp), tmp.Close(), os.Rename(tmp.Name(), bsp)); err != nil {
			return nil, err
		}
	}
	stream, out := filepath.Join(dir, spec.MatchID+".stream"), filepath.Join(dir, spec.MatchID+".batches")
	defer os.Remove(stream)
	defer os.Remove(out)
	f, err := os.Create(stream)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(WriteCS16Stream(f, spec), f.Close()); err != nil {
		return nil, err
	}
	if msg, err := exec.Command(bridge, "convert", stream, "--out", out, "--maps", maps).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%s convert: %w: %s", bridge, err, strings.TrimSpace(string(msg)))
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	var batches []*pb.GameplayBatch
	for len(raw) >= 4 {
		n := int(binary.LittleEndian.Uint32(raw))
		if n > len(raw)-4 {
			return nil, errors.New("truncated batch file")
		}
		b := &pb.GameplayBatch{}
		if err := proto.Unmarshal(raw[4:4+n], b); err != nil {
			return nil, err
		}
		batches, raw = append(batches, b), raw[4+n:]
	}
	return batches, nil
}

// CSRun is one match scored the way the gateway scores it.
type CSRun struct {
	Results []knowledge.Result
	Alerts  map[uint32]float64 // slot -> match seconds at which the live rule fired
	Strong  map[uint32]int     // strong windows per slot
	Best    map[uint32]float64 // best window score per slot
	Windows int
	InSolid float64 // share of player positions inside the map's walls
}

// CSScore scores converted batches: the map comes from the first batch, as it does at the
// gateway.
func CSScore(batches []*pb.GameplayBatch, cfg knowledge.Config, alert knowledge.AlertConfig) (*CSRun, error) {
	if len(batches) == 0 || batches[0].MapGeometry == nil {
		return nil, errors.New("the first batch carries no map geometry")
	}
	m, err := knowledge.Compile(batches[0].MapGeometry)
	if err != nil {
		return nil, err
	}
	sc := knowledge.NewScorer(cfg, m, batches[0].Mode, batches[0].TickRate)
	al := knowledge.NewAlerter(alert, sc)
	run := &CSRun{Alerts: map[uint32]float64{}, Strong: map[uint32]int{}}
	var eyes, inside int
	for _, b := range batches {
		for _, t := range b.Motion {
			var x, y, z int64
			for i := range min(len(t.XCm), len(t.YCm), len(t.ZCm)) {
				x, y, z = x+int64(t.XCm[i]), y+int64(t.YCm[i]), z+int64(t.ZCm[i])
				eyes++
				if m.Solid(knowledge.Vec3{X: float64(x) / 100, Y: float64(y) / 100, Z: float64(z) / 100}) {
					inside++
				}
			}
		}
		sc.Add(b)
		for _, h := range al.Step() {
			run.Alerts[h.Slot] = sc.Analysed()
		}
	}
	run.Results = sc.Finish()
	for _, r := range run.Results {
		run.Strong[r.Slot] = al.Strong(r.Slot)
	}
	run.Best, run.Windows = al.Best, al.Windows()
	if eyes > 0 {
		run.InSolid = float64(inside) / float64(eyes)
	}
	return run, nil
}

// CSCalibration is a calibration run on Counter-Strike matches.
type CSCalibration struct {
	Setting             string
	Matches             int
	Seconds             int
	Review              knowledge.Threshold
	Alert               knowledge.AlertConfig
	Honest              int        // honest player-matches
	Flagged             int        // of them flagged for review at the end of the match
	Strong1             int        // of them with at least one strong window
	Alerted             int        // of them reaching the live rule
	HonestP             [3]float64 // median, 99th percentile and maximum match score
	WindowP             [3]float64 // the same for each honest player's best window
	Informed            int
	Caught              int        // flagged for review
	InfAlert            int        // reached the live rule
	AlertAt             float64    // median match seconds at which they did
	InfP                [2]float64 // 10th percentile and median match score
	Subtle              int
	SubCaught, SubAlert int
	InSolid             float64 // largest share of positions inside walls in any match
}

// CSCalibrate plays matches on the Counter-Strike yard through the bridge at path bridge
// and reports how often honest players are flagged and alerted, and informed ones are.
// With bots, slot 1 is a person and the rest are bots of the game (nobody dead calls out
// positions); without, all ten are people, the dead ones watch and talk, and the bridge
// credits their team for it.
func CSCalibrate(bridge string, matches, seconds int, seed uint64, cfg knowledge.Config, alert knowledge.AlertConfig, bots bool) (*CSCalibration, error) {
	dir, err := os.MkdirTemp("", "carthago-cs-cal-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	// The map file is written before the workers start.
	if _, err := CSBatches(bridge, dir, Spec{MatchID: "warm", Seconds: 1, Seed: 1, Players: CSPlayers(nil, bots), Mode: pb.GameMode_GAME_MODE_ROUND_SHOOTER}); err != nil {
		return nil, err
	}
	type out struct {
		spec Spec
		run  *CSRun
		err  error
	}
	jobs := make(chan int)
	results := make(chan out)
	var wg sync.WaitGroup
	for range max(1, runtime.GOMAXPROCS(0)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				spec := Spec{MatchID: fmt.Sprintf("cscal-%d", i), Mode: pb.GameMode_GAME_MODE_ROUND_SHOOTER, Seconds: seconds,
					Seed: seed + uint64(i)*7919, Players: CSPlayers(calibrationRoles[i%len(calibrationRoles)], bots), CS: true}
				batches, err := CSBatches(bridge, dir, spec)
				var run *CSRun
				if err == nil {
					run, err = CSScore(batches, cfg, alert)
				}
				results <- out{spec, run, err}
			}
		}()
	}
	go func() {
		for i := range matches {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	c := &CSCalibration{Setting: "people", Matches: matches, Seconds: seconds, Alert: alert}
	if bots {
		c.Setting = "bots"
	}
	var honest, window, informed, alertAt []float64
	var first error
	for o := range results {
		if o.err != nil {
			if first == nil {
				first = o.err
			}
			continue
		}
		c.InSolid = max(c.InSolid, o.run.InSolid)
		roles := map[uint32]Role{}
		for _, p := range o.spec.Players {
			roles[p.Slot] = p.Role
		}
		for _, r := range o.run.Results {
			c.Review = r.Threshold
			_, alerted := o.run.Alerts[r.Slot]
			switch roles[r.Slot] {
			case RoleInformed:
				c.Informed++
				c.Caught += b2i(r.Flagged)
				c.InfAlert += b2i(alerted)
				informed = append(informed, r.Score)
				if alerted {
					alertAt = append(alertAt, o.run.Alerts[r.Slot])
				}
			case RoleSubtle:
				c.Subtle++
				c.SubCaught += b2i(r.Flagged)
				c.SubAlert += b2i(alerted)
			default:
				c.Honest++
				c.Flagged += b2i(r.Flagged)
				c.Strong1 += b2i(o.run.Strong[r.Slot] > 0)
				c.Alerted += b2i(alerted)
				honest = append(honest, r.Score)
				window = append(window, o.run.Best[r.Slot])
			}
		}
	}
	if first != nil {
		return nil, first
	}
	c.HonestP = [3]float64{quantile(honest, 0.5), quantile(honest, 0.99), quantile(honest, 1)}
	c.WindowP = [3]float64{quantile(window, 0.5), quantile(window, 0.99), quantile(window, 1)}
	c.InfP = [2]float64{quantile(informed, 0.1), quantile(informed, 0.5)}
	sort.Float64s(alertAt)
	c.AlertAt = quantile(alertAt, 0.5)
	return c, nil
}

// WriteCSCalibration prints calibration runs as a table.
func WriteCSCalibration(w io.Writer, runs []*CSCalibration) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "teammates\tmatches\tminutes\thonest\tflagged\tflag_rate\tscore_p50\tscore_p99\tscore_max\tstrong_window\talerted\talert_rate\twindow_p99\twindow_max\tinformed\tflagged\talerted\talert_at_s\tscore_p10\tscore_p50\tsubtle\tflagged\talerted\tin_walls")
	for _, c := range runs {
		alertAt := "-"
		if c.InfAlert > 0 {
			alertAt = fmt.Sprintf("%.0f", c.AlertAt)
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%.4f\t%.2f\t%.2f\t%.2f\t%d\t%d\t%.4f\t%.2f\t%.2f\t%d\t%d\t%d\t%s\t%.2f\t%.2f\t%d\t%d\t%d\t%.4f\n",
			c.Setting, c.Matches, c.Seconds/60, c.Honest, c.Flagged, ratio(c.Flagged, c.Honest), c.HonestP[0], c.HonestP[1], c.HonestP[2],
			c.Strong1, c.Alerted, ratio(c.Alerted, c.Honest), c.WindowP[1], c.WindowP[2],
			c.Informed, c.Caught, c.InfAlert, alertAt, c.InfP[0], c.InfP[1], c.Subtle, c.SubCaught, c.SubAlert, c.InSolid)
	}
	return tw.Flush()
}
