package main

import (
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"text/tabwriter"

	"carthago/backend/internal/oracle/train"
)

func init() {
	commands["curve"] = command{runCurve, "learning curves: how the behaviour model's quality depends on the number of training sessions"}
}

// runCurve retrains the behaviour model on subsets of the training sessions and measures
// each on the same held-out sessions. It answers "how many labelled sessions are enough"
// for the synthetic data; real play is noisier, so read the answer as a lower bound.
func runCurve(args []string) error {
	fs := flag.NewFlagSet("curve", flag.ExitOnError)
	d := addDataFlags(fs, 320, 1)
	repeats := fs.Int("repeats", 5, "random subsets per size, averaged")
	_ = fs.Parse(args)
	rows, _, err := d.rows(false)
	if err != nil {
		return err
	}
	fit, calib, test := train.Split(rows)
	var honest, cheat []train.Row
	for _, r := range fit {
		if r.Cheating {
			cheat = append(cheat, r)
		} else {
			honest = append(honest, r)
		}
	}
	if len(honest) == 0 || len(cheat) == 0 {
		return errors.New("the dataset needs both honest and cheating sessions")
	}
	type point struct{ auc, recall, fpr float64 }
	measure := func(nh, nc int) (point, error) {
		var sum point
		for rep := range *repeats {
			rng := rand.New(rand.NewSource(int64(1000*rep + nh + 7*nc)))
			pick := func(src []train.Row, n int) []train.Row {
				idx := rng.Perm(len(src))[:min(n, len(src))]
				out := make([]train.Row, 0, len(idx))
				for _, i := range idx {
					out = append(out, src[i])
				}
				return out
			}
			sub := append(pick(honest, nh), pick(cheat, nc)...)
			p := train.DefaultParams()
			// Small subsets cannot fill the default leaves.
			p.MinLeaf = max(5, min(p.MinLeaf, len(sub)/40))
			m, err := train.Fit(sub, p)
			if err != nil {
				return point{}, err
			}
			rep := train.Evaluate(m, train.Thresholds(m, calib, 0.05, 0.005), test)
			caught := 0
			for _, pr := range rep.Profiles {
				caught += pr.Review
			}
			sum.auc += rep.AUC
			sum.recall += float64(caught) / float64(max(1, rep.Cheating))
			sum.fpr += float64(rep.HonestReview) / float64(max(1, rep.Honest))
		}
		n := float64(*repeats)
		return point{sum.auc / n, sum.recall / n, sum.fpr / n}, nil
	}
	fmt.Printf("%d honest and %d cheating training sessions; measured on %d held-out sessions; thresholds chosen on %d; %d random subsets per row\n",
		len(honest), len(cheat), len(test), len(calib), *repeats)
	table := func(title string, sizes [][2]int) error {
		fmt.Printf("\n%s\n", title)
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "Honest\tCheating\tAUC\tCheating sessions in review\tHonest sessions in review")
		for _, s := range sizes {
			p, err := measure(s[0], s[1])
			if err != nil {
				return err
			}
			fmt.Fprintf(tw, "%d\t%d\t%.4f\t%.1f%%\t%.2f%%\n", min(s[0], len(honest)), min(s[1], len(cheat)), p.auc, 100*p.recall, 100*p.fpr)
		}
		return tw.Flush()
	}
	all := 1 << 30
	if err := table("Both classes grow together (about 70% honest)", [][2]int{{35, 15}, {70, 30}, {140, 60}, {280, 120}, {560, 240}, {1120, 480}, {all, all}}); err != nil {
		return err
	}
	if err := table("All honest sessions, fewer cheating ones", [][2]int{{all, 12}, {all, 25}, {all, 50}, {all, 100}, {all, 200}, {all, 400}, {all, all}}); err != nil {
		return err
	}
	return table("All cheating sessions, fewer honest ones", [][2]int{{25, all}, {50, all}, {100, all}, {200, all}, {400, all}, {800, all}, {all, all}})
}
