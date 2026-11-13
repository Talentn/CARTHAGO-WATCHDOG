package train

import (
	"fmt"
	"io"
	"math"
	"sort"
	"text/tabwriter"

	"carthago/backend/internal/knowledge/synth"
	"carthago/backend/internal/oracle"
)

// Report is the evaluation of a model on held-out synthetic sessions.
type Report struct {
	Sessions, Honest, Cheating int
	AUC, Brier, LogLoss        float64
	Thresholds                 oracle.Thresholds
	// Honest sessions at or above each threshold, with the one-sided 95% upper bound on
	// the true rate (Clopper-Pearson) that this many sessions can support.
	HonestWatch, HonestReview           int
	HonestWatchBound, HonestReviewBound float64
	// The rules alone on the same sessions: honest sessions with evidence of medium
	// severity or above.
	HonestRules      int
	HonestRulesBound float64
	Profiles         []ProfileRow
	Reliability      []ReliabilityRow
	// ClientOnly covers the sessions that played no match.
	ClientOnly struct{ Honest, HonestReview, Cheating, CheatingReview int }
}

// ProfileRow is one cheating profile: how many sessions the model sends to review or
// watch, how many the rules flag, and how many either does.
type ProfileRow struct {
	Profile                      string
	N                            int
	Review, Watch, Rules, Either int
	MeanScore                    float64
}

// ReliabilityRow compares the score with what happened, for sessions in one score range.
type ReliabilityRow struct {
	Lo, Hi    float64
	N         int
	MeanScore float64
	Observed  float64 // share of the sessions that were cheating
}

// Evaluate measures m on rows it was neither trained nor calibrated on.
func Evaluate(m *oracle.Model, t oracle.Thresholds, rows []Row) Report {
	rep := Report{Sessions: len(rows), Thresholds: t}
	scores := make([]float64, len(rows))
	by := map[string]*ProfileRow{}
	edges := []float64{0, 0.02, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 0.95, 1.0000001}
	rel := make([]ReliabilityRow, len(edges)-1)
	for i := range rel {
		rel[i].Lo, rel[i].Hi = edges[i], math.Min(1, edges[i+1])
	}
	for i := range rows {
		r := &rows[i]
		s, _ := m.Score(r.Vector)
		scores[i] = s
		y := 0.0
		if r.Cheating {
			y = 1
		}
		rep.Brier += (s - y) * (s - y)
		rep.LogLoss -= y*math.Log(math.Max(s, 1e-9)) + (1-y)*math.Log(math.Max(1-s, 1e-9))
		for k := range rel {
			if s >= edges[k] && s < edges[k+1] {
				rel[k].N++
				rel[k].MeanScore += s
				rel[k].Observed += y
			}
		}
		review, watch := s >= t.Review, s >= t.Watch
		if !r.Cheating {
			rep.Honest++
			rep.HonestReview += b2i(review)
			rep.HonestWatch += b2i(watch)
			rep.HonestRules += b2i(r.RuleFlag)
			if !r.InMatch {
				rep.ClientOnly.Honest++
				rep.ClientOnly.HonestReview += b2i(review)
			}
			continue
		}
		rep.Cheating++
		if !r.InMatch {
			rep.ClientOnly.Cheating++
			rep.ClientOnly.CheatingReview += b2i(review)
		}
		p := by[r.Profile]
		if p == nil {
			p = &ProfileRow{Profile: r.Profile}
			by[r.Profile] = p
		}
		p.N++
		p.MeanScore += s
		p.Review += b2i(review)
		p.Watch += b2i(watch)
		p.Rules += b2i(r.RuleFlag)
		p.Either += b2i(review || r.RuleFlag)
	}
	if n := float64(len(rows)); n > 0 {
		rep.Brier /= n
		rep.LogLoss /= n
	}
	rep.AUC = auc(rows, scores)
	rep.HonestWatchBound = synth.FPRBound(rep.HonestWatch, rep.Honest)
	rep.HonestReviewBound = synth.FPRBound(rep.HonestReview, rep.Honest)
	rep.HonestRulesBound = synth.FPRBound(rep.HonestRules, rep.Honest)
	for _, name := range CheatProfiles {
		if p := by[name]; p != nil {
			p.MeanScore /= float64(p.N)
			rep.Profiles = append(rep.Profiles, *p)
		}
	}
	for _, r := range rel {
		if r.N > 0 {
			r.MeanScore /= float64(r.N)
			r.Observed /= float64(r.N)
			rep.Reliability = append(rep.Reliability, r)
		}
	}
	return rep
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// auc is the chance that a cheating session scores above an honest one (ties count half).
func auc(rows []Row, scores []float64) float64 {
	idx := make([]int, len(rows))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return scores[idx[a]] < scores[idx[b]] })
	var rankSum float64
	pos, neg := 0, 0
	for i := 0; i < len(idx); {
		j := i
		for j < len(idx) && scores[idx[j]] == scores[idx[i]] {
			j++
		}
		avg := float64(i+j+1) / 2 // mean 1-based rank of the tie group
		for k := i; k < j; k++ {
			if rows[idx[k]].Cheating {
				rankSum += avg
				pos++
			} else {
				neg++
			}
		}
		i = j
	}
	if pos == 0 || neg == 0 {
		return math.NaN()
	}
	return (rankSum - float64(pos)*float64(pos+1)/2) / (float64(pos) * float64(neg))
}

func pct(a, b int) string {
	if b == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(a)/float64(b))
}

// Write prints the report as text.
func (r Report) Write(w io.Writer) {
	fmt.Fprintf(w, "Held-out synthetic sessions: %d (%d honest, %d cheating)\n", r.Sessions, r.Honest, r.Cheating)
	fmt.Fprintf(w, "AUC %.4f   Brier %.4f   log loss %.4f\n", r.AUC, r.Brier, r.LogLoss)
	fmt.Fprintf(w, "Thresholds: watch %.3f, review %.3f\n\n", r.Thresholds.Watch, r.Thresholds.Review)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "Honest sessions flagged\tcount\trate\t95% upper bound")
	fmt.Fprintf(tw, "model, review band\t%d/%d\t%s\t%.2f%%\n", r.HonestReview, r.Honest, pct(r.HonestReview, r.Honest), 100*r.HonestReviewBound)
	fmt.Fprintf(tw, "model, watch band or above\t%d/%d\t%s\t%.2f%%\n", r.HonestWatch, r.Honest, pct(r.HonestWatch, r.Honest), 100*r.HonestWatchBound)
	fmt.Fprintf(tw, "rules alone (medium or above)\t%d/%d\t%s\t%.2f%%\n", r.HonestRules, r.Honest, pct(r.HonestRules, r.Honest), 100*r.HonestRulesBound)
	tw.Flush()
	fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "Cheating profile\tn\tmodel review\tmodel watch+\trules\treview or rules\tmean score")
	var tot ProfileRow
	for _, p := range r.Profiles {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n", p.Profile, p.N, pct(p.Review, p.N), pct(p.Watch, p.N), pct(p.Rules, p.N), pct(p.Either, p.N), p.MeanScore)
		tot.N, tot.Review, tot.Watch, tot.Rules, tot.Either = tot.N+p.N, tot.Review+p.Review, tot.Watch+p.Watch, tot.Rules+p.Rules, tot.Either+p.Either
	}
	fmt.Fprintf(tw, "all\t%d\t%s\t%s\t%s\t%s\t\n", tot.N, pct(tot.Review, tot.N), pct(tot.Watch, tot.N), pct(tot.Rules, tot.N), pct(tot.Either, tot.N))
	tw.Flush()
	fmt.Fprintf(w, "\nSessions without a match: honest in review %d/%d, cheating in review %d/%d\n\n",
		r.ClientOnly.HonestReview, r.ClientOnly.Honest, r.ClientOnly.CheatingReview, r.ClientOnly.Cheating)
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "Score range\tsessions\tmean score\tshare cheating")
	for _, b := range r.Reliability {
		fmt.Fprintf(tw, "%.2f-%.2f\t%d\t%.3f\t%.3f\n", b.Lo, b.Hi, b.N, b.MeanScore, b.Observed)
	}
	tw.Flush()
}

// Importance is each feature's mean absolute contribution over rows, largest first.
func Importance(m *oracle.Model, rows []Row) []oracle.Signal {
	var sum [oracle.NumFeatures]float64
	for i := range rows {
		_, c := m.Score(rows[i].Vector)
		for f := range c {
			sum[f] += math.Abs(c[f])
		}
	}
	out := make([]oracle.Signal, 0, oracle.NumFeatures)
	for f, s := range sum {
		out = append(out, oracle.Signal{Key: oracle.Features[f].Key, Label: oracle.Features[f].Label, Family: oracle.Features[f].Family, Effect: s / float64(max(1, len(rows)))})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Effect > out[j].Effect })
	return out
}
