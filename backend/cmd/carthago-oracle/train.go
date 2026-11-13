package main

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"carthago/backend/internal/oracle"
	"carthago/backend/internal/oracle/analyst"
	"carthago/backend/internal/oracle/train"
)

func init() {
	commands["train"] = command{runTrain, "train the behaviour model on synthetic telemetry and write a bundle"}
	commands["dataset"] = command{runDataset, "simulate synthetic sessions and save them for train, eval and bench"}
	commands["eval"] = command{runEval, "evaluate a bundle's behaviour model on synthetic sessions"}
	commands["info"] = command{runInfo, "print what a bundle contains"}
	commands["set"] = command{runSet, "change a bundle's thresholds, prompt version or local analyst model"}
}

type dataFlags struct {
	matches, minSec, maxSec, workers *int
	seed                             *uint64
	file                             *string
}

func addDataFlags(fs *flag.FlagSet, matches int, seed uint64) dataFlags {
	return dataFlags{
		matches: fs.Int("matches", matches, "synthetic matches to simulate (12 sessions each)"),
		minSec:  fs.Int("min-seconds", 480, "shortest simulated match"),
		maxSec:  fs.Int("max-seconds", 1200, "longest simulated match"),
		workers: fs.Int("workers", 0, "matches simulated at once (0 = one per CPU)"),
		seed:    fs.Uint64("seed", seed, "seed of the simulation"),
		file:    fs.String("dataset", "", "use sessions saved by `carthago-oracle dataset` instead of simulating"),
	}
}

type savedData struct {
	Options train.Options
	Rows    []train.Row
}

func (d dataFlags) options() train.Options {
	return train.Options{Matches: *d.matches, MinSeconds: *d.minSec, MaxSeconds: *d.maxSec, Seed: *d.seed, Workers: *d.workers}
}

func (d dataFlags) rows(keepEvidence bool) ([]train.Row, train.Options, error) {
	if *d.file != "" {
		f, err := os.Open(*d.file)
		if err != nil {
			return nil, train.Options{}, err
		}
		defer f.Close()
		var s savedData
		if err := gob.NewDecoder(f).Decode(&s); err != nil {
			return nil, train.Options{}, fmt.Errorf("%s: %w", *d.file, err)
		}
		return s.Rows, s.Options, nil
	}
	opt := d.options()
	opt.KeepEvidence = keepEvidence
	start := time.Now()
	last := time.Now()
	opt.Progress = func(done, total int) {
		if time.Since(last) > 10*time.Second || done == total {
			last = time.Now()
			fmt.Fprintf(os.Stderr, "simulated %d/%d matches (%s)\n", done, total, time.Since(start).Round(time.Second))
		}
	}
	rows, err := train.Generate(opt)
	opt.Progress = nil
	return rows, opt, err
}

func runDataset(args []string) error {
	fs := flag.NewFlagSet("dataset", flag.ExitOnError)
	d := addDataFlags(fs, 320, 1)
	out := fs.String("out", "", "file to write")
	evidence := fs.Bool("evidence", false, "keep each session's evidence (needed by bench)")
	fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	rows, opt, err := d.rows(*evidence)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	// gob cannot carry NaN-free guarantees or funcs; Progress is nil here.
	if err := gob.NewEncoder(f).Encode(savedData{opt, rows}); err != nil {
		f.Close()
		return err
	}
	fmt.Printf("%d sessions from %d matches written to %s\n", len(rows), opt.Matches, *out)
	return f.Close()
}

func runTrain(args []string) error {
	fs := flag.NewFlagSet("train", flag.ExitOnError)
	d := addDataFlags(fs, 320, 1)
	out := fs.String("out", "", "bundle directory to write (kept on the gateway host, outside the repository and any web root)")
	report := fs.String("report", "", "also write the evaluation to this file")
	watch := fs.Float64("watch-fpr", 0.05, "share of held-out honest sessions allowed in the watch band or above")
	review := fs.Float64("review-fpr", 0.005, "share of held-out honest sessions allowed in the review band")
	p := train.DefaultParams()
	fs.IntVar(&p.Rounds, "rounds", p.Rounds, "boosting rounds")
	fs.Float64Var(&p.LearningRate, "learning-rate", p.LearningRate, "learning rate")
	local := localModelFlags(fs)
	fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	rows, opt, err := d.rows(false)
	if err != nil {
		return err
	}
	tr, calib, test := train.Split(rows)
	m, err := train.Fit(tr, p)
	if err != nil {
		return err
	}
	m.Training = oracle.Training{Tool: "carthago-oracle train", Data: "synthetic (knowledge/synth with behaviour profiles)", Seed: opt.Seed,
		Matches: opt.Matches, MatchSeconds: opt.MaxSeconds, Rows: len(tr), Rounds: p.Rounds, LearningRate: p.LearningRate}
	for i := range tr {
		if tr[i].Cheating {
			m.Training.Cheating++
		} else {
			m.Training.Honest++
		}
	}
	data, err := m.Encode()
	if err != nil {
		return err
	}
	th := train.Thresholds(m, calib, *watch, *review)
	pr := analyst.DefaultPrompts()
	man, err := oracle.WriteBundle(*out, oracle.Contents{Model: data, Thresholds: th, PromptVersion: pr.Version, SchemaVersion: analyst.VerdictSchema,
		SystemPrompt: pr.System, CasePrompt: pr.Case, LocalModel: local.ref()})
	if err != nil {
		return err
	}
	fmt.Printf("bundle %s written to %s\nbehaviour model %s (feature version %d), trained on %d sessions, thresholds chosen on %d\n\n",
		man.BundleID, *out, man.Behaviour.ID, man.Behaviour.FeatureVersion, len(tr), len(calib))
	rep := train.Evaluate(m, th, test)
	rep.Write(os.Stdout)
	writeImportance(os.Stdout, m, test)
	if *report != "" {
		f, err := os.Create(*report)
		if err != nil {
			return err
		}
		defer f.Close()
		fmt.Fprintf(f, "bundle %s, behaviour model %s, seed %d, %d matches\n\n", man.BundleID, man.Behaviour.ID, opt.Seed, opt.Matches)
		rep.Write(f)
		writeImportance(f, m, test)
	}
	return nil
}

func writeImportance(w io.Writer, m *oracle.Model, rows []train.Row) {
	fmt.Fprintln(w, "\nMean absolute contribution per signal (log-odds):")
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, s := range train.Importance(m, rows) {
		fmt.Fprintf(tw, "%s\t%.3f\n", s.Key, s.Effect)
	}
	tw.Flush()
}

func runEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	d := addDataFlags(fs, 120, 1009)
	dir := fs.String("bundle", "", "bundle directory")
	profiles := fs.Bool("features", false, "also print each profile's feature medians")
	fs.Parse(args)
	b, err := oracle.LoadBundle(*dir)
	if err != nil {
		return err
	}
	rows, opt, err := d.rows(false)
	if err != nil {
		return err
	}
	if *d.file != "" {
		// A saved dataset may be the one the model was trained on: use its test fifth.
		_, _, rows = train.Split(rows)
	} else if opt.Seed == b.Model.Training.Seed {
		return errors.New("evaluate on a different seed than the model was trained with")
	}
	fmt.Printf("bundle %s, behaviour model %s\n\n", b.Manifest.BundleID, b.Manifest.Behaviour.ID)
	train.Evaluate(b.Model, b.Manifest.Thresholds, rows).Write(os.Stdout)
	writeImportance(os.Stdout, b.Model, rows)
	if *profiles {
		writeFeatures(os.Stdout, rows)
	}
	return nil
}

// writeFeatures prints, per profile, how often each feature is known and its median.
func writeFeatures(w io.Writer, rows []train.Row) {
	by := map[string][]train.Row{}
	for _, r := range rows {
		by[r.Profile] = append(by[r.Profile], r)
	}
	names := append([]string{train.Honest}, train.CheatProfiles...)
	fmt.Fprintln(w, "\nFeature medians per profile (share of sessions where the value is known):")
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprint(tw, "feature")
	for _, n := range names {
		fmt.Fprintf(tw, "\t%s", n)
	}
	fmt.Fprintln(tw)
	for f := range oracle.NumFeatures {
		fmt.Fprint(tw, oracle.Features[f].Key)
		for _, n := range names {
			var xs []float64
			for _, r := range by[n] {
				if x := r.Vector[f]; !math.IsNaN(x) {
					xs = append(xs, x)
				}
			}
			if len(xs) == 0 {
				fmt.Fprint(tw, "\t-")
				continue
			}
			sort.Float64s(xs)
			fmt.Fprintf(tw, "\t%.3g (%.0f%%)", xs[len(xs)/2], 100*float64(len(xs))/float64(len(by[n])))
		}
		fmt.Fprintln(tw)
	}
	tw.Flush()
}

func runInfo(args []string) error {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	dir := fs.String("bundle", "", "bundle directory")
	fs.Parse(args)
	b, err := oracle.LoadBundle(*dir)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(struct {
		Manifest oracle.Manifest `json:"manifest"`
		Training oracle.Training `json:"training"`
	}{b.Manifest, b.Model.Training}, "", "  ")
	fmt.Println(string(out))
	return nil
}

type localFlags struct {
	id, file, sha *string
	ctx           *int
}

func localModelFlags(fs *flag.FlagSet) localFlags {
	return localFlags{
		id:   fs.String("local-model-id", defaultLocalModel.ID, "name of the analyst's local language model"),
		file: fs.String("local-model-file", defaultLocalModel.File, "its file name in the runtime directory"),
		sha:  fs.String("local-model-sha256", defaultLocalModel.SHA256, "SHA-256 of that file"),
		ctx:  fs.Int("local-model-context", defaultLocalModel.ContextTokens, "context size in tokens"),
	}
}

func (l localFlags) ref() oracle.LocalModelRef {
	return oracle.LocalModelRef{ID: *l.id, File: *l.file, SHA256: *l.sha, ContextTokens: *l.ctx}
}

func runSet(args []string) error {
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	dir := fs.String("bundle", "", "bundle directory")
	watch := fs.Float64("watch", 0, "new watch threshold (0 keeps it)")
	review := fs.Float64("review", 0, "new review threshold (0 keeps it)")
	prompt := fs.String("prompt-version", "", "new prompt version, after editing the bundle's prompts")
	local := localModelFlags(fs)
	fs.Parse(args)
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	m, err := oracle.Rewrite(*dir, func(m *oracle.Manifest) error {
		if *watch > 0 {
			m.Thresholds.Watch = *watch
		}
		if *review > 0 {
			m.Thresholds.Review = *review
		}
		if *prompt != "" {
			m.Analyst.PromptVersion = *prompt
		}
		if set["local-model-id"] || set["local-model-file"] || set["local-model-sha256"] || set["local-model-context"] {
			ref := m.Analyst.LocalModel
			if set["local-model-id"] {
				ref.ID = *local.id
			}
			if set["local-model-file"] {
				ref.File = *local.file
			}
			if set["local-model-sha256"] {
				ref.SHA256 = *local.sha
			}
			if set["local-model-context"] {
				ref.ContextTokens = *local.ctx
			}
			m.Analyst.LocalModel = ref
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("bundle is now %s\n", m.BundleID)
	return nil
}
