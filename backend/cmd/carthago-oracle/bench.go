package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"carthago/backend/internal/oracle"
	"carthago/backend/internal/oracle/analyst"
	"carthago/backend/internal/oracle/runtime"
	"carthago/backend/internal/oracle/train"
)

func init() {
	commands["bench"] = command{runBench, "measure candidate analyst models on the same synthetic cases"}
}

// benchCase is one synthetic session turned into the case the gateway would send.
type benchCase struct {
	Group   string // cheat, honest_flagged or honest_clean
	Profile string
	Truth   string
	// Tampered is set when the case carries client-tampering evidence of high or
	// critical severity. Most cheats are loaded into the game, so a cheating session's
	// case often shows the loader as well as the cheat's effect; naming the tampering,
	// or both, is then a correct reading too.
	Tampered bool
	Case     *analyst.Case
}

// benchVerdict is one analyst's answer to one case.
type benchVerdict struct {
	Group      string  `json:"group"`
	Profile    string  `json:"profile"`
	Truth      string  `json:"truth"`
	Tampered   bool    `json:"tampered,omitempty"`
	Session    string  `json:"session"`
	Valid      bool    `json:"valid"`
	Reason     string  `json:"reason,omitempty"`
	CheatType  string  `json:"cheat_type,omitempty"`
	Confidence int     `json:"confidence,omitempty"`
	Action     string  `json:"action,omitempty"`
	Summary    string  `json:"summary,omitempty"`
	Cited      int     `json:"cited"`
	Seconds    float64 `json:"seconds"`
	TokensIn   int     `json:"tokens_in"`
	TokensOut  int     `json:"tokens_out"`
}

// benchResult is one analyst's line in the table.
type benchResult struct {
	Analyst       string         `json:"analyst"`
	File          string         `json:"file,omitempty"`
	FileBytes     int64          `json:"file_bytes,omitempty"`
	Threads       int            `json:"threads,omitempty"`
	Cases         int            `json:"cases"`
	Valid         int            `json:"valid"`
	Cheat         int            `json:"cheat_cases"`
	CheatExact    int            `json:"cheat_type_exact"`
	CheatRight    int            `json:"cheat_type_right"`
	CheatDetected int            `json:"cheat_named"`
	CheatEscalate int            `json:"cheat_sent_to_review"`
	Flagged       int            `json:"honest_flagged_cases"`
	FlaggedAccuse int            `json:"honest_flagged_accused"`
	FlaggedReview int            `json:"honest_flagged_sent_to_review"`
	Clean         int            `json:"honest_clean_cases"`
	CleanAccuse   int            `json:"honest_clean_accused"`
	MedianSeconds float64        `json:"median_seconds"`
	P90Seconds    float64        `json:"p90_seconds"`
	FirstSeconds  float64        `json:"first_case_seconds"`
	PeakRSSMB     float64        `json:"peak_rss_mb,omitempty"`
	AnonMB        float64        `json:"rss_private_mb,omitempty"`
	FileMB        float64        `json:"rss_mapped_file_mb,omitempty"`
	TokensIn      float64        `json:"mean_tokens_in"`
	TokensOut     float64        `json:"mean_tokens_out"`
	Verdicts      []benchVerdict `json:"verdicts"`
}

// benchCases picks the cases: flagged cheating sessions of every profile, honest sessions
// the rules or the model flagged by mistake (the cases where a wrong opinion does harm),
// and honest sessions with nothing against them. Only held-out sessions are used.
func benchCases(b *oracle.Bundle, rows []train.Row, split string, perProfile, flagged, clean int) []benchCase {
	p := analyst.NewPseudonymiser([]byte("carthago-oracle-bench-pseudonyms"))
	_, calib, test := train.Split(rows)
	if split == "calibration" {
		test = calib
	}
	taken := map[string]int{}
	var out []benchCase
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range test {
		r := &test[i]
		row := b.ScoreRow(r.Session, r.Vector, "", at)
		isFlagged := r.RuleFlag || row.Band == "review"
		group, limit := "cheat", perProfile
		switch {
		case r.Cheating && !isFlagged:
			continue // never reaches the analyst
		case !r.Cheating && isFlagged:
			group, limit = "honest_flagged", flagged
		case !r.Cheating:
			group, limit = "honest_clean", clean
		}
		key := group
		if r.Cheating {
			key = r.Profile
		}
		if taken[key] >= limit {
			continue
		}
		taken[key]++
		bc := benchCase{Group: group, Profile: r.Profile, Truth: train.Truth[r.Profile],
			Case: analyst.Build(p, oracle.CaseInput(r.Session, r.Evidence, row))}
		for _, e := range bc.Case.Evidence {
			bc.Tampered = bc.Tampered || e.Tamper && (e.Severity == "high" || e.Severity == "critical")
		}
		out = append(out, bc)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Group < out[j].Group })
	return out
}

func accuses(v benchVerdict) bool {
	return v.Valid && v.CheatType != analyst.TypeNone && v.CheatType != analyst.TypeInconclusive
}

func benchAnalyst(name string, p analyst.Provider, prompts analyst.Prompts, cases []benchCase, timeout time.Duration, progress io.Writer) (benchResult, error) {
	a, err := analyst.New(analyst.Config{Provider: p, Prompts: prompts, Timeout: timeout,
		Limits: analyst.Limits{CasesPerHour: 1 << 30, CasesPerDay: 1 << 30, TokensPerDay: 1 << 30}})
	if err != nil {
		return benchResult{}, err
	}
	res := benchResult{Analyst: name, Cases: len(cases)}
	var secs []float64
	for i, c := range cases {
		r := a.Review(context.Background(), train.Tenant, c.Case)
		v := benchVerdict{Group: c.Group, Profile: c.Profile, Truth: c.Truth, Tampered: c.Tampered, Session: c.Case.Session, Valid: r.Verdict != nil, Reason: r.Reason,
			Seconds: r.Latency.Seconds(), TokensIn: r.TokensIn, TokensOut: r.TokensOut}
		if r.Verdict != nil {
			v.CheatType, v.Confidence, v.Action, v.Summary, v.Cited = r.Verdict.CheatType, r.Verdict.Confidence, r.Verdict.RecommendedAction, r.Verdict.Summary, len(r.Verdict.CitedEvidence)
			res.Valid++
		}
		if i == 0 {
			res.FirstSeconds = v.Seconds
		} else {
			secs = append(secs, v.Seconds)
		}
		res.TokensIn += float64(v.TokensIn)
		res.TokensOut += float64(v.TokensOut)
		escalated := v.Action == analyst.ActionReview || v.Action == analyst.ActionPriority
		switch c.Group {
		case "cheat":
			res.Cheat++
			if v.Valid && v.CheatType == c.Truth {
				res.CheatExact++
			}
			if v.Valid && (v.CheatType == c.Truth || c.Tampered && (v.CheatType == analyst.TypeTampering || v.CheatType == analyst.TypeMixed)) {
				res.CheatRight++
			}
			if accuses(v) {
				res.CheatDetected++
			}
			if v.Valid && escalated {
				res.CheatEscalate++
			}
		case "honest_flagged":
			res.Flagged++
			if accuses(v) {
				res.FlaggedAccuse++
			}
			if v.Valid && escalated {
				res.FlaggedReview++
			}
		case "honest_clean":
			res.Clean++
			if accuses(v) {
				res.CleanAccuse++
			}
		}
		res.Verdicts = append(res.Verdicts, v)
		fmt.Fprintf(progress, "%s %d/%d %s/%s -> %s %s (%.1fs)\n", name, i+1, len(cases), c.Group, c.Profile, v.CheatType, v.Reason, v.Seconds)
	}
	if len(secs) == 0 {
		secs = []float64{res.FirstSeconds}
	}
	sort.Float64s(secs)
	res.MedianSeconds, res.P90Seconds = secs[len(secs)/2], secs[min(len(secs)-1, len(secs)*9/10)]
	if len(cases) > 0 {
		res.TokensIn /= float64(len(cases))
		res.TokensOut /= float64(len(cases))
	}
	return res, nil
}

// memoryOf reads a process's peak resident memory and its current split into private
// (anonymous) and file-backed pages, in MB (Linux only; zeros elsewhere). The file-backed
// part is the memory-mapped model file, which the system can drop and re-read.
func memoryOf(pid int) (peak, anon, file float64) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		kb, _ := strconv.ParseFloat(f[1], 64)
		switch f[0] {
		case "VmHWM:":
			peak = kb / 1024
		case "RssAnon:":
			anon = kb / 1024
		case "RssFile:":
			file = kb / 1024
		}
	}
	return
}

func runBench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	bundleDir := fs.String("bundle", "", "bundle directory (its behaviour model scores the cases, its prompts are used)")
	dataset := fs.String("dataset", "", "sessions saved by `carthago-oracle dataset -evidence`")
	runtimeDir := fs.String("runtime-dir", runtime.DefaultDir(), "directory with the llama.cpp server and models/")
	models := fs.String("models", "", "comma-separated id=file pairs of model files under <runtime-dir>/models; the stub is always measured")
	perProfile := fs.Int("per-profile", 2, "flagged cheating sessions per cheat profile")
	flagged := fs.Int("honest-flagged", 12, "honest sessions that were flagged by mistake")
	clean := fs.Int("honest-clean", 4, "honest sessions with nothing against them")
	split := fs.String("split", "test", "which held-out sessions to draw cases from: test or calibration (neither was used to fit the behaviour model)")
	threads := fs.Int("threads", 0, "CPU threads for the model (0 = the gateway's default cap)")
	timeout := fs.Duration("timeout", 5*time.Minute, "time limit per case")
	out := fs.String("out", "", "write the results, with every verdict, to this JSON file")
	list := fs.Bool("cases", false, "print the cases and stop")
	_ = fs.Parse(args)
	if *bundleDir == "" || *dataset == "" {
		return errors.New("bench needs -bundle and -dataset")
	}
	b, err := oracle.LoadBundle(*bundleDir)
	if err != nil {
		return err
	}
	rows, _, err := dataFlags{file: dataset}.rows(true)
	if err != nil {
		return err
	}
	if *split != "test" && *split != "calibration" {
		return errors.New("-split is test or calibration")
	}
	cases := benchCases(b, rows, *split, *perProfile, *flagged, *clean)
	withEvidence := 0
	for i := range cases {
		if len(cases[i].Case.Evidence) > 0 {
			withEvidence++
		}
	}
	if withEvidence == 0 {
		return errors.New("the dataset holds no evidence; create it with carthago-oracle dataset -evidence")
	}
	if *list {
		for _, c := range cases {
			fmt.Printf("# %s / %s, expected %s\n%s\n", c.Group, c.Profile, c.Truth, c.Case.JSON())
		}
		return nil
	}
	prompts := analyst.Prompts{Version: b.Manifest.Analyst.PromptVersion, System: b.SystemPrompt, Case: b.CasePrompt}
	var results []benchResult
	save := func() error {
		if *out == "" {
			return nil
		}
		data, _ := json.MarshalIndent(results, "", " ")
		return os.WriteFile(*out, data, 0o600)
	}
	r, err := benchAnalyst("stub", analyst.Stub{}, prompts, cases, *timeout, io.Discard)
	if err != nil {
		return err
	}
	results = append(results, r)
	for _, spec := range strings.Split(*models, ",") {
		if spec = strings.TrimSpace(spec); spec == "" {
			continue
		}
		id, file, ok := strings.Cut(spec, "=")
		if !ok {
			return fmt.Errorf("model %q: want id=file", spec)
		}
		rt, err := runtime.New(runtime.Config{Dir: *runtimeDir, ModelFile: file, ModelID: id, Threads: *threads, IdleStop: time.Hour,
			Log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))})
		if err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		r, err := benchAnalyst(id, rt, prompts, cases, *timeout, os.Stderr)
		r.PeakRSSMB, r.AnonMB, r.FileMB = memoryOf(rt.Pid())
		rt.Close()
		if err != nil {
			return err
		}
		r.File, r.Threads = file, rt.Threads()
		if st, err := os.Stat(filepath.Join(*runtimeDir, "models", file)); err == nil {
			r.FileBytes = st.Size()
		}
		results = append(results, r)
		if err := save(); err != nil {
			return err
		}
	}
	if err := save(); err != nil {
		return err
	}
	writeBench(os.Stdout, results)
	return nil
}

func writeBench(w io.Writer, results []benchResult) {
	if len(results) == 0 {
		return
	}
	r0 := results[0]
	fmt.Fprintf(w, "%d cases: %d flagged cheating sessions, %d honest sessions flagged by mistake, %d honest sessions with nothing against them\n\n", r0.Cases, r0.Cheat, r0.Flagged, r0.Clean)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "Analyst\tFile GB\tValid\tCheat type right\texact\tCheat kept for review\tHonest flagged accused\tsent to review\tHonest clean accused\tMedian s\tP90 s\tFirst s\tPeak RSS GB\tTokens in/out")
	frac := func(n, d int) string {
		if d == 0 {
			return "-"
		}
		return fmt.Sprintf("%d/%d", n, d)
	}
	for _, r := range results {
		size, rss := "-", "-"
		if r.FileBytes > 0 {
			size = fmt.Sprintf("%.2f", float64(r.FileBytes)/1e9)
		}
		if r.PeakRSSMB > 0 {
			rss = fmt.Sprintf("%.2f", r.PeakRSSMB/1024)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%.1f\t%.1f\t%.1f\t%s\t%.0f/%.0f\n", r.Analyst, size, frac(r.Valid, r.Cases), frac(r.CheatRight, r.Cheat), frac(r.CheatExact, r.Cheat),
			frac(r.CheatEscalate, r.Cheat), frac(r.FlaggedAccuse, r.Flagged), frac(r.FlaggedReview, r.Flagged), frac(r.CleanAccuse, r.Clean), r.MedianSeconds, r.P90Seconds, r.FirstSeconds, rss, r.TokensIn, r.TokensOut)
	}
	tw.Flush()
}
