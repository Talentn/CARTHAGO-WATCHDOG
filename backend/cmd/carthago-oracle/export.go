package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"carthago/backend/internal/oracle"
	"carthago/backend/internal/oracle/analyst"
	"carthago/backend/internal/oracle/tune"
	"carthago/backend/internal/store"
)

func init() {
	commands["export"] = command{runExport, "export a studio's reviewer-labelled sessions as tuning data (pseudonymised)"}
}

// runExport reads a gateway's data directory and writes two files: behaviour.jsonl, the
// labelled feature rows `train -labelled` reads, and analyst.jsonl, chat-format examples
// for fine-tuning the analyst's language model. Nothing is sent anywhere.
func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	data := fs.String("data", "gateway-data", "the gateway's data directory (gateway.db and oracle-pseudonym.key)")
	tenant := fs.String("tenant", "demo", "tenant whose labels to export")
	bundleDir := fs.String("bundle", "", "bundle whose prompts the analyst examples use (default <data>/oracle)")
	out := fs.String("out", "", "directory to write behaviour.jsonl and analyst.jsonl into (keep it off shared and synced folders)")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	key, err := os.ReadFile(filepath.Join(*data, "oracle-pseudonym.key"))
	if err != nil || len(key) < 16 {
		return fmt.Errorf("no pseudonym key in %s: run the gateway with the Oracle once, so the export uses the names its case files use", *data)
	}
	st, err := store.OpenSQLite(filepath.Join(*data, "gateway.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	dir := *bundleDir
	if dir == "" {
		dir = filepath.Join(*data, "oracle")
	}
	prompts := analyst.DefaultPrompts()
	b, err := oracle.LoadBundle(dir)
	switch {
	case err == nil:
		prompts = analyst.Prompts{Version: b.Manifest.Analyst.PromptVersion, System: b.SystemPrompt, Case: b.CasePrompt}
	case errors.Is(err, oracle.ErrNoBundle):
		fmt.Fprintf(os.Stderr, "no bundle in %s: using the reference prompts\n", dir)
	default:
		return err
	}
	rows, chat, stats, err := tune.Export(context.Background(), st, analyst.NewPseudonymiser(key), *tenant, b, prompts)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	write := func(name string, do func(f *os.File) error) error {
		f, err := os.OpenFile(filepath.Join(*out, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if err := do(f); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	if err := write("behaviour.jsonl", func(f *os.File) error { return tune.WriteJSONL(f, rows) }); err != nil {
		return err
	}
	if err := write("analyst.jsonl", func(f *os.File) error { return tune.WriteJSONL(f, chat) }); err != nil {
		return err
	}
	players := map[string]bool{}
	for _, r := range rows {
		players[r.Subject] = true
	}
	fmt.Printf("%d labelled sessions of tenant %s from %d players written to %s\n", stats.Labels, *tenant, len(players), *out)
	fmt.Printf("  confirmed cheat %d, cleared %d, unsure %d (unsure is exported but not trained on)\n", stats.Confirmed, stats.Cleared, stats.Unsure)
	types := make([]string, 0, len(stats.ByCheatType))
	for t := range stats.ByCheatType {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		fmt.Printf("  confirmed %s: %d\n", t, stats.ByCheatType[t])
	}
	fmt.Printf("  sessions without a match (client evidence only): %d\n", stats.WithoutMatch)
	fmt.Printf("  analyst examples: %d\n", stats.AnalystSamples)
	if stats.Skipped > 0 {
		fmt.Printf("  labels skipped because their session is no longer stored: %d\n", stats.Skipped)
	}
	if lacking := stats.Ready(len(players)); len(lacking) > 0 {
		fmt.Println("\nNot yet enough to retrain the behaviour model on. So far:")
		for _, l := range lacking {
			fmt.Println("  " + l)
		}
		fmt.Println("Until then the labels are best used to check the current model: carthago-oracle eval -labelled.")
	} else {
		fmt.Println("\nEvery minimum for retraining the behaviour model is met: carthago-oracle train -labelled " + filepath.Join(*out, "behaviour.jsonl"))
	}
	if stats.AnalystSamples < tune.MinAnalystSamples {
		fmt.Printf("%d of %d analyst examples: too few to fine-tune a language model on.\n", stats.AnalystSamples, tune.MinAnalystSamples)
	}
	return nil
}
