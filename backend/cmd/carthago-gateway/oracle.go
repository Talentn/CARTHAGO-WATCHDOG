package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"time"

	"carthago/backend/internal/dashboard"
	"carthago/backend/internal/oracle"
	"carthago/backend/internal/oracle/analyst"
	"carthago/backend/internal/oracle/runtime"
	"carthago/backend/internal/pipeline"
)

// Carthago Oracle configuration. Every flag has a CARTHAGO_ORACLE_* environment fallback.
// The key of a hosted analyst is read from the environment only, so it never shows up in a
// process list, a shell history or a service file checked into a repository.
const (
	envOracleKey      = "CARTHAGO_ORACLE_API_KEY"
	envOracleEndpoint = "CARTHAGO_ORACLE_ENDPOINT"
	envOracleModel    = "CARTHAGO_ORACLE_MODEL"
)

type tenantSet map[string]bool

func (t tenantSet) String() string { return fmt.Sprint(len(t)) }
func (t tenantSet) Set(v string) error {
	for _, id := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		t[id] = true
	}
	return nil
}

type oracleFlags struct {
	dir, analyst, runtimeDir      *string
	threads                       *int
	reviewLive                    *bool
	external                      tenantSet
	perHour, perDay, tokensPerDay *int
	timeout                       *time.Duration
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envInt(name string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return n
	}
	return def
}

func oracleFlagSet(fs *flag.FlagSet) *oracleFlags {
	f := &oracleFlags{external: tenantSet{}}
	f.dir = fs.String("oracle-dir", envOr("CARTHAGO_ORACLE_DIR", ""), "Carthago Oracle bundle directory (default <data>/oracle); the Oracle is off when it holds no bundle")
	f.analyst = fs.String("oracle-analyst", envOr("CARTHAGO_ORACLE_ANALYST", "auto"), "Oracle analyst: auto (the local model when installed, else off) | local | stub | openai | anthropic | off")
	f.runtimeDir = fs.String("oracle-runtime-dir", envOr("CARTHAGO_ORACLE_RUNTIME_DIR", ""), "directory the Oracle fetch script installed the local analyst runtime into (default: per-user data directory)")
	f.threads = fs.Int("oracle-threads", envInt("CARTHAGO_ORACLE_THREADS", 0), "CPU threads the local analyst may use (0 = half the CPUs, at most 4)")
	f.reviewLive = fs.Bool("oracle-review-live", os.Getenv("CARTHAGO_ORACLE_REVIEW_LIVE") == "1", "let the analyst review sessions that are still connected (default: after the session has ended)")
	_ = f.external.Set(os.Getenv("CARTHAGO_ORACLE_EXTERNAL_TENANTS"))
	fs.Var(f.external, "oracle-external-tenant", "tenant that opted in to its pseudonymised case files being sent to a hosted analyst (repeatable); nothing leaves the gateway host without it")
	f.perHour = fs.Int("oracle-cases-per-hour", envInt("CARTHAGO_ORACLE_CASES_PER_HOUR", 0), "analyst cases per tenant and hour (0 = default 30)")
	f.perDay = fs.Int("oracle-cases-per-day", envInt("CARTHAGO_ORACLE_CASES_PER_DAY", 0), "analyst cases per tenant and day (0 = default 200)")
	f.tokensPerDay = fs.Int("oracle-tokens-per-day", envInt("CARTHAGO_ORACLE_TOKENS_PER_DAY", 0), "analyst tokens per tenant and day (0 = default 400000)")
	f.timeout = fs.Duration("oracle-timeout", 0, "time limit for one analyst case (0 = default 2m)")
	return f
}

// oracleStore is what the Oracle needs from the gateway's store.
type oracleStore interface {
	oracle.Store
}

// running is the started Oracle: what the pipeline, the dashboard and shutdown need.
type runningOracle struct {
	observer pipeline.Observer // nil when the Oracle is off
	info     *dashboard.OracleInfo
	close    func()
}

// startOracle loads the bundle and starts the engine. The Oracle is optional: without a
// bundle, or with a bundle that fails its checks, the gateway runs exactly as before and
// says so in one line. Log lines name ids and versions; they never carry thresholds,
// prompts, features or anything else from inside the bundle.
func startOracle(ctx context.Context, f *oracleFlags, dataDir string, st oracleStore, log *slog.Logger) (*runningOracle, error) {
	off := &runningOracle{close: func() {}}
	dir := *f.dir
	if dir == "" {
		dir = filepath.Join(dataDir, "oracle")
	}
	bundle, err := oracle.LoadBundle(dir)
	if errors.Is(err, oracle.ErrNoBundle) {
		log.Info("Carthago Oracle off: no bundle", "dir", dir, "hint", "create one with carthago-oracle train")
		return off, nil
	}
	if err != nil {
		// A damaged or tampered bundle must not silently change what the engine does.
		log.Error("Carthago Oracle off: the bundle failed its checks", "dir", dir, "err", err)
		return off, nil
	}
	if goruntime.GOOS != "windows" {
		if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm()&0o007 != 0 {
			log.Warn("the Oracle bundle directory is readable by other users of this machine; restrict it to the gateway's account", "dir", dir)
		}
	}
	key, err := pseudonymKey(filepath.Join(dataDir, "oracle-pseudonym.key"))
	if err != nil {
		return nil, fmt.Errorf("oracle pseudonym key: %w", err)
	}

	provider, closeProvider, why := oracleProvider(f, bundle, log)
	var an *analyst.Analyst
	if provider != nil {
		an, err = analyst.New(analyst.Config{
			Provider:        provider,
			Prompts:         analyst.Prompts{Version: bundle.Manifest.Analyst.PromptVersion, System: bundle.SystemPrompt, Case: bundle.CasePrompt},
			Timeout:         *f.timeout,
			Limits:          analyst.Limits{CasesPerHour: *f.perHour, CasesPerDay: *f.perDay, TokensPerDay: *f.tokensPerDay},
			ExternalTenants: f.external, Usage: st,
		})
		if err != nil {
			closeProvider()
			provider, closeProvider, why = nil, func() {}, "the bundle's prompts failed their checks"
			an = nil
		}
	}
	eng, err := oracle.New(oracle.Config{Bundle: bundle, Analyst: an, PseudonymKey: key, ReviewLive: *f.reviewLive}, st, log)
	if err != nil {
		closeProvider()
		return nil, err
	}
	go eng.Run(ctx)

	s := eng.Status()
	review := "after the session has ended"
	if *f.reviewLive {
		review = "while the session is live"
	}
	attrs := []any{"bundle", s.BundleID, "behaviour_model", s.ModelID, "features", s.FeatureVersion, "analyst", s.Analyst}
	if an != nil {
		attrs = append(attrs, "analyst_model", s.AnalystModel, "prompt", s.PromptVersion, "review", review)
		if rt, ok := provider.(*runtime.Runtime); ok {
			attrs = append(attrs, "threads", rt.Threads(), "priority", "below normal", "runs", "only while a case is open")
		}
		if provider.External() {
			attrs = append(attrs, "external_tenants", len(f.external))
		}
	}
	log.Info("Carthago Oracle ready", attrs...)
	if an == nil {
		log.Info("Carthago Oracle analyst off: sessions are scored, no opinions are written", "reason", why)
	} else if provider.External() && len(f.external) == 0 {
		log.Warn("the Oracle analyst is hosted outside this machine and no tenant has opted in (-oracle-external-tenant): no case will be sent")
	}
	return &runningOracle{observer: eng, close: closeProvider,
		info: &dashboard.OracleInfo{BundleID: s.BundleID, ModelID: s.ModelID, Analyst: s.Analyst, AnalystModel: s.AnalystModel, PromptVersion: s.PromptVersion}}, nil
}

// oracleProvider picks the analyst's provider. A nil provider means the analyst is off,
// and the string says why in words that are safe to log.
func oracleProvider(f *oracleFlags, b *oracle.Bundle, log *slog.Logger) (analyst.Provider, func(), string) {
	none := func() {}
	local := func() (analyst.Provider, func(), string) {
		dir := *f.runtimeDir
		if dir == "" {
			dir = runtime.DefaultDir()
		}
		lm := b.Manifest.Analyst.LocalModel
		rt, err := runtime.New(runtime.Config{Dir: dir, ModelFile: lm.File, ModelSHA256: lm.SHA256, ModelID: lm.ID,
			Threads: *f.threads, ContextTokens: lm.ContextTokens, Log: log})
		if err != nil {
			if errors.Is(err, runtime.ErrNotInstalled) {
				return nil, none, "the local analyst runtime is not installed in " + dir + " (run tools/carthago-oracle-fetch)"
			}
			return nil, none, "the local analyst runtime could not be prepared"
		}
		return rt, rt.Close, ""
	}
	hosted := func(kind string) (analyst.Provider, func(), string) {
		key, model, endpoint := os.Getenv(envOracleKey), os.Getenv(envOracleModel), os.Getenv(envOracleEndpoint)
		if key == "" {
			return nil, none, envOracleKey + " is not set"
		}
		var p analyst.Provider
		var err error
		if kind == "anthropic" {
			p, err = analyst.NewAnthropic(endpoint, key, model)
		} else {
			p, err = analyst.NewOpenAI(endpoint, key, model)
		}
		if err != nil {
			return nil, none, "the hosted analyst is misconfigured: " + err.Error() + " (" + envOracleEndpoint + ", " + envOracleModel + ")"
		}
		return p, none, ""
	}
	switch *f.analyst {
	case "off":
		return nil, none, "switched off (-oracle-analyst off)"
	case "stub":
		return analyst.Stub{}, none, ""
	case "auto", "local", "":
		return local()
	case "openai", "anthropic":
		return hosted(*f.analyst)
	}
	return nil, none, "unknown -oracle-analyst value"
}

// pseudonymKey loads the key that names players and sessions in case files, creating it
// on first use. It stays on the gateway: with it, a pseudonym can be tied back to a player;
// without it, it cannot.
func pseudonymKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("%s: want 32 bytes", path)
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}
