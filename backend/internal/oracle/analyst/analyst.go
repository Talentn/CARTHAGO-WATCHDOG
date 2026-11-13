package analyst

import (
	"context"
	"errors"
	"sync"
	"time"

	"carthago/backend/internal/store"
)

// Limits cap what one tenant's cases may cost. Zero means the default.
type Limits struct {
	CasesPerHour int
	CasesPerDay  int
	TokensPerDay int
}

func (l Limits) withDefaults() Limits {
	if l.CasesPerHour <= 0 {
		l.CasesPerHour = 30
	}
	if l.CasesPerDay <= 0 {
		l.CasesPerDay = 200
	}
	if l.TokensPerDay <= 0 {
		l.TokensPerDay = 400_000
	}
	return l
}

// UsageStore keeps a tenant's daily count of cases and tokens, so the caps hold across a
// restart.
type UsageStore interface {
	AddOracleUsage(ctx context.Context, tenant, day string, cases, tokens int64) (store.OracleUsage, error)
}

type Config struct {
	Provider Provider
	Prompts  Prompts
	// Timeout bounds one case, retries included. Default 2 minutes: a small model on a
	// CPU needs most of a minute for a long case.
	Timeout   time.Duration
	MaxTokens int
	Limits    Limits
	// ExternalTenants are the tenants that opted in to their case files being sent to a
	// provider outside the gateway host. A local provider needs no opt-in.
	ExternalTenants map[string]bool
	Usage           UsageStore
	Now             func() time.Time
}

// Reasons a case got no verdict. They are fixed words: a provider's own error text is
// never stored or shown.
const (
	ReasonTimeout     = "timeout"
	ReasonProvider    = "provider_error"
	ReasonInvalid     = "invalid_output"
	ReasonRateLimited = "rate_limited"
	ReasonBudget      = "budget_exhausted"
	ReasonNotOptedIn  = "external_not_allowed"
	ReasonCase        = "case_rejected"
)

// Result is the outcome of one review.
type Result struct {
	// Verdict is nil when the analyst was unavailable; Reason then says why.
	Verdict       *Verdict
	Reason        string
	Provider      string
	Model         string
	PromptVersion string
	Latency       time.Duration
	TokensIn      int
	TokensOut     int
	// Err is the underlying error, for the gateway's debug log only.
	Err error
}

// Analyst reviews cases with one provider.
type Analyst struct {
	cfg Config

	mu    sync.Mutex
	hours map[string][]time.Time // tenant -> start times of reviews in the last hour
}

func New(cfg Config) (*Analyst, error) {
	if cfg.Provider == nil {
		return nil, errors.New("analyst: no provider")
	}
	if err := cfg.Prompts.check(); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Minute
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 320
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.Limits = cfg.Limits.withDefaults()
	return &Analyst{cfg: cfg, hours: map[string][]time.Time{}}, nil
}

func (a *Analyst) Provider() Provider    { return a.cfg.Provider }
func (a *Analyst) PromptVersion() string { return a.cfg.Prompts.Version }

// CaseHash names a case as this analyst would judge it.
func (a *Analyst) CaseHash(c *Case) string {
	return c.Hash(a.cfg.Prompts.Version, a.cfg.Provider.Name(), a.cfg.Provider.Model())
}

// Allowed reports whether this analyst may see the tenant's cases at all.
func (a *Analyst) Allowed(tenant string) bool {
	return !a.cfg.Provider.External() || a.cfg.ExternalTenants[tenant]
}

// admit applies the tenant's caps and, when the review may run, counts it.
func (a *Analyst) admit(ctx context.Context, tenant string, now time.Time) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	recent := a.hours[tenant][:0]
	for _, t := range a.hours[tenant] {
		if now.Sub(t) < time.Hour {
			recent = append(recent, t)
		}
	}
	a.hours[tenant] = recent
	if len(recent) >= a.cfg.Limits.CasesPerHour {
		return ReasonRateLimited
	}
	if a.cfg.Usage != nil {
		day := now.UTC().Format("2006-01-02")
		u, err := a.cfg.Usage.AddOracleUsage(ctx, tenant, day, 0, 0)
		if err != nil {
			return ReasonProvider
		}
		if u.Cases >= int64(a.cfg.Limits.CasesPerDay) || u.Tokens >= int64(a.cfg.Limits.TokensPerDay) {
			return ReasonBudget
		}
		if _, err := a.cfg.Usage.AddOracleUsage(ctx, tenant, day, 1, 0); err != nil {
			return ReasonProvider
		}
	}
	a.hours[tenant] = append(recent, now)
	return ""
}

// Review asks the provider for a verdict on a case. It never returns an error: a case
// that cannot be judged comes back without a verdict and with the reason, and the caller
// carries on with the hard evidence alone.
func (a *Analyst) Review(ctx context.Context, tenant string, c *Case) Result {
	p := a.cfg.Provider
	res := Result{Provider: p.Name(), Model: p.Model(), PromptVersion: a.cfg.Prompts.Version}
	if !a.Allowed(tenant) {
		res.Reason = ReasonNotOptedIn
		return res
	}
	if err := c.CheckVocabulary(); err != nil {
		res.Reason, res.Err = ReasonCase, err
		return res
	}
	now := a.cfg.Now()
	if reason := a.admit(ctx, tenant, now); reason != "" {
		res.Reason = reason
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	start := time.Now()
	req := Request{System: a.cfg.Prompts.System, User: a.cfg.Prompts.render(c), Schema: Schema(c), MaxTokens: a.cfg.MaxTokens, Case: c}
	// One retry, and only for an answer that came back but failed the check: the second
	// request says what was wrong in a fixed word. A provider that errors or times out
	// is not asked again; the engine retries the case later.
	for attempt := 0; attempt < 2; attempt++ {
		out, err := p.Complete(ctx, req)
		res.TokensIn += out.TokensIn
		res.TokensOut += out.TokensOut
		if err != nil {
			res.Reason, res.Err = ReasonProvider, err
			if ctx.Err() != nil {
				res.Reason = ReasonTimeout
			}
			break
		}
		v, err := ParseVerdict(out.Text, c)
		if err == nil {
			res.Verdict, res.Reason, res.Err = v, "", nil
			break
		}
		res.Reason, res.Err = ReasonInvalid, err
		req.User = a.cfg.Prompts.render(c) + "\n\nYour previous answer was rejected (" + err.Error() + "). Follow the rules exactly and answer again."
	}
	res.Latency = time.Since(start)
	if a.cfg.Usage != nil && res.TokensIn+res.TokensOut > 0 {
		// The request's own context may be past its deadline; the count is still recorded.
		uctx, ucancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_, _ = a.cfg.Usage.AddOracleUsage(uctx, tenant, now.UTC().Format("2006-01-02"), 0, int64(res.TokensIn+res.TokensOut))
		ucancel()
	}
	return res
}
