package oracle

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"carthago/backend/internal/oracle/analyst"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/store"
)

// Store is what the engine reads and writes. It reads evidence and telemetry the
// pipeline stored; it writes only Oracle rows.
type Store interface {
	store.OracleStore
	ListEvidence(ctx context.Context, tenant string, f store.EvidenceFilter) ([]store.Evidence, error)
	GetTelemetry(ctx context.Context, tenant, sessionID string) (*store.Telemetry, error)
	GetSession(ctx context.Context, sessionID string) (*store.Session, error)
}

type Config struct {
	Bundle *Bundle
	// Analyst is nil when the analyst is off; sessions are still scored.
	Analyst *analyst.Analyst
	// PseudonymKey keys the pseudonyms in case files. It should outlive a restart, or the
	// same case gets a new name and is judged again.
	PseudonymKey []byte
	// ReviewLive lets the analyst review a session while it is still connected. By
	// default a case waits until the session has ended (closed, kicked, or silent for
	// EndedAfter): the analyst's model is the one expensive thing the Oracle runs, and on
	// a machine that also hosts the game it should not compete with a match in progress.
	// Scoring is unaffected; it is cheap and always live.
	ReviewLive bool
	// EndedAfter is how long a session must have sent no heartbeat to count as ended.
	// Default 2 minutes.
	EndedAfter time.Duration
	// Settle is how long a session's evidence must have been quiet before its case goes
	// to the analyst, so a burst of findings makes one case and not ten. Default 20 s.
	Settle time.Duration
	// Rescore bounds how often a heartbeat without new evidence rescores a session.
	Rescore time.Duration
	// RetryAfter is how long a case that got no verdict waits before it is tried again.
	RetryAfter time.Duration
	// QueueSize bounds the events waiting to be scored. Default 4096.
	QueueSize int
	Now       func() time.Time
}

// Status describes the running engine for the startup line and the dashboard label. It
// holds names and versions only.
type Status struct {
	BundleID       string
	ModelID        string
	FeatureVersion int
	Analyst        string // provider name, or "off"
	AnalystModel   string
	PromptVersion  string
}

// Engine is the running Oracle. It implements pipeline.Observer.
type Engine struct {
	cfg    Config
	st     Store
	log    *slog.Logger
	pseudo *analyst.Pseudonymiser

	events  chan event
	cases   chan caseJob
	done    chan [2]string
	dropped atomic.Uint64
	// pending counts work not yet finished, for Flush: queued events, sessions whose case
	// is due, and cases with the analyst.
	pending sync.WaitGroup

	// Owned by the scoring goroutine.
	sessions map[[2]string]*sessionState
}

type event struct {
	match   bool
	tenant  string
	matchID string
	players []pipeline.MatchPlayer
	sess    store.Session
	fresh   bool
	at      time.Time
}

type sessionState struct {
	sess     store.Session
	loaded   bool   // the stored score was looked up
	gameplay Vector // the match part of the highest-scoring match; missing when none
	matchID  string
	scoredAt time.Time
	seenAt   time.Time
	due      time.Time // when the case is next considered for the analyst; zero when not
	inFlight bool
}

type caseJob struct {
	key  [2]string
	sess store.Session
	c    *analyst.Case
	hash string
}

var _ pipeline.Observer = (*Engine)(nil)

func New(cfg Config, st Store, log *slog.Logger) (*Engine, error) {
	if cfg.Bundle == nil {
		return nil, ErrNoBundle
	}
	if len(cfg.PseudonymKey) < 16 {
		return nil, errors.New("oracle: pseudonym key must be at least 16 bytes")
	}
	if cfg.Settle <= 0 {
		cfg.Settle = 20 * time.Second
	}
	if cfg.EndedAfter <= 0 {
		cfg.EndedAfter = 2 * time.Minute
	}
	if cfg.Rescore <= 0 {
		cfg.Rescore = time.Minute
	}
	if cfg.RetryAfter <= 0 {
		cfg.RetryAfter = 10 * time.Minute
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 4096
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Engine{cfg: cfg, st: st, log: log, pseudo: analyst.NewPseudonymiser(cfg.PseudonymKey),
		events: make(chan event, cfg.QueueSize), cases: make(chan caseJob, 64), done: make(chan [2]string, 64), sessions: map[[2]string]*sessionState{}}, nil
}

func (e *Engine) Status() Status {
	m := e.cfg.Bundle.Manifest
	s := Status{BundleID: m.BundleID, ModelID: m.Behaviour.ID, FeatureVersion: m.Behaviour.FeatureVersion, Analyst: "off"}
	if a := e.cfg.Analyst; a != nil {
		s.Analyst, s.AnalystModel, s.PromptVersion = a.Provider().Name(), a.Provider().Model(), a.PromptVersion()
	}
	return s
}

func (e *Engine) offer(ev event) {
	e.pending.Add(1)
	select {
	case e.events <- ev:
	default:
		e.pending.Done()
		if e.dropped.Add(1) == 1 {
			e.log.Warn("Carthago Oracle is behind: scoring events are being dropped")
		}
	}
}

// MatchFinished and SessionActivity are called on the pipeline's worker. They queue and
// return.
func (e *Engine) MatchFinished(tenant, matchID string, players []pipeline.MatchPlayer, at time.Time) {
	e.offer(event{match: true, tenant: tenant, matchID: matchID, players: players, at: at})
}

func (e *Engine) SessionActivity(sess store.Session, newEvidence bool, at time.Time) {
	e.offer(event{sess: sess, fresh: newEvidence, at: at})
}

// Run scores sessions and reviews cases until ctx is done.
func (e *Engine) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.reviewLoop(ctx)
	}()
	tick := time.NewTicker(min(e.cfg.Settle, 5*time.Second) / 2)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case ev := <-e.events:
			e.handle(ctx, ev)
			e.pending.Done()
		case k := <-e.done:
			if s := e.sessions[k]; s != nil {
				s.inFlight = false
			}
			e.pending.Done()
		case <-tick.C:
			e.sweep(ctx)
		}
	}
}

// Flush waits until everything queued so far has been scored and every case that became
// due has been reviewed or found to need no review. For tests and the offline tools.
func (e *Engine) Flush(ctx context.Context) {
	ch := make(chan struct{})
	go func() {
		e.pending.Wait()
		close(ch)
	}()
	select {
	case <-ch:
	case <-ctx.Done():
	}
}

func (e *Engine) state(ctx context.Context, sess store.Session) *sessionState {
	k := [2]string{sess.TenantID, sess.SessionID}
	s := e.sessions[k]
	if s == nil {
		s = &sessionState{gameplay: Missing()}
		e.sessions[k] = s
	}
	s.sess = sess
	if !s.loaded {
		// After a restart the best match so far is taken back from the stored score.
		s.loaded = true
		if row, err := e.st.GetOracleScore(ctx, sess.TenantID, sess.SessionID); err == nil && row != nil &&
			row.FeatureVersion == FeatureVersion && row.MatchID != "" {
			var v Vector
			if json.Unmarshal([]byte(row.Features), &v) == nil {
				for i := NumGameplay; i < NumFeatures; i++ {
					v[i] = math.NaN()
				}
				s.gameplay, s.matchID = v, row.MatchID
			}
		}
	}
	return s
}

func (e *Engine) handle(ctx context.Context, ev event) {
	if !ev.match {
		s := e.state(ctx, ev.sess)
		s.seenAt = ev.at
		if ev.fresh || s.scoredAt.IsZero() || ev.at.Sub(s.scoredAt) >= e.cfg.Rescore {
			e.score(ctx, s, nil, "", ev.at)
		}
		return
	}
	for i := range ev.players {
		p := &ev.players[i]
		s := e.state(ctx, p.Session)
		s.seenAt = ev.at
		g := Missing()
		GameplayFeatures(&g, p)
		e.score(ctx, s, &g, ev.matchID, ev.at)
	}
}

// score rescores a session and stores the result. With a new match, the match replaces
// the session's best one if it scores higher under the session's current client evidence.
func (e *Engine) score(ctx context.Context, s *sessionState, match *Vector, matchID string, at time.Time) {
	sess := s.sess
	evidence, err := e.st.ListEvidence(ctx, sess.TenantID, store.EvidenceFilter{SessionID: sess.SessionID, Limit: 500})
	if err != nil {
		e.log.Warn("Carthago Oracle: read evidence", "session", sess.SessionID, "err", err)
		return
	}
	tel, err := e.st.GetTelemetry(ctx, sess.TenantID, sess.SessionID)
	if err != nil {
		tel = nil
	}
	model := e.cfg.Bundle.Model
	full := func(g Vector) Vector {
		ClientFeatures(&g, sess.TrustLevel, evidence, tel)
		return g
	}
	v := full(s.gameplay)
	sc, contrib := model.Score(v)
	if match != nil {
		if nv := full(*match); s.matchID == "" || first(model.Score(nv)) > sc {
			s.gameplay, s.matchID, v = *match, matchID, nv
			sc, contrib = model.Score(v)
		}
	}
	s.scoredAt = at
	band := e.cfg.Bundle.Manifest.Thresholds.Band(sc)
	signals, _ := json.Marshal(TopSignals(contrib, 5))
	features, _ := json.Marshal(v)
	row := &store.OracleScore{TenantID: sess.TenantID, SessionID: sess.SessionID, PlayerHash: sess.PlayerHash, MatchID: s.matchID,
		ModelID: e.cfg.Bundle.Manifest.Behaviour.ID, FeatureVersion: FeatureVersion, Score: math.Round(sc*1e4) / 1e4, Band: band,
		Signals: string(signals), Features: string(features), UpdatedAt: at}
	if err := e.st.PutOracleScore(ctx, row); err != nil {
		e.log.Warn("Carthago Oracle: store score", "session", sess.SessionID, "err", err)
		return
	}
	e.log.Debug("Carthago Oracle scored", "session", sess.SessionID, "band", band)
	if e.cfg.Analyst != nil && (band == store.OracleBandReview || flaggedByRules(evidence)) {
		if s.due.IsZero() {
			e.pending.Add(1)
		}
		s.due = e.cfg.Now().Add(e.cfg.Settle)
	}
}

func first(score float64, _ [NumFeatures]float64) float64 { return score }

// flaggedByRules reports whether the rules produced something a reviewer would look at.
func flaggedByRules(evidence []store.Evidence) bool {
	for i := range evidence {
		if !evidence[i].Bot && evidence[i].Severity >= 2 {
			return true
		}
	}
	return false
}

// sweep sends settled cases to the analyst and forgets sessions that went quiet.
func (e *Engine) sweep(ctx context.Context) {
	now := e.cfg.Now()
	for k, s := range e.sessions {
		if !s.inFlight && s.due.IsZero() && now.Sub(s.seenAt) > 2*time.Hour {
			delete(e.sessions, k)
			continue
		}
		if s.due.IsZero() || now.Before(s.due) || s.inFlight {
			continue
		}
		if !e.cfg.ReviewLive && !e.ended(ctx, s, now) {
			s.due = now.Add(min(e.cfg.EndedAfter/4, 15*time.Second)) // look again shortly
			continue
		}
		job, ok := e.buildCase(ctx, s)
		if !ok {
			s.due = time.Time{}
			e.pending.Done()
			continue
		}
		job.key = k
		select {
		case e.cases <- job:
			// The session's pending count passes to the case.
			s.inFlight, s.due = true, time.Time{}
		default:
			// The analyst is busy; the case stays due.
		}
	}
}

// ended reports whether a session is over: the gateway closed or kicked it, or it has
// been silent for EndedAfter.
func (e *Engine) ended(ctx context.Context, s *sessionState, now time.Time) bool {
	sess, err := e.st.GetSession(ctx, s.sess.SessionID)
	if err != nil || sess == nil {
		return now.Sub(s.seenAt) >= e.cfg.EndedAfter
	}
	if sess.State != store.SessionActive {
		return true
	}
	last := sess.LastHeartbeat
	if s.seenAt.After(last) {
		last = s.seenAt
	}
	return now.Sub(last) >= e.cfg.EndedAfter
}

// buildCase assembles a session's case and reports whether it needs a (new) verdict.
func (e *Engine) buildCase(ctx context.Context, s *sessionState) (caseJob, bool) {
	sess := s.sess
	a := e.cfg.Analyst
	if !a.Allowed(sess.TenantID) {
		return caseJob{}, false
	}
	evidence, err := e.st.ListEvidence(ctx, sess.TenantID, store.EvidenceFilter{SessionID: sess.SessionID, Limit: 500})
	if err != nil {
		return caseJob{}, false
	}
	// Oldest first, so a case's evidence ids do not shift when newer rows arrive.
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].ID < evidence[j].ID })
	in := analyst.Input{TenantID: sess.TenantID, PlayerHash: sess.PlayerHash, SessionID: sess.SessionID,
		TrustLevel: sess.TrustLevel, Evidence: evidence, SignalKeys: signalKeys}
	if row, err := e.st.GetOracleScore(ctx, sess.TenantID, sess.SessionID); err == nil && row != nil {
		in.Scored, in.Score, in.Band = true, row.Score, row.Band
		var sigs []Signal
		_ = json.Unmarshal([]byte(row.Signals), &sigs)
		for _, sg := range sigs {
			in.Signals = append(in.Signals, analyst.Signal{Key: sg.Key, Family: sg.Family, Effect: sg.Effect})
		}
	}
	c := analyst.Build(e.pseudo, in)
	hash := a.CaseHash(c)
	if prev, err := e.st.GetOracleVerdict(ctx, sess.TenantID, sess.SessionID); err == nil && prev != nil && prev.CaseHash == hash {
		if prev.Status == store.OracleVerdictOK || e.cfg.Now().Sub(prev.CreatedAt) < e.cfg.RetryAfter {
			return caseJob{}, false // the cached verdict stands
		}
	}
	return caseJob{sess: sess, c: c, hash: hash}, true
}

var signalKeys = func() map[string]bool {
	m := map[string]bool{}
	for _, f := range Features {
		m[f.Key] = true
	}
	return m
}()

// CitedEvidence is one cited item of a stored verdict: the case's id for it, the rule,
// and the stored evidence rows it stands for.
type CitedEvidence struct {
	ID       string  `json:"id"`
	Rule     string  `json:"rule"`
	Evidence []int64 `json:"evidence"`
}

func (e *Engine) reviewLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-e.cases:
			e.review(ctx, job)
			select {
			case e.done <- job.key:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (e *Engine) review(ctx context.Context, job caseJob) {
	res := e.cfg.Analyst.Review(ctx, job.sess.TenantID, job.c)
	row := VerdictRow(job.sess, job.c, job.hash, res, e.cfg.Now())
	if err := e.st.PutOracleVerdict(ctx, row); err != nil {
		e.log.Warn("Carthago Oracle: store verdict", "session", job.sess.SessionID, "err", err)
		return
	}
	if res.Verdict == nil {
		// The reason is a fixed word; the provider's own error goes to the debug log.
		e.log.Warn("Carthago Oracle analyst unavailable for a case", "session", job.sess.SessionID, "reason", res.Reason)
		e.log.Debug("Carthago Oracle analyst error", "session", job.sess.SessionID, "err", res.Err)
		return
	}
	e.log.Debug("Carthago Oracle analyst reviewed a case", "session", job.sess.SessionID, "latency", res.Latency)
}

// VerdictRow turns a review's result into the row that is stored.
func VerdictRow(sess store.Session, c *analyst.Case, hash string, res analyst.Result, at time.Time) *store.OracleVerdict {
	row := &store.OracleVerdict{TenantID: sess.TenantID, SessionID: sess.SessionID, PlayerHash: sess.PlayerHash, CaseHash: hash,
		Status: store.OracleVerdictUnavailable, Reason: res.Reason, Provider: res.Provider, AnalystModel: res.Model,
		PromptVersion: res.PromptVersion, CaseFile: string(c.JSON()), LatencyMs: res.Latency.Milliseconds(),
		TokensIn: int64(res.TokensIn), TokensOut: int64(res.TokensOut), CreatedAt: at}
	if v := res.Verdict; v != nil {
		cited := make([]CitedEvidence, 0, len(v.CitedEvidence))
		for _, id := range v.CitedEvidence {
			for _, ce := range c.Evidence {
				if ce.ID == id {
					cited = append(cited, CitedEvidence{ID: id, Rule: ce.Rule, Evidence: c.Refs[id]})
				}
			}
		}
		b, _ := json.Marshal(cited)
		row.Status, row.Reason = store.OracleVerdictOK, ""
		row.CheatType, row.Confidence, row.Action, row.Summary, row.Cited = v.CheatType, v.Confidence, v.RecommendedAction, v.Summary, string(b)
	}
	return row
}
