// Package pipeline connects the gateway to the analyzer and the evidence store. Heartbeats and
// gameplay batches are queued to one worker goroutine, which owns all per-session and per-match
// analyzer state (so it needs no locks) and writes evidence, telemetry and match progress.
//
// The queue is bounded. A full queue drops heartbeat analysis (the heartbeat itself was
// already acknowledged; only its telemetry is lost and counted) and answers gameplay batches
// with "busy" so the game server retries the same batch_seq later. Nothing on the client's
// heartbeat path ever waits on the database.
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/store"
)

// Kicker is satisfied by gateway.Manager.
type Kicker interface {
	Kick(sessionID, reason string)
}

// SessionLookup resolves a session id named by a game server to its tenant and player, so a
// game server cannot attach evidence to another tenant's session.
type SessionLookup interface {
	GetSession(ctx context.Context, sessionID string) (*store.Session, error)
}

type Config struct {
	Rules     analyzer.Config
	QueueSize int
	// AutoKick kicks a session on integrity evidence at or above AutoKickSeverity. Off by
	// default: Phase 1 detections feed the dashboard for review; behavioural evidence never
	// kicks regardless of this setting.
	AutoKick         bool
	AutoKickSeverity analyzer.Severity
	// ClientIdle and MatchIdle bound how long analyzer state is kept without traffic.
	ClientIdle time.Duration
	MatchIdle  time.Duration
	Now        func() time.Time
}

func (c *Config) defaults() {
	if c.Rules.OverlayAllow == nil {
		c.Rules = analyzer.Defaults()
	}
	if c.QueueSize == 0 {
		c.QueueSize = 4096
	}
	if c.AutoKickSeverity == 0 {
		c.AutoKickSeverity = analyzer.SeverityCritical
	}
	if c.ClientIdle == 0 {
		c.ClientIdle = 10 * time.Minute
	}
	if c.MatchIdle == 0 {
		c.MatchIdle = 30 * time.Minute
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

var ErrBusy = errors.New("busy")

type Pipeline struct {
	cfg      Config
	st       store.EvidenceStore
	sessions SessionLookup
	kick     Kicker
	log      *slog.Logger

	q    chan func()
	stop chan struct{}
	done chan struct{}
	once sync.Once

	dropped atomic.Uint64

	// worker-owned
	clients map[string]*clientState
	matches map[[2]string]*matchState
}

type clientState struct {
	an            analyzer.ClientState
	seen          map[string]bool
	findingsTotal uint64
	mitApplied    uint64
	mitFailed     uint64
	lastSeen      time.Time
}

type matchState struct {
	m        *analyzer.Match
	reported map[string]bool // slot|rule
	sessions map[uint32]store.Session
	lastSeen time.Time
}

// maxSeenPerSession caps client-evidence dedupe keys per session; a client spraying unique
// findings cannot grow server memory without bound.
const maxSeenPerSession = 1024

func New(cfg Config, st store.EvidenceStore, sessions SessionLookup, kick Kicker, log *slog.Logger) *Pipeline {
	cfg.defaults()
	p := &Pipeline{
		cfg: cfg, st: st, sessions: sessions, kick: kick, log: log,
		q: make(chan func(), cfg.QueueSize), stop: make(chan struct{}), done: make(chan struct{}),
		clients: map[string]*clientState{}, matches: map[[2]string]*matchState{},
	}
	go p.run()
	return p
}

// Close drains queued work and stops the worker.
func (p *Pipeline) Close() {
	p.once.Do(func() { close(p.stop) })
	<-p.done
}

// Dropped is the number of heartbeats whose analysis was skipped because the queue was full.
func (p *Pipeline) Dropped() uint64 { return p.dropped.Load() }

func (p *Pipeline) run() {
	defer close(p.done)
	prune := time.NewTicker(time.Minute)
	defer prune.Stop()
	for {
		select {
		case f := <-p.q:
			f()
		case <-prune.C:
			p.prune()
		case <-p.stop:
			for {
				select {
				case f := <-p.q:
					f()
				default:
					return
				}
			}
		}
	}
}

func (p *Pipeline) enqueue(f func()) bool {
	select {
	case <-p.stop:
		return false
	default:
	}
	select {
	case p.q <- f:
		return true
	default:
		return false
	}
}

// Heartbeat queues analysis of one heartbeat. It never blocks.
func (p *Pipeline) Heartbeat(sess store.Session, hb *pb.Heartbeat) {
	at := p.cfg.Now()
	if !p.enqueue(func() { p.heartbeat(sess, hb, at) }) {
		p.dropped.Add(1)
	}
}

// Gameplay records and analyses one batch. accepted=false with a nil error means the batch
// was a duplicate (already processed); ErrBusy means retry later.
func (p *Pipeline) Gameplay(ctx context.Context, tenant string, b *pb.GameplayBatch) (accepted bool, err error) {
	if b.MatchId == "" || len(b.MatchId) > 128 {
		return false, errors.New("match_id must be 1-128 bytes")
	}
	type result struct {
		fresh bool
		err   error
	}
	reply := make(chan result, 1)
	at := p.cfg.Now()
	if !p.enqueue(func() {
		fresh, err := p.gameplay(tenant, b, at)
		reply <- result{fresh, err}
	}) {
		return false, ErrBusy
	}
	select {
	case r := <-reply:
		return r.fresh, r.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (p *Pipeline) heartbeat(sess store.Session, hb *pb.Heartbeat, at time.Time) {
	ctx := context.Background()
	cs := p.clients[sess.SessionID]
	if cs == nil {
		cs = &clientState{seen: map[string]bool{}}
		p.clients[sess.SessionID] = cs
	}
	cs.lastSeen = at

	var evs []store.Evidence
	add := func(key string, e analyzer.Evidence, raw string) {
		if cs.seen[key] {
			return
		}
		if len(cs.seen) >= maxSeenPerSession && e.Severity == analyzer.SeverityInfo {
			return
		}
		cs.seen[key] = true
		evs = append(evs, store.Evidence{
			TenantID: sess.TenantID, PlayerHash: sess.PlayerHash, SessionID: sess.SessionID, Source: store.SourceClient,
			Rule: e.Rule, Severity: int(e.Severity), Score: e.Score, Integrity: e.Integrity, Summary: e.Summary, Raw: raw, ObservedAt: at,
		})
	}

	for _, f := range hb.Findings {
		cs.findingsTotal++
		if pb.FindingCode(f.Code) == pb.FindingCode_FINDING_CODE_MITIGATIONS {
			cs.mitApplied, cs.mitFailed = f.A, f.B
			continue
		}
		e, ok := p.cfg.Rules.ClassifyFinding(f.Code, f.A, f.B, f.Detail)
		if !ok {
			continue
		}
		raw, _ := json.Marshal(map[string]any{"job": f.Job, "code": pb.FindingCode(f.Code).String(), "a": fmt.Sprintf("%#x", f.A), "b": fmt.Sprintf("%#x", f.B), "detail": f.Detail})
		add(fmt.Sprintf("f|%d|%x|%s", f.Code, f.A, f.Detail), e, string(raw))
	}
	for _, e := range p.cfg.Rules.Heartbeat(&cs.an, hb, at) {
		add("h|"+e.Rule, e, "")
	}

	if len(evs) > 0 {
		if err := p.st.AddEvidence(ctx, evs); err != nil {
			p.log.Warn("persist evidence", "session", sess.SessionID, "err", err)
		}
		for _, e := range evs {
			p.log.Info("detection", "session", sess.SessionID, "player", sess.PlayerHash, "rule", e.Rule, "severity", analyzer.Severity(e.Severity).String(), "summary", e.Summary)
		}
		p.maybeKick(sess.SessionID, evs)
	}
	if err := p.st.PutTelemetry(ctx, telemetry(sess.SessionID, hb, cs, at)); err != nil {
		p.log.Warn("persist telemetry", "session", sess.SessionID, "err", err)
	}
}

func (p *Pipeline) maybeKick(sessionID string, evs []store.Evidence) {
	if !p.cfg.AutoKick || p.kick == nil {
		return
	}
	for _, e := range evs {
		if e.Integrity && analyzer.Severity(e.Severity) >= p.cfg.AutoKickSeverity {
			p.kick.Kick(sessionID, "integrity_violation: "+e.Rule)
			return
		}
	}
}

func telemetry(id string, hb *pb.Heartbeat, cs *clientState, at time.Time) *store.Telemetry {
	t := &store.Telemetry{SessionID: id, UpdatedAt: at, Activity: hb.Activity, FindingsTotal: cs.findingsTotal, MitigationsApplied: cs.mitApplied, MitigationsFailed: cs.mitFailed}
	if s := hb.Sched; s != nil {
		t.WorkerCPUNs, t.Slices, t.SliceCPUMaxNs, t.SliceOverruns, t.Frames = s.WorkerCpuNs, s.Slices, s.SliceCpuMaxNs, s.SliceOverruns, s.Frames
		t.JobsQuarantined, t.FindingsDropped, t.InputThreadCPUNs = s.JobsQuarantined, s.FindingsDropped, s.InputThreadCpuNs
	}
	if in := hb.Input; in != nil {
		t.MouseEvents, t.InjectedEvents = in.MouseEvents, in.Injected
	}
	if len(hb.Coverage) > 0 {
		type cov struct {
			Job         string `json:"job"`
			Runs        uint64 `json:"runs"`
			Overruns    uint64 `json:"overruns"`
			Quarantined bool   `json:"quarantined,omitempty"`
		}
		c := make([]cov, 0, len(hb.Coverage))
		for _, j := range hb.Coverage {
			c = append(c, cov{j.Job, j.RunsCompleted, j.Overruns, j.Quarantined})
		}
		b, _ := json.Marshal(c)
		t.Coverage = string(b)
	}
	return t
}

func (p *Pipeline) gameplay(tenant string, b *pb.GameplayBatch, at time.Time) (bool, error) {
	ctx := context.Background()
	fresh, err := p.st.AdvanceMatch(ctx, tenant, b.MatchId, b.BatchSeq, at, b.MatchOver)
	if err != nil || !fresh {
		return false, err
	}
	key := [2]string{tenant, b.MatchId}
	ms := p.matches[key]
	if ms == nil {
		ms = &matchState{m: analyzer.NewMatch(p.cfg.Rules), reported: map[string]bool{}, sessions: map[uint32]store.Session{}}
		p.matches[key] = ms
	}
	ms.lastSeen = at
	for _, mp := range b.Players {
		if mp.SessionId == "" {
			continue
		}
		s, err := p.sessions.GetSession(ctx, mp.SessionId)
		if err != nil || s.TenantID != tenant {
			p.log.Warn("gameplay names a session outside the tenant; ignoring the link", "tenant", tenant, "match", b.MatchId, "slot", mp.Slot)
			delete(ms.sessions, mp.Slot)
			continue
		}
		ms.sessions[mp.Slot] = *s
	}
	ms.m.Add(b)

	var evs []store.Evidence
	for slot, list := range ms.m.Evaluate() {
		for _, e := range list {
			k := fmt.Sprintf("%d|%s", slot, e.Rule)
			if ms.reported[k] {
				continue
			}
			ms.reported[k] = true
			player := ms.m.Players[slot]
			ev := store.Evidence{
				TenantID: tenant, PlayerHash: player.PlayerHash, MatchID: b.MatchId, Source: store.SourceGameplay,
				Rule: e.Rule, Severity: int(e.Severity), Score: e.Score, Summary: e.Summary, ObservedAt: at,
				Raw: fmt.Sprintf(`{"slot":%d,"batch_seq":%d}`, slot, b.BatchSeq),
			}
			// The verified session wins over whatever player hash the game server sent.
			if s, ok := ms.sessions[slot]; ok {
				ev.SessionID, ev.PlayerHash = s.SessionID, s.PlayerHash
			}
			if ev.PlayerHash == "" {
				ev.PlayerHash = fmt.Sprintf("slot-%d", slot)
			}
			evs = append(evs, ev)
		}
	}
	if len(evs) > 0 {
		if err := p.st.AddEvidence(ctx, evs); err != nil {
			return true, err
		}
		for _, e := range evs {
			p.log.Info("detection", "match", b.MatchId, "player", e.PlayerHash, "rule", e.Rule, "severity", analyzer.Severity(e.Severity).String(), "summary", e.Summary)
		}
	}
	if b.MatchOver {
		delete(p.matches, key)
	}
	return true, nil
}

func (p *Pipeline) prune() {
	now := p.cfg.Now()
	for id, c := range p.clients {
		if now.Sub(c.lastSeen) > p.cfg.ClientIdle {
			delete(p.clients, id)
		}
	}
	for k, m := range p.matches {
		if now.Sub(m.lastSeen) > p.cfg.MatchIdle {
			delete(p.matches, k)
		}
	}
}
