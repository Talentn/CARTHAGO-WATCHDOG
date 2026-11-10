package store

import (
	"context"
	"sort"
	"time"
)

type memMatch struct {
	seq     uint64
	updated time.Time
}

type memEvidence struct {
	evidence  []Evidence
	telemetry map[string]Telemetry
	matches   map[[2]string]memMatch
}

func (m *Memory) ev() *memEvidence {
	if m.evid == nil {
		m.evid = &memEvidence{telemetry: map[string]Telemetry{}, matches: map[[2]string]memMatch{}}
	}
	return m.evid
}

func (m *Memory) AddEvidence(_ context.Context, evs []Evidence) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	x := m.ev()
	for i := range evs {
		evs[i].ID = int64(len(x.evidence) + 1)
		x.evidence = append(x.evidence, evs[i])
	}
	return nil
}

func (m *Memory) PutTelemetry(_ context.Context, t *Telemetry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ev().telemetry[t.SessionID] = *t
	return nil
}

func (m *Memory) AdvanceMatch(_ context.Context, tenant, matchID string, seq uint64, at time.Time, _ bool) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{tenant, matchID}
	x := m.ev()
	if cur, ok := x.matches[k]; ok && seq <= cur.seq {
		return false, nil
	}
	x.matches[k] = memMatch{seq: seq, updated: at}
	return true, nil
}

func (m *Memory) Overview(_ context.Context, tenant string, since, online time.Time) (Overview, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var o Overview
	players := map[string]bool{}
	for _, s := range m.sessions {
		if s.TenantID != tenant {
			continue
		}
		if s.State == SessionActive && !s.LastHeartbeat.Before(online) {
			o.OnlineSessions++
		}
		if !s.CreatedAt.Before(since) {
			o.Sessions++
			players[s.PlayerHash] = true
			if int(s.TrustLevel) < len(o.TrustLevels) {
				o.TrustLevels[s.TrustLevel]++
			}
		}
	}
	o.Players = len(players)
	risk := map[string]float64{}
	for _, e := range m.ev().evidence {
		if e.TenantID != tenant || e.Severity <= 0 {
			continue
		}
		if !e.ObservedAt.Before(since) {
			o.Evidence++
		}
		risk[e.PlayerHash] += riskOf(e.Severity, e.Score)
	}
	for _, r := range risk {
		if r >= FlaggedRisk {
			o.FlaggedPlayers++
		}
	}
	for k, mm := range m.ev().matches {
		if k[0] == tenant && !mm.updated.Before(since) {
			o.Matches++
		}
	}
	return o, nil
}

func (m *Memory) ListSessions(_ context.Context, tenant string, f SessionFilter) ([]SessionRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SessionRow
	for _, s := range m.sessions {
		if s.TenantID != tenant || (f.PlayerHash != "" && s.PlayerHash != f.PlayerHash) {
			continue
		}
		r := SessionRow{Session: s, MaxSeverity: -1}
		for _, e := range m.ev().evidence {
			if e.SessionID == s.SessionID && e.Severity > 0 {
				r.EvidenceCount++
				r.MaxSeverity = max(r.MaxSeverity, e.Severity)
			}
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if n := limitOr(f.Limit, 100); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) GetTelemetry(_ context.Context, tenant, sessionID string) (*Telemetry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	t, tok := m.ev().telemetry[sessionID]
	if !ok || !tok || s.TenantID != tenant {
		return nil, ErrNotFound
	}
	return &t, nil
}

func (m *Memory) ListEvidence(_ context.Context, tenant string, f EvidenceFilter) ([]Evidence, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Evidence
	evs := m.ev().evidence
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		if e.TenantID != tenant || e.Severity < f.MinSeverity ||
			(f.PlayerHash != "" && e.PlayerHash != f.PlayerHash) || (f.SessionID != "" && e.SessionID != f.SessionID) {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ObservedAt.After(out[j].ObservedAt) })
	if n := limitOr(f.Limit, 100); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) GetEvidence(_ context.Context, tenant string, id int64) (*Evidence, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	evs := m.ev().evidence
	if id < 1 || id > int64(len(evs)) || evs[id-1].TenantID != tenant {
		return nil, ErrNotFound
	}
	e := evs[id-1]
	return &e, nil
}

func (m *Memory) ListPlayers(_ context.Context, tenant string, f PlayerFilter) ([]PlayerRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := map[string]*PlayerRow{}
	latest := map[string]time.Time{}
	row := func(p string) *PlayerRow {
		if rows[p] == nil {
			rows[p] = &PlayerRow{PlayerHash: p, MaxSeverity: -1}
		}
		return rows[p]
	}
	for _, s := range m.sessions {
		if s.TenantID != tenant {
			continue
		}
		r := row(s.PlayerHash)
		r.Sessions++
		if s.CreatedAt.After(r.LastSeen) {
			r.LastSeen = s.CreatedAt
		}
		if !s.CreatedAt.Before(latest[s.PlayerHash]) {
			latest[s.PlayerHash], r.TrustLevel = s.CreatedAt, s.TrustLevel
		}
	}
	topScore := map[string][2]float64{}
	for _, e := range m.ev().evidence {
		if e.TenantID != tenant || e.Severity <= 0 {
			continue
		}
		r := row(e.PlayerHash)
		r.EvidenceCount++
		r.MaxSeverity = max(r.MaxSeverity, e.Severity)
		if e.Integrity {
			r.Integrity++
		}
		r.Risk += riskOf(e.Severity, e.Score)
		if e.ObservedAt.After(r.LastSeen) {
			r.LastSeen = e.ObservedAt
		}
		if t, ok := topScore[e.PlayerHash]; !ok || float64(e.Severity) > t[0] || (float64(e.Severity) == t[0] && e.Score > t[1]) {
			topScore[e.PlayerHash], r.TopRule = [2]float64{float64(e.Severity), e.Score}, e.Rule
		}
	}
	var out []PlayerRow
	for _, r := range rows {
		if f.FlaggedOnly && r.Risk < FlaggedRisk {
			continue
		}
		out = append(out, *r)
	}
	sortPlayers(out)
	if n := limitOr(f.Limit, 100); len(out) > n {
		out = out[:n]
	}
	return out, nil
}
