package store

import (
	"context"
	"sort"
)

type memOracle struct {
	scores   map[[2]string]OracleScore
	verdicts map[[2]string]OracleVerdict
	usage    map[[2]string]OracleUsage
	labels   map[[2]string]SessionLabel
	audit    []LabelAudit
}

func (m *Memory) orc() *memOracle {
	if m.oracle == nil {
		m.oracle = &memOracle{scores: map[[2]string]OracleScore{}, verdicts: map[[2]string]OracleVerdict{}, usage: map[[2]string]OracleUsage{}, labels: map[[2]string]SessionLabel{}}
	}
	return m.oracle
}

func (m *Memory) PutOracleScore(_ context.Context, s *OracleScore) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.orc().scores[[2]string{s.TenantID, s.SessionID}] = *s
	return nil
}

func (m *Memory) GetOracleScore(_ context.Context, tenant, sessionID string) (*OracleScore, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.orc().scores[[2]string{tenant, sessionID}]
	if !ok {
		return nil, ErrNotFound
	}
	return &s, nil
}

func (m *Memory) ListOracleScores(_ context.Context, tenant string, f OracleFilter) ([]OracleScore, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []OracleScore
	for k, s := range m.orc().scores {
		if k[0] == tenant && (f.PlayerHash == "" || s.PlayerHash == f.PlayerHash) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].UpdatedAt.Equal(out[j].UpdatedAt) {
			return out[i].UpdatedAt.After(out[j].UpdatedAt)
		}
		return out[i].SessionID < out[j].SessionID
	})
	if n := limitOr(f.Limit, 100); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) PutOracleVerdict(_ context.Context, v *OracleVerdict) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.orc().verdicts[[2]string{v.TenantID, v.SessionID}] = *v
	return nil
}

func (m *Memory) GetOracleVerdict(_ context.Context, tenant, sessionID string) (*OracleVerdict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.orc().verdicts[[2]string{tenant, sessionID}]
	if !ok {
		return nil, ErrNotFound
	}
	return &v, nil
}

func (m *Memory) listVerdicts(tenant, player string) []OracleVerdict {
	var out []OracleVerdict
	for k, v := range m.orc().verdicts {
		if k[0] == tenant && (player == "" || v.PlayerHash == player) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].SessionID < out[j].SessionID
	})
	return out
}

func (m *Memory) ListOracleVerdicts(_ context.Context, tenant string, f OracleFilter) ([]OracleVerdict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.listVerdicts(tenant, f.PlayerHash)
	if n := limitOr(f.Limit, 100); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) AddOracleUsage(_ context.Context, tenant, day string, cases, tokens int64) (OracleUsage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{tenant, day}
	u := m.orc().usage[k]
	u.Cases, u.Tokens = u.Cases+cases, u.Tokens+tokens
	m.orc().usage[k] = u
	return u, nil
}

func (m *Memory) SetSessionLabel(_ context.Context, l *SessionLabel, action, remote string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := m.orc()
	k := [2]string{l.TenantID, l.SessionID}
	if l.Label == "" {
		delete(o.labels, k)
	} else {
		o.labels[k] = *l
	}
	o.audit = append(o.audit, LabelAudit{ID: int64(len(o.audit) + 1), TenantID: l.TenantID, SessionID: l.SessionID, Action: action, Label: l.Label,
		CheatType: l.CheatType, Note: l.Note, Reviewer: l.Reviewer, Remote: remote, At: l.LabelledAt})
	return nil
}

func (m *Memory) GetSessionLabel(_ context.Context, tenant, sessionID string) (*SessionLabel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.orc().labels[[2]string{tenant, sessionID}]
	if !ok {
		return nil, ErrNotFound
	}
	return &l, nil
}

func (m *Memory) ListSessionLabels(_ context.Context, tenant string, f OracleFilter) ([]SessionLabel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SessionLabel
	for k, l := range m.orc().labels {
		if k[0] == tenant && (f.PlayerHash == "" || l.PlayerHash == f.PlayerHash) {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LabelledAt.Equal(out[j].LabelledAt) {
			return out[i].LabelledAt.After(out[j].LabelledAt)
		}
		return out[i].SessionID < out[j].SessionID
	})
	if n := limitOr(f.Limit, 100); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) ListLabelAudit(_ context.Context, tenant, sessionID string, limit int) ([]LabelAudit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []LabelAudit
	a := m.orc().audit
	for i := len(a) - 1; i >= 0 && len(out) < limitOr(limit, 50); i-- {
		if a[i].TenantID == tenant && a[i].SessionID == sessionID {
			out = append(out, a[i])
		}
	}
	return out, nil
}
