package store

import (
	"context"
	"sort"
)

type memOracle struct {
	scores   map[[2]string]OracleScore
	verdicts map[[2]string]OracleVerdict
	usage    map[[2]string]OracleUsage
	reviews  map[[2]string]OracleReview
}

func (m *Memory) orc() *memOracle {
	if m.oracle == nil {
		m.oracle = &memOracle{scores: map[[2]string]OracleScore{}, verdicts: map[[2]string]OracleVerdict{}, usage: map[[2]string]OracleUsage{}, reviews: map[[2]string]OracleReview{}}
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

func (m *Memory) PutOracleReview(_ context.Context, r *OracleReview) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.orc().reviews[[2]string{r.TenantID, r.SessionID}] = *r
	return nil
}

func (m *Memory) ListOracleCases(_ context.Context, tenant string, reviewedOnly bool, limit int) ([]OracleCase, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []OracleCase
	for _, v := range m.listVerdicts(tenant, "") {
		if v.CaseFile == "" {
			continue
		}
		c := OracleCase{Verdict: v}
		if r, ok := m.orc().reviews[[2]string{tenant, v.SessionID}]; ok {
			c.Review = &r
		} else if reviewedOnly {
			continue
		}
		out = append(out, c)
	}
	if n := limitOr(limit, 1000); len(out) > n {
		out = out[:n]
	}
	return out, nil
}
