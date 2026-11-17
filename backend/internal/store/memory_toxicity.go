package store

import (
	"context"
	"sort"
	"time"
)

type memToxicity struct {
	rows   []ToxicityFinding
	seq    int64
	limits map[string]string
}

func (m *Memory) tox() *memToxicity {
	if m.toxicity == nil {
		m.toxicity = &memToxicity{limits: map[string]string{}}
	}
	return m.toxicity
}

func (m *Memory) AddToxicityFindings(_ context.Context, rows []ToxicityFinding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tox()
	for i := range rows {
		t.seq++
		rows[i].ID = t.seq
		t.rows = append(t.rows, rows[i])
	}
	return nil
}

func (m *Memory) ListToxicityFindings(_ context.Context, tenant string, f ToxicityFilter) ([]ToxicityFinding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ToxicityFinding
	for _, r := range m.tox().rows {
		if r.TenantID != tenant || (f.PlayerHash != "" && r.PlayerHash != f.PlayerHash) || (f.MatchID != "" && r.MatchID != f.MatchID) ||
			(!f.Since.IsZero() && r.ObservedAt.Before(f.Since)) {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].ObservedAt.Equal(out[j].ObservedAt) {
			return out[i].ObservedAt.After(out[j].ObservedAt)
		}
		return out[i].ID > out[j].ID
	})
	if n := limitOr(f.Limit, 100); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) PruneToxicityFindings(_ context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tox()
	kept := t.rows[:0]
	var n int64
	for _, r := range t.rows {
		if r.ObservedAt.Before(before) {
			n++
			continue
		}
		kept = append(kept, r)
	}
	t.rows = kept
	return n, nil
}

func (m *Memory) GetToxicityLimits(_ context.Context, tenant string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tox().limits[tenant], nil
}

func (m *Memory) SetToxicityLimits(_ context.Context, tenant, limits string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limits == "" {
		delete(m.tox().limits, tenant)
	} else {
		m.tox().limits[tenant] = limits
	}
	return nil
}
