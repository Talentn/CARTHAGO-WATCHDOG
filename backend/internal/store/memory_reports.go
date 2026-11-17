package store

import (
	"context"
	"sort"
	"time"
)

type memReports struct {
	rows []PlayerReport
	seq  int64
}

func (m *Memory) rep() *memReports {
	if m.reports == nil {
		m.reports = &memReports{}
	}
	return m.reports
}

func (m *Memory) AddPlayerReport(_ context.Context, r *PlayerReport) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.rep()
	for _, old := range t.rows {
		if old.TenantID == r.TenantID && old.Reporter == r.Reporter && old.Reported == r.Reported && old.MatchID == r.MatchID {
			r.ID = old.ID
			return false, nil
		}
	}
	if r.State == "" {
		r.State = ReportOpen
	}
	t.seq++
	r.ID = t.seq
	t.rows = append(t.rows, *r)
	return true, nil
}

func (m *Memory) GetPlayerReport(_ context.Context, tenant string, id int64) (*PlayerReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rep().rows {
		if r.TenantID == tenant && r.ID == id {
			return &r, nil
		}
	}
	return nil, ErrNotFound
}

func (f ReportFilter) matches(tenant string, r *PlayerReport) bool {
	return r.TenantID == tenant && (f.State == "" || r.State == f.State) && (f.Reporter == "" || r.Reporter == f.Reporter) &&
		(f.Reported == "" || r.Reported == f.Reported) && (f.MatchID == "" || r.MatchID == f.MatchID) && (f.Since.IsZero() || !r.CreatedAt.Before(f.Since))
}

func (m *Memory) ListPlayerReports(_ context.Context, tenant string, f ReportFilter) ([]PlayerReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PlayerReport
	for i := range m.rep().rows {
		if f.matches(tenant, &m.rep().rows[i]) {
			out = append(out, m.rep().rows[i])
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	if n := limitOr(f.Limit, 100); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) CountPlayerReports(_ context.Context, tenant string, f ReportFilter) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for i := range m.rep().rows {
		if f.matches(tenant, &m.rep().rows[i]) {
			n++
		}
	}
	return n, nil
}

func (m *Memory) SetPlayerReportState(_ context.Context, tenant string, id int64, state, by string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.rep().rows
	for i := range rows {
		if rows[i].TenantID == tenant && rows[i].ID == id {
			rows[i].State, rows[i].DecidedBy, rows[i].DecidedAt = state, by, at
			return nil
		}
	}
	return ErrNotFound
}

func (m *Memory) TallyPlayerReports(_ context.Context, tenant string, since time.Time) (map[string]ReportTally, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]ReportTally{}
	who := map[string]map[string]bool{}
	for _, r := range m.rep().rows {
		if r.TenantID != tenant || r.CreatedAt.Before(since) || r.State == ReportDismissed {
			continue
		}
		if who[r.Reported] == nil {
			who[r.Reported] = map[string]bool{}
		}
		who[r.Reported][r.Reporter] = true
		t := out[r.Reported]
		t.Reports++
		t.Reporters = len(who[r.Reported])
		out[r.Reported] = t
	}
	return out, nil
}

func (m *Memory) PrunePlayerReports(_ context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.rep()
	kept := t.rows[:0]
	var n int64
	for _, r := range t.rows {
		if r.CreatedAt.Before(before) {
			n++
			continue
		}
		kept = append(kept, r)
	}
	t.rows = kept
	return n, nil
}
