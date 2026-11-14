package store

import (
	"context"
	"sort"
)

type memEconomy struct {
	entries   []EconomyEntry
	flags     []EconomyFlag
	limits    []EconomyLimit
	tolerance map[string]int64
}

func (m *Memory) ec() *memEconomy {
	if m.econ == nil {
		m.econ = &memEconomy{tolerance: map[string]int64{}}
	}
	return m.econ
}

func (m *Memory) AddEconomyEntry(_ context.Context, e *EconomyEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ec := m.ec()
	for _, have := range ec.entries {
		if have.TenantID == e.TenantID && have.EventID == e.EventID {
			return ErrDuplicate
		}
	}
	e.ID = int64(len(ec.entries) + 1)
	ec.entries = append(ec.entries, *e)
	return nil
}

func (m *Memory) ListEconomyEntries(_ context.Context, tenant string, f EconomyFilter) ([]EconomyEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []EconomyEntry
	for _, e := range m.ec().entries {
		if e.TenantID != tenant || f.PlayerHash != "" && e.PlayerHash != f.PlayerHash || f.Currency != "" && e.Currency != f.Currency ||
			f.Counterparty != "" && e.Counterparty != f.Counterparty || f.DirtyFrom != "" && e.DirtyFrom != f.DirtyFrom ||
			f.DirtyOnly && e.Dirty <= 0 || !f.Since.IsZero() && e.At.Before(f.Since) {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if f.OldestFirst {
			a, b = b, a
		}
		if !a.At.Equal(b.At) {
			return a.At.After(b.At)
		}
		return a.ID > b.ID
	})
	if n := limitOr(f.Limit, 200); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) SumEconomy(_ context.Context, tenant, player, currency string, f EconomySum) (int64, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var sum int64
	n := 0
	for _, e := range m.ec().entries {
		if e.TenantID != tenant || e.PlayerHash != player || e.Currency != currency || f.Source != "" && e.Source != f.Source || f.CreditsOnly && e.Amount <= 0 ||
			!f.After.IsZero() && !e.At.After(f.After) || !f.Until.IsZero() && e.At.After(f.Until) {
			continue
		}
		sum += e.Amount
		n++
	}
	return sum, n, nil
}

func (m *Memory) SetEconomyDirty(_ context.Context, tenant string, id, dirty int64, from string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ec := m.ec()
	if id >= 1 && id <= int64(len(ec.entries)) && ec.entries[id-1].TenantID == tenant {
		ec.entries[id-1].Dirty, ec.entries[id-1].DirtyFrom = dirty, from
	}
	return nil
}

func (m *Memory) AddEconomyFlag(_ context.Context, f *EconomyFlag) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ec := m.ec()
	f.ID = int64(len(ec.flags) + 1)
	ec.flags = append(ec.flags, *f)
	return nil
}

func (m *Memory) ListEconomyFlags(_ context.Context, tenant, player string, limit int) ([]EconomyFlag, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ec := m.ec()
	var out []EconomyFlag
	for i := len(ec.flags) - 1; i >= 0 && len(out) < limitOr(limit, 200); i-- {
		if f := ec.flags[i]; f.TenantID == tenant && (player == "" || f.PlayerHash == player) {
			out = append(out, f)
		}
	}
	return out, nil
}

func (m *Memory) EconomyLimits(_ context.Context, tenant string) ([]EconomyLimit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []EconomyLimit
	for _, l := range m.ec().limits {
		if l.TenantID == tenant {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Source < out[j].Source || out[i].Source == out[j].Source && out[i].Currency < out[j].Currency
	})
	return out, nil
}

func (m *Memory) SetEconomyLimit(_ context.Context, l EconomyLimit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ec := m.ec()
	for i, have := range ec.limits {
		if have.TenantID == l.TenantID && have.Source == l.Source && have.Currency == l.Currency {
			ec.limits[i] = l
			return nil
		}
	}
	ec.limits = append(ec.limits, l)
	return nil
}

func (m *Memory) RemoveEconomyLimit(_ context.Context, tenant, source, currency string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ec := m.ec()
	for i, have := range ec.limits {
		if have.TenantID == tenant && have.Source == source && have.Currency == currency {
			ec.limits = append(ec.limits[:i:i], ec.limits[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}

func (m *Memory) EconomyTolerance(_ context.Context, tenant string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ec().tolerance[tenant], nil
}

func (m *Memory) SetEconomyTolerance(_ context.Context, tenant string, tolerance int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ec().tolerance[tenant] = tolerance
	return nil
}
