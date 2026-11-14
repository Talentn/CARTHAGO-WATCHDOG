package store

import (
	"context"
	"sort"
	"time"
)

type memBans struct {
	bans   []Ban
	delay  map[string]time.Duration
	shadow map[string]time.Duration
}

func (m *Memory) bn() *memBans {
	if m.bans == nil {
		m.bans = &memBans{delay: map[string]time.Duration{}, shadow: map[string]time.Duration{}}
	}
	return m.bans
}

func (m *Memory) AddBan(_ context.Context, b *Ban) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	mb := m.bn()
	b.ID = int64(len(mb.bans) + 1)
	mb.bans = append(mb.bans, *b)
	return nil
}

func (m *Memory) LiftBan(_ context.Context, tenant string, id int64, by, note string, at time.Time) (*Ban, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mb := m.bn()
	if id < 1 || id > int64(len(mb.bans)) {
		return nil, ErrNotFound
	}
	b := &mb.bans[id-1]
	if b.TenantID != tenant || b.Lifted() {
		return nil, ErrNotFound
	}
	b.LiftedBy, b.LiftedAt, b.LiftNote = by, at, note
	out := *b
	return &out, nil
}

func (m *Memory) ListBans(_ context.Context, tenant string, limit int) ([]Ban, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mb := m.bn()
	var out []Ban
	for i := len(mb.bans) - 1; i >= 0 && len(out) < limitOr(limit, 200); i-- {
		if mb.bans[i].TenantID == tenant {
			out = append(out, mb.bans[i])
		}
	}
	return out, nil
}

func (m *Memory) StandingBan(_ context.Context, tenant, playerHash, deviceID string) (*Ban, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var found *Ban
	for i := range m.bn().bans {
		b := &m.bans.bans[i]
		if b.TenantID != tenant || b.Lifted() || (b.PlayerHash != playerHash && (deviceID == "" || b.DeviceID != deviceID)) {
			continue
		}
		if found == nil || b.EffectiveAt.Before(found.EffectiveAt) {
			found = b
		}
	}
	if found == nil {
		return nil, ErrNotFound
	}
	out := *found
	return &out, nil
}

func (m *Memory) BanDelay(_ context.Context, tenant string) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bn().delay[tenant], nil
}

func (m *Memory) SetBanDelay(_ context.Context, tenant string, d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bn().delay[tenant] = clampBanDelay(d)
	return nil
}

func (m *Memory) ShadowPeriod(_ context.Context, tenant string) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bn().shadow[tenant], nil
}

func (m *Memory) SetShadowPeriod(_ context.Context, tenant string, d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bn().shadow[tenant] = clampShadowPeriod(d)
	return nil
}

func (m *Memory) ListShadowBans(_ context.Context, tenant string) ([]Ban, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Ban
	for _, b := range m.bn().bans {
		if b.Shadow && !b.Lifted() && b.LandedAt.IsZero() && (tenant == "" || b.TenantID == tenant) {
			out = append(out, b)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].EffectiveAt.Before(out[j].EffectiveAt) })
	return out, nil
}

func (m *Memory) LandShadowBan(_ context.Context, tenant string, id int64, at time.Time) (*Ban, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mb := m.bn()
	if id < 1 || id > int64(len(mb.bans)) {
		return nil, ErrNotFound
	}
	b := &mb.bans[id-1]
	if b.TenantID != tenant || !b.Shadow || b.Lifted() || !b.LandedAt.IsZero() {
		return nil, ErrNotFound
	}
	b.LandedAt = at
	if at.Before(b.EffectiveAt) {
		b.EffectiveAt = at
	}
	out := *b
	return &out, nil
}

func (m *Memory) ListShadowMembers(_ context.Context, tenant, of string) ([]Ban, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mb := m.bn()
	var out []Ban
	for i := len(mb.bans) - 1; i >= 0 && of != ""; i-- {
		if b := mb.bans[i]; b.TenantID == tenant && b.ShadowOf == of {
			out = append(out, b)
		}
	}
	return out, nil
}
