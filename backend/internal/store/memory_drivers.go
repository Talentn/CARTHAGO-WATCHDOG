package store

import "context"

type memDrivers struct {
	lists []DriverList
	pool  map[string]bool
}

func (m *Memory) drv() *memDrivers {
	if m.drivers == nil {
		m.drivers = &memDrivers{pool: map[string]bool{}}
	}
	return m.drivers
}

func (m *Memory) PutDriverList(_ context.Context, d *DriverList) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *d
	c.Drivers = append([]ListedDriver{}, d.Drivers...)
	lists := m.drv().lists
	for i := range lists {
		if lists[i].TenantID == d.TenantID && lists[i].SessionID == d.SessionID {
			lists = append(lists[:i:i], lists[i+1:]...)
			break
		}
	}
	m.drv().lists = append(lists, c)
	return nil
}

func (m *Memory) SessionDriverList(_ context.Context, tenant, sessionID string) (*DriverList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.drv().lists {
		if d.TenantID == tenant && d.SessionID == sessionID {
			return &d, nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) LatestDriverList(_ context.Context, tenant, playerHash string) (*DriverList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var best *DriverList
	for i, d := range m.drv().lists {
		if d.TenantID == tenant && d.PlayerHash == playerHash && (best == nil || !d.ReceivedAt.Before(best.ReceivedAt)) {
			best = &m.drv().lists[i]
		}
	}
	if best == nil {
		return nil, ErrNotFound
	}
	c := *best
	return &c, nil
}

func (m *Memory) UnattestedPool(_ context.Context, tenant string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.drv().pool[tenant], nil
}

func (m *Memory) SetUnattestedPool(_ context.Context, tenant string, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drv().pool[tenant] = on
	return nil
}
