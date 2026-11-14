package store

import "context"

func (m *Memory) AddKnownCheat(_ context.Context, c *KnownCheat) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, have := range m.cheats {
		if have.TenantID == c.TenantID && have.SHA256 == c.SHA256 {
			return ErrDuplicate
		}
	}
	m.cheatSeq++
	c.ID = m.cheatSeq
	m.cheats = append(m.cheats, *c)
	return nil
}

func (m *Memory) RemoveKnownCheat(_ context.Context, tenant string, id int64) (*KnownCheat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, c := range m.cheats {
		if c.TenantID == tenant && c.ID == id {
			m.cheats = append(m.cheats[:i:i], m.cheats[i+1:]...)
			return &c, nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) ListKnownCheats(_ context.Context, tenant string) ([]KnownCheat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []KnownCheat
	for i := len(m.cheats) - 1; i >= 0; i-- {
		if m.cheats[i].TenantID == tenant {
			out = append(out, m.cheats[i])
		}
	}
	return out, nil
}

func (m *Memory) KnownCheat(_ context.Context, tenant, sha256 string) (*KnownCheat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.cheats {
		if c.TenantID == tenant && c.SHA256 == sha256 {
			return &c, nil
		}
	}
	return nil, ErrNotFound
}
