package store

import (
	"context"
	"sort"
	"time"
)

type memAuth struct {
	users    []DashUser // index = id - 1
	codes    map[int64]map[string]bool
	invites  map[string]DashInvite
	sessions map[string]DashSession
	settings map[string]TenantSettings
	audit    []AuditEntry
}

func (m *Memory) au() *memAuth {
	if m.auth == nil {
		m.auth = &memAuth{codes: map[int64]map[string]bool{}, invites: map[string]DashInvite{}, sessions: map[string]DashSession{}, settings: map[string]TenantSettings{}}
	}
	return m.auth
}

func (a *memAuth) user(tenant string, id int64) *DashUser {
	if id < 1 || id > int64(len(a.users)) || a.users[id-1].TenantID != tenant {
		return nil
	}
	return &a.users[id-1]
}

func cloneUser(u *DashUser) *DashUser {
	c := *u
	c.TOTPSecret = append([]byte(nil), u.TOTPSecret...)
	if len(u.TOTPSecret) == 0 {
		c.TOTPSecret = nil
	}
	return &c
}

func (m *Memory) CountDashUsers(_ context.Context, tenant string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for i := range m.au().users {
		if m.auth.users[i].TenantID == tenant {
			n++
		}
	}
	return n, nil
}

func (m *Memory) CreateDashUser(_ context.Context, u *DashUser) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.au()
	for i := range a.users {
		if a.users[i].TenantID == u.TenantID && a.users[i].Name == u.Name {
			return ErrConflict
		}
	}
	u.ID = int64(len(a.users) + 1)
	a.users = append(a.users, *cloneUser(u))
	return nil
}

func (m *Memory) GetDashUser(_ context.Context, tenant string, id int64) (*DashUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.au().user(tenant, id)
	if u == nil {
		return nil, ErrNotFound
	}
	return cloneUser(u), nil
}

func (m *Memory) GetDashUserByName(_ context.Context, tenant, name string) (*DashUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.au()
	for i := range a.users {
		if a.users[i].TenantID == tenant && a.users[i].Name == name {
			return cloneUser(&a.users[i]), nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) ListDashUsers(_ context.Context, tenant string) ([]DashUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []DashUser
	for i := range m.au().users {
		if m.auth.users[i].TenantID == tenant {
			out = append(out, *cloneUser(&m.auth.users[i]))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) UpdateDashUser(_ context.Context, u *DashUser) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.au().user(u.TenantID, u.ID)
	if cur == nil {
		return ErrNotFound
	}
	c := cloneUser(u)
	cur.Role, cur.PasswordHash, cur.TOTPSecret, cur.Disabled = c.Role, c.PasswordHash, c.TOTPSecret, c.Disabled
	cur.PasswordChangedAt, cur.LastLoginAt = c.PasswordChangedAt, c.LastLoginAt
	return nil
}

func (m *Memory) AdvanceTOTPStep(_ context.Context, userID, step int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.au()
	if userID < 1 || userID > int64(len(a.users)) || a.users[userID-1].TOTPLastStep >= step {
		return false, nil
	}
	a.users[userID-1].TOTPLastStep = step
	return true, nil
}

func (m *Memory) SetRecoveryCodes(_ context.Context, userID int64, hashes []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := map[string]bool{}
	for _, h := range hashes {
		set[h] = true
	}
	m.au().codes[userID] = set
	return nil
}

func (m *Memory) UseRecoveryCode(_ context.Context, userID int64, hash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.au().codes[userID]
	if !set[hash] {
		return false, nil
	}
	delete(set, hash)
	return true, nil
}

func (m *Memory) CountRecoveryCodes(_ context.Context, userID int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.au().codes[userID]), nil
}

func (m *Memory) CreateDashInvite(_ context.Context, v *DashInvite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.au().invites[v.TokenHash] = *v
	return nil
}

func (m *Memory) GetDashInvite(_ context.Context, tokenHash string, now time.Time) (*DashInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.au().invites[tokenHash]
	if !ok || !v.UsedAt.IsZero() || !v.ExpiresAt.After(now) {
		return nil, ErrNotFound
	}
	return &v, nil
}

func (m *Memory) RedeemDashInvite(_ context.Context, tokenHash string, now time.Time) (*DashInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.au().invites[tokenHash]
	if !ok || !v.UsedAt.IsZero() || !v.ExpiresAt.After(now) {
		return nil, ErrNotFound
	}
	v.UsedAt = now
	m.auth.invites[tokenHash] = v
	return &v, nil
}

func (m *Memory) ListDashInvites(_ context.Context, tenant string, now time.Time) ([]DashInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []DashInvite
	for _, v := range m.au().invites {
		if v.TenantID == tenant && v.UsedAt.IsZero() && v.ExpiresAt.After(now) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].TokenHash < out[j].TokenHash
	})
	return out, nil
}

func (m *Memory) RevokeDashInvite(_ context.Context, tenant, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.au().invites[tokenHash]
	if !ok || v.TenantID != tenant || !v.UsedAt.IsZero() {
		return ErrNotFound
	}
	delete(m.auth.invites, tokenHash)
	return nil
}

func (m *Memory) PutDashSession(_ context.Context, x *DashSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.au().sessions[x.IDHash] = *x
	return nil
}

func (m *Memory) GetDashSession(_ context.Context, idHash string) (*DashSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.au().sessions[idHash]
	if !ok {
		return nil, ErrNotFound
	}
	return &x, nil
}

func (m *Memory) TouchDashSession(_ context.Context, idHash string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if x, ok := m.au().sessions[idHash]; ok {
		x.LastSeenAt = at
		m.auth.sessions[idHash] = x
	}
	return nil
}

func (m *Memory) DeleteDashSession(_ context.Context, idHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.au().sessions, idHash)
	return nil
}

func (m *Memory) DeleteDashSessions(_ context.Context, tenant string, userID int64, exceptHash string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, x := range m.au().sessions {
		if x.TenantID == tenant && x.UserID == userID && k != exceptHash {
			delete(m.auth.sessions, k)
			n++
		}
	}
	return n, nil
}

func (m *Memory) ListDashSessions(_ context.Context, tenant string, userID int64, now time.Time) ([]DashSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []DashSession
	for _, x := range m.au().sessions {
		if x.TenantID == tenant && x.UserID == userID && x.ExpiresAt.After(now) {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeenAt.Equal(out[j].LastSeenAt) {
			return out[i].LastSeenAt.After(out[j].LastSeenAt)
		}
		return out[i].IDHash < out[j].IDHash
	})
	return out, nil
}

func (m *Memory) PruneDashSessions(_ context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, x := range m.au().sessions {
		if !x.ExpiresAt.After(now) {
			delete(m.auth.sessions, k)
		}
	}
	return nil
}

func (m *Memory) GetTenantSettings(_ context.Context, tenant string) (TenantSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.au().settings[tenant], nil
}

func (m *Memory) PutTenantSettings(_ context.Context, tenant string, t TenantSettings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.au().settings[tenant] = t
	return nil
}

func (m *Memory) AppendAudit(_ context.Context, e *AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.au()
	prev := ""
	for i := len(a.audit) - 1; i >= 0; i-- {
		if a.audit[i].TenantID == e.TenantID {
			prev = a.audit[i].Hash
			break
		}
	}
	e.At = fromMS(ms(e.At))
	e.ID = int64(len(a.audit) + 1)
	e.PrevHash, e.Hash = prev, auditHash(prev, e)
	a.audit = append(a.audit, *e)
	return nil
}

func (m *Memory) ListAudit(_ context.Context, tenant string, f AuditFilter) ([]AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.au()
	limit := limitOr(f.Limit, 100)
	var out []AuditEntry
	for i := len(a.audit) - 1; i >= 0 && len(out) < limit; i-- {
		e := a.audit[i]
		if e.TenantID != tenant || f.BeforeID > 0 && e.ID >= f.BeforeID || !matchesAction(e.Action, f.ActionPrefixes) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (m *Memory) VerifyAudit(_ context.Context, tenant string) (int, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, prev := 0, ""
	for i := range m.au().audit {
		e := &m.auth.audit[i]
		if e.TenantID != tenant {
			continue
		}
		n++
		if e.PrevHash != prev || e.Hash != auditHash(prev, e) {
			return n, e.ID, nil
		}
		prev = e.Hash
	}
	return n, 0, nil
}
