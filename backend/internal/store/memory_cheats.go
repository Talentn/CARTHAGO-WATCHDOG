package store

import (
	"context"
	"encoding/json"
	"time"
)

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

func (m *Memory) ListModuleSightings(_ context.Context, tenant string) ([]ModuleSighting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	type key struct {
		sum, module, player string
		sig, class          uint8
	}
	at := map[key]int{}
	sessions := map[key]map[string]bool{}
	var out []ModuleSighting
	for _, e := range m.ev().evidence {
		if e.TenantID != tenant || e.Source != SourceClient || e.Raw == "" {
			continue
		}
		var raw struct {
			Code   string `json:"code"`
			SHA256 string `json:"sha256"`
			Detail string `json:"detail"`
			B      string `json:"b"`
		}
		if json.Unmarshal([]byte(e.Raw), &raw) != nil || raw.Code != moduleSignatureCode {
			continue
		}
		sum, ok := CleanSHA256(raw.SHA256)
		if !ok {
			continue
		}
		k := key{sum: sum, module: raw.Detail, player: e.PlayerHash}
		k.sig, k.class = moduleBits(raw.B)
		i, ok := at[k]
		if !ok {
			i = len(out)
			at[k], sessions[k] = i, map[string]bool{}
			out = append(out, ModuleSighting{SHA256: sum, Module: raw.Detail, PlayerHash: e.PlayerHash, Signature: k.sig, PathClass: k.class})
		}
		sessions[k][e.SessionID] = true
		out[i].Sessions = len(sessions[k])
		if e.ObservedAt.After(out[i].LastSeen) {
			out[i].LastSeen = e.ObservedAt
		}
	}
	return out, nil
}

func (m *Memory) CheatProposalAccounts(_ context.Context, tenant string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n, ok := m.proposalAccounts[tenant]; ok {
		return n, nil
	}
	return DefaultProposalAccounts, nil
}

func (m *Memory) SetCheatProposalAccounts(_ context.Context, tenant string, n int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proposalAccounts == nil {
		m.proposalAccounts = map[string]int{}
	}
	m.proposalAccounts[tenant] = n
	return nil
}

func (m *Memory) DismissCheatProposal(_ context.Context, tenant, sha256, _ string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dismissedCheats == nil {
		m.dismissedCheats = map[[2]string]bool{}
	}
	m.dismissedCheats[[2]string{tenant, sha256}] = true
	return nil
}

func (m *Memory) DismissedCheatProposals(_ context.Context, tenant string) (map[string]bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for k := range m.dismissedCheats {
		if k[0] == tenant {
			out[k[1]] = true
		}
	}
	return out, nil
}
