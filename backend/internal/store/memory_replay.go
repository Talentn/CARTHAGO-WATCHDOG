package store

import (
	"bytes"
	"context"
	"sort"
	"time"
)

func (m *Memory) PutMatchReplay(_ context.Context, r *MatchReplay) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.replays == nil {
		m.replays = map[[2]string]MatchReplay{}
	}
	c := *r
	c.Data, c.Players = bytes.Clone(r.Data), append([]ReplayPlayer(nil), r.Players...)
	if old, ok := m.replays[[2]string{r.TenantID, r.MatchID}]; ok {
		c.StartedAt = old.StartedAt
	}
	m.replays[[2]string{r.TenantID, r.MatchID}] = c
	return nil
}

func (m *Memory) GetMatchReplay(_ context.Context, tenant, matchID string) (*MatchReplay, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.replays[[2]string{tenant, matchID}]
	if !ok {
		return nil, ErrNotFound
	}
	r.Data, r.Players = bytes.Clone(r.Data), append([]ReplayPlayer(nil), r.Players...)
	return &r, nil
}

func (m *Memory) ListMatchReplays(_ context.Context, tenant string, f ReplayFilter) ([]MatchReplay, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []MatchReplay
	for k, r := range m.replays {
		if k[0] != tenant {
			continue
		}
		player, session := f.PlayerHash == "", f.SessionID == ""
		for _, p := range r.Players {
			player = player || p.PlayerHash == f.PlayerHash
			session = session || p.SessionID == f.SessionID
		}
		if !player || !session {
			continue
		}
		r.Data, r.Players = nil, nil
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].StartedAt.After(out[j].StartedAt)
		}
		return out[i].MatchID < out[j].MatchID
	})
	if n := limitOr(f.Limit, 100); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) PruneMatchReplays(_ context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for k, r := range m.replays {
		if r.UpdatedAt.Before(before) {
			delete(m.replays, k)
			n++
		}
	}
	return n, nil
}
