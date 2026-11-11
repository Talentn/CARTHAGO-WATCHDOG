package store

import (
	"bytes"
	"context"
	"sort"
	"time"
)

type memGameplay struct {
	maps      map[mapKey]MapRecord
	batches   map[[2]string][]GameplayBatchRow
	summaries map[sumKey]GameplaySummary
}

type mapKey struct {
	tenant, id string
	version    uint32
}

type sumKey struct {
	tenant, match string
	slot          uint32
}

func (m *Memory) gp() *memGameplay {
	if m.play == nil {
		m.play = &memGameplay{maps: map[mapKey]MapRecord{}, batches: map[[2]string][]GameplayBatchRow{}, summaries: map[sumKey]GameplaySummary{}}
	}
	return m.play
}

func (m *Memory) PutMap(_ context.Context, r *MapRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := mapKey{r.TenantID, r.MapID, r.Version}
	if cur, ok := m.gp().maps[k]; ok {
		if cur.Hash != r.Hash {
			return ErrMapConflict
		}
		return nil
	}
	c := *r
	c.Geometry = bytes.Clone(r.Geometry)
	m.gp().maps[k] = c
	return nil
}

func (m *Memory) GetMap(_ context.Context, tenant, mapID string, version uint32) (*MapRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.gp().maps[mapKey{tenant, mapID, version}]
	if !ok {
		return nil, ErrNotFound
	}
	r.Geometry = bytes.Clone(r.Geometry)
	return &r, nil
}

func (m *Memory) PutGameplayBatch(_ context.Context, b *GameplayBatchRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{b.TenantID, b.MatchID}
	for _, x := range m.gp().batches[k] {
		if x.BatchSeq == b.BatchSeq {
			return nil
		}
	}
	c := *b
	c.Data = bytes.Clone(b.Data)
	m.gp().batches[k] = append(m.gp().batches[k], c)
	return nil
}

func (m *Memory) ListGameplayBatches(_ context.Context, tenant, matchID string, limit int) ([]GameplayBatchRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]GameplayBatchRow(nil), m.gp().batches[[2]string{tenant, matchID}]...)
	sort.Slice(out, func(i, j int) bool { return out[i].BatchSeq < out[j].BatchSeq })
	if n := limitOr(limit, 100000); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) PruneGameplayBatches(_ context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for k, list := range m.gp().batches {
		kept := list[:0]
		for _, b := range list {
			if b.ReceivedAt.Before(before) {
				n++
				continue
			}
			kept = append(kept, b)
		}
		if len(kept) == 0 {
			delete(m.gp().batches, k)
		} else {
			m.gp().batches[k] = kept
		}
	}
	return n, nil
}

func (m *Memory) UpsertGameplaySummaries(_ context.Context, rows []GameplaySummary) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range rows {
		m.gp().summaries[sumKey{r.TenantID, r.MatchID, r.Slot}] = r
	}
	return nil
}

func (m *Memory) ListGameplaySummaries(_ context.Context, tenant string, f GameplayFilter) ([]GameplaySummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []GameplaySummary
	for _, r := range m.gp().summaries {
		if r.TenantID != tenant || (f.SessionID != "" && r.SessionID != f.SessionID) || (f.MatchID != "" && r.MatchID != f.MatchID) {
			continue
		}
		out = append(out, r)
	}
	sortSummaries(out)
	if n := limitOr(f.Limit, 100); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func sortSummaries(rows []GameplaySummary) {
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].UpdatedAt.Equal(rows[j].UpdatedAt) {
			return rows[i].UpdatedAt.After(rows[j].UpdatedAt)
		}
		if rows[i].MatchID != rows[j].MatchID {
			return rows[i].MatchID < rows[j].MatchID
		}
		return rows[i].Slot < rows[j].Slot
	})
}
