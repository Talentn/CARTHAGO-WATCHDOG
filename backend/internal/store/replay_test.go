package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReplayStores(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000).UTC()
	ctx := context.Background()
	for name, b := range backends(t) {
		st := b.(ReplayStore)
		t.Run(name, func(t *testing.T) {
			r := &MatchReplay{TenantID: "t1", MatchID: "m/1", StartedAt: now, UpdatedAt: now, DurationMs: 1000, Samples: 8, Data: []byte{1, 2},
				Players: []ReplayPlayer{{Slot: 1, PlayerHash: "alice", SessionID: "sa"}, {Slot: 2, PlayerHash: "bot:Hawk", Bot: true}}}
			if err := st.PutMatchReplay(ctx, r); err != nil {
				t.Fatal(err)
			}
			// A later write replaces the recording and the player list and keeps the start.
			later := *r
			later.StartedAt, later.UpdatedAt, later.DurationMs, later.Samples, later.Truncated, later.Data = now.Add(time.Minute), now.Add(time.Minute), 61_000, 400, true, []byte{3, 4, 5}
			later.Players = []ReplayPlayer{{Slot: 1, PlayerHash: "alice", SessionID: "sa"}, {Slot: 3, PlayerHash: "carol", SessionID: "sc"}}
			if err := st.PutMatchReplay(ctx, &later); err != nil {
				t.Fatal(err)
			}
			got, err := st.GetMatchReplay(ctx, "t1", "m/1")
			if err != nil || !got.StartedAt.Equal(now) || !got.UpdatedAt.Equal(now.Add(time.Minute)) || got.DurationMs != 61_000 || got.Samples != 400 || !got.Truncated ||
				string(got.Data) != "\x03\x04\x05" || len(got.Players) != 2 || got.Players[1] != (ReplayPlayer{Slot: 3, PlayerHash: "carol", SessionID: "sc"}) {
				t.Fatalf("GetMatchReplay = %+v, %v", got, err)
			}
			if _, err := st.GetMatchReplay(ctx, "t2", "m/1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("another tenant reads the recording: %v", err)
			}
			other := &MatchReplay{TenantID: "t2", MatchID: "m/1", StartedAt: now, UpdatedAt: now, Data: []byte{9}, Players: []ReplayPlayer{{Slot: 1, PlayerHash: "alice", SessionID: "sa"}}}
			if err := st.PutMatchReplay(ctx, other); err != nil {
				t.Fatal(err)
			}
			second := &MatchReplay{TenantID: "t1", MatchID: "m2", StartedAt: now.Add(time.Hour), UpdatedAt: now.Add(time.Hour), Data: []byte{7}, Players: []ReplayPlayer{{Slot: 1, PlayerHash: "dave"}}}
			if err := st.PutMatchReplay(ctx, second); err != nil {
				t.Fatal(err)
			}
			if got, _ := st.GetMatchReplay(ctx, "t1", "m/1"); string(got.Data) != "\x03\x04\x05" {
				t.Fatalf("another tenant's write changed the recording: %v", got.Data)
			}

			list := func(f ReplayFilter) []string {
				rows, err := st.ListMatchReplays(ctx, "t1", f)
				if err != nil {
					t.Fatal(err)
				}
				var ids []string
				for _, r := range rows {
					if r.Data != nil || r.Players != nil {
						t.Fatal("a list carries the recording")
					}
					ids = append(ids, r.MatchID)
				}
				return ids
			}
			for _, c := range []struct {
				f    ReplayFilter
				want []string
			}{
				{ReplayFilter{}, []string{"m2", "m/1"}},
				{ReplayFilter{PlayerHash: "alice"}, []string{"m/1"}},
				{ReplayFilter{PlayerHash: "bot:Hawk"}, nil}, // replaced with the second write
				{ReplayFilter{SessionID: "sc"}, []string{"m/1"}},
				{ReplayFilter{PlayerHash: "dave", SessionID: "sc"}, nil},
				{ReplayFilter{Limit: 1}, []string{"m2"}},
			} {
				if got := list(c.f); len(got) != len(c.want) || (len(got) > 0 && got[0] != c.want[0]) {
					t.Errorf("list %+v = %v, want %v", c.f, got, c.want)
				}
			}

			if n, err := st.PruneMatchReplays(ctx, now.Add(30*time.Minute)); err != nil || n != 2 {
				t.Fatalf("prune = %d, %v; want m/1 of both tenants", n, err)
			}
			if _, err := st.GetMatchReplay(ctx, "t1", "m/1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("pruned recording: %v", err)
			}
			if got := list(ReplayFilter{PlayerHash: "alice"}); len(got) != 0 {
				t.Fatalf("a pruned match is still listed for its player: %v", got)
			}
			if got := list(ReplayFilter{}); len(got) != 1 || got[0] != "m2" {
				t.Fatalf("after prune: %v", got)
			}
		})
	}
}

func TestEvidenceByMatch(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000).UTC()
	ctx := context.Background()
	for name, st := range backends(t) {
		t.Run(name, func(t *testing.T) {
			if err := st.AddEvidence(ctx, []Evidence{
				{TenantID: "t1", PlayerHash: "a", MatchID: "m1", Source: SourceGameplay, Rule: "angle_snap", Severity: 2, Score: 1, ObservedAt: now},
				{TenantID: "t1", PlayerHash: "a", MatchID: "m2", Source: SourceGameplay, Rule: "angle_snap", Severity: 2, Score: 1, ObservedAt: now},
				{TenantID: "t2", PlayerHash: "b", MatchID: "m1", Source: SourceGameplay, Rule: "angle_snap", Severity: 2, Score: 1, ObservedAt: now},
			}); err != nil {
				t.Fatal(err)
			}
			evs, err := st.ListEvidence(ctx, "t1", EvidenceFilter{MatchID: "m1"})
			if err != nil || len(evs) != 1 || evs[0].PlayerHash != "a" || evs[0].MatchID != "m1" {
				t.Fatalf("evidence of match m1: %+v, %v", evs, err)
			}
		})
	}
}
