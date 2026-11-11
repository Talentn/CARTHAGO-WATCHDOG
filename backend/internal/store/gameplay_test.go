package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGameplayStores(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000).UTC()
	ctx := context.Background()
	for name, st := range backends(t) {
		t.Run(name, func(t *testing.T) {
			m := &MapRecord{TenantID: "t1", MapID: "yard", Version: 1, Hash: "aa", Geometry: []byte{1, 2, 3}, CreatedAt: now}
			if err := st.PutMap(ctx, m); err != nil {
				t.Fatal(err)
			}
			if err := st.PutMap(ctx, m); err != nil {
				t.Fatalf("same upload twice: %v", err)
			}
			bad := *m
			bad.Hash, bad.Geometry = "bb", []byte{9}
			if err := st.PutMap(ctx, &bad); !errors.Is(err, ErrMapConflict) {
				t.Fatalf("changed geometry for a stored version: %v", err)
			}
			got, err := st.GetMap(ctx, "t1", "yard", 1)
			if err != nil || got.Hash != "aa" || string(got.Geometry) != "\x01\x02\x03" || !got.CreatedAt.Equal(now) {
				t.Fatalf("GetMap = %+v, %v", got, err)
			}
			if _, err := st.GetMap(ctx, "t2", "yard", 1); !errors.Is(err, ErrNotFound) {
				t.Fatalf("other tenant's map: %v", err)
			}
			other := *m
			other.TenantID, other.Hash = "t2", "cc"
			if err := st.PutMap(ctx, &other); err != nil {
				t.Fatalf("maps are per tenant: %v", err)
			}

			for seq := uint64(1); seq <= 3; seq++ {
				b := &GameplayBatchRow{TenantID: "t1", MatchID: "m1", BatchSeq: seq, ReceivedAt: now.Add(time.Duration(seq) * time.Hour), Data: []byte{byte(seq)}}
				if err := st.PutGameplayBatch(ctx, b); err != nil {
					t.Fatal(err)
				}
				if err := st.PutGameplayBatch(ctx, b); err != nil {
					t.Fatalf("retried batch: %v", err)
				}
			}
			bs, err := st.ListGameplayBatches(ctx, "t1", "m1", 0)
			if err != nil || len(bs) != 3 || bs[0].BatchSeq != 1 || bs[2].Data[0] != 3 {
				t.Fatalf("batches = %+v, %v", bs, err)
			}
			if bs, _ := st.ListGameplayBatches(ctx, "t2", "m1", 0); len(bs) != 0 {
				t.Fatal("other tenant sees batches")
			}
			n, err := st.PruneGameplayBatches(ctx, now.Add(150*time.Minute))
			if err != nil || n != 2 {
				t.Fatalf("pruned %d, %v", n, err)
			}
			if bs, _ := st.ListGameplayBatches(ctx, "t1", "m1", 0); len(bs) != 1 || bs[0].BatchSeq != 3 {
				t.Fatalf("after prune: %+v", bs)
			}

			rows := []GameplaySummary{
				{TenantID: "t1", MatchID: "m1", Slot: 1, SessionID: "s1", PlayerHash: "alice", Team: 1, Device: "mouse_keyboard", Mode: "competitive_shooter",
					MapID: "yard", MapVersion: 1, SchemaVersion: 2, Batches: 5, MotionSamples: 400, Sounds: 12, Shots: 3, UpdatedAt: now},
				{TenantID: "t1", MatchID: "m1", Slot: 2, SessionID: "s2", PlayerHash: "bob", Team: 2, UpdatedAt: now},
				{TenantID: "t2", MatchID: "m1", Slot: 1, SessionID: "x1", PlayerHash: "mallory", UpdatedAt: now},
			}
			if err := st.UpsertGameplaySummaries(ctx, rows); err != nil {
				t.Fatal(err)
			}
			rows[0].LeakScored, rows[0].LeakScore, rows[0].LeakFlagged, rows[0].Batches, rows[0].DroppedEvents = true, 6.5, true, 9, 4
			rows[0].UpdatedAt = now.Add(time.Minute)
			if err := st.UpsertGameplaySummaries(ctx, rows[:1]); err != nil {
				t.Fatal(err)
			}
			list, err := st.ListGameplaySummaries(ctx, "t1", GameplayFilter{SessionID: "s1"})
			if err != nil || len(list) != 1 {
				t.Fatalf("by session: %+v, %v", list, err)
			}
			if g := list[0]; !g.LeakScored || g.LeakScore != 6.5 || !g.LeakFlagged || g.Batches != 9 || g.DroppedEvents != 4 || g.MapID != "yard" || !g.UpdatedAt.Equal(now.Add(time.Minute)) {
				t.Fatalf("upsert lost fields: %+v", g)
			}
			list, _ = st.ListGameplaySummaries(ctx, "t1", GameplayFilter{MatchID: "m1"})
			if len(list) != 2 || list[0].Slot != 1 {
				t.Fatalf("by match: %+v", list)
			}
			list, _ = st.ListGameplaySummaries(ctx, "t2", GameplayFilter{})
			if len(list) != 1 || list[0].PlayerHash != "mallory" {
				t.Fatalf("tenant scoping: %+v", list)
			}
		})
	}
}
