package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestEconomyStore(t *testing.T) {
	sq, err := OpenSQLite(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sq.Close()
	for name, st := range map[string]EconomyStore{"sqlite": sq, "memory": NewMemory()} {
		ctx := context.Background()
		t0 := time.UnixMilli(1_700_000_000_000).UTC()
		add := func(tenant, id, player string, amount int64, source, counterparty string, at time.Duration) *EconomyEntry {
			e := &EconomyEntry{TenantID: tenant, EventID: id, PlayerHash: player, Currency: "money", Amount: amount, Source: source, Counterparty: counterparty, At: t0.Add(at), ReceivedAt: t0}
			if err := st.AddEconomyEntry(ctx, e); err != nil || e.ID == 0 {
				t.Fatalf("%s: add %s: %v", name, id, err)
			}
			return e
		}
		add("t1", "e1", "ann", 500, "job", "", 0)
		add("t1", "e2", "ann", -200, "trade", "bob", time.Minute)
		got := add("t1", "e3", "bob", 200, "trade", "ann", time.Minute)
		add("t1", "e4", "ann", 300, "robbery", "", 2*time.Hour)
		add("t2", "e1", "ann", 9000, "job", "", 0)
		if err := st.AddEconomyEntry(ctx, &EconomyEntry{TenantID: "t1", EventID: "e1", PlayerHash: "ann", Currency: "money", Amount: 1, At: t0}); !errors.Is(err, ErrDuplicate) {
			t.Fatalf("%s: the same event twice: %v", name, err)
		}
		for _, c := range []struct {
			f    EconomySum
			sum  int64
			n    int
			what string
		}{
			{EconomySum{}, 600, 3, "everything"},
			{EconomySum{Until: t0.Add(time.Hour)}, 300, 2, "until"},
			{EconomySum{CreditsOnly: true, After: t0, Until: t0.Add(3 * time.Hour)}, 300, 1, "credits after"},
			{EconomySum{Source: "job"}, 500, 1, "one source"},
		} {
			if sum, n, err := st.SumEconomy(ctx, "t1", "ann", "money", c.f); err != nil || sum != c.sum || n != c.n {
				t.Errorf("%s: sum %s: %d over %d entries (%v), want %d over %d", name, c.what, sum, n, err, c.sum, c.n)
			}
		}
		if err := st.SetEconomyDirty(ctx, "t1", got.ID, 200, "ann"); err != nil {
			t.Fatal(err)
		}
		list, err := st.ListEconomyEntries(ctx, "t1", EconomyFilter{DirtyOnly: true})
		if err != nil || len(list) != 1 || list[0].EventID != "e3" || list[0].Dirty != 200 || list[0].DirtyFrom != "ann" || !list[0].At.Equal(t0.Add(time.Minute)) {
			t.Fatalf("%s: dirty entries: %+v %v", name, list, err)
		}
		if list, _ := st.ListEconomyEntries(ctx, "t1", EconomyFilter{PlayerHash: "ann"}); len(list) != 3 || list[0].EventID != "e4" {
			t.Fatalf("%s: a player's entries, newest first: %+v", name, list)
		}
		if list, _ := st.ListEconomyEntries(ctx, "t1", EconomyFilter{Counterparty: "ann", Since: t0, OldestFirst: true}); len(list) != 1 || list[0].PlayerHash != "bob" {
			t.Fatalf("%s: entries by counterparty: %+v", name, list)
		}

		for _, f := range []EconomyFlag{{TenantID: "t1", PlayerHash: "ann", Rule: "economy_over_limit", Amount: 5, At: t0}, {TenantID: "t1", PlayerHash: "bob", Rule: "economy_no_source", Certain: true, BanRef: "CW-1", At: t0},
			{TenantID: "t2", PlayerHash: "ann", Rule: "x", At: t0}} {
			if err := st.AddEconomyFlag(ctx, &f); err != nil {
				t.Fatal(err)
			}
		}
		if flags, _ := st.ListEconomyFlags(ctx, "t1", "", 0); len(flags) != 2 || flags[0].PlayerHash != "bob" || !flags[0].Certain || flags[0].BanRef != "CW-1" {
			t.Fatalf("%s: flags: %+v", name, flags)
		}
		if flags, _ := st.ListEconomyFlags(ctx, "t1", "ann", 0); len(flags) != 1 || flags[0].Rule != "economy_over_limit" {
			t.Fatalf("%s: a player's flags: %+v", name, flags)
		}

		if v, err := st.EconomyTolerance(ctx, "t1"); err != nil || v != 0 {
			t.Fatalf("%s: default tolerance %d %v", name, v, err)
		}
		st.SetEconomyTolerance(ctx, "t1", 25)
		st.SetEconomyTolerance(ctx, "t1", 50)
		if v, _ := st.EconomyTolerance(ctx, "t1"); v != 50 {
			t.Fatalf("%s: tolerance %d", name, v)
		}
		st.SetEconomyLimit(ctx, EconomyLimit{TenantID: "t1", Source: "robbery", Currency: "money", PerHour: 10, PerDay: 100})
		st.SetEconomyLimit(ctx, EconomyLimit{TenantID: "t1", Source: "robbery", Currency: "money", PerHour: 20, PerDay: 200})
		st.SetEconomyLimit(ctx, EconomyLimit{TenantID: "t1", Source: "job", Currency: "money", PerDay: 7})
		if l, _ := st.EconomyLimits(ctx, "t1"); len(l) != 2 || l[0].Source != "job" || l[1].PerHour != 20 || l[1].PerDay != 200 {
			t.Fatalf("%s: limits: %+v", name, l)
		}
		if err := st.RemoveEconomyLimit(ctx, "t2", "job", "money"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: removed another studio's limit: %v", name, err)
		}
		if err := st.RemoveEconomyLimit(ctx, "t1", "job", "money"); err != nil {
			t.Fatal(err)
		}
		if l, _ := st.EconomyLimits(ctx, "t1"); len(l) != 1 {
			t.Fatalf("%s: limits after removal: %+v", name, l)
		}
	}
}
