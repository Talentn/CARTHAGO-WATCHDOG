package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestBans(t *testing.T) {
	sq, err := OpenSQLite(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sq.Close()
	for name, st := range map[string]BanStore{"sqlite": sq, "memory": NewMemory()} {
		ctx := context.Background()
		t0 := time.UnixMilli(1_700_000_000_000).UTC()
		if _, err := st.StandingBan(ctx, "t1", "p1", "d1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: no ban yet: %v", name, err)
		}
		b := &Ban{TenantID: "t1", Ref: "B-1", PlayerHash: "p1", DeviceID: "d1", DeviceTPM: true, Reason: "wallhack", Rule: "renderer_replaced",
			SessionID: "s1", BannedBy: "ada", BannedAt: t0, EffectiveAt: t0}
		if err := st.AddBan(ctx, b); err != nil || b.ID == 0 {
			t.Fatalf("%s: add: %v id %d", name, err, b.ID)
		}
		// By account, by device key with another account, and neither.
		for _, c := range []struct {
			tenant, player, device string
			found                  bool
		}{{"t1", "p1", "other", true}, {"t1", "p2", "d1", true}, {"t1", "p1", "", true}, {"t1", "p2", "d2", false}, {"t1", "p2", "", false}, {"t2", "p1", "d1", false}} {
			got, err := st.StandingBan(ctx, c.tenant, c.player, c.device)
			if c.found != (err == nil) || (!c.found && !errors.Is(err, ErrNotFound)) {
				t.Errorf("%s: %+v: %v", name, c, err)
			}
			if c.found && (got.ID != b.ID || got.Ref != "B-1" || !got.DeviceTPM || got.Rule != "renderer_replaced" || !got.BannedAt.Equal(t0) || got.Lifted() || !got.Active(t0)) {
				t.Errorf("%s: %+v: got %+v", name, c, got)
			}
		}
		// A pending ban stands but is not active; the one that takes effect first is returned.
		later := &Ban{TenantID: "t1", Ref: "B-2", PlayerHash: "p3", DeviceID: "d1", BannedBy: BanAutomatic, BannedAt: t0, EffectiveAt: t0.Add(time.Hour)}
		if err := st.AddBan(ctx, later); err != nil {
			t.Fatal(err)
		}
		if got, err := st.StandingBan(ctx, "t1", "p3", "d3"); err != nil || !got.Pending(t0) || got.Active(t0) || !got.Active(t0.Add(time.Hour)) {
			t.Errorf("%s: pending: %+v %v", name, got, err)
		}
		if got, err := st.StandingBan(ctx, "t1", "p3", "d1"); err != nil || got.ID != b.ID {
			t.Errorf("%s: the earlier ban comes first: %+v %v", name, got, err)
		}
		if _, err := st.LiftBan(ctx, "t2", b.ID, "eve", "", t0); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: another tenant lifted the ban: %v", name, err)
		}
		lifted, err := st.LiftBan(ctx, "t1", b.ID, "grace", "appeal accepted", t0.Add(time.Minute))
		if err != nil || !lifted.Lifted() || lifted.LiftedBy != "grace" || lifted.LiftNote != "appeal accepted" || lifted.Active(t0.Add(time.Hour)) {
			t.Fatalf("%s: lift: %+v %v", name, lifted, err)
		}
		if _, err := st.LiftBan(ctx, "t1", b.ID, "grace", "", t0); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: lifted twice: %v", name, err)
		}
		if _, err := st.StandingBan(ctx, "t1", "p1", "other"); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: a lifted ban still stands: %v", name, err)
		}
		list, err := st.ListBans(ctx, "t1", 0)
		if err != nil || len(list) != 2 || list[0].ID != later.ID || !list[1].Lifted() {
			t.Errorf("%s: list: %+v %v", name, list, err)
		}
		if other, _ := st.ListBans(ctx, "t2", 0); len(other) != 0 {
			t.Errorf("%s: another tenant sees %d bans", name, len(other))
		}
		if d, err := st.BanDelay(ctx, "t1"); err != nil || d != 0 {
			t.Errorf("%s: default delay %v %v", name, d, err)
		}
		if err := st.SetBanDelay(ctx, "t1", 90*time.Minute); err != nil {
			t.Fatal(err)
		}
		if d, _ := st.BanDelay(ctx, "t1"); d != 90*time.Minute {
			t.Errorf("%s: delay %v", name, d)
		}
		_ = st.SetBanDelay(ctx, "t1", 1000*time.Hour)
		if d, _ := st.BanDelay(ctx, "t1"); d != MaxBanDelay {
			t.Errorf("%s: delay not bounded: %v", name, d)
		}
		if d, _ := st.BanDelay(ctx, "t2"); d != 0 {
			t.Errorf("%s: another tenant's delay %v", name, d)
		}
	}
}
