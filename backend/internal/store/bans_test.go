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

func TestShadowBans(t *testing.T) {
	sq, err := OpenSQLite(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sq.Close()
	for name, st := range map[string]BanStore{"sqlite": sq, "memory": NewMemory()} {
		ctx := context.Background()
		t0 := time.UnixMilli(1_700_000_000_000).UTC()
		end := t0.Add(48 * time.Hour)
		if d, err := st.ShadowPeriod(ctx, "t1"); err != nil || d != 0 {
			t.Errorf("%s: the period is off by default: %v %v", name, d, err)
		}
		if err := st.SetShadowPeriod(ctx, "t1", 48*time.Hour); err != nil {
			t.Fatal(err)
		}
		_ = st.SetBanDelay(ctx, "t1", 5*time.Minute)
		if d, _ := st.ShadowPeriod(ctx, "t1"); d != 48*time.Hour {
			t.Errorf("%s: period %v", name, d)
		}
		if d, _ := st.BanDelay(ctx, "t1"); d != 5*time.Minute {
			t.Errorf("%s: the delay is a setting of its own: %v", name, d)
		}
		_ = st.SetShadowPeriod(ctx, "t2", 100000*time.Hour)
		if d, _ := st.ShadowPeriod(ctx, "t2"); d != MaxShadowPeriod {
			t.Errorf("%s: period not bounded: %v", name, d)
		}

		caught := &Ban{TenantID: "t1", Ref: "S-1", PlayerHash: "p1", DeviceID: "d1", Rule: "renderer_replaced", BannedBy: BanAutomatic, BannedAt: t0, EffectiveAt: end, Shadow: true}
		alt := &Ban{TenantID: "t1", Ref: "S-2", PlayerHash: "p2", BannedBy: BanAutomatic, BannedAt: t0.Add(time.Hour), EffectiveAt: end, Shadow: true, ShadowOf: "S-1"}
		plain := &Ban{TenantID: "t1", Ref: "B-1", PlayerHash: "p3", BannedBy: "ada", BannedAt: t0, EffectiveAt: t0}
		other := &Ban{TenantID: "t2", Ref: "S-3", PlayerHash: "p1", BannedBy: BanAutomatic, BannedAt: t0, EffectiveAt: t0.Add(time.Hour), Shadow: true}
		for _, b := range []*Ban{caught, alt, plain, other} {
			if err := st.AddBan(ctx, b); err != nil {
				t.Fatal(err)
			}
		}
		got, err := st.StandingBan(ctx, "t1", "p1", "")
		if err != nil || !got.Shadow || !got.InPool(t0) || got.InPool(end) || got.ShadowOf != "" || !got.LandedAt.IsZero() {
			t.Fatalf("%s: the caught player: %+v %v", name, got, err)
		}
		// The device key alone finds the caught player's ban, not the alternate's.
		if got, err := st.StandingBan(ctx, "t1", "", "d1"); err != nil || got.Ref != "S-1" {
			t.Errorf("%s: by device key: %+v %v", name, got, err)
		}
		if got, err := st.StandingBan(ctx, "t1", "p2", ""); err != nil || got.ShadowOf != "S-1" || !got.InPool(t0) {
			t.Errorf("%s: the alternate account: %+v %v", name, got, err)
		}
		if plain.InPool(t0) {
			t.Errorf("%s: a plain ban is in no pool", name)
		}
		pool, err := st.ListShadowBans(ctx, "t1")
		if err != nil || len(pool) != 2 || pool[0].Ref != "S-1" || pool[1].Ref != "S-2" || pool[0].TenantID != "t1" {
			t.Fatalf("%s: pool: %+v %v", name, pool, err)
		}
		all, err := st.ListShadowBans(ctx, "")
		if err != nil || len(all) != 3 || all[0].Ref != "S-3" || all[0].TenantID != "t2" || all[1].TenantID != "t1" {
			t.Fatalf("%s: every tenant's pool: %+v %v", name, all, err)
		}
		if m, err := st.ShadowMember(ctx, "t1", "S-1", "p2"); err != nil || m.Ref != "S-2" {
			t.Errorf("%s: member: %+v %v", name, m, err)
		}
		if _, err := st.ShadowMember(ctx, "t1", "S-1", "p9"); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: no such member: %v", name, err)
		}

		// "Ban now" after a day: the ban takes effect then, once.
		now := t0.Add(24 * time.Hour)
		if _, err := st.LandShadowBan(ctx, "t2", caught.ID, now); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: another tenant landed the ban: %v", name, err)
		}
		if _, err := st.LandShadowBan(ctx, "t1", plain.ID, now); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: a plain ban landed: %v", name, err)
		}
		landed, err := st.LandShadowBan(ctx, "t1", caught.ID, now)
		if err != nil || !landed.LandedAt.Equal(now) || !landed.EffectiveAt.Equal(now) || landed.InPool(now) || !landed.Active(now) || !landed.Shadow {
			t.Fatalf("%s: ban now: %+v %v", name, landed, err)
		}
		if _, err := st.LandShadowBan(ctx, "t1", caught.ID, now); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: landed twice: %v", name, err)
		}
		// At the end of the period the time the ban took effect stays what it was.
		late := end.Add(time.Minute)
		landed, err = st.LandShadowBan(ctx, "t1", alt.ID, late)
		if err != nil || !landed.LandedAt.Equal(late) || !landed.EffectiveAt.Equal(end) {
			t.Fatalf("%s: end of the period: %+v %v", name, landed, err)
		}
		if pool, _ := st.ListShadowBans(ctx, "t1"); len(pool) != 0 {
			t.Errorf("%s: landed bans are still in the pool: %+v", name, pool)
		}
		// A released ban leaves the pool and is still found as the account's entry.
		if _, err := st.LiftBan(ctx, "t2", other.ID, "ada", "", now); err != nil {
			t.Fatal(err)
		}
		if all, _ := st.ListShadowBans(ctx, ""); len(all) != 0 {
			t.Errorf("%s: a released ban is still in the pool: %+v", name, all)
		}
		if _, err := st.LandShadowBan(ctx, "t2", other.ID, now); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: a released ban landed: %v", name, err)
		}
	}
}
