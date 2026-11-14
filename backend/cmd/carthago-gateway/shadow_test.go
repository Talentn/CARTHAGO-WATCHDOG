package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

func TestShadowCommand(t *testing.T) {
	dir := t.TempDir()
	run := func(cmd func([]string, *bytes.Buffer, *bytes.Buffer) int, args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := cmd(args, &out, &errOut)
		return code, out.String(), errOut.String()
	}
	shadow := func(args ...string) (int, string, string) {
		return run(func(a []string, o, e *bytes.Buffer) int { return shadowCommand(a, o, e) }, args...)
	}
	bans := func(args ...string) (int, string, string) {
		return run(func(a []string, o, e *bytes.Buffer) int { return bansCommand(a, o, e) }, args...)
	}

	if code, _, errOut := shadow("list", "-data", dir, "-tenant", "demo"); code != 1 || !strings.Contains(errOut, "no gateway database") {
		t.Fatalf("list without a database: %d %q", code, errOut)
	}
	for _, bad := range [][]string{{"-hours", "0"}, {"-days", "91"}, {"-hours", "-3"}, {"-hours", "2", "-days", "1"}, {"-hours", "2", "-off"}} {
		if code, _, _ := shadow(append([]string{"period", "-data", dir, "-tenant", "demo"}, bad...)...); code != 1 {
			t.Errorf("period %v: exit %d, want 1", bad, code)
		}
	}
	if code, _, _ := shadow("period", "-data", dir, "-hours", "2"); code != 1 {
		t.Errorf("period without -tenant: exit %d", code)
	}
	if code, out, _ := shadow("period", "-data", dir, "-tenant", "demo", "-hours", "36"); code != 0 || !strings.Contains(out, "for 36 hours") {
		t.Fatalf("period -hours: %d %q", code, out)
	}
	if code, out, _ := shadow("period", "-data", dir, "-tenant", "demo", "-days", "2"); code != 0 || !strings.Contains(out, "for 2 days") {
		t.Fatalf("period -days: %d %q", code, out)
	}
	if code, out, _ := shadow("period", "-data", dir, "-tenant", "demo"); code != 0 || !strings.Contains(out, "for 2 days") {
		t.Fatalf("period, shown: %d %q", code, out)
	}
	if code, out, _ := shadow("period", "-data", dir, "-tenant", "rival"); code != 0 || !strings.Contains(out, "is off") {
		t.Fatalf("another studio's period: %d %q", code, out)
	}
	if code, out, _ := shadow("list", "-data", dir, "-tenant", "demo"); code != 0 || !strings.Contains(out, "nobody is in the shadow pool") {
		t.Fatalf("empty pool: %d %q", code, out)
	}

	st, err := store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()
	end := now.Add(48 * time.Hour)
	for _, b := range []store.Ban{
		{TenantID: "demo", Ref: "CW-POOL-ROOT", PlayerHash: "p1", DeviceID: "d1", Rule: "renderer_replaced", SessionID: "s1", BannedBy: store.BanAutomatic, BannedAt: now, EffectiveAt: end, Shadow: true},
		{TenantID: "demo", Ref: "CW-POOL-ALT1", PlayerHash: "p2", Rule: "renderer_replaced", SessionID: "s2", BannedBy: store.BanAutomatic, BannedAt: now, EffectiveAt: end, Shadow: true, ShadowOf: "CW-POOL-ROOT"},
		{TenantID: "demo", Ref: "CW-DONE-0001", PlayerHash: "p3", BannedBy: "ada", BannedAt: now, EffectiveAt: now},
		{TenantID: "rival", Ref: "CW-POOL-RIVL", PlayerHash: "p9", BannedBy: store.BanAutomatic, BannedAt: now, EffectiveAt: end, Shadow: true},
	} {
		if err := st.AddBan(ctx, &b); err != nil {
			t.Fatal(err)
		}
	}
	// The labels a pool entry put on the sessions go when it is released.
	for _, l := range []store.SessionLabel{
		{TenantID: "demo", SessionID: "s1", PlayerHash: "p1", Label: store.LabelConfirmedCheat, Source: store.LabelSourceShadow, BanRef: "CW-POOL-ROOT", Reviewer: "automatic", LabelledAt: now},
		{TenantID: "demo", SessionID: "s2", PlayerHash: "p2", Label: store.LabelConfirmedCheat, Source: store.LabelSourceShadow, BanRef: "CW-POOL-ALT1", Reviewer: "automatic", LabelledAt: now},
	} {
		if err := st.SetSessionLabel(ctx, &l, store.LabelSet, ""); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()

	code, out, _ := shadow("list", "-data", dir, "-tenant", "demo")
	if code != 0 || !strings.Contains(out, "CW-POOL-ROOT") || !strings.Contains(out, "CW-POOL-ALT1  player p2") || !strings.Contains(out, "another account on the PC of CW-POOL-ROOT") ||
		strings.Contains(out, "CW-DONE") || strings.Contains(out, "RIVL") {
		t.Fatalf("list: %d %q", code, out)
	}
	if code, out, _ := bans("list", "-data", dir, "-tenant", "demo"); code != 0 || strings.Count(out, "in the shadow pool until") != 2 || !strings.Contains(out, "active") {
		t.Fatalf("bans list: %d %q", code, out)
	}
	// Lifting the caught player's ban releases the second account with it; -all then
	// finds the one ban that is left.
	if code, out, _ := bans("lift", "-data", dir, "-tenant", "demo", "-ref", "CW-POOL-ROOT", "-note", "test"); code != 0 || !strings.Contains(out, "lifted CW-POOL-ROOT") ||
		!strings.Contains(out, "lifted CW-POOL-ALT1 (player p2), in the shadow pool through the device key of CW-POOL-ROOT") {
		t.Fatalf("lift of a pool entry: %d %q", code, out)
	}
	if code, out, _ := shadow("list", "-data", dir, "-tenant", "demo"); code != 0 || !strings.Contains(out, "nobody is in the shadow pool") {
		t.Fatalf("pool after the lift: %d %q", code, out)
	}
	if code, out, _ := bans("lift", "-data", dir, "-tenant", "demo", "-all"); code != 0 || strings.Count(out, "lifted ") != 1 || !strings.Contains(out, "CW-DONE-0001") {
		t.Fatalf("lift -all afterwards: %d %q", code, out)
	}
	if code, out, _ := shadow("period", "-data", dir, "-tenant", "demo", "-off"); code != 0 || !strings.Contains(out, "is off") {
		t.Fatalf("period -off: %d %q", code, out)
	}

	st, err = store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if d, _ := st.ShadowPeriod(ctx, "demo"); d != 0 {
		t.Errorf("period after -off: %v", d)
	}
	if labels, _ := st.ListSessionLabels(ctx, "demo", store.OracleFilter{}); len(labels) != 0 {
		t.Errorf("labels left after the release: %+v", labels)
	}
	if pool, _ := st.ListShadowBans(ctx, "rival"); len(pool) != 1 {
		t.Errorf("the other studio's pool was touched: %+v", pool)
	}
	audit, _ := st.ListAudit(ctx, "demo", store.AuditFilter{Limit: 20})
	periods, lifts, with := 0, 0, false
	for _, e := range audit {
		switch e.Action {
		case "shadow.period":
			periods++
		case "ban.lift":
			lifts++
			with = with || strings.Contains(e.Detail, "with it CW-POOL-ALT1 of player p2")
		}
		if e.Actor != "command line" {
			t.Errorf("audit actor: %+v", e)
		}
	}
	if periods != 3 || lifts != 2 || !with {
		t.Errorf("audit: %d period changes, %d lifts, second account named %v: %+v", periods, lifts, with, audit)
	}
}

// -all meets the second account of a pool entry after the entry took it along.
func TestBansLiftAllWithAShadowEntry(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()
	for _, b := range []store.Ban{
		{TenantID: "demo", Ref: "CW-POOL-ROOT", PlayerHash: "p1", DeviceID: "d1", BannedBy: store.BanAutomatic, BannedAt: now, EffectiveAt: now.Add(time.Hour), Shadow: true},
		{TenantID: "demo", Ref: "CW-POOL-ALT1", PlayerHash: "p2", BannedBy: store.BanAutomatic, BannedAt: now.Add(time.Second), EffectiveAt: now.Add(time.Hour), Shadow: true, ShadowOf: "CW-POOL-ROOT"},
		{TenantID: "demo", Ref: "CW-POOL-ALT2", PlayerHash: "p3", BannedBy: store.BanAutomatic, BannedAt: now.Add(-time.Second), EffectiveAt: now.Add(time.Hour), Shadow: true, ShadowOf: "CW-POOL-ROOT"},
	} {
		if err := st.AddBan(ctx, &b); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	var out, errOut bytes.Buffer
	if code := bansCommand([]string{"lift", "-data", dir, "-tenant", "demo", "-all"}, &out, &errOut); code != 0 || strings.Count(out.String(), "lifted ") != 3 {
		t.Fatalf("lift -all: %d %q %q", code, out.String(), errOut.String())
	}
	st, err = store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, p := range []string{"p1", "p2", "p3"} {
		if _, err := st.StandingBan(ctx, "demo", p, ""); err == nil {
			t.Errorf("%s still has a ban", p)
		}
	}
}
