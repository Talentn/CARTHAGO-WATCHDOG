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

func TestBansCommand(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := bansCommand(args, &out, &errOut)
		return code, out.String(), errOut.String()
	}
	// Before the gateway ever ran there is nobody to unban, and that is not an error.
	if code, out, _ := run("lift", "-data", dir, "-tenant", "demo", "-all"); code != 0 || !strings.Contains(out, "nobody is banned") {
		t.Fatalf("lift without a database: %d %q", code, out)
	}
	st, err := store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()
	for _, b := range []store.Ban{
		{TenantID: "demo", Ref: "CW-AAAA-AAAA", PlayerHash: "p1", DeviceID: "d1", Rule: "renderer_replaced", BannedBy: store.BanAutomatic, BannedAt: now, EffectiveAt: now},
		{TenantID: "demo", Ref: "CW-BBBB-BBBB", PlayerHash: "p2", BannedBy: "ada", BannedAt: now, EffectiveAt: now},
		{TenantID: "rival", Ref: "CW-CCCC-CCCC", PlayerHash: "p1", BannedBy: "rex", BannedAt: now, EffectiveAt: now},
	} {
		if err := st.AddBan(ctx, &b); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()

	if code, out, _ := run("list", "-data", dir, "-tenant", "demo"); code != 0 || !strings.Contains(out, "CW-AAAA-AAAA") || !strings.Contains(out, "CW-BBBB-BBBB") || strings.Contains(out, "CW-CCCC") {
		t.Fatalf("list: %d %q", code, out)
	}
	if code, _, errOut := run("lift", "-data", dir, "-tenant", "demo"); code != 1 || !strings.Contains(errOut, "exactly one of -ref and -all") {
		t.Fatalf("lift without -ref or -all: %d %q", code, errOut)
	}
	if code, _, errOut := run("lift", "-data", dir, "-tenant", "demo", "-ref", "CW-CCCC-CCCC"); code != 1 || !strings.Contains(errOut, "no standing ban") {
		t.Fatalf("lifting another studio's ban: %d %q", code, errOut)
	}
	if code, out, _ := run("lift", "-data", dir, "-tenant", "demo", "-ref", "CW-BBBB-BBBB", "-note", "test"); code != 0 || !strings.Contains(out, "lifted CW-BBBB-BBBB") {
		t.Fatalf("lift -ref: %d %q", code, out)
	}
	if code, out, _ := run("lift", "-data", dir, "-tenant", "demo", "-all"); code != 0 || !strings.Contains(out, "lifted CW-AAAA-AAAA") || strings.Contains(out, "BBBB") {
		t.Fatalf("lift -all: %d %q", code, out)
	}
	if code, out, _ := run("delay", "-data", dir, "-tenant", "demo", "-minutes", "15"); code != 0 || !strings.Contains(out, "15 minutes") {
		t.Fatalf("delay: %d %q", code, out)
	}
	if code, _, _ := run("delay", "-data", dir, "-tenant", "demo"); code != 1 {
		t.Fatalf("delay without -minutes: %d", code)
	}

	st, err = store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.StandingBan(ctx, "demo", "p1", "d1"); err == nil {
		t.Error("a ban of the studio still stands")
	}
	if b, err := st.StandingBan(ctx, "rival", "p1", ""); err != nil || b.Ref != "CW-CCCC-CCCC" {
		t.Errorf("the other studio's ban was touched: %+v %v", b, err)
	}
	if d, _ := st.BanDelay(ctx, "demo"); d != 15*time.Minute {
		t.Errorf("delay %v", d)
	}
	audit, _ := st.ListAudit(ctx, "demo", store.AuditFilter{Limit: 10})
	if len(audit) != 3 {
		t.Errorf("audit entries: %+v", audit)
	}
}
