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

func TestDriversCommand(t *testing.T) {
	dir := t.TempDir()
	drivers := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := driversCommand(args, &out, &errOut)
		return code, out.String(), errOut.String()
	}
	if code, _, errOut := drivers("pool", "-data", dir, "-tenant", "demo"); code != 1 || !strings.Contains(errOut, "no gateway database") {
		t.Fatalf("pool without a database: %d %q", code, errOut)
	}
	for _, bad := range [][]string{{"pool", "-data", dir}, {"pool", "-data", dir, "-tenant", "demo", "-on", "-off"}, {"show", "-data", dir, "-tenant", "demo"}} {
		if code, _, _ := drivers(bad...); code != 1 {
			t.Errorf("%v: exit %d, want 1", bad, code)
		}
	}
	if code, _, _ := drivers("drop", "-data", dir, "-tenant", "demo"); code != 2 {
		t.Errorf("unknown subcommand: exit %d", code)
	}
	if code, out, _ := drivers("pool", "-data", dir, "-tenant", "demo", "-on"); code != 0 || !strings.Contains(out, "is on") {
		t.Fatalf("pool -on: %d %q", code, out)
	}
	if code, out, _ := drivers("pool", "-data", dir, "-tenant", "demo"); code != 0 || !strings.Contains(out, "is on") {
		t.Fatalf("pool, shown: %d %q", code, out)
	}
	if code, out, _ := drivers("pool", "-data", dir, "-tenant", "rival"); code != 0 || !strings.Contains(out, "is off") {
		t.Fatalf("another studio: %d %q", code, out)
	}

	st, err := store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	audit, _ := st.ListAudit(ctx, "demo", store.AuditFilter{})
	if len(audit) != 1 || audit[0].Action != "drivers.pool" || audit[0].Actor != "command line" {
		t.Errorf("audit %+v", audit)
	}
	now := time.Now()
	if err := st.PutDriverList(ctx, &store.DriverList{TenantID: "demo", SessionID: "s1", PlayerHash: "ala", TrustLevel: 3, Status: store.DriversVerified, Flagged: 1, ReceivedAt: now,
		Drivers: []store.ListedDriver{{Name: "ntfs.sys", HashAlg: "sha256", ImageHash: "11"}, {Name: "gdrv.sys", HashAlg: "sha256", ImageHash: "22", Flags: []string{store.DriverFlagVulnerable}}}}); err != nil {
		t.Fatal(err)
	}
	_ = st.PutDriverList(ctx, &store.DriverList{TenantID: "demo", SessionID: "s2", PlayerHash: "old", Status: store.DriversUnavailable, Reason: "memory integrity (HVCI) is off on this PC", ReceivedAt: now})
	st.Close()

	code, out, _ := drivers("show", "-data", dir, "-tenant", "demo", "-player", "ala")
	if code != 0 || !strings.HasPrefix(out, "DRIVER LIST of session s1 (trust level 3): 2 drivers loaded since boot, signature verified; 1 raised for review; this session counts as unattested\n") ||
		!strings.Contains(out, "for review: gdrv.sys (vulnerable) sha256 22") {
		t.Errorf("show: %d %q", code, out)
	}
	if code, out, _ := drivers("show", "-data", dir, "-tenant", "demo", "-player", "old"); code != 0 || !strings.Contains(out, "unavailable: memory integrity (HVCI) is off") {
		t.Errorf("show, unavailable: %d %q", code, out)
	}
	if code, out, _ := drivers("show", "-data", dir, "-tenant", "demo", "-player", "nobody"); code != 0 || !strings.Contains(out, "no session of nobody") {
		t.Errorf("show, unknown player: %d %q", code, out)
	}
	if code, out, _ := drivers("pool", "-data", dir, "-tenant", "demo", "-off"); code != 0 || !strings.Contains(out, "is off") {
		t.Fatalf("pool -off: %d %q", code, out)
	}
}
