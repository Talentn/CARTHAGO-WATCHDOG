package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"carthago/backend/internal/store"
)

func TestToxicityCommand(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := toxicityCommand(args, &out, &errOut)
		return code, out.String(), errOut.String()
	}
	if code, _, errOut := run(); code != 2 || !strings.Contains(errOut, "usage:") {
		t.Fatalf("no arguments: %d %q", code, errOut)
	}
	if code, _, errOut := run("limits", "-data", dir, "-tenant", "demo"); code != 1 || !strings.Contains(errOut, "no gateway database") {
		t.Fatalf("without a database: %d %q", code, errOut)
	}
	st, err := store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	if code, _, errOut := run("limits", "-data", dir); code != 1 || !strings.Contains(errOut, "-tenant is required") {
		t.Fatalf("without -tenant: %d %q", code, errOut)
	}
	const defaults = "team damage from 6 hits, team kills from 2, idle from 90 s, left early with more than 25% to play, feeding from 10 deaths"
	if code, out, _ := run("limits", "-data", dir, "-tenant", "demo"); code != 0 || !strings.Contains(out, defaults) {
		t.Fatalf("defaults shown: %d %q", code, out)
	}
	for _, bad := range [][]string{{"-team-kills", "-1"}, {"-left-early-percent", "100"}, {"-defaults", "-team-kills", "3"}} {
		if code, _, _ := run(append([]string{"limits", "-data", dir, "-tenant", "demo"}, bad...)...); code != 1 {
			t.Errorf("%v: exit %d, want 1", bad, code)
		}
	}
	// A change keeps the limits it does not name; 0 turns a kind off.
	if code, out, _ := run("limits", "-data", dir, "-tenant", "demo", "-team-kills", "1", "-afk-seconds", "0"); code != 0 ||
		!strings.Contains(out, "team damage from 6 hits, team kills from 1, idle off, left early with more than 25% to play") {
		t.Fatalf("change: %d %q", code, out)
	}
	if code, out, _ := run("limits", "-data", dir, "-tenant", "demo", "-feeding-deaths", "15"); code != 0 || !strings.Contains(out, "team kills from 1, idle off") || !strings.Contains(out, "feeding from 15 deaths") {
		t.Fatalf("second change: %d %q", code, out)
	}
	if code, out, _ := run("limits", "-data", dir, "-tenant", "rival"); code != 0 || !strings.Contains(out, defaults) {
		t.Fatalf("another studio's limits: %d %q", code, out)
	}
	if code, out, _ := run("limits", "-data", dir, "-tenant", "demo", "-defaults"); code != 0 || !strings.Contains(out, defaults) {
		t.Fatalf("-defaults: %d %q", code, out)
	}

	st, err = store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if stored, _ := st.GetToxicityLimits(ctx, "demo"); stored != "" {
		t.Fatalf("-defaults left stored limits: %q", stored)
	}
	log, err := st.ListAudit(ctx, "demo", store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range log {
		if e.Action == "toxicity.limits" && e.Actor == "command line" && e.Detail != "" {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("audit entries for three changes: %d of %d", n, len(log))
	}
	if log, _ := st.ListAudit(ctx, "rival", store.AuditFilter{}); len(log) != 0 {
		t.Fatalf("showing a studio's limits was audited: %+v", log)
	}
}
