package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

// The studio's own test on one PC, from the command line: the threshold is set to 1, the
// banned account's unsigned file is proposed, and lifting the ban from the command line
// takes the ban's session label away, as lifting it on the dashboard does.
func TestProposalsAndBanLabelsFromTheCommandLine(t *testing.T) {
	dir := t.TempDir()
	cheats := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := cheatsCommand(append(args, "-data", dir, "-tenant", "demo"), &out, &errOut)
		return code, out.String(), errOut.String()
	}
	if code, out, _ := cheats("proposed"); code != 0 || !strings.Contains(out, "empty") {
		t.Fatalf("proposed without a database: %d %q", code, out)
	}
	for _, bad := range []string{"0", "1001"} {
		if code, _, errOut := cheats("propose-after", "-accounts", bad); code != 1 || !strings.Contains(errOut, "from 1 to 1000") {
			t.Fatalf("propose-after %s: %d %q", bad, code, errOut)
		}
	}
	st, err := store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()
	sum := strings.Repeat("ab", 32)
	if err := st.AddEvidence(ctx, []store.Evidence{{TenantID: "demo", PlayerHash: "p1", SessionID: "s1", Source: store.SourceClient, Rule: "renderer_replaced", Severity: 3, Integrity: true,
		Summary: "renderer", Raw: `{"code":"FINDING_CODE_MODULE_SIGNATURE","b":"0x50102","detail":"OPENGL32.dll","sha256":"` + sum + `"}`, ObservedAt: now}}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddBan(ctx, &store.Ban{TenantID: "demo", Ref: "CW-AAAA-AAAA", PlayerHash: "p1", Rule: "renderer_replaced", SessionID: "s1", BannedBy: store.BanAutomatic, BannedAt: now, EffectiveAt: now}); err != nil {
		t.Fatal(err)
	}
	for id, l := range map[string]store.SessionLabel{
		"s1": {Label: store.LabelConfirmedCheat, Reviewer: "ban CW-AAAA-AAAA", Source: store.LabelSourceBan, BanRef: "CW-AAAA-AAAA"},
		"s2": {Label: store.LabelConfirmedCheat, Reviewer: "rev"},
	} {
		l.TenantID, l.SessionID, l.PlayerHash, l.LabelledAt = "demo", id, "p1", now
		if err := st.SetSessionLabel(ctx, &l, store.LabelSet, ""); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()

	if code, out, _ := cheats("proposed"); code != 0 || !strings.Contains(out, "nothing is proposed") || !strings.Contains(out, "proposed after 2 banned accounts") {
		t.Fatalf("proposed under the default threshold: %d %q", code, out)
	}
	if code, out, errOut := cheats("propose-after", "-accounts", "1"); code != 0 || !strings.Contains(out, "once 1 banned account has loaded it") {
		t.Fatalf("propose-after 1: %d %q %q", code, out, errOut)
	}
	if code, out, _ := cheats("proposed"); code != 0 || !strings.Contains(out, sum+"  OPENGL32.dll  not signed  banned accounts 1") ||
		!strings.Contains(out, "proposed after 1 banned account; compared with 0 accounts that are not banned") {
		t.Fatalf("proposed: %d %q", code, out)
	}
	var out, errOut bytes.Buffer
	if code := bansCommand([]string{"lift", "-data", dir, "-tenant", "demo", "-all"}, &out, &errOut); code != 0 {
		t.Fatalf("lift: %d %q", code, errOut.String())
	}
	if code, out, _ := cheats("proposed"); code != 0 || !strings.Contains(out, "nothing is proposed") {
		t.Fatalf("proposed after the lift: %d %q", code, out)
	}
	st, err = store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.GetSessionLabel(ctx, "demo", "s1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the ban's label outlived the lift: %v", err)
	}
	if _, err := st.GetSessionLabel(ctx, "demo", "s2"); err != nil {
		t.Fatalf("the reviewer's label went with the lift: %v", err)
	}
}
