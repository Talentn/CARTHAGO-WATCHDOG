package dashboard

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"carthago/backend/internal/store"
)

// Everybody of the studio reads the Economy page; the limits and the tolerance are an
// admin's to change, and the changes are in the audit log.
func TestEconomyPageByRole(t *testing.T) {
	f := newOracleFixture(t, testOracle)
	ctx := context.Background()
	f.addUser(t, "demo", "ada", store.RoleAdmin, goodPW)
	f.addUser(t, "demo", "rev", store.RoleReviewer, goodPW)
	f.addUser(t, "rival", "rex", store.RoleAdmin, goodPW)
	ada, rev, rex := f.signIn(t, "demo", "ada", goodPW), f.signIn(t, "demo", "rev", goodPW), f.signIn(t, "rival", "rex", goodPW)

	for _, e := range []store.EconomyEntry{
		{TenantID: "demo", EventID: "e1", PlayerHash: "fay", Currency: "money", Amount: 300, Source: "trade", Counterparty: "max", At: f.now, ReceivedAt: f.now, Dirty: 300, DirtyFrom: "max"},
		{TenantID: "demo", EventID: "e2", PlayerHash: "fay", Currency: "money", Amount: -120, Source: "purchase", At: f.now, ReceivedAt: f.now},
	} {
		if err := f.st.AddEconomyEntry(ctx, &e); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.st.AddEconomyFlag(ctx, &store.EconomyFlag{TenantID: "demo", PlayerHash: "max", Rule: "economy_balance_mismatch", Certain: true, Currency: "money", Amount: 90000,
		Summary: "balance of 90 200 money is 90 000 above the ledger (200)", BanRef: "CW-TESTREF1", At: f.now}); err != nil {
		t.Fatal(err)
	}

	body := f.get(rev, "/economy").Body.String()
	for _, want := range []string{"economy_balance_mismatch", "CW-TESTREF1", "90 000 above the ledger", `href="/economy?player=fay#ledger"`, "banned player", "needs the admin role", "No limits yet"} {
		if !strings.Contains(body, want) {
			t.Errorf("reviewer page: %q is missing", want)
		}
	}
	if strings.Contains(body, `action="/economy/limits"`) {
		t.Error("reviewer page offers the limit form")
	}
	if body := f.get(rev, "/economy?player=fay").Body.String(); !strings.Contains(body, "+300") || !strings.Contains(body, "-120") || !strings.Contains(body, "300 dirty") || !strings.Contains(body, ">180<") {
		t.Error("a player's ledger: entries, balance or dirty amount missing")
	}
	if body := f.get(rex, "/economy?player=fay").Body.String(); strings.Contains(body, "CW-TESTREF1") || strings.Contains(body, "+300") {
		t.Error("another studio sees the ledger")
	}

	for path, form := range map[string][]string{"/economy/limits": {"source", "robbery", "per_hour", "5000", "per_day", "20000"}, "/economy/tolerance": {"tolerance", "10"},
		"/economy/limits/remove": {"source", "robbery", "currency", "money"}} {
		if w := f.post(rev, path, form...); w.Code != http.StatusForbidden {
			t.Errorf("reviewer POST %s: %d, want 403", path, w.Code)
		}
	}
	for _, bad := range [][]string{{"source", "", "per_hour", "1", "per_day", "1"}, {"source", "robbery", "per_hour", "-1", "per_day", "1"}, {"source", "robbery", "per_hour", "x", "per_day", "1"}} {
		if w := f.post(ada, "/economy/limits", bad...); w.Code != http.StatusBadRequest {
			t.Errorf("limit %v: %d, want 400", bad, w.Code)
		}
	}
	if w := f.post(ada, "/economy/limits", "source", "Robbery", "per_hour", "5000", "per_day", "20000"); w.Code != http.StatusSeeOther {
		t.Fatalf("admin sets a limit: %d", w.Code)
	}
	if l, _ := f.st.EconomyLimits(ctx, "demo"); len(l) != 1 || l[0] != (store.EconomyLimit{TenantID: "demo", Source: "robbery", Currency: "money", PerHour: 5000, PerDay: 20000}) {
		t.Fatalf("limits: %+v", l)
	}
	f.wantAudit(t, "demo", "economy.limit", "ada", "limit for robbery in money")
	if w := f.post(ada, "/economy/tolerance", "tolerance", "25"); w.Code != http.StatusSeeOther {
		t.Fatalf("admin sets the tolerance: %d", w.Code)
	}
	if v, _ := f.st.EconomyTolerance(ctx, "demo"); v != 25 {
		t.Fatalf("tolerance: %d", v)
	}
	f.wantAudit(t, "demo", "economy.tolerance", "ada", "balance tolerance")
	if body := f.get(ada, "/economy").Body.String(); !strings.Contains(body, "5 000") || !strings.Contains(body, "20 000") || !strings.Contains(body, `value="25"`) {
		t.Error("admin page: the limit or the tolerance is missing")
	}
	if l, _ := f.st.EconomyLimits(ctx, "rival"); len(l) != 0 {
		t.Error("the limit reached another studio")
	}
	if w := f.post(ada, "/economy/limits/remove", "source", "robbery", "currency", "money"); w.Code != http.StatusSeeOther {
		t.Fatalf("admin removes the limit: %d", w.Code)
	}
	if l, _ := f.st.EconomyLimits(ctx, "demo"); len(l) != 0 {
		t.Fatalf("limits after the removal: %+v", l)
	}
}
