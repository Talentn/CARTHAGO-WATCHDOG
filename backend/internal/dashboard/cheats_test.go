package dashboard

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"carthago/backend/internal/store"
)

// Everybody of the studio reads the list; adding and removing need the reviewer role and
// are in the audit log; an evidence row about a module's file links to the add form.
func TestKnownCheatsByRole(t *testing.T) {
	f := newOracleFixture(t, testOracle)
	ctx := context.Background()
	f.addUser(t, "demo", "rev", store.RoleReviewer, goodPW)
	f.addUser(t, "demo", "ron", store.RoleReadOnly, goodPW)
	f.addUser(t, "rival", "rex", store.RoleAdmin, goodPW)
	rev, ron, rex := f.signIn(t, "demo", "rev", goodPW), f.signIn(t, "demo", "ron", goodPW), f.signIn(t, "rival", "rex", goodPW)
	sum := strings.Repeat("ab", 32)

	body := f.get(ron, "/cheats").Body.String()
	if !strings.Contains(body, "No known cheat files yet") || !strings.Contains(body, "needs the reviewer role") || strings.Contains(body, `action="/cheats"`) {
		t.Error("read-only page: no list, or the add form is offered")
	}
	if w := f.post(ron, "/cheats", "sha256", sum, "name", "Wall"); w.Code != http.StatusForbidden {
		t.Fatalf("read-only add: %d, want 403", w.Code)
	}
	if w := f.do("POST", "/cheats", rev, nil, sameOriginHdr); w.Code != http.StatusForbidden {
		t.Fatalf("add without a CSRF token: %d, want 403", w.Code)
	}
	for _, bad := range [][]string{{"sha256", "abcd", "name", "Wall"}, {"sha256", sum, "name", " "}} {
		if w := f.post(rev, "/cheats", bad...); w.Code != http.StatusBadRequest {
			t.Errorf("add %v: %d, want 400", bad, w.Code)
		}
	}
	if w := f.post(rev, "/cheats", "sha256", strings.ToUpper(sum), "name", "Wall v2", "note", "from a report"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/cheats?added=1" {
		t.Fatalf("reviewer add: %d %q", w.Code, w.Header().Get("Location"))
	}
	c, err := f.st.KnownCheat(ctx, "demo", sum)
	if err != nil || c.Name != "Wall v2" || c.Note != "from a report" || c.AddedBy != "rev" {
		t.Fatalf("entry: %+v %v", c, err)
	}
	f.wantAudit(t, "demo", "cheat.add", "rev", "known cheat Wall v2")
	if w := f.post(rev, "/cheats", "sha256", sum, "name", "again"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "already on the list") {
		t.Errorf("the same file twice: %d", w.Code)
	}
	if body := f.get(ron, "/cheats").Body.String(); !strings.Contains(body, "Wall v2") || !strings.Contains(body, sum) || strings.Contains(body, "/remove") {
		t.Error("read-only page: the entry is missing, or Remove is offered")
	}
	// The list is one studio's.
	if body := f.get(rex, "/cheats").Body.String(); strings.Contains(body, "Wall v2") {
		t.Error("another studio sees the list")
	}
	if w := f.post(rex, "/cheats/1/remove"); w.Code != http.StatusNotFound {
		t.Fatalf("remove across studios: %d, want 404", w.Code)
	}
	if w := f.post(ron, "/cheats/1/remove"); w.Code != http.StatusForbidden {
		t.Fatalf("read-only remove: %d, want 403", w.Code)
	}

	// An evidence row that carries a file hash offers the hash to the add form.
	other := strings.Repeat("cd", 32)
	if err := f.st.AddEvidence(ctx, []store.Evidence{{TenantID: "demo", PlayerHash: "bob", SessionID: "bbbb2222", Source: store.SourceClient, Rule: "foreign_module",
		Severity: 3, Score: 0.8, Integrity: true, Summary: "unsigned module late.dll", Raw: `{"detail":"late.dll","sha256":"` + other + `"}`, ObservedAt: f.now}}); err != nil {
		t.Fatal(err)
	}
	link := `href="/cheats?sha256=` + other + `&amp;module=late.dll#add"`
	if body := f.get(rev, "/sessions/bbbb2222").Body.String(); !strings.Contains(body, link) || strings.Count(body, "Add to known cheats") != 1 {
		t.Error("session page: no link to add the module's file, or a link on evidence without a file")
	}
	if body := f.get(rev, "/cheats?sha256="+other+"&module=late.dll").Body.String(); !strings.Contains(body, `value="`+other+`"`) || !strings.Contains(body, "seen loaded as late.dll") {
		t.Error("the add form does not start with the hash from the evidence row")
	}

	if w := f.post(rev, "/cheats/1/remove"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/cheats?removed=1" {
		t.Fatalf("reviewer remove: %d", w.Code)
	}
	if _, err := f.st.KnownCheat(ctx, "demo", sum); err == nil {
		t.Fatal("still on the list after Remove")
	}
	f.wantAudit(t, "demo", "cheat.remove", "rev", "known cheat Wall v2")
}
