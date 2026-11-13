package dashboard

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"carthago/backend/internal/store"
)

// With accounts, a label belongs to the person who is signed in: the form cannot name
// somebody else, a read-only account cannot label at all, and every label is in the
// studio's audit log under the account that set it.
func TestLabelsByAccountAndRole(t *testing.T) {
	f := newOracleFixture(t, testOracle)
	ctx := context.Background()
	f.addUser(t, "demo", "ada", store.RoleAdmin, goodPW)
	f.addUser(t, "demo", "rev", store.RoleReviewer, goodPW)
	f.addUser(t, "demo", "ron", store.RoleReadOnly, goodPW)
	f.addUser(t, "rival", "rex", store.RoleAdmin, goodPW)
	ada, rev, ron, rex := f.signIn(t, "demo", "ada", goodPW), f.signIn(t, "demo", "rev", goodPW), f.signIn(t, "demo", "ron", goodPW), f.signIn(t, "rival", "rex", goodPW)
	const form = `action="/sessions/bbbb2222/label"`

	// Read-only: the Oracle's result and the label are visible, the forms are not, and
	// the route refuses what a hand-made request sends.
	body := f.get(ron, "/sessions/bbbb2222").Body.String()
	for _, want := range []string{"<h2>Carthago Oracle</h2>", "<h2>Reviewer label</h2>", "Not labelled yet", "Labelling a session needs the reviewer role"} {
		if !strings.Contains(body, want) {
			t.Errorf("read-only session page lacks %q", want)
		}
	}
	for _, not := range []string{form, "Suggested:", "Accept suggestion", "Save label"} {
		if strings.Contains(body, not) {
			t.Errorf("read-only session page offers %q", not)
		}
	}
	if w := f.post(ron, "/sessions/bbbb2222/label", "label", "cleared"); w.Code != http.StatusForbidden {
		t.Fatalf("read-only label: %d, want 403", w.Code)
	}
	if w := f.post(ron, "/sessions/bbbb2222/label", "label", "confirmed_cheat", "cheat_type", "client_tampering", "suggested", "1"); w.Code != http.StatusForbidden {
		t.Fatalf("read-only accepting the suggestion: %d, want 403", w.Code)
	}
	if l, _ := f.st.GetSessionLabel(ctx, "demo", "bbbb2222"); l != nil {
		t.Fatalf("a read-only account stored a label: %+v", l)
	}
	if au, _ := f.st.ListLabelAudit(ctx, "demo", "bbbb2222", 0); len(au) != 0 {
		t.Fatalf("a refused label is in the label history: %+v", au)
	}
	f.wantAudit(t, "demo", "access.denied", "ron", "/sessions/bbbb2222/label")

	// Another studio's admin cannot label this studio's session, or see it.
	if w := f.post(rex, "/sessions/bbbb2222/label", "label", "cleared"); w.Code != http.StatusNotFound {
		t.Fatalf("label across studios: %d, want 404", w.Code)
	}
	if l, _ := f.st.GetSessionLabel(ctx, "demo", "bbbb2222"); l != nil {
		t.Fatalf("another studio stored a label: %+v", l)
	}

	// Reviewer: the form does not ask for a name, and one sent anyway is ignored.
	body = f.get(rev, "/sessions/bbbb2222").Body.String()
	for _, want := range []string{form, "Suggested: <b>Confirmed cheat</b>", "Saved under your account, <b>rev</b>"} {
		if !strings.Contains(body, want) {
			t.Errorf("reviewer session page lacks %q", want)
		}
	}
	if strings.Contains(body, `name="reviewer"`) || strings.Contains(body, "Your name") {
		t.Error("an account is asked for a reviewer name")
	}
	w := f.post(rev, "/sessions/bbbb2222/label", "label", "confirmed_cheat", "cheat_type", "client_tampering", "suggested", "1", "reviewer", "ada", "note", "saw it")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/sessions/bbbb2222?labelled=1#label" {
		t.Fatalf("reviewer label: %d %q", w.Code, w.Header().Get("Location"))
	}
	if cookieNamed(w, reviewerCookie) != nil {
		t.Error("an account's label set the demo login's name cookie")
	}
	l, _ := f.st.GetSessionLabel(ctx, "demo", "bbbb2222")
	if l == nil || l.Reviewer != "rev" || l.Label != store.LabelConfirmedCheat || l.Note != "saw it" {
		t.Fatalf("label: %+v", l)
	}
	if au, _ := f.st.ListLabelAudit(ctx, "demo", "bbbb2222", 0); len(au) != 1 || au[0].Reviewer != "rev" || au[0].Action != store.LabelAcceptSuggestion || au[0].Remote != "127.0.0.1" {
		t.Fatalf("label history: %+v", au)
	}
	f.wantAudit(t, "demo", "label.accept_suggestion", "rev", "session bbbb2222")
	f.wantAudit(t, "demo", "label.accept_suggestion", "rev", "confirmed_cheat (client_tampering), suggestion accepted; player bob")

	// A name left in the browser by an earlier demo login does not reach an account's label.
	stale := &http.Cookie{Name: reviewerCookie, Value: "Mallory"}
	if body := f.doWith("GET", "/sessions/bbbb2222", nil, nil, rev, stale).Body.String(); strings.Contains(body, "Mallory") {
		t.Error("the demo login's name cookie shows on an account's page")
	}

	// The admin relabels and removes; each step is under the admin's own name.
	if w := f.post(ada, "/sessions/bbbb2222/label", "label", "unsure", "reviewer", "rev"); w.Code != http.StatusSeeOther {
		t.Fatalf("admin label: %d", w.Code)
	}
	if l, _ := f.st.GetSessionLabel(ctx, "demo", "bbbb2222"); l == nil || l.Reviewer != "ada" || l.Label != store.LabelUnsure {
		t.Fatalf("admin label: %+v", l)
	}
	if w := f.post(ada, "/sessions/bbbb2222/label", "label", ""); w.Code != http.StatusSeeOther {
		t.Fatalf("admin removal: %d", w.Code)
	}
	f.wantAudit(t, "demo", "label.set", "ada", "unsure; player bob")
	f.wantAudit(t, "demo", "label.remove", "ada", "label removed; player bob")
	for _, e := range f.auditLog(t, "demo") {
		if strings.HasPrefix(e.Action, "label.") && (e.ActorID == 0 || strings.Contains(e.Detail, "demo login")) {
			t.Errorf("an account's label is audited without the account: %+v", e)
		}
		if e.Action == "request.post" {
			t.Errorf("a label left only the generic entry: %+v", e)
		}
	}
	if rows := f.auditLog(t, "rival"); len(rows) != 0 {
		for _, e := range rows {
			if strings.HasPrefix(e.Action, "label.") {
				t.Errorf("the other studio's log has this studio's label: %+v", e)
			}
		}
	}

	// Where a label came from is shown to admins only, in the history and in the log.
	if body := f.get(rev, "/sessions/bbbb2222").Body.String(); !strings.Contains(body, "History (3)") || strings.Contains(body, "<th>From</th>") || strings.Contains(body, "127.0.0.1") {
		t.Error("reviewer: label history missing, or it shows addresses")
	}
	if body := f.get(ada, "/sessions/bbbb2222").Body.String(); !strings.Contains(body, "<th>From</th>") || !strings.Contains(body, `<td class="mono">127.0.0.1</td>`) {
		t.Error("admin: label history lacks the address")
	}
	body = f.get(ada, "/audit?show=changes").Body.String()
	for _, want := range []string{"label.accept_suggestion", "label.set", "label.remove", "session bbbb2222"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit page, changes tab, lacks %q", want)
		}
	}
	if w := f.get(rev, "/audit"); w.Code != http.StatusForbidden {
		t.Errorf("reviewer reads the audit log: %d", w.Code)
	}

	// Labels did not touch sessions, evidence or bans.
	if s, _ := f.st.GetSession(ctx, "bbbb2222"); s.State != store.SessionClosed || s.KickReason != "" {
		t.Fatalf("labelling changed the session: %+v", s)
	}
}
