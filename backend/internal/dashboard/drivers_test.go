package dashboard

import (
	"context"
	"strings"
	"testing"

	"carthago/backend/internal/store"
)

// The session page shows how the driver list was read, what was raised in it and the list
// itself, to the session's own studio only.
func TestSessionPageShowsTheDriverList(t *testing.T) {
	f := newOracleFixture(t, testOracle)
	ctx := context.Background()
	f.addUser(t, "demo", "rev", store.RoleReviewer, goodPW)
	f.addUser(t, "rival", "rex", store.RoleAdmin, goodPW)
	rev, rex := f.signIn(t, "demo", "rev", goodPW), f.signIn(t, "rival", "rex", goodPW)

	// A session from before driver lists has no card.
	if body := f.get(rev, "/sessions/bbbb2222").Body.String(); strings.Contains(body, "Kernel drivers") {
		t.Fatal("a session without a driver list has the card")
	}

	list := &store.DriverList{TenantID: "demo", SessionID: "bbbb2222", PlayerHash: "bob", TrustLevel: 3, Status: store.DriversVerified, Flagged: 2, ReceivedAt: f.now,
		Drivers: []store.ListedDriver{
			{Name: "ntfs.sys", HashAlg: "sha256", ImageHash: strings.Repeat("11", 32), Signer: strings.Repeat("aa", 20), Loads: 1, Boot: true},
			{Name: "RTCore64.sys", HashAlg: "sha256", ImageHash: strings.Repeat("22", 32), Signer: strings.Repeat("bb", 20), OEM: "Micro-Star <b>", Loads: 2, Unloaded: true,
				Flags: []string{store.DriverFlagVulnerable}},
			{Name: "mapped.sys", HashAlg: "sha256", ImageHash: strings.Repeat("33", 32), Loads: 1, Flags: []string{store.DriverFlagUnsigned}},
		}}
	if err := f.st.PutDriverList(ctx, list); err != nil {
		t.Fatal(err)
	}
	body := f.get(rev, "/sessions/bbbb2222").Body.String()
	for _, want := range []string{"Kernel drivers", ">Verified<", "3 loaded since boot", "2 drivers raised", "RTCore64.sys", "known vulnerable", "mapped.sys", "no signer",
		"Micro-Star &lt;b&gt;", strings.Repeat("22", 32), "The full list (3)", "unloaded since", "boot driver", "unattested", "off for this studio"} {
		if !strings.Contains(body, want) {
			t.Errorf("verified list: page lacks %q", want)
		}
	}

	if rec := f.get(rex, "/sessions/bbbb2222"); strings.Contains(rec.Body.String(), "RTCore64") {
		t.Error("another studio read the list")
	}

	// A clean verified list at the ranked level, with the studio's pool on.
	list.Flagged, list.Drivers = 0, list.Drivers[:1]
	_ = f.st.PutDriverList(ctx, list)
	_ = f.st.SetUnattestedPool(ctx, "demo", true)
	body = f.get(rev, "/sessions/bbbb2222").Body.String()
	if !strings.Contains(body, "nothing raised") || !strings.Contains(body, "<dd>attested <span") || !strings.Contains(body, "on: the game-server status call") {
		t.Error("clean list: the page does not say attested with the pool on")
	}

	for _, c := range []struct {
		status string
		want   []string
	}{
		{store.DriversUnverified, []string{">Not verified<", "no verified boot record", "treat it as a claim", "The full list (1)"}},
		{store.DriversUnavailable, []string{">Unavailable<", "no verified boot record"}},
		{store.DriversRejected, []string{">Not accepted<"}},
		{store.DriversNotSent, []string{">Not sent<"}},
	} {
		status, want := c.status, c.want
		list.Status, list.Reason = status, "this session has no verified boot record"
		if status != store.DriversUnverified {
			list.Drivers = nil
		}
		_ = f.st.PutDriverList(ctx, list)
		body := f.get(rev, "/sessions/bbbb2222").Body.String()
		for _, w := range want {
			if !strings.Contains(body, w) {
				t.Errorf("%s: page lacks %q", status, w)
			}
		}
		if strings.Contains(body, "<dd>attested") {
			t.Errorf("%s: shown as attested", status)
		}
	}
}
