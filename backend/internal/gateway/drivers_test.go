package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"net/http"
	"strings"
	"testing"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/attest"
	"carthago/backend/internal/attest/driverlisttest"
	"carthago/backend/internal/protocol"
	"carthago/backend/internal/store"
)

var listKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

func listed(name string, signed bool) attest.ListedDriver {
	h := sha256.Sum256([]byte(name))
	d := attest.ListedDriver{Name: name, HashAlg: "sha256", ImageHash: h[:], Loads: 1}
	if signed {
		d.Signer = h[:20]
	}
	return d
}

func signedList(nonce [32]byte, drivers ...attest.ListedDriver) *pb.DriverList {
	return &pb.DriverList{Package: driverlisttest.Package(driverlisttest.DriverReport(drivers, 0), nonce, listKey)}
}

// bootRecord is a verified boot record that measured the list's signing key.
func bootRecord(testSigning bool) *attest.BootResult {
	return &attest.BootResult{QuoteOK: true, Security: &attest.SecurityState{TestSigning: testSigning,
		VBS: attest.VBSState{IDKS: driverlisttest.IDKSEvent(&listKey.PublicKey)}}}
}

func TestDriverListIsReadAgainstTheBootRecord(t *testing.T) {
	nonce := [32]byte{5}
	clean := signedList(nonce, listed("ntfs.sys", true), listed("vgk.sys", true))

	d := readDriverList(clean, nonce, bootRecord(false))
	if d.Status != store.DriversVerified || d.Reason != "" || d.Flagged != 0 || len(d.Drivers) != 2 || len(driverEvidence(d)) != 0 {
		t.Fatalf("clean list with a boot record: %+v", d)
	}
	if note := driverListNote(d); note != "driver list: verified, 2 drivers" {
		t.Errorf("note %q", note)
	}

	// No TPM quote: the list is kept and not called verified.
	d = readDriverList(clean, nonce, nil)
	if d.Status != store.DriversUnverified || !strings.Contains(d.Reason, "no verified boot record") || len(d.Drivers) != 2 {
		t.Fatalf("without a boot record: %+v", d)
	}
	// A boot record that did not verify gives no key either.
	if d := readDriverList(clean, nonce, &attest.BootResult{Security: bootRecord(false).Security}); d.Status != store.DriversUnverified {
		t.Fatalf("with a boot record that did not verify: %+v", d)
	}
	// A verified boot record without the key event.
	if d := readDriverList(clean, nonce, &attest.BootResult{QuoteOK: true, Security: &attest.SecurityState{}}); d.Status != store.DriversUnverified || !strings.Contains(d.Reason, "no signing key") {
		t.Fatalf("with a boot record without the key: %+v", d)
	}
	// Signed by a key the boot record does not hold.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := &pb.DriverList{Package: driverlisttest.Package(driverlisttest.DriverReport([]attest.ListedDriver{listed("ntfs.sys", true)}, 0), nonce, other)}
	if d := readDriverList(forged, nonce, bootRecord(false)); d.Status != store.DriversRejected || len(d.Drivers) != 0 || !strings.Contains(d.Reason, "signature") {
		t.Fatalf("a list signed by another key: %+v", d)
	}
	// Made for another handshake.
	if d := readDriverList(clean, [32]byte{6}, bootRecord(false)); d.Status != store.DriversRejected {
		t.Fatalf("a replayed list: %+v", d)
	}

	for reason, want := range map[pb.DriverListUnavailable]string{
		pb.DriverListUnavailable_DRIVER_LIST_UNAVAILABLE_NO_INTERFACE: "has no signed driver list",
		pb.DriverListUnavailable_DRIVER_LIST_UNAVAILABLE_HVCI_OFF:     "memory integrity",
		pb.DriverListUnavailable_DRIVER_LIST_UNAVAILABLE_VBS_OFF:      "virtualization-based security",
		pb.DriverListUnavailable_DRIVER_LIST_UNAVAILABLE_FAILED:       "error 87",
	} {
		d := readDriverList(&pb.DriverList{Unavailable: reason, Win32Error: 87}, nonce, bootRecord(false))
		if d.Status != store.DriversUnavailable || !strings.Contains(d.Reason, want) || len(driverEvidence(d)) != 0 {
			t.Errorf("%v: %+v", reason, d)
		}
	}
	if d := readDriverList(nil, nonce, bootRecord(false)); d.Status != store.DriversNotSent {
		t.Errorf("no list in Prove: %+v", d)
	}
}

// What is raised from a list is for review: three rules of the suspicious tier, none of
// which is integrity evidence, so none can ban, kick or tell the player.
func TestDriverListRaisesReviewSignalsOnly(t *testing.T) {
	nonce := [32]byte{5}
	list := signedList(nonce, listed("ntfs.sys", true), listed("RTCore64.sys", true), listed("gdrv", true), listed("mapped.sys", false), listed("", false))
	d := readDriverList(list, nonce, bootRecord(true))
	d.TenantID, d.SessionID, d.PlayerHash = "demo", "s1", "p1"
	if d.Status != store.DriversVerified || d.Flagged != 4 || !d.TestSigning {
		t.Fatalf("list %+v", d)
	}
	evs := driverEvidence(d)
	want := map[string]string{
		"driver_vulnerable":   "RTCore64.sys, gdrv",
		"driver_unsigned":     "mapped.sys, (no name) ",
		"driver_test_signing": "test-signed",
	}
	if len(evs) != len(want) {
		t.Fatalf("evidence %+v", evs)
	}
	for _, e := range evs {
		if !strings.Contains(e.Summary, want[e.Rule]) || want[e.Rule] == "" {
			t.Errorf("%s: %q", e.Rule, e.Summary)
		}
		if e.Integrity || e.Severity >= int(analyzer.SeverityHigh) || e.SessionID != "s1" || e.PlayerHash != "p1" || e.TenantID != "demo" {
			t.Errorf("%s: %+v", e.Rule, e)
		}
		if analyzer.TierOf(e.Rule) != analyzer.TierSuspicious || (analyzer.Evidence{Rule: e.Rule, Severity: analyzer.SeverityCritical, Integrity: true, Notice: pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY}).Certain() {
			t.Errorf("%s can ban", e.Rule)
		}
	}
	if d.Attested() {
		t.Error("a list with raised drivers is attested")
	}
	// The same drivers in a list nobody could verify are raised too, and say so.
	u := readDriverList(list, nonce, nil)
	if evs := driverEvidence(u); len(evs) != 2 || !strings.Contains(evs[0].Summary, "not verified") {
		t.Errorf("unverified list: %+v", evs)
	}
	for name, hit := range map[string]bool{"iqvw64e.sys": true, "IQVW64E.SYS": true, "WinRing0x64": true, "ntoskrnl.exe": false, "gdrv.sys.bak": false, "": false} {
		if vulnerableDriver(name) != hit {
			t.Errorf("%q: vulnerable %v", name, !hit)
		}
	}
}

// Whatever a client sends as its driver list, or does not send, it gets its session.
func TestHandshakeNeverFailsForTheDriverList(t *testing.T) {
	e := newPoolEnv(t, 0)
	ctx := context.Background()
	connect := func(player string, list func(th [32]byte) *pb.DriverList) (*store.DriverList, []string) {
		t.Helper()
		e.driverList = list
		c, err := handshakeAs(t, e.env, softwareKey(), player, false)
		if err != nil {
			t.Fatalf("%s: the handshake failed: %v", player, err)
		}
		d, err := e.st.SessionDriverList(ctx, "demo", sessionOf(t, e.env, c).SessionID)
		if err != nil || d.PlayerHash != player {
			t.Fatalf("%s: no stored list: %v", player, err)
		}
		var notes []string
		for _, n := range c.session.Notes {
			if strings.Contains(n, "driver list") {
				notes = append(notes, n)
			}
		}
		return d, notes
	}

	d, notes := connect("listed", func(th [32]byte) *pb.DriverList {
		return signedList(protocol.DriverListNonce(th), listed("ntfs.sys", true), listed("gdrv.sys", true))
	})
	if d.Status != store.DriversUnverified || len(d.Drivers) != 2 || d.Flagged != 1 || d.Drivers[1].Flags[0] != store.DriverFlagVulnerable {
		t.Fatalf("listed: %+v", d)
	}
	// The note says how the list was read and nothing of what was raised in it.
	if len(notes) != 1 || !strings.HasPrefix(notes[0], "driver list: 2 drivers, not verified") || strings.Contains(notes[0], "gdrv") {
		t.Errorf("listed: notes %q", notes)
	}
	evs, _ := e.st.ListEvidence(ctx, "demo", store.EvidenceFilter{SessionID: d.SessionID, Limit: 10})
	if len(evs) != 1 || evs[0].Rule != "driver_vulnerable" || !strings.Contains(evs[0].Summary, "gdrv.sys") {
		t.Errorf("listed: evidence %+v", evs)
	}

	if d, notes := connect("replayed", func([32]byte) *pb.DriverList { return signedList([32]byte{1}, listed("ntfs.sys", true)) }); d.Status != store.DriversRejected || len(notes) != 1 {
		t.Errorf("replayed: %+v %q", d, notes)
	}
	if d, _ := connect("garbage", func([32]byte) *pb.DriverList { return &pb.DriverList{Package: []byte("not a package")} }); d.Status != store.DriversRejected {
		t.Errorf("garbage: %+v", d)
	}
	d, notes = connect("old-windows", func([32]byte) *pb.DriverList {
		return &pb.DriverList{Unavailable: pb.DriverListUnavailable_DRIVER_LIST_UNAVAILABLE_NO_INTERFACE}
	})
	if d.Status != store.DriversUnavailable || len(notes) != 1 || !strings.HasPrefix(notes[0], "driver list unavailable: ") {
		t.Errorf("old Windows: %+v %q", d, notes)
	}
	if d, notes := connect("old-client", nil); d.Status != store.DriversNotSent || len(notes) != 0 {
		t.Errorf("old client: %+v %q", d, notes)
	}
	// None of it made a ban.
	if all, _ := e.st.ListBans(ctx, "demo", 0); len(all) != 0 {
		t.Errorf("bans %+v", all)
	}
}

// The unattested pool is a second answer on the status call, off until the studio turns
// it on. It is the same for a player in the shadow pool as for any other, leaves the
// shadow answer alone, and makes no ban and no label.
func TestUnattestedPoolOnTheStatusCall(t *testing.T) {
	e := newPoolEnv(t, 48*time.Hour)
	ctx := context.Background()

	// Two players with the same kind of PC; one is caught and goes to the shadow pool.
	for _, p := range []string{"fair", "caught"} {
		c, err := handshakeAs(t, e.env, softwareKey(), p, false)
		if err != nil {
			t.Fatal(err)
		}
		if p == "caught" {
			time.Sleep(15 * time.Millisecond)
			sendFindings(c, rendererFinding())
			eventually(t, "caught in the pool", func() bool { b, _ := e.bans.Pooled(ctx, "demo", "caught"); return b != nil })
		}
	}
	// A player on a ranked boot with a verified, clean list.
	at := time.Now()
	if err := e.st.PutDriverList(ctx, &store.DriverList{TenantID: "demo", SessionID: "s-ranked", PlayerHash: "ranked", TrustLevel: int(protocol.TrustRankedBoot),
		Status: store.DriversVerified, Drivers: []store.ListedDriver{{Name: "ntfs.sys"}}, ReceivedAt: at}); err != nil {
		t.Fatal(err)
	}

	ask := func(key string) map[string][2]string {
		t.Helper()
		code, out := e.api(t, "POST", "/v1/shadow/status", key, `{"players":["fair","caught","ranked","stranger"]}`)
		if code != http.StatusOK {
			t.Fatalf("status call: %d %v", code, out)
		}
		got := map[string][2]string{}
		for _, row := range out["players"].([]any) {
			r := row.(map[string]any)
			att, has := r["attestation"].(string)
			if !has && r["attestation"] != nil {
				t.Fatalf("attestation %v", r["attestation"])
			}
			got[r["player"].(string)] = [2]string{r["status"].(string), att}
		}
		return got
	}

	off := ask(serverKey)
	for p, a := range off {
		if a[1] != "" {
			t.Errorf("pool off: %s has attestation %q", p, a[1])
		}
	}
	if off["caught"][0] != "shadow" || off["fair"][0] != "normal" {
		t.Fatalf("shadow answers %v", off)
	}

	if err := e.st.SetUnattestedPool(ctx, "demo", true); err != nil {
		t.Fatal(err)
	}
	on := ask(serverKey)
	want := map[string][2]string{"fair": {"normal", "unattested"}, "caught": {"shadow", "unattested"}, "ranked": {"normal", "attested"}, "stranger": {"normal", "unattested"}}
	for p, w := range want {
		if on[p] != w {
			t.Errorf("pool on: %s is %v, want %v", p, on[p], w)
		}
	}
	// The single-player form carries it too.
	if code, out := e.api(t, "GET", "/v1/shadow/status?player=ranked", serverKey, ""); code != http.StatusOK || out["attestation"] != "attested" || out["status"] != "normal" {
		t.Errorf("GET: %d %v", code, out)
	}
	// A later session of the same player with a raised driver is unattested again.
	if err := e.st.PutDriverList(ctx, &store.DriverList{TenantID: "demo", SessionID: "s-ranked-2", PlayerHash: "ranked", TrustLevel: int(protocol.TrustRankedBoot),
		Status: store.DriversVerified, Flagged: 1, Drivers: []store.ListedDriver{{Name: "gdrv.sys", Flags: []string{store.DriverFlagVulnerable}}}, ReceivedAt: at.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	if got := ask(serverKey)["ranked"]; got != [2]string{"normal", "unattested"} {
		t.Errorf("after a session with a raised driver: %v", got)
	}
	// Another studio has its own switch.
	for p, a := range ask("rival-server-key") {
		if a[1] != "" {
			t.Errorf("rival studio: %s has attestation %q", p, a[1])
		}
	}

	// Turning it on banned nobody and labelled nobody: the only ban is the caught
	// player's shadow entry, the only label the one that ban taught.
	all, _ := e.st.ListBans(ctx, "demo", 0)
	if len(all) != 1 || all[0].PlayerHash != "caught" {
		t.Errorf("bans %+v", all)
	}
	labels, _ := e.st.ListSessionLabels(ctx, "demo", store.OracleFilter{})
	for _, l := range labels {
		if l.PlayerHash != "caught" {
			t.Errorf("label %+v", l)
		}
	}
}
