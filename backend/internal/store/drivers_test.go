package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestDriverLists(t *testing.T) {
	sq, err := OpenSQLite(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sq.Close()
	for name, st := range map[string]DriverStore{"sqlite": sq, "memory": NewMemory()} {
		ctx := context.Background()
		at := time.UnixMilli(1_790_000_000_000).UTC()
		if _, err := st.LatestDriverList(ctx, "t1", "p1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: a player without a session: %v", name, err)
		}
		first := &DriverList{TenantID: "t1", SessionID: "s1", PlayerHash: "p1", TrustLevel: 3, Status: DriversVerified, ReceivedAt: at,
			Drivers: []ListedDriver{{Name: "ntfs.sys", HashAlg: "sha256", ImageHash: "ab", Signer: "cd", Loads: 1, Boot: true}}}
		second := &DriverList{TenantID: "t1", SessionID: "s2", PlayerHash: "p1", TrustLevel: 3, Status: DriversVerified, Flagged: 1, ReceivedAt: at.Add(time.Minute),
			Drivers: []ListedDriver{{Name: "gdrv.sys", HashAlg: "sha256", ImageHash: "ef", Signer: "01", OEM: "Vendor", Loads: 2, Unloaded: true, Flags: []string{DriverFlagVulnerable}}}}
		for _, d := range []*DriverList{first, second, {TenantID: "t1", SessionID: "s3", PlayerHash: "p2", Status: DriversUnavailable, Reason: "memory integrity is off", ReceivedAt: at}} {
			if err := st.PutDriverList(ctx, d); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		got, err := st.SessionDriverList(ctx, "t1", "s1")
		if err != nil || !got.Attested() || len(got.Drivers) != 1 || got.Drivers[0].Name != "ntfs.sys" || got.Drivers[0].ImageHash != "ab" || got.Drivers[0].Signer != "cd" || !got.Drivers[0].Boot || got.Drivers[0].Loads != 1 || !got.ReceivedAt.Equal(at) {
			t.Fatalf("%s: session list %+v %v", name, got, err)
		}
		latest, err := st.LatestDriverList(ctx, "t1", "p1")
		if err != nil || latest.SessionID != "s2" || latest.Attested() || latest.Drivers[0].Flags[0] != DriverFlagVulnerable || !latest.Drivers[0].Unloaded {
			t.Fatalf("%s: latest list %+v %v", name, latest, err)
		}
		if d, err := st.LatestDriverList(ctx, "t1", "p2"); err != nil || d.Status != DriversUnavailable || d.Reason == "" || d.Attested() || len(d.Drivers) != 0 {
			t.Fatalf("%s: unavailable list %+v %v", name, d, err)
		}
		if _, err := st.SessionDriverList(ctx, "t2", "s1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: another studio read the list: %v", name, err)
		}
		// The same session again replaces its list.
		first.Status, first.Reason = DriversUnverified, "no boot record"
		if err := st.PutDriverList(ctx, first); err != nil {
			t.Fatal(err)
		}
		if got, _ := st.SessionDriverList(ctx, "t1", "s1"); got == nil || got.Status != DriversUnverified || got.Attested() {
			t.Fatalf("%s: replaced list %+v", name, got)
		}

		if on, err := st.UnattestedPool(ctx, "t1"); err != nil || on {
			t.Fatalf("%s: the pool is on before anyone set it: %v", name, err)
		}
		if err := st.SetUnattestedPool(ctx, "t1", true); err != nil {
			t.Fatal(err)
		}
		if on, _ := st.UnattestedPool(ctx, "t1"); !on {
			t.Fatalf("%s: the pool did not turn on", name)
		}
		if on, _ := st.UnattestedPool(ctx, "t2"); on {
			t.Fatalf("%s: the switch crossed studios", name)
		}
		_ = st.SetUnattestedPool(ctx, "t1", false)
		if on, _ := st.UnattestedPool(ctx, "t1"); on {
			t.Fatalf("%s: the pool did not turn off", name)
		}
	}
}

func TestAttestedNeedsEverything(t *testing.T) {
	good := DriverList{TrustLevel: 3, Status: DriversVerified, Drivers: []ListedDriver{{Name: "a"}}}
	if !good.Attested() {
		t.Fatal("a ranked boot with a verified clean list is attested")
	}
	var none *DriverList
	for name, change := range map[string]func(d *DriverList){
		"trust below ranked": func(d *DriverList) { d.TrustLevel = 2 },
		"unverified list":    func(d *DriverList) { d.Status = DriversUnverified },
		"no list":            func(d *DriverList) { d.Status = DriversUnavailable },
		"incomplete list":    func(d *DriverList) { d.Overflowed = true },
		"a flagged driver":   func(d *DriverList) { d.Flagged = 1 },
		"test signing":       func(d *DriverList) { d.TestSigning = true },
		"an empty list":      func(d *DriverList) { d.Drivers = nil },
	} {
		d := good
		change(&d)
		if d.Attested() {
			t.Errorf("%s: attested", name)
		}
	}
	if none.Attested() {
		t.Error("a player without a session is attested")
	}
}
