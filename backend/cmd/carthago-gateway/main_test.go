package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCheckExposure(t *testing.T) {
	strong := "k3y-with-enough-entropy-000"
	demo := map[string]string{"demo": demoServerKey}
	demoDash := map[string]string{"demo": demoDashboardKey}
	for _, c := range []struct {
		name               string
		listen, dashListen string
		tenants, dashKeys  map[string]string
		secure             bool
		wantErr            string
	}{
		{"demo keys on loopback", "127.0.0.1:8750", "127.0.0.1:8751", demo, demoDash, false, ""},
		{"demo keys on localhost", "localhost:8750", "[::1]:8751", demo, demoDash, false, ""},
		{"demo server key exposed", "0.0.0.0:8750", "127.0.0.1:8751", demo, demoDash, false, "server key"},
		{"short server key exposed", "10.0.0.5:8750", "", map[string]string{"studio": "short"}, nil, false, "server key"},
		{"strong server key exposed", "0.0.0.0:8750", "127.0.0.1:8751", map[string]string{"studio": strong}, demoDash, false, ""},
		{"demo dashboard key exposed", "127.0.0.1:8750", "0.0.0.0:8751", demo, demoDash, true, "works on loopback only"},
		{"any shared dashboard key exposed", "127.0.0.1:8750", "0.0.0.0:8751", demo, map[string]string{"demo": strong}, true, "works on loopback only"},
		{"plaintext dashboard exposed", "127.0.0.1:8750", "0.0.0.0:8751", demo, nil, false, "plain HTTP"},
		{"plaintext dashboard exposed, with a key", "127.0.0.1:8750", "0.0.0.0:8751", demo, demoDash, false, "plain HTTP"},
		{"dashboard over TLS or behind a TLS proxy, accounts only", "127.0.0.1:8750", "0.0.0.0:8751", demo, nil, true, ""},
		{"dashboard disabled", "127.0.0.1:8750", "", demo, nil, false, ""},
		{"shared server key", "127.0.0.1:8750", "", map[string]string{"a": strong, "b": strong}, nil, false, "share a server key"},
	} {
		err := checkExposure(c.listen, c.dashListen, c.tenants, c.dashKeys, c.secure)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: want an error mentioning %q, got %v", c.name, c.wantErr, err)
		}
	}
}

func TestDashboardHosts(t *testing.T) {
	if got := dashboardHosts("127.0.0.1:8751", ""); !slices.Equal(got, []string{"localhost", "127.0.0.1", "::1"}) {
		t.Errorf("loopback: %v", got)
	}
	if got := dashboardHosts("127.0.0.1:8751", "watchdog.studio.example"); !slices.Contains(got, "watchdog.studio.example") || !slices.Contains(got, "localhost") {
		t.Errorf("loopback with proxy name: %v", got)
	}
	if got := dashboardHosts("0.0.0.0:8751", ""); len(got) != 0 {
		t.Errorf("non-loopback without names: %v", got)
	}
	if got := dashboardHosts("0.0.0.0:8751", "a.example, b.example"); !slices.Equal(got, []string{"a.example", "b.example"}) {
		t.Errorf("non-loopback with names: %v", got)
	}
}

func TestExtraRootsWarning(t *testing.T) {
	for _, c := range []struct {
		dir, listen string
		warn        bool
	}{
		{"", "0.0.0.0:8750", false},
		{"/etc/carthago/dev-roots", "127.0.0.1:8750", false},
		{"/etc/carthago/dev-roots", "0.0.0.0:8750", true},
		{"/etc/carthago/dev-roots", ":8750", true},
	} {
		if got := extraRootsWarning(c.dir, c.listen) != ""; got != c.warn {
			t.Errorf("dir %q listen %q: warning %v, want %v", c.dir, c.listen, got, c.warn)
		}
	}
}

func TestLoadMapPins(t *testing.T) {
	a, b := strings.Repeat("ab", 32), strings.Repeat("CD", 32)
	write := func(text string) string {
		p := filepath.Join(t.TempDir(), "pins.txt")
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// The form carthago-cs16-bridge map-hash prints, with Windows line ends.
	pins, err := loadMapPins(write("# de_dust2.bsp: 5121 splits\r\nde_dust2 " + a + "\r\n\r\ncs_office " + b + " # checked\r\nde_dust2 " + strings.ToUpper(a) + "\r\n"))
	if err != nil || len(pins) != 2 || pins["de_dust2"] != a || pins["cs_office"] != strings.ToLower(b) {
		t.Fatalf("pins %v, err %v", pins, err)
	}
	for text, want := range map[string]string{
		"de_dust2\n":                        "want `map_id sha256`",
		"de_dust2 " + a + " extra\n":        "want `map_id sha256`",
		"de_dust2 abcd\n":                   "not a SHA-256",
		"de_dust2 " + a + "\nde_dust2 " + b: "pinned twice",
	} {
		if _, err := loadMapPins(write(text)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", text, err)
		}
	}
	if _, err := loadMapPins(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file must be an error")
	}
}
