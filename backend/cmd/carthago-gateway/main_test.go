package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
