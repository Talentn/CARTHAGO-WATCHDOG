package main

import (
	"bytes"
	"strings"
	"testing"
)

// The whole run against its own gateway: every scene passes, the players left for the
// dashboard are in the pool, and nothing is said that a scene did not check.
func TestSimulatedMatchmaker(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a shadow period to end")
	}
	var out bytes.Buffer
	code := run("127.0.0.1:0", "127.0.0.1:0", minPeriod, true, false, &out)
	got := out.String()
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, got)
	}
	for _, want := range []string{
		"RESULT: 5 of 5 scenes passed",
		"match (shadow): kex lod mav nyx",
		"waiting in the pool for 3 more: kex2",
		"match (normal): nyx ivo jan kim",
		"match (shadow): kex lod mav kex2",
		`reason "banned"`,
		"kex3 refused: banned (CW-",
		"12 normal, 0 shadow",
		"ork, pax and ork2",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "FAIL") || strings.Contains(got, "ERROR") {
		t.Errorf("a scene failed:\n%s", got)
	}
}

func TestPeriodTooShort(t *testing.T) {
	var out bytes.Buffer
	if code := run("127.0.0.1:0", "127.0.0.1:0", minPeriod/2, true, false, &out); code != 2 || !strings.Contains(out.String(), "-period is at least") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
}
