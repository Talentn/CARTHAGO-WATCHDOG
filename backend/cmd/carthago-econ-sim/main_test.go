package main

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
)

// The four scenarios against the tool's own gateway, over HTTP, come out as the ledger
// promises; a second run on the same gateway does too.
func TestScenarios(t *testing.T) {
	l, err := newLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	srv := httptest.NewServer(l.api)
	defer srv.Close()
	for i, run := range []string{"aaaa", "bbbb"} {
		var out bytes.Buffer
		g := newGameServer(srv.URL, demoServerKey)
		g.run = run
		passed, total := scenarios(g, &out)
		if i == 0 {
			t.Log("\n" + out.String())
		}
		if passed != 4 || total != 4 || strings.Contains(out.String(), "FAIL") {
			t.Fatalf("run %s: %d of %d passed\n%s", run, passed, total, out.String())
		}
	}
	// A game server with the wrong key gets nowhere.
	var out bytes.Buffer
	if passed, _ := scenarios(newGameServer(srv.URL, "not-the-key"), &out); passed != 0 || !strings.Contains(out.String(), "401") {
		t.Fatalf("wrong key: %d passed\n%s", passed, out.String())
	}
}
