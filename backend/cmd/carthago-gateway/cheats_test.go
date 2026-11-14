package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheatsCommand(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := cheatsCommand(append(args, "-data", filepath.Join(dir, "data"), "-tenant", "demo"), &out, &errOut)
		return code, out.String(), errOut.String()
	}
	file := filepath.Join(dir, "OPENGL32.dll")
	if err := os.WriteFile(file, []byte("a cheat"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("a cheat"))
	want := hex.EncodeToString(sum[:])
	if code, out, _ := run("list"); code != 0 || !strings.Contains(out, "empty") {
		t.Fatalf("list without a database: %d %q", code, out)
	}
	if code, _, errOut := run("add", "-file", file); code != 1 || !strings.Contains(errOut, "-name") {
		t.Fatalf("add without a name: %d %q", code, errOut)
	}
	if code, out, errOut := run("add", "-file", file, "-name", "Wall v2", "-note", "from a report"); code != 0 || !strings.Contains(out, `added "Wall v2": `+want) {
		t.Fatalf("add: %d %q %q", code, out, errOut)
	}
	if code, out, _ := run("add", "-sha256", strings.ToUpper(want), "-name", "again"); code != 0 || !strings.Contains(out, `already on the list as "Wall v2"`) {
		t.Fatalf("the same file twice: %d %q", code, out)
	}
	if code, _, errOut := run("add", "-sha256", "abcd", "-name", "short"); code != 1 || !strings.Contains(errOut, "64 hex digits") {
		t.Fatalf("a bad hash: %d %q", code, errOut)
	}
	if code, out, _ := run("list"); code != 0 || !strings.Contains(out, want+"  Wall v2") || !strings.Contains(out, "from a report") {
		t.Fatalf("list: %d %q", code, out)
	}
	if code, _, errOut := run("remove", "-name", "nothing"); code != 1 || !strings.Contains(errOut, "no such entry") {
		t.Fatalf("removing what is not there: %d %q", code, errOut)
	}
	if code, out, _ := run("remove", "-file", file); code != 0 || !strings.Contains(out, `removed "Wall v2"`) {
		t.Fatalf("remove: %d %q", code, out)
	}
	if code, out, _ := run("list"); code != 0 || !strings.Contains(out, "empty") {
		t.Fatalf("list after remove: %d %q", code, out)
	}
}
