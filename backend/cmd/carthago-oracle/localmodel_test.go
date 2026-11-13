package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The bundle names the analyst model by file and hash, and the fetch scripts download it:
// the three places must agree, and nothing may be left unpinned.
func TestFetchScriptsMatchTheDefaultModel(t *testing.T) {
	m := defaultLocalModel
	if m.ID == "" || !strings.HasSuffix(m.File, ".gguf") || len(m.SHA256) != 64 || m.ContextTokens < 2048 {
		t.Fatalf("default local model: %+v", m)
	}
	tools := filepath.Join("..", "..", "..", "tools")
	hash := regexp.MustCompile(`\b[0-9a-f]{64}\b`)
	revision := regexp.MustCompile(`\b[0-9a-f]{40}\b`)
	var tags []string
	for _, name := range []string{"carthago-oracle-fetch.sh", "carthago-oracle-fetch.ps1"} {
		data, err := os.ReadFile(filepath.Join(tools, name))
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		if !strings.Contains(s, m.File) || !strings.Contains(s, m.SHA256) {
			t.Errorf("%s does not fetch %s with SHA-256 %s", name, m.File, m.SHA256)
		}
		// Two pinned hashes (runtime archive and model) and one pinned model revision.
		if n := len(hash.FindAllString(s, -1)); n != 2 {
			t.Errorf("%s: %d SHA-256 hashes, want 2", name, n)
		}
		if !revision.MatchString(s) || strings.Contains(s, "/resolve/main/") || strings.Contains(s, "releases/latest") {
			t.Errorf("%s: the model or the runtime is not pinned to a revision", name)
		}
		if strings.Contains(s, "@MODEL") {
			t.Errorf("%s still has a placeholder", name)
		}
		tag := regexp.MustCompile(`(?i)llama_?tag\s*=\s*['"]([a-z0-9]+)['"]`).FindStringSubmatch(s)
		if tag == nil {
			t.Fatalf("%s: no llama.cpp tag", name)
		}
		tags = append(tags, tag[1])
	}
	if tags[0] != tags[1] {
		t.Errorf("the scripts pin different llama.cpp releases: %v", tags)
	}
	notices, err := os.ReadFile(filepath.Join("..", "..", "..", "THIRD-PARTY-NOTICES.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{m.File, m.SHA256, tags[0]} {
		if !strings.Contains(string(notices), want) {
			t.Errorf("THIRD-PARTY-NOTICES.md does not mention %s", want)
		}
	}
}
