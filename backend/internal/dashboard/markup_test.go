package dashboard

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

var (
	classAttr  = regexp.MustCompile(`class="([^"]*)"`)
	tmplAction = regexp.MustCompile(`\{\{[^}]*\}\}`)
)

// The CSP forbids inline styles, so the stylesheet is the only place a class can get its
// look. A class that a template uses and app.css does not define is a mark that silently
// renders as plain text, which is how the old "pill ok" statuses would have ended up.
func TestTemplateClassesAreStyled(t *testing.T) {
	cssBytes, err := fs.ReadFile(staticFS, "static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(cssBytes)
	defined := func(name string, prefix bool) bool {
		for i := strings.Index(css, "."+name); i >= 0; {
			rest := css[i+1+len(name):]
			if prefix || rest == "" || !isNameByte(rest[0]) {
				return true
			}
			j := strings.Index(rest, "."+name)
			if j < 0 {
				break
			}
			i += 1 + len(name) + j
		}
		return false
	}
	files, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("templates: %v %v", files, err)
	}
	for _, file := range files {
		src, err := fs.ReadFile(templateFS, file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range classAttr.FindAllStringSubmatch(string(src), -1) {
			// `sev-{{sev .Severity}}` becomes the prefix `sev-`; `{{if …}} warn{{end}}` becomes `warn`.
			for _, tok := range strings.Fields(tmplAction.ReplaceAllString(m[1], "\x00 ")) {
				name := strings.TrimSuffix(tok, "\x00")
				if name == "" {
					continue
				}
				if !defined(name, name != tok) {
					t.Errorf("%s: class %q has no rule in app.css", file, name)
				}
			}
		}
		if strings.Contains(string(src), "style=") || strings.Contains(string(src), "<script") || strings.Contains(string(src), "<style") {
			t.Errorf("%s: inline style or script, which the CSP blocks", file)
		}
	}
}

func isNameByte(c byte) bool {
	return c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// Trust is shown the same way everywhere: the pips mark with the level's class and name.
func TestTrustMark(t *testing.T) {
	f := newFixture(t)
	c := f.login(t, "demo", "demo-key")
	for page, want := range map[string]string{
		"/":                  `<span class="trust t3" title="attested, and the boot state meets the ranked policy">Ranked boot</span>`,
		"/sessions":          `<span class="trust t0" title="software device key, no TPM">`,
		"/sessions/aaaa1111": `<span class="trust t3">Ranked boot</span>`,
		"/players":           `<span class="trust t0">`,
		"/players/alice":     `<span class="trust t3">Ranked boot</span><small>attested, and the boot state meets the ranked policy</small>`,
	} {
		if body := f.do("GET", page, c, nil, nil).Body.String(); !strings.Contains(body, want) {
			t.Errorf("%s lacks %s", page, want)
		}
	}
}

// Statuses are a dot and a word; tags label things. Neither may fall back to the old pills.
func TestStatusMarkup(t *testing.T) {
	f := newFixture(t)
	c := f.login(t, "demo", "demo-key")
	sess := f.do("GET", "/sessions/aaaa1111", c, nil, nil).Body.String()
	for _, want := range []string{
		`<span class="tag">Secure Boot</span>`,
		`<span class="bad">quarantined</span>`,
		`<td>covering</td>`,
		`<span class="state st-active">active</span>`,
	} {
		if !strings.Contains(sess, want) {
			t.Errorf("session page lacks %s", want)
		}
	}
	list := f.do("GET", "/sessions", c, nil, nil).Body.String()
	for _, want := range []string{
		`<span class="state st-kicked">kicked</span>`,
		`<span class="n mono">1</span><span class="sev sev-critical">critical</span>`,
		`<span class="mono">11:00:00</span> <span class="muted">`,
	} {
		if !strings.Contains(list, want) {
			t.Errorf("session list lacks %s", want)
		}
	}
	players := f.do("GET", "/players", c, nil, nil).Body.String()
	if !strings.Contains(players, `<span class="tier tier-review">review</span>`) || !strings.Contains(players, `<th>Severity</th>`) {
		t.Error("players list: status mark or severity column missing")
	}
	// On a player's own page the session table hides its player column.
	if own := f.do("GET", "/players/bob", c, nil, nil).Body.String(); !strings.Contains(own, `<section class="card no-player">`) || !strings.Contains(own, `<h1 class="wrapall">Player <span class="mono">bob</span></h1>`) {
		t.Error("player page: title or session table markup changed")
	}
	for _, p := range []string{"/login", "/", "/sessions", "/sessions/aaaa1111", "/sessions/bbbb2222", "/players", "/players?all=1", "/players/bob", "/players/alice", "/evidence/1"} {
		body := f.do("GET", p, c, nil, nil).Body.String()
		if strings.Contains(body, "style=") || strings.Contains(body, "<script") || strings.Contains(body, `class="pill`) {
			t.Errorf("%s: inline style, script or a leftover pill", p)
		}
	}
}
