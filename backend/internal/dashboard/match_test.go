package dashboard

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge/synth"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/store"
)

func TestMatchReplayPage(t *testing.T) {
	f := newFixture(t)
	st := f.srv.st.(*store.Memory)
	ctx := context.Background()
	s := store.Session{SessionID: "cccc3333", TenantID: "demo", PlayerHash: "mallory", DeviceID: "d3", TrustLevel: 2, State: store.SessionActive, CreatedAt: f.now, LastHeartbeat: f.now}
	if err := st.PutSession(ctx, &s); err != nil {
		t.Fatal(err)
	}
	mode := pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER
	ps := synth.DefaultPlayers(mode, 1, []synth.Role{synth.RoleLegit, synth.RoleInformed, synth.RolePrefire, synth.RoleSound})
	ps[1].SessionID = "cccc3333"
	spec := synth.Spec{MatchID: "dash/match 1", Mode: mode, TickRate: 64, Seconds: 1800, Seed: 11, Players: ps}
	// The pipeline's clock is the fixture's, so the match is received "now".
	p := pipeline.New(pipeline.Config{Now: func() time.Time { return f.now }}, st, st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, b := range synth.Batches(spec) {
		if ok, _, err := p.Gameplay(ctx, "demo", b); !ok || err != nil {
			t.Fatalf("batch %d: %v %v", b.BatchSeq, ok, err)
		}
	}
	p.Close()
	// A client finding of the same session while the match was being received, one from
	// long before it, and an Oracle score of the session for this match.
	if err := st.AddEvidence(ctx, []store.Evidence{
		{TenantID: "demo", PlayerHash: "mallory", SessionID: "cccc3333", Source: store.SourceClient, Rule: "api_hook", Severity: 3, Score: 0.9, Integrity: true, Summary: "hook during the match", ObservedAt: f.now},
		{TenantID: "demo", PlayerHash: "mallory", SessionID: "cccc3333", Source: store.SourceClient, Rule: "overlay_window", Severity: 1, Score: 0.5, Summary: "overlay an hour earlier", ObservedAt: f.now.Add(-time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutOracleScore(ctx, &store.OracleScore{TenantID: "demo", SessionID: "cccc3333", PlayerHash: "mallory", MatchID: spec.MatchID, Score: 0.91, Band: store.OracleBandReview, UpdatedAt: f.now}); err != nil {
		t.Fatal(err)
	}

	const page = "/matches/dash%2Fmatch%201"
	if w := f.do("GET", page, nil, nil, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("signed out: %d", w.Code)
	}
	if w := f.do("GET", page+"/replay.json", nil, nil, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("the recording, signed out: %d", w.Code)
	}
	c := f.login(t, "demo", "demo-key")
	w := f.do("GET", page+"?player=mallory&t=90000", c, nil, nil)
	if w.Code != 200 {
		t.Fatalf("match page: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		`data-src="/matches/dash%2Fmatch%201/replay.json"`, `data-t="90000"`, `data-focus="2"`,
		`<script src="/static/replay.js" defer></script>`,
		"information_leak", `data-kind="moment"`, `data-kind="finding"`,
		"api_hook", "hook during the match",
		"oracle_review", "scored this player&#39;s session 91%", `href="/sessions/cccc3333"`,
		`href="/players/mallory"`, "30:00",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("match page lacks %q", want)
		}
	}
	if strings.Contains(body, "overlay an hour earlier") {
		t.Error("a finding from before the match is on its timeline")
	}
	if strings.Contains(body, "style=") || strings.Count(body, "<script") != 1 || strings.Contains(body, "onclick") {
		t.Error("the page needs inline style or script, which the CSP blocks")
	}
	// The match page alone may run the dashboard's own script and fetch the recording.
	if got := w.Header().Get("Content-Security-Policy"); got != matchCSP || strings.Contains(got, "unsafe") || !strings.Contains(got, "script-src 'self'") {
		t.Errorf("match page policy: %q", got)
	}
	for _, other := range []string{"/", "/players/mallory", "/sessions/cccc3333", page + "/replay.json", "/static/replay.js"} {
		if got := f.do("GET", other, c, nil, nil).Header().Get("Content-Security-Policy"); strings.Contains(got, "script-src") {
			t.Errorf("%s allows script: %q", other, got)
		}
	}

	w = f.do("GET", page+"/replay.json", c, nil, nil)
	if w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("recording: %d %v", w.Code, w.Header())
	}
	zr, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Match   string `json:"match"`
		Players []struct {
			Name string  `json:"name"`
			T    []int32 `json:"t"`
		} `json:"players"`
		Shots [][5]int32 `json:"shots"`
	}
	if err := json.NewDecoder(zr).Decode(&rec); err != nil {
		t.Fatal(err)
	}
	if rec.Match != spec.MatchID || len(rec.Players) != len(ps) || rec.Players[1].Name != "mallory" || len(rec.Players[1].T) < 1000 || len(rec.Shots) == 0 {
		t.Fatalf("recording: %s, %d players, %d shots", rec.Match, len(rec.Players), len(rec.Shots))
	}

	// The player and the session link to the replay.
	for _, from := range []string{"/players/mallory", "/sessions/cccc3333"} {
		if b := f.do("GET", from, c, nil, nil).Body.String(); !strings.Contains(b, `href="/matches/dash%2Fmatch%201?player=mallory"`) || !strings.Contains(b, "Watch replay") {
			t.Errorf("%s does not link to the replay", from)
		}
	}
	if b := f.do("GET", "/players/alice", c, nil, nil).Body.String(); strings.Contains(b, "Recorded matches") {
		t.Error("a player without a recorded match has the card")
	}

	// Another studio sees neither the page nor the recording.
	rival := f.login(t, "rival", "rival-key")
	for _, path := range []string{page, page + "/replay.json"} {
		if w := f.do("GET", path, rival, nil, nil); w.Code != http.StatusNotFound {
			t.Errorf("rival opens %s: %d", path, w.Code)
		}
	}
	if w := f.do("GET", "/matches/none", c, nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("unknown match: %d", w.Code)
	}
}

func TestMatchReplayRoles(t *testing.T) {
	f := newFixture(t)
	st := f.srv.st.(*store.Memory)
	if err := st.PutMatchReplay(context.Background(), &store.MatchReplay{TenantID: "demo", MatchID: "m1", StartedAt: f.now, UpdatedAt: f.now, DurationMs: 1000,
		Data: emptyRecording(t), Players: []store.ReplayPlayer{{Slot: 1, PlayerHash: "alice", SessionID: "aaaa1111"}}}); err != nil {
		t.Fatal(err)
	}
	f.addUser(t, "demo", "vera", store.RoleReadOnly, goodPW)
	c := f.signIn(t, "demo", "vera", goodPW)
	if w := f.get(c, "/matches/m1"); w.Code != 200 || !strings.Contains(w.Body.String(), "Nothing was found in this match") {
		t.Fatalf("a read-only user opens a match: %d", w.Code)
	}
	if w := f.get(c, "/matches/m1/replay.json"); w.Code != 200 {
		t.Fatalf("a read-only user reads the recording: %d", w.Code)
	}
}

func emptyRecording(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(`{"v":1,"match":"m1","tick_rate":64,"step_ms":250,"duration_ms":1000,"bounds":[0,0,0,0],"players":[],"shots":[],"batches":[]}`)); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	return buf.Bytes()
}
