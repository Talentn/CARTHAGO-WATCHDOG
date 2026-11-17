package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/replay"
	"carthago/backend/internal/review"
	"carthago/backend/internal/store"
)

func TestReviewEndpoints(t *testing.T) {
	keys, err := LoadOrCreateKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Review) < 32 || bytes.Equal(keys.Review, keys.Identity.Seed()) {
		t.Fatal("the review key is missing or is the identity key")
	}
	st := store.NewMemory()
	ctx := context.Background()
	now := time.Now()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := review.New(st, review.Config{Key: keys.Review, PerHour: 3})
	gw := New(Config{Tenants: map[string]string{"demo": serverKey, "rival": "rival-server-key"}, Review: svc}, keys, st, log)
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	call := func(method, key, path, body string) (*http.Response, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp, out
	}

	// Recorded matches with a flagged player each, for both studios.
	for _, m := range []struct{ tenant, id, suspect string }{{"demo", "m1", "sus1"}, {"demo", "m2", "sus2"}, {"demo", "m3", "sus3"}, {"demo", "m4", "sus4"}, {"rival", "m1", "sus1"}} {
		d := replay.Data{V: 1, Match: m.id, TickRate: 64, StepMs: 250, DurationMs: 1000, Bounds: [4]int32{0, 0, 100, 100}, Players: []replay.Player{
			{Slot: 1, Name: m.suspect, Team: 1, T: []int32{0, 16}, X: []int32{10, 20}, Y: []int32{10, 20}, Yaw: []int32{0, 0}},
			{Slot: 2, Name: "acct-other", Team: 2, T: []int32{0, 16}, X: []int32{90, 80}, Y: []int32{90, 80}, Yaw: []int32{180, 180}}}}
		data, err := d.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if err := st.PutMatchReplay(ctx, &store.MatchReplay{TenantID: m.tenant, MatchID: m.id, StartedAt: now, UpdatedAt: now, DurationMs: 1000, Data: data,
			Players: []store.ReplayPlayer{{Slot: 1, PlayerHash: m.suspect, SessionID: "s-" + m.id}, {Slot: 2, PlayerHash: "acct-other"}}}); err != nil {
			t.Fatal(err)
		}
		if err := st.PutOracleScore(ctx, &store.OracleScore{TenantID: m.tenant, SessionID: "s-" + m.id, PlayerHash: m.suspect, MatchID: m.id, Band: store.OracleBandReview, Score: 0.9, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}

	for _, key := range []string{"", "wrong-key"} {
		for _, ep := range [][2]string{{"POST", "/v1/review/links"}, {"GET", "/v1/review/standing?player=rev1"}, {"GET", "/v1/review/badges"}, {"POST", "/v1/review/badges/ack"}} {
			if resp, _ := call(ep[0], key, ep[1], `{"player":"rev1"}`); resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s with key %q: %d, want 401", ep[0], ep[1], key, resp.StatusCode)
			}
		}
	}
	// Off by default.
	if resp, out := call("POST", serverKey, "/v1/review/links", `{"player":"rev1"}`); resp.StatusCode != http.StatusForbidden || out["status"] != "off" {
		t.Fatalf("a link with the feature off: %d %v", resp.StatusCode, out)
	}
	set := store.DefaultReviewSettings()
	set.Enabled = true
	if err := svc.SetSettings(ctx, "demo", set); err != nil {
		t.Fatal(err)
	}
	// One studio's switch is its own.
	if resp, out := call("POST", "rival-server-key", "/v1/review/links", `{"player":"rev1"}`); resp.StatusCode != http.StatusForbidden || out["status"] != "off" {
		t.Fatalf("the other studio's link: %d %v", resp.StatusCode, out)
	}
	for _, body := range []string{``, `{}`, `{"player":"two words"}`, `{"player":"rev1","case":3}`, `{"player":"rev1","match":"m2"}`, `[`} {
		if resp, _ := call("POST", serverKey, "/v1/review/links", body); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("link with body %q: %d, want 400", body, resp.StatusCode)
		}
	}
	// A player of every match there is gets none.
	if resp, out := call("POST", serverKey, "/v1/review/links", `{"player":"acct-other"}`); resp.StatusCode != http.StatusOK || out["status"] != "none" || out["url"] != nil {
		t.Fatalf("a link for a player of every match: %d %v", resp.StatusCode, out)
	}

	resp, out := call("POST", serverKey, "/v1/review/links", `{"player":"rev1"}`)
	link, _ := out["url"].(string)
	if resp.StatusCode != http.StatusCreated || out["status"] != "assigned" || !strings.HasPrefix(link, srv.URL+"/review/v1.") || out["expires_ms"].(float64) <= float64(now.UnixMilli()) {
		t.Fatalf("link: %d %v", resp.StatusCode, out)
	}
	// The answer names no match, case or suspect.
	if len(out) != 3 {
		t.Fatalf("the link answer says more than status, url and expires_ms: %v", out)
	}
	// The page is on the gateway, needs no key and sets no cookie.
	page, err := http.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if page.StatusCode != 200 || !strings.Contains(string(body), "Suspect") || strings.Contains(string(body), "sus1") || strings.Contains(string(body), "acct-other") ||
		len(page.Cookies()) != 0 || !strings.Contains(page.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("review page: %d %v", page.StatusCode, page.Header)
	}
	// The server key opens nothing under /review/, and there is nothing to list.
	for _, path := range []string{"/review/", "/review/cases", "/v1/review/cases", "/v1/review/links", "/v1/review"} {
		if resp, _ := call("GET", serverKey, path, ""); resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: %d", path, resp.StatusCode)
		}
	}
	vote := func(link, verdict string) int {
		t.Helper()
		resp, err := http.Post(link+"/verdict", "application/x-www-form-urlencoded", strings.NewReader("verdict="+verdict))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := vote(link, review.VerdictAim); code != 200 {
		t.Fatalf("verdict: %d", code)
	}

	// The hourly limit, with Retry-After.
	for i := 0; i < 2; i++ {
		resp, out := call("POST", serverKey, "/v1/review/links", `{"player":"rev1"}`)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("link %d: %d %v", i+2, resp.StatusCode, out)
		}
		if code := vote(out["url"].(string), review.VerdictInsufficient); code != 200 {
			t.Fatalf("verdict %d: %d", i+2, code)
		}
	}
	if resp, out := call("POST", serverKey, "/v1/review/links", `{"player":"rev1"}`); resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("a fourth link within the hour: %d %v", resp.StatusCode, out)
	}

	// Standing and badges. A calibration case scores rev2 at once and earns a badge.
	if _, err := svc.AddCalibration(ctx, "demo", "m4", "acct-other", review.ClassInsufficient); err != nil {
		t.Fatal(err)
	}
	_, out = call("POST", serverKey, "/v1/review/links", `{"player":"rev2"}`)
	if code := vote(out["url"].(string), review.VerdictInsufficient); code != 200 {
		t.Fatalf("rev2's verdict: %d", code)
	}
	resp, out = call("GET", serverKey, "/v1/review/standing?player=rev2", "")
	badges, _ := out["badges"].([]any)
	if resp.StatusCode != 200 || out["player"] != "rev2" || out["verdicts"].(float64) != 1 || out["correct"].(float64) != 1 || out["eligible"] != true || out["level_name"] != "Reviewer" || len(badges) != 1 {
		t.Fatalf("standing: %d %v", resp.StatusCode, out)
	}
	if resp, out := call("GET", serverKey, "/v1/review/standing?player=never-reviewed", ""); resp.StatusCode != 200 || out["weight"].(float64) != 0.5 || out["level_name"] != "New" {
		t.Fatalf("the standing of a player who never reviewed: %d %v", resp.StatusCode, out)
	}
	if resp, _ := call("GET", serverKey, "/v1/review/standing", ""); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("standing without a player: %d", resp.StatusCode)
	}
	_, out = call("GET", serverKey, "/v1/review/badges", "")
	fresh, _ := out["badges"].([]any)
	if len(fresh) != 1 || fresh[0].(map[string]any)["player"] != "rev2" || fresh[0].(map[string]any)["badge"] != "first_correct_verdict" {
		t.Fatalf("new badges: %v", out)
	}
	// The other studio sees none of it and cannot acknowledge it.
	if _, out := call("GET", "rival-server-key", "/v1/review/badges", ""); len(out["badges"].([]any)) != 0 {
		t.Fatalf("the other studio's badges: %v", out)
	}
	if _, out := call("GET", "rival-server-key", "/v1/review/standing?player=rev2", ""); out["verdicts"].(float64) != 0 {
		t.Fatalf("the other studio's standing of rev2: %v", out)
	}
	if _, out := call("POST", "rival-server-key", "/v1/review/badges/ack", `{"player":"rev2","badges":["first_correct_verdict"]}`); out["acknowledged"].(float64) != 0 {
		t.Fatalf("the other studio acknowledged the badge: %v", out)
	}
	if resp, out := call("POST", serverKey, "/v1/review/badges/ack", `{"player":"rev2","badges":["first_correct_verdict"]}`); resp.StatusCode != 200 || out["acknowledged"].(float64) != 1 {
		t.Fatalf("ack: %d %v", resp.StatusCode, out)
	}
	if _, out := call("POST", serverKey, "/v1/review/badges/ack", `{"player":"rev2","badges":["first_correct_verdict"]}`); out["acknowledged"].(float64) != 0 {
		t.Fatalf("ack twice: %v", out)
	}
	if resp, _ := call("POST", serverKey, "/v1/review/badges/ack", `{"player":"rev2","badges":[]}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("ack without badges: %d", resp.StatusCode)
	}
	if _, out := call("GET", serverKey, "/v1/review/badges", ""); len(out["badges"].([]any)) != 0 {
		t.Fatalf("badges after the ack: %v", out)
	}

	// Verdicts changed nothing a ban or the Oracle reads.
	bans, _ := st.ListBans(ctx, "demo", 100)
	ev, _ := st.ListEvidence(ctx, "demo", store.EvidenceFilter{Limit: 100})
	labels, _ := st.ListSessionLabels(ctx, "demo", store.OracleFilter{Limit: 100})
	if len(bans) != 0 || len(ev) != 0 || len(labels) != 0 {
		t.Fatalf("community review made %d bans, %d pieces of evidence, %d labels", len(bans), len(ev), len(labels))
	}

	// A configured public address is where links point.
	gw2 := New(Config{Tenants: map[string]string{"demo": serverKey}, Review: svc, ReviewURL: "https://ac.example.com/"}, keys, st, log)
	srv2 := httptest.NewServer(gw2.Handler())
	t.Cleanup(srv2.Close)
	req, _ := http.NewRequest("POST", srv2.URL+"/v1/review/links", strings.NewReader(`{"player":"rev3"}`))
	req.Header.Set("Authorization", "Bearer "+serverKey)
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	var l2 struct{ URL string }
	_ = json.NewDecoder(r2.Body).Decode(&l2)
	if !strings.HasPrefix(l2.URL, "https://ac.example.com/review/v1.") {
		t.Fatalf("link under the public address: %q", l2.URL)
	}

	// A gateway without community review has none of the routes.
	bare := httptest.NewServer(New(Config{Tenants: map[string]string{"demo": serverKey}}, keys, st, log).Handler())
	t.Cleanup(bare.Close)
	for _, path := range []string{"/v1/review/badges", strings.TrimPrefix(link, srv.URL)} {
		req, _ := http.NewRequest("GET", bare.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+serverKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s on a gateway without community review: %d", path, resp.StatusCode)
		}
	}
}
