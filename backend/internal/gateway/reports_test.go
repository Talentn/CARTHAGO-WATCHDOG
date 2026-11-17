package gateway

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"carthago/backend/internal/reports"
	"carthago/backend/internal/store"
)

func TestPlayerReportsEndpoint(t *testing.T) {
	keys, err := LoadOrCreateKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	gw := New(Config{Tenants: map[string]string{"demo": serverKey, "rival": "rival-server-key"}, Reports: reports.New(st, nil)}, keys, st, log)
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	post := func(key, body string) (int, map[string]any, http.Header) {
		t.Helper()
		req, _ := http.NewRequest("POST", srv.URL+"/v1/reports", strings.NewReader(body))
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
		return resp.StatusCode, out, resp.Header
	}
	const report = `{"reporter":"amira","reported":"sami","match":"ranked-yard-0001","tick":41280,"tick_rate":64,"reason":"cheating","note":"he knew where I was"}`
	ctx := context.Background()

	// Authenticated like the other game-server calls.
	for _, key := range []string{"", "wrong-key"} {
		if code, _, _ := post(key, report); code != http.StatusUnauthorized {
			t.Errorf("key %q: %d, want 401", key, code)
		}
	}
	if n, _ := st.CountPlayerReports(ctx, "demo", store.ReportFilter{}); n != 0 {
		t.Fatalf("a call without the key stored %d reports", n)
	}
	code, out, _ := post(serverKey, report)
	if code != http.StatusCreated || out["status"] != "accepted" || out["id"] == nil {
		t.Fatalf("a report: %d %v", code, out)
	}
	if code, again, _ := post(serverKey, report); code != http.StatusOK || again["status"] != "duplicate" || again["id"] != out["id"] {
		t.Fatalf("the same report again: %d %v", code, again)
	}
	rows, _ := st.ListPlayerReports(ctx, "demo", store.ReportFilter{})
	if len(rows) != 1 || rows[0].Reported != "sami" || rows[0].MatchMs != 645_000 || rows[0].Note != "he knew where I was" {
		t.Fatalf("stored: %+v", rows)
	}
	// The key decides the studio: the same report under another key is that studio's.
	if code, _, _ := post("rival-server-key", report); code != http.StatusCreated {
		t.Fatalf("the rival's report: %d", code)
	}
	if n, _ := st.CountPlayerReports(ctx, "demo", store.ReportFilter{}); n != 1 {
		t.Fatalf("the rival's report reached demo: %d", n)
	}
	if rows, _ := st.ListPlayerReports(ctx, "rival", store.ReportFilter{}); len(rows) != 1 {
		t.Fatalf("the rival's reports: %+v", rows)
	}

	for name, body := range map[string]string{
		"not JSON":       `reporter=amira`,
		"unknown field":  `{"reporter":"amira","reported":"bilel","match":"m","reason":"other","severity":"high"}`,
		"tenant in body": `{"tenant":"rival","reporter":"amira","reported":"bilel","match":"m","reason":"other"}`,
		"made-up reason": `{"reporter":"amira","reported":"bilel","match":"m","reason":"he is bad"}`,
		"self report":    `{"reporter":"amira","reported":"amira","match":"m","reason":"other"}`,
		"long note":      `{"reporter":"amira","reported":"bilel","match":"m","reason":"other","note":"` + strings.Repeat("x", reports.MaxNote+1) + `"}`,
		"two reports":    `{"reporter":"amira","reported":"bilel","match":"m","reason":"other"} {"reporter":"amira","reported":"dali","match":"m","reason":"other"}`,
		"huge body":      `{"reporter":"amira","reported":"bilel","match":"m","reason":"other","note":"` + strings.Repeat("x", maxReportBody) + `"}`,
	} {
		if code, out, _ := post(serverKey, body); code != http.StatusBadRequest || out["error"] == "" {
			t.Errorf("%s: %d %v, want 400", name, code, out)
		}
	}
	if n, _ := st.CountPlayerReports(ctx, "demo", store.ReportFilter{}); n != 1 {
		t.Fatalf("a refused report was stored: %d", n)
	}

	// One reporter cannot flood the queue.
	accepted, limited := 0, 0
	var retry string
	for i := range reports.MaxPerHour + 4 {
		code, _, hdr := post(serverKey, `{"reporter":"spammer","reported":"player-`+string(rune('a'+i))+`","match":"m","reason":"griefing"}`)
		switch code {
		case http.StatusCreated:
			accepted++
		case http.StatusTooManyRequests:
			limited++
			retry = hdr.Get("Retry-After")
		default:
			t.Fatalf("report %d: %d", i, code)
		}
	}
	if accepted != reports.MaxPerHour || limited != 4 || retry == "" || retry == "0" {
		t.Fatalf("accepted %d, limited %d, Retry-After %q", accepted, limited, retry)
	}
	if code, _, _ := post(serverKey, `{"reporter":"bilel","reported":"sami","match":"m","reason":"cheating"}`); code != http.StatusCreated {
		t.Fatalf("another reporter while one is limited: %d", code)
	}

	// Without the service the route does not exist.
	bare := httptest.NewServer(New(Config{Tenants: map[string]string{"demo": serverKey}}, keys, store.NewMemory(), log).Handler())
	defer bare.Close()
	req, _ := http.NewRequest("POST", bare.URL+"/v1/reports", strings.NewReader(report))
	req.Header.Set("Authorization", "Bearer "+serverKey)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a gateway without reports: %v %v", resp, err)
	}
}
