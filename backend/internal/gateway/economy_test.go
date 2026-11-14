package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"carthago/backend/internal/bans"
	"carthago/backend/internal/economy"
	"carthago/backend/internal/store"
)

// The economy API takes the tenant's server key and nothing else, and one studio's game
// server neither reads nor writes another studio's ledger.
func TestEconomyAPIKeysAndTenants(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.NewMemory()
	keys, err := LoadOrCreateKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	banning := bans.New(st, log)
	ledger := economy.New(st, banning, log)
	banning.SetHook(ledger)
	gw := New(Config{Tenants: map[string]string{"demo": "demo-key", "rival": "rival-key"}, Economy: ledger}, keys, st, log)
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()

	call := func(method, path, key, body string) (int, map[string]any) {
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
		return resp.StatusCode, out
	}
	event := `{"events":[{"event_id":"e1","player":"max","amount":900,"source":"job","at_ms":0}]}`
	for _, key := range []string{"", "nope", "demo-dashboard-key"} {
		for _, c := range [][2]string{{"POST", "/v1/economy/events"}, {"POST", "/v1/economy/balances"}, {"GET", "/v1/economy/dirty"}, {"GET", "/v1/economy/status?player=max"}} {
			if code, _ := call(c[0], c[1], key, event); code != http.StatusUnauthorized {
				t.Errorf("%s %s with key %q: %d, want 401", c[0], c[1], key, code)
			}
		}
	}
	if code, out := call("POST", "/v1/economy/events", "demo-key", event); code != http.StatusOK || out["results"].([]any)[0].(map[string]any)["status"] != "recorded" {
		t.Fatalf("event: %d %v", code, out)
	}
	if code, out := call("POST", "/v1/economy/events", "demo-key", event); code != http.StatusOK || out["results"].([]any)[0].(map[string]any)["status"] != "duplicate" {
		t.Fatalf("the same event again: %d %v", code, out)
	}
	// The same event id is another event for another studio, and its ledger is its own.
	if code, out := call("POST", "/v1/economy/events", "rival-key", event); code != http.StatusOK || out["results"].([]any)[0].(map[string]any)["status"] != "recorded" {
		t.Fatalf("rival event: %d %v", code, out)
	}
	if code, out := call("POST", "/v1/economy/balances", "demo-key", `{"balances":[{"player":"max","balance":900}]}`); code != http.StatusOK || out["results"].([]any)[0].(map[string]any)["status"] != "opened" {
		t.Fatalf("first balance: %d %v", code, out)
	}
	if code, out := call("POST", "/v1/economy/balances", "demo-key", `{"balances":[{"player":"max","balance":70900}]}`); code != http.StatusOK || out["results"].([]any)[0].(map[string]any)["banned"] == nil {
		t.Fatalf("injected money: %d %v", code, out)
	}
	if _, out := call("GET", "/v1/economy/status?player=max", "demo-key", ""); out["banned"] == "" || len(out["flags"].([]any)) != 1 {
		t.Fatalf("status: %v", out)
	}
	if _, out := call("GET", "/v1/economy/dirty", "demo-key", ""); len(out["players"].([]any)) != 1 {
		t.Fatalf("dirty: %v", out)
	}
	if _, out := call("GET", "/v1/economy/status?player=max", "rival-key", ""); out["banned"] != "" || len(out["flags"].([]any)) != 0 {
		t.Fatalf("the rival studio sees the ban or the flag: %v", out)
	}
	if _, out := call("GET", "/v1/economy/dirty", "rival-key", ""); len(out["players"].([]any)) != 0 {
		t.Fatalf("the rival studio sees the dirty money: %v", out)
	}
	for _, bad := range []string{`{"events":[]}`, `not json`, `{"events":[{"event_id":"x","player":"max","amount":1.5,"source":"job"}]}`, `{"events":[{"event_id":"x","surprise":1}]}`} {
		if code, _ := call("POST", "/v1/economy/events", "demo-key", bad); code != http.StatusBadRequest {
			t.Errorf("body %s: %d, want 400", bad, code)
		}
	}
}
