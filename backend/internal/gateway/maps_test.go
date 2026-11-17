package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"carthago/backend/internal/outline"
	"carthago/backend/internal/store"
)

func TestMapOutlineEndpoint(t *testing.T) {
	keys, err := LoadOrCreateKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	gw := New(Config{Tenants: map[string]string{"demo": serverKey, "rival": "rival-server-key"}, Maps: st}, keys, st, log)
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	call := func(method, key, query, ctype string, body []byte) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+"/v1/maps"+query, bytes.NewReader(body))
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
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
	ctx := context.Background()
	lines := []byte(`{"map":"de_test","lines":[[0,0,1000,0],[1000,0,1000,800]]}`)
	var pic bytes.Buffer
	if err := png.Encode(&pic, image.NewRGBA(image.Rect(0, 0, 16, 8))); err != nil {
		t.Fatal(err)
	}
	picQuery := "?map=" + url.QueryEscape("de picture") + "&rect=-100,-50,300,150"

	for _, key := range []string{"", "wrong-key"} {
		if code, _ := call("POST", key, "", "application/json", lines); code != http.StatusUnauthorized {
			t.Errorf("upload with key %q: %d, want 401", key, code)
		}
		if code, _ := call("GET", key, "", "", nil); code != http.StatusUnauthorized {
			t.Errorf("list with key %q: %d, want 401", key, code)
		}
		if code, _ := call("DELETE", key, "?map=de_test", "", nil); code != http.StatusUnauthorized {
			t.Errorf("remove with key %q: %d, want 401", key, code)
		}
	}
	if rows, _ := st.ListMapOutlines(ctx, "demo"); len(rows) != 0 {
		t.Fatalf("a call without the key stored %d outlines", len(rows))
	}

	code, out := call("POST", serverKey, "", "application/json", lines)
	if code != http.StatusCreated || out["map"] != "de_test" || out["kind"] != "lines" || out["segments"] != float64(2) {
		t.Fatalf("wall lines: %d %v", code, out)
	}
	code, out = call("POST", serverKey, picQuery, "image/png", pic.Bytes())
	if code != http.StatusCreated || out["map"] != "de picture" || out["kind"] != "image" || out["width"] != float64(16) || out["height"] != float64(8) {
		t.Fatalf("a picture: %d %v", code, out)
	}
	got, err := st.GetMapOutline(ctx, "demo", "de picture")
	if err != nil || got.Rect != [4]int32{-100, -50, 300, 150} || got.UpdatedBy != "game server" || len(got.PNG) == 0 {
		t.Fatalf("stored picture: %+v %v", got, err)
	}
	if _, err := png.Decode(bytes.NewReader(got.PNG)); err != nil {
		t.Fatalf("the stored picture is not a PNG: %v", err)
	}

	// Nothing but the two forms is taken.
	for name, c := range map[string]struct {
		query, ctype string
		body         []byte
		want         int
	}{
		"no content type":             {"", "", lines, http.StatusUnsupportedMediaType},
		"a JPEG content type":         {picQuery, "image/jpeg", pic.Bytes(), http.StatusUnsupportedMediaType},
		"an SVG content type":         {picQuery, "image/svg+xml", []byte("<svg/>"), http.StatusUnsupportedMediaType},
		"a form":                      {"", "multipart/form-data; boundary=x", lines, http.StatusUnsupportedMediaType},
		"not a PNG under image/png":   {picQuery, "image/png", []byte("<svg/>"), http.StatusBadRequest},
		"wall lines under image/png":  {picQuery, "image/png", lines, http.StatusBadRequest},
		"a picture without a rect":    {"?map=x", "image/png", pic.Bytes(), http.StatusBadRequest},
		"a picture without a map":     {"?rect=0,0,1,1", "image/png", pic.Bytes(), http.StatusBadRequest},
		"lines without a map":         {"", "application/json", []byte(`{"lines":[[0,0,1,1]]}`), http.StatusBadRequest},
		"lines with an extra field":   {"", "application/json", []byte(`{"map":"x","lines":[[0,0,1,1]],"png":"x"}`), http.StatusBadRequest},
		"lines over the size cap":     {"", "application/json", []byte(`{"map":"x","lines":[[0,0,1,1]` + strings.Repeat(" ", outline.MaxLinesBytes) + `]}`), http.StatusRequestEntityTooLarge},
		"a picture over the size cap": {picQuery, "image/png", append(append([]byte{}, pic.Bytes()...), make([]byte, outline.MaxPNGBytes)...), http.StatusRequestEntityTooLarge},
	} {
		if code, out := call("POST", serverKey, c.query, c.ctype, c.body); code != c.want || out["error"] == nil {
			t.Errorf("%s: %d %v, want %d", name, code, out, c.want)
		}
	}
	if rows, _ := st.ListMapOutlines(ctx, "demo"); len(rows) != 2 {
		t.Fatalf("after the refused uploads: %d outlines, want 2", len(rows))
	}

	// The key decides the studio.
	if code, out := call("GET", "rival-server-key", "", "", nil); code != 200 || len(out["maps"].([]any)) != 0 {
		t.Fatalf("the rival lists demo's outlines: %d %v", code, out)
	}
	if code, _ := call("DELETE", "rival-server-key", "?map=de_test", "", nil); code != http.StatusNotFound {
		t.Fatalf("the rival removes demo's outline: %d", code)
	}
	code, out = call("GET", serverKey, "", "", nil)
	if maps, _ := out["maps"].([]any); code != 200 || len(maps) != 2 || maps[1].(map[string]any)["map"] != "de_test" || maps[1].(map[string]any)["lines"] != nil {
		t.Fatalf("list: %d %v", code, out)
	}
	if code, _ := call("DELETE", serverKey, "?map=de_test", "", nil); code != http.StatusNoContent {
		t.Fatalf("remove: %d", code)
	}
	if _, err := st.GetMapOutline(ctx, "demo", "de_test"); err == nil {
		t.Fatal("the outline is still there")
	}
}
