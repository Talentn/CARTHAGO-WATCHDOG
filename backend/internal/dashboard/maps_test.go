package dashboard

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"image"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"carthago/backend/internal/outline"
	"carthago/backend/internal/store"
)

// upload posts a file form the way the browser holding c would.
func (f *fixture) upload(t *testing.T, c *http.Cookie, path, csrf string, file []byte, kv ...string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if csrf != "" {
		_ = mw.WriteField("csrf", csrf)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		_ = mw.WriteField(kv[i], kv[i+1])
	}
	if file != nil {
		fw, err := mw.CreateFormFile("file", "upload.bin")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(file)
	}
	mw.Close()
	r := httptest.NewRequest("POST", path, &body)
	r.RemoteAddr, r.Host = "127.0.0.1:5555", "127.0.0.1:8751"
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

// wallRecording is a match on the map "arena": slot 1 at (100,100) shoots slot 2 at
// (900,100) and slot 3 at (100,900).
func wallRecording(t *testing.T, mapID string) []byte {
	t.Helper()
	doc := map[string]any{"v": 1, "match": "m1", "map": mapID, "tick_rate": 64, "step_ms": 250, "duration_ms": 4000, "bounds": []int{100, 100, 900, 900},
		"players": []map[string]any{
			{"slot": 1, "name": "alice", "team": 1, "t": []int{0, 16}, "x": []int{100, 0}, "y": []int{100, 0}, "yaw": []int{0, 0}},
			{"slot": 2, "name": "bob", "team": 2, "t": []int{0, 16}, "x": []int{900, 0}, "y": []int{100, 0}, "yaw": []int{180, 0}},
			{"slot": 3, "name": "carol", "team": 2, "t": []int{0, 16}, "x": []int{100, 0}, "y": []int{900, 0}, "yaw": []int{270, 0}},
		},
		"shots":   [][]int{{1500, 1, 2, 1, 1}, {2500, 1, 3, 0, 0}},
		"batches": [][]int{},
	}
	raw, _ := json.Marshal(doc)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	zw.Close()
	return buf.Bytes()
}

func TestMapOutlines(t *testing.T) {
	f := newFixture(t)
	st := f.srv.st.(*store.Memory)
	ctx := context.Background()
	players := []store.ReplayPlayer{{Slot: 1, PlayerHash: "alice"}, {Slot: 2, PlayerHash: "bob"}, {Slot: 3, PlayerHash: "carol"}}
	for _, m := range []struct{ tenant, id, mapID string }{{"demo", "m1", "arena"}, {"demo", "m-pic", "arena pic"}, {"demo", "m-plain", ""}, {"demo", "m-unknown", "no outline"}, {"rival", "m1", "arena"}} {
		if err := st.PutMatchReplay(ctx, &store.MatchReplay{TenantID: m.tenant, MatchID: m.id, StartedAt: f.now, UpdatedAt: f.now, DurationMs: 4000, Data: wallRecording(t, m.mapID), Players: players}); err != nil {
			t.Fatal(err)
		}
	}
	// What the fixture starts with; the outline and its wall shots must add nothing.
	seeded, _ := st.ListEvidence(ctx, "demo", store.EvidenceFilter{Limit: 100})
	seededBans, _ := st.ListBans(ctx, "demo", 100)
	evBefore, bansBefore := len(seeded), len(seededBans)
	f.addUser(t, "demo", "ada", "admin", "correct horse battery")
	f.addUser(t, "demo", "rita", "reviewer", "correct horse battery")
	f.addUser(t, "demo", "olga", "read_only", "correct horse battery")
	f.addUser(t, "rival", "zoe", "admin", "correct horse battery")
	ada := f.signIn(t, "demo", "ada", "correct horse battery")
	rita := f.signIn(t, "demo", "rita", "correct horse battery")
	olga := f.signIn(t, "demo", "olga", "correct horse battery")
	zoe := f.signIn(t, "rival", "zoe", "correct horse battery")

	lines := []byte(`{"lines":[[500,0,500,600],[0,0,1000,0]]}`)
	var pic bytes.Buffer
	if err := png.Encode(&pic, image.NewRGBA(image.Rect(0, 0, 20, 10))); err != nil {
		t.Fatal(err)
	}

	// Signed out, without the page's token, and below the admin role: nothing is stored.
	if w := f.upload(t, nil, "/maps/lines", "", lines, "map", "arena"); w.Code != http.StatusSeeOther {
		t.Fatalf("signed out: %d", w.Code)
	}
	if w := f.upload(t, ada, "/maps/lines", "", lines, "map", "arena"); w.Code != http.StatusForbidden {
		t.Fatalf("without the token: %d", w.Code)
	}
	if w := f.upload(t, ada, "/maps/lines", csrfFor(rita.Value), lines, "map", "arena"); w.Code != http.StatusForbidden {
		t.Fatalf("with another session's token: %d", w.Code)
	}
	for name, c := range map[string]*http.Cookie{"reviewer": rita, "read-only": olga} {
		if w := f.upload(t, c, "/maps/lines", csrfFor(c.Value), lines, "map", "arena"); w.Code != http.StatusForbidden {
			t.Fatalf("%s uploads wall lines: %d", name, w.Code)
		}
		if w := f.upload(t, c, "/maps/picture", csrfFor(c.Value), pic.Bytes(), "map", "arena", "min_x", "0", "min_y", "0", "max_x", "1000", "max_y", "500"); w.Code != http.StatusForbidden {
			t.Fatalf("%s uploads a picture: %d", name, w.Code)
		}
		if w := f.post(c, "/maps/remove", "map", "arena"); w.Code != http.StatusForbidden {
			t.Fatalf("%s removes an outline: %d", name, w.Code)
		}
		if w := f.get(c, "/maps"); w.Code != 200 || strings.Contains(w.Body.String(), `action="/maps/lines"`) || !strings.Contains(w.Body.String(), "needs the admin role") {
			t.Fatalf("%s opens the page: %d", name, w.Code)
		}
	}
	if rows, _ := st.ListMapOutlines(ctx, "demo"); len(rows) != 0 {
		t.Fatalf("refused uploads stored %d outlines", len(rows))
	}

	// Without an outline the match page is as it was.
	plain := f.get(ada, "/matches/m1").Body.String()
	if strings.Contains(plain, "data-outline") || strings.Contains(plain, "wall-shots") || !strings.Contains(plain, "no map is drawn") || !strings.Contains(plain, "has no outline") {
		t.Fatal("a match without an outline shows one")
	}
	if w := f.get(ada, "/matches/m1/outline.json"); w.Code != http.StatusNotFound {
		t.Fatalf("outline.json without an outline: %d", w.Code)
	}

	// What an upload must be.
	for name, w := range map[string]*httptest.ResponseRecorder{
		"no file":             f.upload(t, ada, "/maps/lines", csrfFor(ada.Value), nil, "map", "arena"),
		"no map name":         f.upload(t, ada, "/maps/lines", csrfFor(ada.Value), lines),
		"lines that are HTML": f.upload(t, ada, "/maps/lines", csrfFor(ada.Value), []byte("<script>alert(1)</script>"), "map", "arena"),
		"an SVG as a picture": f.upload(t, ada, "/maps/picture", csrfFor(ada.Value), []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), "map", "arena", "min_x", "0", "min_y", "0", "max_x", "1000", "max_y", "500"),
		"a picture, no rect":  f.upload(t, ada, "/maps/picture", csrfFor(ada.Value), pic.Bytes(), "map", "arena"),
		"an empty rect":       f.upload(t, ada, "/maps/picture", csrfFor(ada.Value), pic.Bytes(), "map", "arena", "min_x", "0", "min_y", "0", "max_x", "0", "max_y", "500"),
	} {
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `role="alert"`) || strings.Contains(w.Body.String(), "<script>alert") {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	// A body past the cap is refused before anything is read into the form.
	if w := f.upload(t, ada, "/maps/lines", csrfFor(ada.Value), make([]byte, outline.MaxLinesBytes+64<<10), "map", "arena"); w.Code != http.StatusForbidden && w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("an upload past the cap: %d", w.Code)
	}
	if rows, _ := st.ListMapOutlines(ctx, "demo"); len(rows) != 0 {
		t.Fatalf("refused uploads stored %d outlines", len(rows))
	}

	if w := f.upload(t, ada, "/maps/lines", csrfFor(ada.Value), lines, "map", "arena"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/maps?ok=saved" {
		t.Fatalf("wall lines: %d %s", w.Code, w.Body.String())
	}
	if w := f.upload(t, ada, "/maps/picture", csrfFor(ada.Value), pic.Bytes(), "map", "arena pic", "min_x", "0", "min_y", "0", "max_x", "1000", "max_y", "1000"); w.Code != http.StatusSeeOther {
		t.Fatalf("a picture: %d %s", w.Code, w.Body.String())
	}
	page := f.get(ada, "/maps?ok=saved").Body.String()
	for _, want := range []string{"Outline saved", `<td class="mono">arena</td>`, `<span class="mono">2</span> wall lines`, `Picture <span class="mono">20 × 10</span>`, "0, 0 to 1000, 600", ">ada<", `action="/maps/remove"`, `enctype="multipart/form-data"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the maps page lacks %q", want)
		}
	}
	var saved int
	for _, e := range f.auditLog(t, "demo") {
		if e.Action == "map.outline" && e.Actor == "ada" && (e.Target == "arena" || e.Target == "arena pic") && !strings.HasPrefix(e.Detail, "refused") {
			saved++
		}
	}
	if saved != 2 {
		t.Errorf("audit log: %d saved outlines by ada, want 2", saved)
	}

	// The match page: the outline, and the one shot across the wall line as an aid.
	w := f.get(rita, "/matches/m1")
	body := w.Body.String()
	if w.Code != 200 || w.Header().Get("Content-Security-Policy") != matchCSP {
		t.Fatalf("match page: %d, policy %q", w.Code, w.Header().Get("Content-Security-Policy"))
	}
	for _, want := range []string{`data-outline="/matches/m1/outline.json"`, `id="wall-shots"`, "Shots across a wall line", "not a finding",
		`data-t="1500" data-slot="1" data-level="low" data-kind="wall"`, `href="/players/bob"`, ">Kill<", "Nothing was found in this match", `<b>0</b>`} {
		if !strings.Contains(body, want) {
			t.Errorf("the match page lacks %q", want)
		}
	}
	if strings.Contains(body, `data-t="2500"`) || strings.Contains(body, "no map is drawn") {
		t.Error("the match page lists the shot in the open, or says no map is drawn")
	}
	w = f.get(olga, "/matches/m1/outline.json")
	var got struct {
		Kind      string
		Rect      [4]int32
		Lines     [][4]int32
		Crossings []int
		Src       string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 || got.Kind != "lines" || len(got.Lines) != 2 || got.Lines[0] != [4]int32{500, 0, 500, 600} ||
		len(got.Crossings) != 1 || got.Crossings[0] != 0 || got.Src != "" || got.Rect != [4]int32{0, 0, 1000, 600} {
		t.Fatalf("outline.json: %d %s %v", w.Code, w.Body.String(), err)
	}
	if w := f.get(olga, "/matches/m1/map.png"); w.Code != http.StatusNotFound {
		t.Fatalf("map.png of a lines outline: %d", w.Code)
	}

	// A picture: served as the gateway's own PNG, and no wall shots.
	body = f.get(rita, "/matches/m-pic").Body.String()
	if !strings.Contains(body, `data-outline="/matches/m-pic/outline.json"`) || strings.Contains(body, "wall-shots") {
		t.Error("the match page of a picture outline")
	}
	w = f.get(rita, "/matches/m-pic/outline.json")
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Kind != "image" || got.Src != "/matches/m-pic/map.png" || got.Rect != [4]int32{0, 0, 1000, 1000} {
		t.Fatalf("outline.json of a picture: %s %v", w.Body.String(), err)
	}
	w = f.get(rita, "/matches/m-pic/map.png")
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("map.png: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if img, err := png.Decode(bytes.NewReader(w.Body.Bytes())); err != nil || img.Bounds().Dx() != 20 {
		t.Fatalf("map.png is not the picture: %v", err)
	}
	// Signed out, nothing of a match's outline is served.
	for _, p := range []string{"/maps", "/matches/m1/outline.json", "/matches/m-pic/map.png"} {
		if w := f.get(nil, p); w.Code != http.StatusSeeOther {
			t.Errorf("%s signed out: %d", p, w.Code)
		}
	}
	// A match that names no map, or a map without an outline, is as before.
	for _, id := range []string{"m-plain", "m-unknown"} {
		if b := f.get(rita, "/matches/"+id).Body.String(); strings.Contains(b, "data-outline") || !strings.Contains(b, "no map is drawn") {
			t.Errorf("match %s shows an outline", id)
		}
	}

	// The other studio has the same match and map names and none of this.
	if b := f.get(zoe, "/maps").Body.String(); strings.Contains(b, "arena") || !strings.Contains(b, "No outlines yet") {
		t.Error("the rival's maps page lists demo's outlines")
	}
	if b := f.get(zoe, "/matches/m1").Body.String(); strings.Contains(b, "data-outline") {
		t.Error("the rival's match is drawn with demo's outline")
	}
	if w := f.get(zoe, "/matches/m1/outline.json"); w.Code != http.StatusNotFound {
		t.Errorf("the rival reads demo's outline: %d", w.Code)
	}
	if w := f.post(zoe, "/maps/remove", "map", "arena"); w.Code != http.StatusNotFound {
		t.Errorf("the rival removes demo's outline: %d", w.Code)
	}

	// A shot across a wall line is an aid and nothing else: looking at it made no
	// finding, no ban, no shadow-pool entry, no Oracle score, no behaviour note, no report.
	if ev, _ := st.ListEvidence(ctx, "demo", store.EvidenceFilter{Limit: 100}); len(ev) != evBefore {
		t.Errorf("evidence appeared: %d findings, %d before", len(ev), evBefore)
	}
	if bans, _ := st.ListBans(ctx, "demo", 100); len(bans) != bansBefore {
		t.Errorf("bans appeared: %d, %d before", len(bans), bansBefore)
	}
	if pool, _ := st.ListShadowBans(ctx, "demo"); len(pool) != 0 {
		t.Errorf("shadow-pool entries appeared: %+v", pool)
	}
	if n, _ := st.CountPlayerReports(ctx, "demo", store.ReportFilter{}); n != 0 {
		t.Errorf("%d reports appeared", n)
	}
	if b := f.get(rita, "/players/alice").Body.String(); strings.Contains(b, "wall") {
		t.Error("alice's player page mentions the wall shot")
	}

	if w := f.post(ada, "/maps/remove", "map", "arena"); w.Code != http.StatusSeeOther {
		t.Fatalf("remove: %d", w.Code)
	}
	if b := f.get(ada, "/matches/m1").Body.String(); strings.Contains(b, "data-outline") {
		t.Error("the outline is still drawn after it was removed")
	}
	removed := false
	for _, e := range f.auditLog(t, "demo") {
		removed = removed || (e.Action == "map.outline_remove" && e.Target == "arena" && e.Actor == "ada")
	}
	if !removed {
		t.Error("removing the outline is not in the audit log")
	}
}
