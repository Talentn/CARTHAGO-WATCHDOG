package outline

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/replay"
	"carthago/backend/internal/store"
)

func TestLines(t *testing.T) {
	o, err := Lines("", []byte(`{"map":"de_test","lines":[[0,0,1000,0],[1000,0,1000,-500]]}`))
	if err != nil {
		t.Fatal(err)
	}
	if o.MapID != "de_test" || o.Kind != store.OutlineLines || o.Segments != 2 || o.Rect != [4]int32{0, -500, 1000, 0} || o.Lines != `[[0,0,1000,0],[1000,0,1000,-500]]` {
		t.Fatalf("outline: %+v", o)
	}
	if lines, err := StoredLines(o); err != nil || len(lines) != 2 || lines[1] != [4]int32{1000, 0, 1000, -500} {
		t.Fatalf("stored lines: %v %v", lines, err)
	}
	// The caller's map name wins over the document's.
	if o, err := Lines("other", []byte(`{"map":"de_test","lines":[[0,0,1,0]]}`)); err != nil || o.MapID != "other" {
		t.Fatalf("named by the caller: %+v %v", o, err)
	}
	many := `{"lines":[` + strings.TrimSuffix(strings.Repeat("[0,0,1,1],", MaxLines+1), ",") + `]}`
	for name, body := range map[string]string{
		"not JSON":            `lines`,
		"no lines":            `{"lines":[]}`,
		"three numbers":       `{"lines":[[0,0,1]]}`,
		"five numbers":        `{"lines":[[0,0,1,1,1]]}`,
		"a fraction":          `{"lines":[[0,0,1.5,1]]}`,
		"a string":            `{"lines":[["0",0,1,1]]}`,
		"out of range":        `{"lines":[[0,0,10000001,1]]}`,
		"far out of range":    `{"lines":[[0,0,99999999999999,1]]}`,
		"no length":           `{"lines":[[5,5,5,5]]}`,
		"an unknown field":    `{"lines":[[0,0,1,1]],"script":"x"}`,
		"two documents":       `{"lines":[[0,0,1,1]]}{"lines":[[0,0,1,1]]}`,
		"too many lines":      many,
		"larger than the cap": `{"lines":[[0,0,1,1]` + strings.Repeat(" ", MaxLinesBytes) + `]}`,
	} {
		if o, err := Lines("m", []byte(body)); err == nil {
			t.Errorf("%s: accepted as %+v", name, o)
		} else if _, ok := IsError(err); !ok {
			t.Errorf("%s: %v is not an upload error", name, err)
		}
	}
	for _, name := range []string{"", " padded", "line\nbreak", strings.Repeat("m", 129), "bad\xffutf8"} {
		if _, err := Lines(name, []byte(`{"lines":[[0,0,1,1]]}`)); err == nil && name != "" {
			t.Errorf("map name %q accepted", name)
		}
	}
	if _, err := Lines("", []byte(`{"lines":[[0,0,1,1]]}`)); err == nil {
		t.Error("an outline without a map name accepted")
	}
}

func testPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := 0; x < w; x++ {
		img.Set(x, 0, color.RGBA{200, 10, 10, 255})
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// withTextChunk adds a tEXt chunk after the header chunk: bytes a PNG may carry that are
// not pixels.
func withTextChunk(raw []byte, text string) []byte {
	const ihdrEnd = 8 + 4 + 4 + 13 + 4
	chunk := []byte{0, 0, 0, byte(len(text)), 't', 'E', 'X', 't'}
	chunk = append(chunk, text...)
	chunk = binary.BigEndian.AppendUint32(chunk, crc32.ChecksumIEEE(chunk[4:]))
	out := append([]byte{}, raw[:ihdrEnd]...)
	out = append(out, chunk...)
	return append(out, raw[ihdrEnd:]...)
}

func TestPicture(t *testing.T) {
	rect := [4]int32{-1000, -500, 3000, 1500}
	raw := withTextChunk(testPNG(t, 64, 32), "Comment\x00<script>alert(1)</script>")
	o, err := Picture("de_test", raw, rect)
	if err != nil {
		t.Fatal(err)
	}
	if o.Kind != store.OutlineImage || o.Width != 64 || o.Height != 32 || o.Rect != rect || o.Segments != 0 {
		t.Fatalf("outline: %+v", o)
	}
	// What is kept is the gateway's own encoding of the pixels: a PNG, and none of the
	// rest of the upload.
	if bytes.Equal(o.PNG, raw) || bytes.Contains(o.PNG, []byte("script")) || bytes.Contains(o.PNG, []byte("tEXt")) {
		t.Fatal("the stored picture carries bytes of the upload that are not pixels")
	}
	img, err := png.Decode(bytes.NewReader(o.PNG))
	if err != nil || img.Bounds().Dx() != 64 || img.Bounds().Dy() != 32 {
		t.Fatalf("the stored picture: %v", err)
	}
	if r, g, b, a := img.At(3, 0).RGBA(); r>>8 != 200 || g>>8 != 10 || b>>8 != 10 || a>>8 != 255 {
		t.Fatalf("pixel: %d %d %d %d", r>>8, g>>8, b>>8, a>>8)
	}

	var jpg bytes.Buffer
	if err := jpeg.Encode(&jpg, image.NewRGBA(image.Rect(0, 0, 8, 8)), nil); err != nil {
		t.Fatal(err)
	}
	good := testPNG(t, 8, 8)
	for name, c := range map[string]struct {
		body []byte
		rect [4]int32
	}{
		"a JPEG":              {jpg.Bytes(), rect},
		"an SVG":              {[]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), rect},
		"HTML":                {[]byte(`<html><script>alert(1)</script></html>`), rect},
		"a cut-off PNG":       {good[:len(good)-20], rect},
		"only the PNG magic":  {good[:8], rect},
		"nothing":             {nil, rect},
		"too many pixels":     {testPNG(t, MaxSide+1, 1), rect},
		"an empty rectangle":  {good, [4]int32{0, 0, 0, 100}},
		"a flipped rectangle": {good, [4]int32{100, 0, 0, 100}},
		"a rectangle too far": {good, [4]int32{0, 0, MaxCoord + 1, 100}},
		"larger than the cap": {append(append([]byte{}, good...), make([]byte, MaxPNGBytes)...), rect},
	} {
		if o, err := Picture("m", c.body, c.rect); err == nil {
			t.Errorf("%s: accepted (%d x %d)", name, o.Width, o.Height)
		} else if _, ok := IsError(err); !ok {
			t.Errorf("%s: %v is not an upload error", name, err)
		}
	}
	if _, err := Picture("", good, rect); err == nil {
		t.Error("a picture without a map name accepted")
	}
}

func TestParseRect(t *testing.T) {
	if r, err := ParseRect("-100, 0,200,300"); err != nil || r != [4]int32{-100, 0, 200, 300} {
		t.Fatalf("%v %v", r, err)
	}
	for _, s := range []string{"", "1,2,3", "1,2,3,4,5", "a,b,c,d", "1.5,0,2,3", "0,0,99999999999,1"} {
		if _, err := ParseRect(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestPutCapsOutlinesPerStudio(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	now := time.UnixMilli(1_800_000_000_000)
	for i := 0; i < MaxMaps; i++ {
		o, _ := Lines(fmt.Sprintf("map-%d", i), []byte(`{"lines":[[0,0,1,1]]}`))
		if err := Put(ctx, st, "t1", o, "ada", now); err != nil {
			t.Fatal(err)
		}
	}
	extra, _ := Lines("one-more", []byte(`{"lines":[[0,0,1,1]]}`))
	if err := Put(ctx, st, "t1", extra, "ada", now); err == nil {
		t.Fatal("an outline past the cap was stored")
	}
	// Replacing a map's outline and another studio's first outline are not past the cap.
	again, _ := Lines("map-3", []byte(`{"lines":[[0,0,2,2]]}`))
	if err := Put(ctx, st, "t1", again, "ada", now); err != nil {
		t.Fatalf("replace at the cap: %v", err)
	}
	if err := Put(ctx, st, "t2", extra, "bob", now); err != nil {
		t.Fatalf("another studio: %v", err)
	}
}

func TestCrossings(t *testing.T) {
	// Slot 1 stands at (100,100), slot 2 behind a wall at (900,100), slot 3 in the open at
	// (100,900). Slot 4 leaves after the first second.
	still := func(slot uint32, x, y int32, steps ...int32) replay.Player {
		p := replay.Player{Slot: slot}
		for _, s := range steps {
			p.T, p.X, p.Y, p.Yaw = append(p.T, s), append(p.X, x), append(p.Y, y), append(p.Yaw, 0)
		}
		return p
	}
	d := &replay.Data{StepMs: 250, Players: []replay.Player{
		still(1, 100, 100, 0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40), still(2, 900, 100, 0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40),
		still(3, 100, 900, 0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40), still(4, 900, 100, 0, 4),
	}, Shots: []replay.Shot{
		{500, 1, 2, 1, 0},   // across the wall, a hit
		{600, 1, 3, 0, 0},   // in the open
		{700, 1, -1, 0, 0},  // at nobody
		{800, 2, 1, 1, 1},   // across the wall the other way, a kill
		{900, 3, 2, 0, 0},   // diagonal, across the wall
		{9000, 1, 4, 1, 0},  // at a player who is no longer there
		{1000, 1, 1, 0, 0},  // at oneself
		{1100, 1, 77, 0, 0}, // at a slot the recording does not have
	}}
	wall := [][4]int32{{500, -100, 500, 700}}
	got := Crossings(d, wall, 100)
	if len(got) != 3 || got[0].Shot != 0 || got[1].Shot != 3 || got[2].Shot != 4 {
		t.Fatalf("crossings: %+v", got)
	}
	if c := got[1]; c.Ms != 800 || c.Slot != 2 || c.Target != 1 || !c.Hit || !c.Kill {
		t.Fatalf("the kill: %+v", c)
	}
	if got := Crossings(d, wall, 2); len(got) != 2 {
		t.Fatalf("capped at 2: %d", len(got))
	}
	if got := Crossings(d, nil, 100); len(got) != 0 {
		t.Fatalf("no lines: %+v", got)
	}
	// A wall the shooter leans on, a wall beside the line and a wall along it do not count.
	for name, w := range map[string][4]int32{
		"at the shooter's feet": {120, -100, 120, 700}, "beside the line": {500, 200, 500, 700}, "along the line": {300, 100, 700, 100},
		// The target shows round the end of the wall: its middle is behind, its side is not.
		"a corner": {500, 60, 500, 700}, "a pillar": {500, 40, 500, 160},
	} {
		if got := Crossings(d, [][4]int32{w}, 100); len(got) != 0 && got[0].Shot == 0 {
			t.Errorf("%s: counted as a crossing", name)
		}
	}
}
