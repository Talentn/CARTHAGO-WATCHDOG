// Package outline checks the outline of a map a studio registers for the match replay:
// either the map's walls as line segments in world coordinates, or a picture of the map
// with the world rectangle it covers.
//
// An outline is a drawing aid. The replay draws it under the players, and with wall lines
// it can point a reviewer at shots whose line crosses a wall. Neither is evidence: no
// rule reads an outline, and a shot across a wall line is not a finding.
//
// Everything a studio sends is checked strictly: a size and a count cap, coordinates
// within range, and a picture is decoded and written out again by the gateway, so what
// is stored and later served is the gateway's own PNG and nothing that came with the
// upload.
package outline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"carthago/backend/internal/replay"
	"carthago/backend/internal/store"
)

const (
	// MaxLines is the most wall segments of one outline.
	MaxLines = 5000
	// MaxCoord bounds a coordinate, in centimetres: 100 km either way.
	MaxCoord = 10_000_000
	// MaxLinesBytes and MaxPNGBytes bound an upload.
	MaxLinesBytes = 512 << 10
	MaxPNGBytes   = 2 << 20
	// MaxSide and MaxPixels bound a picture.
	MaxSide   = 4096
	MaxPixels = 4 << 20
	// maxStoredPNG bounds the picture the gateway writes out again.
	maxStoredPNG = 8 << 20
	// MaxMaps is the most outlines one studio keeps.
	MaxMaps = 200
)

// Error says what is wrong with an upload, in words for the person who sent it.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func bad(format string, a ...any) error { return &Error{fmt.Sprintf(format, a...)} }

// ValidMapID reports whether s can name a map: what a game server puts in a match's
// telemetry, 1 to 128 bytes, no control characters.
func ValidMapID(s string) bool {
	return s != "" && len(s) <= replay.MaxMapID && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}

// Lines reads wall lines: {"map":"name","lines":[[x0,y0,x1,y1], ...]}, centimetres in the
// coordinates of the match's telemetry. A map name given by the caller wins over the one
// in the document. Nothing else is accepted in the document.
func Lines(mapID string, body []byte) (*store.MapOutline, error) {
	if len(body) > MaxLinesBytes {
		return nil, bad("the wall lines are larger than %d KB", MaxLinesBytes>>10)
	}
	var doc struct {
		Map   string    `json:"map"`
		Lines [][]int64 `json:"lines"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, bad("the wall lines are not the JSON this takes, {\"lines\":[[x0,y0,x1,y1],...]}: %v", err)
	}
	if dec.More() {
		return nil, bad("the wall lines are one JSON document")
	}
	if mapID == "" {
		mapID = doc.Map
	}
	if !ValidMapID(mapID) {
		return nil, bad("the map name must be 1 to %d bytes without control characters", replay.MaxMapID)
	}
	if len(doc.Lines) == 0 || len(doc.Lines) > MaxLines {
		return nil, bad("an outline has 1 to %d wall lines, this one has %d", MaxLines, len(doc.Lines))
	}
	lines := make([][4]int32, len(doc.Lines))
	for i, l := range doc.Lines {
		if len(l) != 4 {
			return nil, bad("wall line %d does not have four numbers (x0, y0, x1, y1)", i+1)
		}
		for j, v := range l {
			if v < -MaxCoord || v > MaxCoord {
				return nil, bad("wall line %d has a coordinate outside ±%d cm", i+1, MaxCoord)
			}
			lines[i][j] = int32(v)
		}
		if lines[i][0] == lines[i][2] && lines[i][1] == lines[i][3] {
			return nil, bad("wall line %d has no length", i+1)
		}
	}
	stored, err := json.Marshal(lines)
	if err != nil {
		return nil, err
	}
	o := &store.MapOutline{MapID: mapID, Kind: store.OutlineLines, Lines: string(stored), Segments: len(lines)}
	o.Rect = [4]int32{lines[0][0], lines[0][1], lines[0][0], lines[0][1]}
	for _, l := range lines {
		o.Rect[0], o.Rect[1] = min(o.Rect[0], l[0], l[2]), min(o.Rect[1], l[1], l[3])
		o.Rect[2], o.Rect[3] = max(o.Rect[2], l[0], l[2]), max(o.Rect[3], l[1], l[3])
	}
	return o, nil
}

// StoredLines reads the wall lines of a stored outline.
func StoredLines(o *store.MapOutline) ([][4]int32, error) {
	if o.Kind != store.OutlineLines {
		return nil, nil
	}
	var lines [][4]int32
	err := json.Unmarshal([]byte(o.Lines), &lines)
	return lines, err
}

var pngMagic = []byte("\x89PNG\r\n\x1a\n")

// Picture reads a PNG of the map seen from above and the world rectangle it covers
// (min x, min y, max x, max y in centimetres; the picture's top edge is max y). The PNG
// is decoded and written out again: the stored picture is the gateway's own encoding of
// the pixels, without whatever else the file carried.
func Picture(mapID string, body []byte, rect [4]int32) (*store.MapOutline, error) {
	if !ValidMapID(mapID) {
		return nil, bad("the map name must be 1 to %d bytes without control characters", replay.MaxMapID)
	}
	if len(body) > MaxPNGBytes {
		return nil, bad("the picture is larger than %d MB", MaxPNGBytes>>20)
	}
	if !bytes.HasPrefix(body, pngMagic) {
		return nil, bad("the picture is not a PNG; no other format is accepted")
	}
	for _, v := range rect {
		if v < -MaxCoord || v > MaxCoord {
			return nil, bad("the world rectangle has a coordinate outside ±%d cm", MaxCoord)
		}
	}
	if rect[2] <= rect[0] || rect[3] <= rect[1] {
		return nil, bad("the world rectangle needs max x above min x and max y above min y")
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(body))
	if err != nil {
		return nil, bad("the PNG cannot be read: %v", err)
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > MaxSide || cfg.Height > MaxSide || cfg.Width*cfg.Height > MaxPixels {
		return nil, bad("the picture is %d x %d; at most %d on a side and %d megapixels are accepted", cfg.Width, cfg.Height, MaxSide, MaxPixels>>20)
	}
	img, err := png.Decode(bytes.NewReader(body))
	if err != nil {
		return nil, bad("the PNG cannot be read: %v", err)
	}
	b := img.Bounds()
	if b.Dx() != cfg.Width || b.Dy() != cfg.Height {
		return nil, bad("the PNG's header and its pixels disagree")
	}
	plain := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(plain, plain.Bounds(), img, b.Min, draw.Src)
	var out bytes.Buffer
	if err := png.Encode(&out, plain); err != nil {
		return nil, err
	}
	if out.Len() > maxStoredPNG {
		return nil, bad("the picture is too large once written out again; use fewer pixels")
	}
	return &store.MapOutline{MapID: mapID, Kind: store.OutlineImage, PNG: out.Bytes(), Rect: rect, Width: b.Dx(), Height: b.Dy()}, nil
}

// Put stores an outline for a studio, replacing the map's previous one. A studio keeps at
// most MaxMaps outlines.
func Put(ctx context.Context, st store.MapOutlineStore, tenant string, o *store.MapOutline, by string, now time.Time) error {
	have, err := st.ListMapOutlines(ctx, tenant)
	if err != nil {
		return err
	}
	if len(have) >= MaxMaps {
		known := false
		for _, h := range have {
			known = known || h.MapID == o.MapID
		}
		if !known {
			return bad("a studio keeps at most %d map outlines; remove one first", MaxMaps)
		}
	}
	o.TenantID, o.UpdatedBy, o.UpdatedAt = tenant, by, now
	return st.PutMapOutline(ctx, o)
}

// ParseRect reads a world rectangle written "min_x,min_y,max_x,max_y" in centimetres.
func ParseRect(s string) ([4]int32, error) {
	var rect [4]int32
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return rect, bad("the world rectangle is four whole numbers of centimetres: min_x,min_y,max_x,max_y")
	}
	for i, p := range parts {
		v, err := strconv.ParseInt(strings.TrimSpace(p), 10, 32)
		if err != nil {
			return rect, bad("the world rectangle is four whole numbers of centimetres: min_x,min_y,max_x,max_y")
		}
		rect[i] = int32(v)
	}
	return rect, nil
}

// IsError reports whether err is about the upload, and gives its words.
func IsError(err error) (string, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Msg, true
	}
	return "", false
}

// Crossing is a shot whose line from the shooter to the player shot at crosses a wall
// line of the outline.
type Crossing struct {
	Shot   int // index into the recording's shots
	Ms     int64
	Slot   uint32
	Target uint32
	Hit    bool
	Kill   bool
}

// endTrimCm is left out at both ends of a shot's line: a player stands about that close
// to the wall they lean on, and positions are kept four times a second.
const endTrimCm = 40

// Crossings finds the shots at another player whose line crosses a wall line, up to max.
// It is an aid for a reviewer looking at the replay and nothing more: the outline is flat,
// so a shot over a low wall or through a window crosses a line too, and the positions are
// the recording's, a quarter of a second apart. A shot at nobody has no line to test.
func Crossings(d *replay.Data, lines [][4]int32, max int) []Crossing {
	var out []Crossing
	for i, s := range d.Shots {
		if len(out) >= max {
			break
		}
		if s[2] < 0 || s[1] < 0 || s[1] == s[2] {
			continue
		}
		ax, ay, ok := d.Pose(uint32(s[1]), int64(s[0]))
		if !ok {
			continue
		}
		bx, by, ok := d.Pose(uint32(s[2]), int64(s[0]))
		if !ok {
			continue
		}
		if crosses(ax, ay, bx, by, lines) {
			out = append(out, Crossing{Shot: i, Ms: int64(s[0]), Slot: uint32(s[1]), Target: uint32(s[2]), Hit: s[3] != 0, Kill: s[4] != 0})
		}
	}
	return out
}

// sideCm is how far to either side a shot's line is also tried: a shot counts only when
// the line and both lines beside it cross the same wall line. It stands for the width of
// a player, the part of a target that shows round a corner while its middle is behind it,
// and the quarter second between two kept positions; without it every shot at a player
// peeking round a corner would count. The price: a shot through a wall within this
// distance of the wall's end, or through a wall shorter than twice this, is not listed.
const sideCm = 80.0

func crosses(ax, ay, bx, by float64, lines [][4]int32) bool {
	dx, dy := bx-ax, by-ay
	length := math.Sqrt(dx*dx + dy*dy)
	if length <= 2*endTrimCm {
		return false
	}
	// Positions along the shot between which a crossing counts, and the step across it.
	trim := endTrimCm / length
	nx, ny := -dy/length*sideCm, dx/length*sideCm
	for _, l := range lines {
		cx, cy, ex, ey := float64(l[0]), float64(l[1]), float64(l[2])-float64(l[0]), float64(l[3])-float64(l[1])
		den := dx*ey - dy*ex
		if den == 0 {
			continue // parallel
		}
		all := true
		for _, side := range [3]float64{0, 1, -1} {
			px, py := ax+nx*side, ay+ny*side
			t := ((cx-px)*ey - (cy-py)*ex) / den
			u := ((cx-px)*dy - (cy-py)*dx) / den
			if t <= trim || t >= 1-trim || u < 0 || u > 1 {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}
