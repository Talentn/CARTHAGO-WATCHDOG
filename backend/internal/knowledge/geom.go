// Package knowledge is the information-leak detector (detection strategy A3, version 1). For
// every analysed tick it works out what each player could legitimately know: who their team
// could see through the uploaded map occluders, which sounds they could hear, what the game
// shared with the team, and where enemies were last seen or heard. It then measures how much
// better the player's aim, shots and movement line up with the true hidden state than with
// the same state at other moments, which is what a wallhack, ESP, radar or DMA reader adds.
//
// Like analyzer, it is pure: no I/O and no clock. Memory per match is bounded by the
// analysis window, not by the match length.
package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
)

// Vec3 is a map position in metres, Z up.
type Vec3 struct{ X, Y, Z float64 }

func (a Vec3) Sub(b Vec3) Vec3      { return Vec3{a.X - b.X, a.Y - b.Y, a.Z - b.Z} }
func (a Vec3) Add(b Vec3) Vec3      { return Vec3{a.X + b.X, a.Y + b.Y, a.Z + b.Z} }
func (a Vec3) Scale(k float64) Vec3 { return Vec3{a.X * k, a.Y * k, a.Z * k} }
func (a Vec3) Dot(b Vec3) float64   { return a.X*b.X + a.Y*b.Y + a.Z*b.Z }
func (a Vec3) Len() float64         { return math.Sqrt(a.Dot(a)) }
func (a Vec3) Dist(b Vec3) float64  { return a.Sub(b).Len() }

// Vec2 is a point in the XY plane, metres.
type Vec2 struct{ X, Y float64 }

// Map limits keep an uploaded geometry cheap to store and to trace against.
const (
	MaxOccluders      = 4096
	MaxPolyVertices   = 32
	MaxZones          = 256
	MaxLootSpawns     = 1024
	MaxMapIDLen       = 64
	MaxZoneNameLen    = 48
	MaxGeometryBytes  = 512 << 10
	maxCoordinateCm   = 1 << 24 // 167 km: anything larger is a unit mistake
	minOccluderHeight = 0.05
)

type occluder struct {
	poly                   []Vec2 // convex, counter-clockwise
	zMin, zMax             float64
	minX, minY, maxX, maxY float64
}

type zone struct {
	name string
	poly []Vec2
}

// LootSpawn is a place loot can appear.
type LootSpawn struct {
	ID  uint32
	Pos Vec3
}

// Map is compiled MapGeometry, ready for line-of-sight queries.
type Map struct {
	ID      string
	Version uint32
	Mode    pb.GameMode
	Hash    string // SHA-256 of the deterministic encoding of the uploaded geometry
	Loot    []LootSpawn
	Min     Vec2 // bounds of the occluders and loot spawns
	Max     Vec2
	occ     []occluder
	zones   []zone
}

func cm(v int32) float64 { return float64(v) / 100 }

// GeometryHash is the identity of an uploaded geometry: two uploads under one (map_id,
// version) must hash the same.
func GeometryHash(g *pb.MapGeometry) (string, []byte, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(g)
	if err != nil {
		return "", nil, err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), b, nil
}

// Compile validates an uploaded geometry and builds the query structure.
func Compile(g *pb.MapGeometry) (*Map, error) {
	if g == nil {
		return nil, errors.New("no map geometry")
	}
	if g.MapId == "" || len(g.MapId) > MaxMapIDLen {
		return nil, fmt.Errorf("map_id must be 1-%d bytes", MaxMapIDLen)
	}
	if g.Version == 0 {
		return nil, errors.New("map version must be set; a version is immutable once uploaded")
	}
	if len(g.Occluders) > MaxOccluders || len(g.Zones) > MaxZones || len(g.LootSpawns) > MaxLootSpawns {
		return nil, fmt.Errorf("map geometry over limits (%d occluders, %d zones, %d loot spawns)", MaxOccluders, MaxZones, MaxLootSpawns)
	}
	hash, raw, err := GeometryHash(g)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxGeometryBytes {
		return nil, fmt.Errorf("map geometry is %d bytes (limit %d)", len(raw), MaxGeometryBytes)
	}
	m := &Map{ID: g.MapId, Version: g.Version, Mode: g.Mode, Hash: hash,
		Min: Vec2{math.Inf(1), math.Inf(1)}, Max: Vec2{math.Inf(-1), math.Inf(-1)}}
	grow := func(p Vec2) {
		m.Min.X, m.Min.Y = math.Min(m.Min.X, p.X), math.Min(m.Min.Y, p.Y)
		m.Max.X, m.Max.Y = math.Max(m.Max.X, p.X), math.Max(m.Max.Y, p.Y)
	}
	for i, o := range g.Occluders {
		poly, err := polygon(o.XyCm)
		if err != nil {
			return nil, fmt.Errorf("occluder %d: %w", i, err)
		}
		if !convex(poly) {
			return nil, fmt.Errorf("occluder %d: polygon is not convex", i)
		}
		if signedArea(poly) < 0 {
			for a, b := 0, len(poly)-1; a < b; a, b = a+1, b-1 {
				poly[a], poly[b] = poly[b], poly[a]
			}
		}
		oc := occluder{poly: poly, zMin: cm(o.ZMinCm), zMax: cm(o.ZMaxCm), minX: math.Inf(1), minY: math.Inf(1), maxX: math.Inf(-1), maxY: math.Inf(-1)}
		if oc.zMax-oc.zMin < minOccluderHeight {
			return nil, fmt.Errorf("occluder %d: z range is empty", i)
		}
		for _, p := range poly {
			oc.minX, oc.minY = math.Min(oc.minX, p.X), math.Min(oc.minY, p.Y)
			oc.maxX, oc.maxY = math.Max(oc.maxX, p.X), math.Max(oc.maxY, p.Y)
			grow(p)
		}
		m.occ = append(m.occ, oc)
	}
	for i, z := range g.Zones {
		if z.Name == "" || len(z.Name) > MaxZoneNameLen {
			return nil, fmt.Errorf("zone %d: name must be 1-%d bytes", i, MaxZoneNameLen)
		}
		poly, err := polygon(z.XyCm)
		if err != nil {
			return nil, fmt.Errorf("zone %d: %w", i, err)
		}
		m.zones = append(m.zones, zone{name: z.Name, poly: poly})
	}
	for _, l := range g.LootSpawns {
		p := Vec3{cm(l.XCm), cm(l.YCm), cm(l.ZCm)}
		m.Loot = append(m.Loot, LootSpawn{ID: l.SpawnId, Pos: p})
		grow(Vec2{p.X, p.Y})
	}
	if len(m.occ) == 0 && len(m.Loot) == 0 {
		m.Min, m.Max = Vec2{}, Vec2{1, 1}
	}
	return m, nil
}

func polygon(xy []int32) ([]Vec2, error) {
	if len(xy)%2 != 0 || len(xy) < 6 || len(xy) > 2*MaxPolyVertices {
		return nil, fmt.Errorf("polygon needs 3-%d x,y pairs", MaxPolyVertices)
	}
	out := make([]Vec2, 0, len(xy)/2)
	for i := 0; i < len(xy); i += 2 {
		if abs32(xy[i]) > maxCoordinateCm || abs32(xy[i+1]) > maxCoordinateCm {
			return nil, errors.New("coordinate out of range")
		}
		out = append(out, Vec2{cm(xy[i]), cm(xy[i+1])})
	}
	if math.Abs(signedArea(out)) < 1e-6 {
		return nil, errors.New("degenerate polygon")
	}
	return out, nil
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}

func signedArea(p []Vec2) float64 {
	a := 0.0
	for i := range p {
		j := (i + 1) % len(p)
		a += p[i].X*p[j].Y - p[j].X*p[i].Y
	}
	return a / 2
}

func cross(o, a, b Vec2) float64 { return (a.X-o.X)*(b.Y-o.Y) - (a.Y-o.Y)*(b.X-o.X) }

func convex(p []Vec2) bool {
	sign := 0.0
	for i := range p {
		c := cross(p[i], p[(i+1)%len(p)], p[(i+2)%len(p)])
		if math.Abs(c) < 1e-9 {
			continue
		}
		if sign == 0 {
			sign = c
		} else if (c > 0) != (sign > 0) {
			return false
		}
	}
	return sign != 0
}

// LineOfSight reports whether the segment a-b passes through no occluder.
func (m *Map) LineOfSight(a, b Vec3) bool {
	minX, maxX := math.Min(a.X, b.X), math.Max(a.X, b.X)
	minY, maxY := math.Min(a.Y, b.Y), math.Max(a.Y, b.Y)
	for i := range m.occ {
		o := &m.occ[i]
		if o.maxX < minX || o.minX > maxX || o.maxY < minY || o.minY > maxY {
			continue
		}
		if o.blocks(a, b) {
			return false
		}
	}
	return true
}

// blocks clips the segment against the convex prism (Cyrus-Beck in XY, then the Z interval).
func (o *occluder) blocks(a, b Vec3) bool {
	t0, t1 := 0.0, 1.0
	dx, dy := b.X-a.X, b.Y-a.Y
	n := len(o.poly)
	for i := range n {
		p, q := o.poly[i], o.poly[(i+1)%n]
		// Outward normal of a counter-clockwise edge.
		nx, ny := q.Y-p.Y, -(q.X - p.X)
		num := nx*(p.X-a.X) + ny*(p.Y-a.Y)
		den := nx*dx + ny*dy
		if math.Abs(den) < 1e-12 {
			if num < 0 {
				return false
			}
			continue
		}
		t := num / den
		if den < 0 {
			t0 = math.Max(t0, t)
		} else {
			t1 = math.Min(t1, t)
		}
		if t0 > t1 {
			return false
		}
	}
	za, zb := a.Z+t0*(b.Z-a.Z), a.Z+t1*(b.Z-a.Z)
	return math.Max(za, zb) >= o.zMin && math.Min(za, zb) <= o.zMax
}

// ZoneName names the area a point is in, or "" outside every zone.
func (m *Map) ZoneName(p Vec3) string {
	for _, z := range m.zones {
		if pointInPolygon(z.poly, Vec2{p.X, p.Y}) {
			return z.name
		}
	}
	return ""
}

func pointInPolygon(poly []Vec2, p Vec2) bool {
	in := false
	for i, j := 0, len(poly)-1; i < len(poly); j, i = i, i+1 {
		a, b := poly[i], poly[j]
		if (a.Y > p.Y) != (b.Y > p.Y) && p.X < (b.X-a.X)*(p.Y-a.Y)/(b.Y-a.Y)+a.X {
			in = !in
		}
	}
	return in
}

// Occluders returns the footprints, for rendering evidence.
func (m *Map) Occluders() [][]Vec2 {
	out := make([][]Vec2, len(m.occ))
	for i := range m.occ {
		out[i] = m.occ[i].poly
	}
	return out
}

// TallOccluder reports whether occluder i reaches eye height, for rendering.
func (m *Map) TallOccluder(i int, eye float64) bool { return m.occ[i].zMax >= eye }
