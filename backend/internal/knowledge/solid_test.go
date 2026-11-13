package knowledge

import (
	"math/rand"
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge/bsptree"
)

// Units of the test brushes are GoldSrc units; 2.54 cm each.
const unitM = 0.0254

func testBrushes() []bsptree.Brush {
	return []bsptree.Brush{
		bsptree.Box(-1024, -1024, -64, 1024, 1024, 0),   // floor
		bsptree.Box(-1024, -1024, 512, 1024, 1024, 576), // ceiling
		bsptree.Box(-1088, -1024, 0, -1024, 1024, 512),
		bsptree.Box(1024, -1024, 0, 1088, 1024, 512),
		bsptree.Box(-1024, -1088, 0, 1024, -1024, 512),
		bsptree.Box(-1024, 1024, 0, 1024, 1088, 512),
		bsptree.Box(-64, -512, 0, 64, 512, 256), // a long wall
		bsptree.Box(300, 200, 0, 500, 260, 48),  // a crate, lower than eye height
		bsptree.Box(-600, -700, 0, -400, -500, 512),
		bsptree.Box(-450, -550, 0, -250, -350, 300), // overlaps the pillar before it
		bsptree.Ramp(400, -800, 0, 800, -600, 200),
	}
}

func treeMap(t testing.TB, brushes []bsptree.Brush) *Map {
	t.Helper()
	tr, err := bsptree.Build(brushes)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Compile(&pb.MapGeometry{MapId: "cs_test", Version: 1, Solid: tr.Proto(2.54)})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSolidTreeAgreesWithBrushes(t *testing.T) {
	brushes := testBrushes()
	m := treeMap(t, brushes)
	rng := rand.New(rand.NewSource(7))
	pt := func() [3]float64 {
		return [3]float64{rng.Float64()*2200 - 1100, rng.Float64()*2200 - 1100, rng.Float64()*640 - 64}
	}
	v := func(p [3]float64) Vec3 { return Vec3{p[0] * unitM, p[1] * unitM, p[2] * unitM} }
	points, solids, lines, blocked := 0, 0, 0, 0
	for range 200000 {
		p := pt()
		in, near := false, false
		for _, b := range brushes {
			in = in || b.Contains(p, -0.05)
			near = near || b.Contains(p, 0.05)
		}
		if in != near {
			continue // on a surface
		}
		points++
		if in {
			solids++
		}
		if m.Solid(v(p)) != in {
			t.Fatalf("point %v: tree says solid=%v, brushes say %v", p, !in, in)
		}
	}
	for range 200000 {
		a, b := pt(), pt()
		hit, graze := false, false
		for _, br := range brushes {
			hit = hit || br.Hits(a, b, 0.05)
			graze = graze || br.Hits(a, b, -0.05)
		}
		if hit != graze {
			continue
		}
		lines++
		if hit {
			blocked++
		}
		if m.LineOfSight(v(a), v(b)) == hit {
			t.Fatalf("line %v-%v: tree says sight=%v, brushes say blocked=%v", a, b, hit, hit)
		}
	}
	if points < 150000 || solids < 10000 || lines < 150000 || blocked < 50000 || lines-blocked < 5000 {
		t.Fatalf("weak sample: %d points (%d solid), %d lines (%d blocked)", points, solids, lines, blocked)
	}
}

func TestSolidTreeSightAroundAWall(t *testing.T) {
	m := treeMap(t, testBrushes())
	eye := func(x, y float64) Vec3 { return Vec3{x * unitM, y * unitM, 64 * unitM} }
	if m.LineOfSight(eye(-300, 0), eye(300, 0)) {
		t.Fatal("sight through the long wall")
	}
	if !m.LineOfSight(eye(-300, 600), eye(300, 600)) {
		t.Fatal("no sight past the end of the wall")
	}
	if !m.LineOfSight(eye(200, 230), eye(600, 230)) {
		t.Fatal("no sight over a crate that is below eye height")
	}
	// The eyes are just behind the corner of the wall, a shoulder is past it.
	a, b := eye(-100, 520), eye(100, 500)
	if m.LineOfSight(a, b) || m.LineOfSight(a, aimPoint(b)) {
		t.Fatal("the centre of the body should be hidden")
	}
	if !m.bodySight(a, b) {
		t.Fatal("a shoulder past the corner should count as seen")
	}
	if m.bodySight(eye(-300, 0), eye(300, 0)) {
		t.Fatal("a body fully behind the wall counted as seen")
	}
}

func TestSolidTreeSlice(t *testing.T) {
	m := treeMap(t, testBrushes())
	polys := m.SolidSlice(64*unitM, Vec2{-30, -30}, Vec2{30, 30}, 1000)
	area := 0.0
	for _, p := range polys {
		a := signedArea(p)
		if a < 0 {
			a = -a
		}
		area += a
	}
	// At eye height: four outer walls, the long wall, the two pillars (which
	// overlap) and the part of the ramp above 64 units; the rest of the 60 m square is
	// outside the room and open.
	u := unitM * unitM
	want := (2*64*2048 + 2*64*2048 + 128*1024 + 200*200 + 200*200 - 50*50 + 272*200) * u
	if area < want*0.99 || area > want*1.01 {
		t.Fatalf("slice area %.2f m², want about %.2f", area, want)
	}
}

func TestSolidTreeIsValidated(t *testing.T) {
	good := func() *pb.MapGeometry {
		return &pb.MapGeometry{MapId: "m", Version: 1, Solid: &pb.SolidTree{
			Planes: []float32{1, 0, 0, 0, 0, 1, 0, 100},
			Nodes:  []int32{0, 1, -2, 1, -1, -2},
		}}
	}
	if _, err := Compile(good()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(g *pb.MapGeometry){
		"planes come in fours": func(g *pb.MapGeometry) { g.Solid.Planes = g.Solid.Planes[:7] },
		"nodes in threes":      func(g *pb.MapGeometry) { g.Solid.Nodes = g.Solid.Nodes[:5] },
		"empty":                func(g *pb.MapGeometry) { g.Solid.Nodes = nil },
		"unit normal":          func(g *pb.MapGeometry) { g.Solid.Planes[0] = 3 },
		"names plane":          func(g *pb.MapGeometry) { g.Solid.Nodes[3] = 2 },
		"has child":            func(g *pb.MapGeometry) { g.Solid.Nodes[4] = 0 },
		"a later node":         func(g *pb.MapGeometry) { g.Solid.Nodes[1] = 2 },
		"-1 or -2":             func(g *pb.MapGeometry) { g.Solid.Nodes[2] = -3 },
		"both solid and open":  func(g *pb.MapGeometry) { g.Solid.Nodes[4] = -2 },
		"source_sha256":        func(g *pb.MapGeometry) { g.SourceSha256 = []byte{1, 2, 3} },
	} {
		g := good()
		mutate(g)
		if _, err := Compile(g); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	nan := good()
	nan.Solid.Planes[3] = float32(maxCoordinateCm) * 2
	if _, err := Compile(nan); err == nil {
		t.Error("a plane distance out of range was accepted")
	}
	deep := &pb.MapGeometry{MapId: "m", Version: 1, Solid: &pb.SolidTree{Planes: []float32{1, 0, 0, 0}}}
	for i := range int32(MaxTreeDepth + 2) {
		deep.Solid.Nodes = append(deep.Solid.Nodes, 0, i+1, -2)
	}
	deep.Solid.Nodes[len(deep.Solid.Nodes)-2] = -1
	if _, err := Compile(deep); err == nil || !strings.Contains(err.Error(), "deeper") {
		t.Errorf("deep tree: got %v", err)
	}
}

// testdata/cs_fixture.pb is what the Counter-Strike bridge made of a map compiled by a real
// map compiler (client/cs16/bridge/tests/data): it must compile here, hash to what the
// bridge printed, and trace like the brushes the map was written from.
func TestSolidTreeFromACompiledMap(t *testing.T) {
	raw, err := os.ReadFile("testdata/cs_fixture.pb")
	if err != nil {
		t.Fatal(err)
	}
	var g pb.MapGeometry
	if err := proto.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	m, err := Compile(&g)
	if err != nil {
		t.Fatal(err)
	}
	if m.Hash != "72dfe43a9661ac35be2fa4820549dc229a1846bd7c44fa2ec00801ad7aa0b988" || m.Source != "904481bc3653f3db853ea9595da63ac71d1a7ab44806c241b231c710433bf2a6" {
		t.Fatalf("hash %s, source %s", m.Hash, m.Source)
	}
	brushes := testBrushes()
	rng := rand.New(rand.NewSource(3))
	pt := func() [3]float64 {
		return [3]float64{rng.Float64()*2040 - 1020, rng.Float64()*2040 - 1020, rng.Float64()*504 + 4}
	}
	v := func(p [3]float64) Vec3 { return Vec3{p[0] * unitM, p[1] * unitM, p[2] * unitM} }
	lines, blocked := 0, 0
	for range 100000 {
		a, b := pt(), pt()
		hit, graze := false, false
		for _, br := range brushes {
			hit = hit || br.Hits(a, b, 0.1)
			graze = graze || br.Hits(a, b, -0.1)
		}
		if hit != graze {
			continue
		}
		lines++
		if hit {
			blocked++
		}
		if m.LineOfSight(v(a), v(b)) == hit {
			t.Fatalf("line %v-%v: tree says sight=%v, brushes say blocked=%v", a, b, hit, hit)
		}
	}
	if lines < 90000 || blocked < 20000 || lines-blocked < 20000 {
		t.Fatalf("weak sample: %d lines, %d blocked", lines, blocked)
	}
	if !m.Solid(Vec3{80, 0, 2}) {
		t.Fatal("outside the sealed room should be solid")
	}
}
