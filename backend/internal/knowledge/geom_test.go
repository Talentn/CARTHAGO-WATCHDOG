package knowledge

import (
	"strings"
	"testing"

	pb "carthago/backend/gen/carthago/v1"
)

func box(x0, y0, x1, y1 float64, zMax float64) *pb.Occluder {
	c := func(v float64) int32 { return int32(v * 100) }
	return &pb.Occluder{XyCm: []int32{c(x0), c(y0), c(x1), c(y0), c(x1), c(y1), c(x0), c(y1)}, ZMinCm: 0, ZMaxCm: c(zMax)}
}

func testGeometry() *pb.MapGeometry {
	return &pb.MapGeometry{
		MapId: "test", Version: 1, Mode: pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER,
		Occluders: []*pb.Occluder{
			box(10, -5, 11, 5, 3),  // a wall across the X axis
			box(20, -1, 21, 1, 1),  // a crate below eye height
			box(30, 2, 31, 3, 3.0), // a pillar off the axis
		},
		Zones: []*pb.Zone{{Name: "West", XyCm: []int32{-1000, -1000, 1500, -1000, 1500, 1000, -1000, 1000}}},
	}
}

func TestLineOfSight(t *testing.T) {
	m, err := Compile(testGeometry())
	if err != nil {
		t.Fatal(err)
	}
	eye := 1.7
	cases := []struct {
		name string
		a, b Vec3
		want bool
	}{
		{"through the wall", Vec3{0, 0, eye}, Vec3{15, 0, eye}, false},
		{"around the wall", Vec3{0, 6, eye}, Vec3{15, 6, eye}, true},
		{"over the crate", Vec3{15, 0, eye}, Vec3{25, 0, eye}, true},
		{"into the crate low", Vec3{15, 0, 0.5}, Vec3{25, 0, 0.5}, false},
		{"past the pillar", Vec3{25, 0, eye}, Vec3{35, 0, eye}, true},
		{"behind the pillar", Vec3{25, 2.5, eye}, Vec3{35, 2.5, eye}, false},
		{"both inside nothing", Vec3{0, 0, eye}, Vec3{0, 0, eye}, true},
	}
	for _, c := range cases {
		if got := m.LineOfSight(c.a, c.b); got != c.want {
			t.Errorf("%s: LineOfSight = %v, want %v", c.name, got, c.want)
		}
		if got := m.LineOfSight(c.b, c.a); got != c.want {
			t.Errorf("%s reversed: LineOfSight = %v, want %v", c.name, got, c.want)
		}
	}
	if z := m.ZoneName(Vec3{0, 0, 0}); z != "West" {
		t.Errorf("zone = %q", z)
	}
	if z := m.ZoneName(Vec3{40, 0, 0}); z != "" {
		t.Errorf("zone outside = %q", z)
	}
}

func TestCompileNormalisesWinding(t *testing.T) {
	g := testGeometry()
	o := g.Occluders[0]
	// Clockwise: reverse the vertex order.
	var rev []int32
	for i := len(o.XyCm) - 2; i >= 0; i -= 2 {
		rev = append(rev, o.XyCm[i], o.XyCm[i+1])
	}
	o.XyCm = rev
	m, err := Compile(g)
	if err != nil {
		t.Fatal(err)
	}
	if m.LineOfSight(Vec3{0, 0, 1.7}, Vec3{15, 0, 1.7}) {
		t.Error("clockwise wall does not block")
	}
}

func TestCompileRejects(t *testing.T) {
	cases := map[string]func(g *pb.MapGeometry){
		"no id":      func(g *pb.MapGeometry) { g.MapId = "" },
		"no version": func(g *pb.MapGeometry) { g.Version = 0 },
		"concave": func(g *pb.MapGeometry) {
			g.Occluders[0].XyCm = []int32{0, 0, 400, 0, 400, 400, 200, 100, 0, 400}
		},
		"odd coordinates": func(g *pb.MapGeometry) { g.Occluders[0].XyCm = g.Occluders[0].XyCm[:7] },
		"two vertices":    func(g *pb.MapGeometry) { g.Occluders[0].XyCm = []int32{0, 0, 100, 0} },
		"flat":            func(g *pb.MapGeometry) { g.Occluders[0].ZMaxCm = g.Occluders[0].ZMinCm },
		"too many occluders": func(g *pb.MapGeometry) {
			for len(g.Occluders) <= MaxOccluders {
				g.Occluders = append(g.Occluders, box(0, 0, 1, 1, 2))
			}
		},
		"huge coordinate": func(g *pb.MapGeometry) { g.Occluders[0].XyCm[0] = 1 << 30 },
		"long zone name":  func(g *pb.MapGeometry) { g.Zones[0].Name = strings.Repeat("z", MaxZoneNameLen+1) },
	}
	for name, mutate := range cases {
		g := testGeometry()
		mutate(g)
		if _, err := Compile(g); err == nil {
			t.Errorf("%s: compiled", name)
		}
	}
}

func TestGeometryHashIsStable(t *testing.T) {
	a, _, err := GeometryHash(testGeometry())
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := GeometryHash(testGeometry())
	if a != b || len(a) != 64 {
		t.Fatalf("hash %q vs %q", a, b)
	}
	g := testGeometry()
	g.Occluders[1].ZMaxCm++
	if c, _, _ := GeometryHash(g); c == a {
		t.Fatal("edit did not change the hash")
	}
}

func TestThresholds(t *testing.T) {
	cfg := DefaultConfig()
	mouse := Segment{Mode: pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, Device: pb.InputDevice_INPUT_DEVICE_MOUSE_KEYBOARD}
	pad := Segment{Mode: pb.GameMode_GAME_MODE_EXTRACTION, Device: pb.InputDevice_INPUT_DEVICE_CONTROLLER}
	other := Segment{Mode: pb.GameMode_GAME_MODE_UNSPECIFIED, Device: pb.InputDevice_INPUT_DEVICE_TOUCH}
	if !cfg.Calibrated(mouse) || !cfg.Calibrated(pad) || cfg.Calibrated(other) {
		t.Fatal("calibrated segments")
	}
	if cfg.threshold(pad).Z <= cfg.threshold(mouse).Z {
		t.Error("controller threshold should be stricter than mouse")
	}
	if cfg.threshold(other) != FallbackThreshold {
		t.Error("uncalibrated segment should use the fallback")
	}
	for seg, th := range cfg.Thresholds {
		if th.TargetFPR != TargetFPR || th.Z < 4 {
			t.Errorf("%s: %+v", seg, th)
		}
	}
}
