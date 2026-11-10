// Package synth generates synthetic matches on a small test map for the information-leak
// detector's tests, its calibration (carthago-sim -calibrate) and the end-to-end check
// (carthago-sim -scenario-out, replayed by gs-stub simulate --scenario). Every player is
// simulated; "informed" players are driven by the simulator's own ground-truth positions,
// standing in for what an ESP or radar user would act on. Nothing here touches a game.
package synth

import (
	pb "carthago/backend/gen/carthago/v1"
)

// Yard is the "carthago-yard" test map: 60 x 40 m, two spawns, three lanes joined by doors,
// a building in mid, pillars, and twelve loot spots. Units in metres.
const (
	YardID      = "carthago-yard"
	YardVersion = 1
	EyeHeight   = 1.6
)

type box struct{ x0, y0, x1, y1, h float64 }

var yardBoxes = []box{
	// outer walls
	{0, -1, 60, 0, 4}, {0, 40, 60, 41, 4}, {-1, 0, 0, 40, 4}, {60, 0, 61, 40, 4},
	// spawn walls, gaps at the three lanes
	{10, 0, 11, 4, 3}, {10, 9, 11, 17, 3}, {10, 23, 11, 31, 3}, {10, 36, 11, 40, 3},
	{49, 0, 50, 4, 3}, {49, 9, 50, 17, 3}, {49, 23, 50, 31, 3}, {49, 36, 50, 40, 3},
	// north / mid wall, doors at x 18-21 and 38-41
	{11, 26, 18, 27, 3}, {21, 26, 38, 27, 3}, {41, 26, 49, 27, 3},
	// mid / south wall, doors at x 24-27 and 33-36
	{11, 13, 24, 14, 3}, {27, 13, 33, 14, 3}, {36, 13, 49, 14, 3},
	// mid building
	{27, 17, 33, 23, 4},
	// pillars
	{24, 35.5, 26, 38, 3}, {34, 29, 36, 31, 3}, {29, 1.5, 31, 4, 3}, {29, 9, 31, 11, 3},
	// low crates (below eye height: they block nothing standing)
	{15, 29, 16.5, 30.5, 1}, {43.5, 9.5, 45, 11, 1},
}

type namedRect struct {
	name           string
	x0, y0, x1, y1 float64
}

var yardZones = []namedRect{
	{"West Spawn", 0, 0, 10.5, 40}, {"East Spawn", 49.5, 0, 60, 40},
	{"North Lane", 10.5, 26.5, 49.5, 40}, {"South Lane", 10.5, 0, 49.5, 13.5},
	{"Mid West", 10.5, 13.5, 26, 26.5}, {"Mid Building", 26, 13.5, 34, 26.5}, {"Mid East", 34, 13.5, 49.5, 26.5},
}

type node struct{ x, y float64 }

var nodes = []node{
	{4, 20}, {7, 33.5}, {7, 20}, {7, 6.5}, // 0-3 west spawn
	{10.5, 33.5}, {10.5, 20}, {10.5, 6.5}, // 4-6 west gates
	{15, 33.5}, {19.5, 33.5}, {30, 33.5}, {39.5, 33.5}, {45, 33.5}, // 7-11 north
	{15, 20}, {19.5, 20}, {25, 20}, {25, 15.5}, {25, 24.5}, {35, 15.5}, {35, 24.5}, {35, 20}, {39.5, 20}, {45, 20}, // 12-21 mid
	{15, 6.5}, {25.5, 6.5}, {30, 6.5}, {34.5, 6.5}, {45, 6.5}, // 22-26 south
	{49.5, 33.5}, {49.5, 20}, {49.5, 6.5}, // 27-29 east gates
	{53, 33.5}, {53, 20}, {53, 6.5}, {56, 20}, // 30-33 east spawn
}

var edges = [][2]int{
	{0, 2}, {2, 1}, {2, 3}, {1, 4}, {2, 5}, {3, 6}, {4, 7}, {5, 12}, {6, 22},
	{7, 8}, {8, 9}, {9, 10}, {10, 11}, {11, 27},
	{12, 13}, {13, 14}, {14, 15}, {14, 16}, {15, 17}, {16, 18}, {17, 19}, {18, 19}, {19, 20}, {20, 21}, {21, 28},
	{22, 23}, {23, 24}, {24, 25}, {25, 26}, {26, 29},
	{8, 13}, {10, 20}, {23, 15}, {25, 17},
	{27, 30}, {28, 31}, {29, 32}, {30, 31}, {31, 32}, {31, 33},
}

// laneNodes are where players roam; lootNodes hold the loot spots.
var (
	laneNodes = []int{7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26}
	lootNodes = []int{7, 9, 11, 12, 16, 17, 21, 22, 24, 26, 15, 18}
)

// commonAngles are the doors, gates and corners players habitually hold and prefire.
var commonAngles = []node{
	{19.5, 26.5}, {39.5, 26.5}, {25.5, 13.5}, {34.5, 13.5},
	{10.5, 33.5}, {10.5, 20}, {10.5, 6.5}, {49.5, 33.5}, {49.5, 20}, {49.5, 6.5},
	{26.6, 16.6}, {33.4, 16.6}, {26.6, 23.4}, {33.4, 23.4},
	{24, 34.8}, {36.4, 31}, {31.4, 4.4}, {31.4, 8.6},
}

func cmv(m float64) int32 { return int32(m*100 + 0.5*sign(m)) }

func sign(v float64) float64 {
	if v < 0 {
		return -1
	}
	return 1
}

func rect(x0, y0, x1, y1 float64) []int32 {
	return []int32{cmv(x0), cmv(y0), cmv(x1), cmv(y0), cmv(x1), cmv(y1), cmv(x0), cmv(y1)}
}

// YardGeometry is the map upload for the test map.
func YardGeometry() *pb.MapGeometry {
	g := &pb.MapGeometry{MapId: YardID, Version: YardVersion, Mode: pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER}
	for _, b := range yardBoxes {
		g.Occluders = append(g.Occluders, &pb.Occluder{XyCm: rect(b.x0, b.y0, b.x1, b.y1), ZMinCm: 0, ZMaxCm: cmv(b.h)})
	}
	for _, z := range yardZones {
		g.Zones = append(g.Zones, &pb.Zone{Name: z.name, XyCm: rect(z.x0, z.y0, z.x1, z.y1)})
	}
	for i, n := range lootNodes {
		g.LootSpawns = append(g.LootSpawns, &pb.LootSpawn{SpawnId: uint32(i + 1), XCm: cmv(nodes[n].x), YCm: cmv(nodes[n].y), ZCm: 30})
	}
	return g
}
