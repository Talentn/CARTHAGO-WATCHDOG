package knowledge

import (
	"errors"
	"fmt"
	"math"

	pb "carthago/backend/gen/carthago/v1"
)

// Limits of an uploaded solid tree. GoldSrc itself stops at 32767 nodes; the room above is
// for other engines of the family.
const (
	MaxTreeNodes  = 1 << 17
	MaxTreePlanes = 1 << 17
	MaxTreeDepth  = 2048
	// MaxTreeBytes is the size limit of a geometry that carries a solid tree.
	MaxTreeBytes = 3 << 20
)

const (
	childOpen  = -1
	childSolid = -2
)

// treeNode is one split with its plane inlined, in metres.
type treeNode struct {
	nx, ny, nz, d float64
	front, back   int32
}

type tree struct {
	nodes  []treeNode
	planes int
	solids int
}

// compileTree checks an uploaded tree and converts it. Nothing in it is trusted: indices,
// the direction of child links (a child index above its parent cannot loop), depth, and
// every number.
func compileTree(st *pb.SolidTree) (*tree, error) {
	if len(st.Planes)%4 != 0 || len(st.Nodes)%3 != 0 {
		return nil, errors.New("solid tree: planes come in fours and nodes in threes")
	}
	np, nn := len(st.Planes)/4, len(st.Nodes)/3
	if nn == 0 || np == 0 {
		return nil, errors.New("solid tree: empty")
	}
	if nn > MaxTreeNodes || np > MaxTreePlanes {
		return nil, fmt.Errorf("solid tree over limits (%d nodes, %d planes)", MaxTreeNodes, MaxTreePlanes)
	}
	for i := range np {
		nx, ny, nz, d := float64(st.Planes[4*i]), float64(st.Planes[4*i+1]), float64(st.Planes[4*i+2]), float64(st.Planes[4*i+3])
		l := math.Sqrt(nx*nx + ny*ny + nz*nz)
		if math.IsNaN(l) || math.IsNaN(d) || l < 0.99 || l > 1.01 || math.Abs(d) > maxCoordinateCm {
			return nil, fmt.Errorf("solid tree: plane %d is not a unit normal with a distance in range", i)
		}
	}
	t := &tree{nodes: make([]treeNode, nn), planes: np}
	depth := make([]int32, nn)
	opens := 0
	for i := range nn {
		pl, front, back := st.Nodes[3*i], st.Nodes[3*i+1], st.Nodes[3*i+2]
		if pl < 0 || int(pl) >= np {
			return nil, fmt.Errorf("solid tree: node %d names plane %d of %d", i, pl, np)
		}
		for _, c := range [2]int32{front, back} {
			switch {
			case c == childOpen:
				opens++
			case c == childSolid:
				t.solids++
			case c > int32(i) && int(c) < nn:
				depth[c] = max(depth[c], depth[i]+1)
				if depth[c] > MaxTreeDepth {
					return nil, fmt.Errorf("solid tree: deeper than %d", MaxTreeDepth)
				}
			default:
				return nil, fmt.Errorf("solid tree: node %d has child %d (a child is a later node, -1 or -2)", i, c)
			}
		}
		t.nodes[i] = treeNode{float64(st.Planes[4*pl]), float64(st.Planes[4*pl+1]), float64(st.Planes[4*pl+2]), float64(st.Planes[4*pl+3]) / 100, front, back}
	}
	if t.solids == 0 || opens == 0 {
		return nil, errors.New("solid tree: needs both solid and open space")
	}
	return t, nil
}

// solid reports whether a point is inside the solid world.
func (t *tree) solid(p Vec3) bool {
	n := int32(0)
	for n >= 0 {
		nd := &t.nodes[n]
		if nd.nx*p.X+nd.ny*p.Y+nd.nz*p.Z-nd.d >= 0 {
			n = nd.front
		} else {
			n = nd.back
		}
	}
	return n == childSolid
}

// blocked reports whether the segment a-b touches solid space.
func (t *tree) blocked(a, b Vec3) bool {
	return t.cross(0, a, b)
}

func (t *tree) cross(n int32, a, b Vec3) bool {
	for n >= 0 {
		nd := &t.nodes[n]
		da := nd.nx*a.X + nd.ny*a.Y + nd.nz*a.Z - nd.d
		db := nd.nx*b.X + nd.ny*b.Y + nd.nz*b.Z - nd.d
		switch {
		case da >= 0 && db >= 0:
			n = nd.front
		case da < 0 && db < 0:
			n = nd.back
		default:
			f := da / (da - db)
			mid := Vec3{a.X + f*(b.X-a.X), a.Y + f*(b.Y-a.Y), a.Z + f*(b.Z-a.Z)}
			near, far := nd.front, nd.back
			if da < 0 {
				near, far = far, near
			}
			if t.cross(near, a, mid) {
				return true
			}
			n, a = far, mid
		}
	}
	return n == childSolid
}

// slice cuts the tree with the horizontal plane at height z and returns the solid areas
// inside the rectangle lo-hi as convex polygons, at most limit of them.
func (t *tree) slice(z float64, lo, hi Vec2, limit int) [][]Vec2 {
	var out [][]Vec2
	var rec func(n int32, poly []Vec2)
	rec = func(n int32, poly []Vec2) {
		if len(out) >= limit || len(poly) < 3 || math.Abs(signedArea(poly)) < 1e-4 {
			return
		}
		if n < 0 {
			if n == childSolid {
				out = append(out, poly)
			}
			return
		}
		nd := &t.nodes[n]
		c := nd.nz*z - nd.d
		side := func(p Vec2) float64 { return nd.nx*p.X + nd.ny*p.Y + c }
		var front, back []Vec2
		for i := range poly {
			p, q := poly[i], poly[(i+1)%len(poly)]
			dp, dq := side(p), side(q)
			if dp >= 0 {
				front = append(front, p)
			} else {
				back = append(back, p)
			}
			if (dp >= 0) != (dq >= 0) {
				f := dp / (dp - dq)
				x := Vec2{p.X + f*(q.X-p.X), p.Y + f*(q.Y-p.Y)}
				front, back = append(front, x), append(back, x)
			}
		}
		rec(nd.front, front)
		rec(nd.back, back)
	}
	rec(0, []Vec2{lo, {hi.X, lo.Y}, hi, {lo.X, hi.Y}})
	return out
}

// A standing body around its eye position, metres: half its width, and how far below the
// eyes the chest and the knees are.
const (
	bodyHalfWidth = 0.42
	eyeToKnee     = 1.15
)

// bodySight reports whether any of the edges of a body standing at target (its eye
// position) can be seen from eye. On a map with real walls a shoulder or a leg shows
// around a corner before the eyes do, and a player who shoots at it has seen it. A map
// without a solid tree has only coarse occluders, for which the two central points do.
func (m *Map) bodySight(eye, target Vec3) bool {
	if m.tree == nil {
		return false
	}
	dx, dy := target.X-eye.X, target.Y-eye.Y
	l := math.Hypot(dx, dy)
	if l < 1e-6 {
		return true
	}
	sx, sy := -dy/l*bodyHalfWidth, dx/l*bodyHalfWidth
	for _, dz := range [3]float64{0, eyeToAim, eyeToKnee} {
		for _, k := range [3]float64{-1, 1, 0} {
			if dz != eyeToKnee && k == 0 {
				continue // the central eye and chest points were tried first
			}
			if m.LineOfSight(eye, Vec3{target.X + k*sx, target.Y + k*sy, target.Z - dz}) {
				return true
			}
		}
	}
	return false
}

// HasSolid reports whether the map carries a solid tree.
func (m *Map) HasSolid() bool { return m.tree != nil }

// Solid reports whether a point lies inside the map's solid world. A map without a solid
// tree has none.
func (m *Map) Solid(p Vec3) bool { return m.tree != nil && m.tree.solid(p) }

// SolidSlice is the solid world at height z inside a rectangle, for drawing.
func (m *Map) SolidSlice(z float64, lo, hi Vec2, limit int) [][]Vec2 {
	if m.tree == nil {
		return nil
	}
	return m.tree.slice(z, lo, hi, limit)
}

// Describe words the geometry for an explanation.
func (m *Map) Describe() string {
	switch {
	case m.tree != nil && len(m.occ) > 0:
		return fmt.Sprintf("the solid world (%d splits) and the %d occluders of %s v%d", len(m.tree.nodes), len(m.occ), m.ID, m.Version)
	case m.tree != nil:
		return fmt.Sprintf("the solid world of %s v%d (%d splits, read from the game's own map file)", m.ID, m.Version, len(m.tree.nodes))
	}
	return fmt.Sprintf("the %d occluders of %s v%d", len(m.occ), m.ID, m.Version)
}
