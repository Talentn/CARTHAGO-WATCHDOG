// Package bsptree builds a solid tree from convex brushes and writes it as a GoldSrc BSP
// (version 30) file. It exists for tests and for the synthetic Counter-Strike map of the
// calibration: real maps are compiled by the game's own tools and read by the game server
// side, never by this package.
package bsptree

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	pb "carthago/backend/gen/carthago/v1"
)

// Plane is n·p = D with a unit normal.
type Plane struct {
	X, Y, Z, D float64
}

func (p Plane) side(v [3]float64) float64 { return p.X*v[0] + p.Y*v[1] + p.Z*v[2] - p.D }

// Brush is a convex solid: the points behind all of its planes. Verts are its corners.
type Brush struct {
	Planes []Plane
	Verts  [][3]float64
}

// Box is an axis-aligned brush.
func Box(x0, y0, z0, x1, y1, z1 float64) Brush {
	b := Brush{Planes: []Plane{{1, 0, 0, x1}, {-1, 0, 0, -x0}, {0, 1, 0, y1}, {0, -1, 0, -y0}, {0, 0, 1, z1}, {0, 0, -1, -z0}}}
	for _, x := range []float64{x0, x1} {
		for _, y := range []float64{y0, y1} {
			for _, z := range []float64{z0, z1} {
				b.Verts = append(b.Verts, [3]float64{x, y, z})
			}
		}
	}
	return b
}

// Ramp is a wedge over the box footprint that rises along +X from z0 at x0 to z1 at x1.
func Ramp(x0, y0, z0, x1, y1, z1 float64) Brush {
	dx, dz := x1-x0, z1-z0
	l := math.Hypot(dx, dz)
	top := Plane{X: -dz / l, Z: dx / l}
	top.D = top.X*x0 + top.Z*z0
	return Brush{
		Planes: []Plane{top, {1, 0, 0, x1}, {0, 1, 0, y1}, {0, -1, 0, -y0}, {0, 0, -1, -z0}},
		Verts:  [][3]float64{{x0, y0, z0}, {x0, y1, z0}, {x1, y0, z0}, {x1, y1, z0}, {x1, y0, z1}, {x1, y1, z1}},
	}
}

// Contains reports whether a point is inside the brush, grown by margin.
func (b Brush) Contains(v [3]float64, margin float64) bool {
	for _, p := range b.Planes {
		if p.side(v) > margin {
			return false
		}
	}
	return true
}

// Hits reports whether the segment a-b passes through the brush shrunk by margin.
func (b Brush) Hits(a, c [3]float64, margin float64) bool {
	t0, t1 := 0.0, 1.0
	for _, p := range b.Planes {
		da, dc := p.side(a)+margin, p.side(c)+margin
		switch {
		case da > 0 && dc > 0:
			return false
		case da <= 0 && dc <= 0:
		default:
			t := da / (da - dc)
			if da > 0 {
				t0 = math.Max(t0, t)
			} else {
				t1 = math.Min(t1, t)
			}
		}
		if t0 > t1 {
			return false
		}
	}
	return true
}

// Tree is a solid tree in the units of its brushes. Node children that are zero or more
// index Nodes; Open and Solid are the leaves.
type Tree struct {
	Planes []Plane
	Nodes  []Node
}

type Node struct {
	Plane       int32
	Front, Back int32
}

const (
	Open  = -1
	Solid = -2
)

const eps = 1e-6

type frag struct {
	b     *Brush
	verts [][3]float64
	used  uint64 // planes of b the region is known to lie behind
}

// Build compiles brushes into a tree. A brush may have at most 64 planes.
func Build(brushes []Brush) (*Tree, error) {
	t := &Tree{}
	frags := make([]frag, 0, len(brushes))
	for i := range brushes {
		if len(brushes[i].Planes) > 64 || len(brushes[i].Verts) < 4 {
			return nil, fmt.Errorf("brush %d: needs corners and at most 64 planes", i)
		}
		frags = append(frags, frag{b: &brushes[i], verts: brushes[i].Verts})
	}
	planeIndex := map[Plane]int32{}
	var build func(frags []frag, depth int) (int32, error)
	build = func(frags []frag, depth int) (int32, error) {
		if len(frags) == 0 {
			return Open, nil
		}
		if depth > 4096 {
			return 0, errors.New("tree too deep")
		}
		// Split on the first plane of the first fragment that the region is not known to be
		// behind. When there is none, the region is inside that brush.
		f0 := frags[0]
		pick := -1
		for i := range f0.b.Planes {
			if f0.used&(1<<i) == 0 {
				pick = i
				break
			}
		}
		if pick < 0 {
			return Solid, nil
		}
		pl := f0.b.Planes[pick]
		var front, back []frag
		for _, f := range frags {
			var fv, bv [][3]float64
			anyFront, anyBack := false, false
			for _, v := range f.verts {
				s := pl.side(v)
				if s > eps {
					anyFront = true
				}
				if s < -eps {
					anyBack = true
				}
			}
			switch {
			case !anyFront:
				bv = f.verts
			case !anyBack:
				fv = f.verts
			default:
				for i, v := range f.verts {
					si := pl.side(v)
					if si >= -eps {
						fv = append(fv, v)
					}
					if si <= eps {
						bv = append(bv, v)
					}
					for _, w := range f.verts[i+1:] {
						sj := pl.side(w)
						if (si > eps && sj < -eps) || (si < -eps && sj > eps) {
							k := si / (si - sj)
							x := [3]float64{v[0] + k*(w[0]-v[0]), v[1] + k*(w[1]-v[1]), v[2] + k*(w[2]-v[2])}
							fv, bv = append(fv, x), append(bv, x)
						}
					}
				}
			}
			if anyFront {
				nf := frag{f.b, fv, f.used}
				for i, q := range f.b.Planes {
					if math.Abs(q.X+pl.X)+math.Abs(q.Y+pl.Y)+math.Abs(q.Z+pl.Z)+math.Abs(q.D+pl.D) < 1e-9 {
						nf.used |= 1 << i
					}
				}
				front = append(front, nf)
			}
			if anyBack {
				nf := frag{f.b, bv, f.used}
				for i, q := range f.b.Planes {
					if math.Abs(q.X-pl.X)+math.Abs(q.Y-pl.Y)+math.Abs(q.Z-pl.Z)+math.Abs(q.D-pl.D) < 1e-9 {
						nf.used |= 1 << i
					}
				}
				back = append(back, nf)
			}
		}
		pi, ok := planeIndex[pl]
		if !ok {
			pi = int32(len(t.Planes))
			planeIndex[pl] = pi
			t.Planes = append(t.Planes, pl)
		}
		me := int32(len(t.Nodes))
		t.Nodes = append(t.Nodes, Node{Plane: pi})
		fr, err := build(front, depth+1)
		if err != nil {
			return 0, err
		}
		bk, err := build(back, depth+1)
		if err != nil {
			return 0, err
		}
		t.Nodes[me].Front, t.Nodes[me].Back = fr, bk
		return me, nil
	}
	root, err := build(frags, 0)
	if err != nil {
		return nil, err
	}
	if root != 0 {
		return nil, errors.New("no brushes")
	}
	return t, nil
}

// Proto is the tree as uploaded geometry. scale turns the brushes' units into centimetres
// (2.54 for GoldSrc units).
func (t *Tree) Proto(scale float64) *pb.SolidTree {
	st := &pb.SolidTree{}
	for _, p := range t.Planes {
		st.Planes = append(st.Planes, float32(p.X), float32(p.Y), float32(p.Z), float32(p.D)*float32(scale))
	}
	for _, n := range t.Nodes {
		st.Nodes = append(st.Nodes, n.Plane, n.Front, n.Back)
	}
	return st
}

// WriteBSP30 writes the tree as the world model of a GoldSrc map file: the planes, nodes,
// leaves and model lumps a line trace needs, and a worldspawn entity. Everything a renderer
// needs is left empty.
func (t *Tree) WriteBSP30(w io.Writer, mins, maxs [3]float32) error {
	if len(t.Nodes) > math.MaxInt16 {
		return errors.New("too many nodes for a version 30 file")
	}
	le := binary.LittleEndian
	var lumps [15]bytes.Buffer
	lumps[0].WriteString("{\n\"classname\" \"worldspawn\"\n}\n\x00")
	for _, p := range t.Planes {
		typ := int32(3)
		switch {
		case p.X == 1:
			typ = 0
		case p.Y == 1:
			typ = 1
		case p.Z == 1:
			typ = 2
		}
		binary.Write(&lumps[1], le, [4]float32{float32(p.X), float32(p.Y), float32(p.Z), float32(p.D)})
		binary.Write(&lumps[1], le, typ)
	}
	child := func(c int32) int16 {
		switch c {
		case Solid:
			return -1 // leaf 0
		case Open:
			return -2 // leaf 1
		}
		return int16(c)
	}
	for _, n := range t.Nodes {
		binary.Write(&lumps[5], le, n.Plane)
		binary.Write(&lumps[5], le, [2]int16{child(n.Front), child(n.Back)})
		binary.Write(&lumps[5], le, [6]int16{})
		binary.Write(&lumps[5], le, [2]uint16{})
	}
	for _, contents := range []int32{-2, -1} {
		binary.Write(&lumps[10], le, contents)
		binary.Write(&lumps[10], le, int32(-1))
		binary.Write(&lumps[10], le, [6]int16{})
		binary.Write(&lumps[10], le, [2]uint16{})
		binary.Write(&lumps[10], le, [4]uint8{})
	}
	binary.Write(&lumps[14], le, mins)
	binary.Write(&lumps[14], le, maxs)
	binary.Write(&lumps[14], le, [3]float32{})
	binary.Write(&lumps[14], le, [4]int32{0, 0, 0, 0})
	binary.Write(&lumps[14], le, [3]int32{1, 0, 0})

	var out bytes.Buffer
	binary.Write(&out, le, int32(30))
	off := int32(4 + 15*8)
	for i := range lumps {
		binary.Write(&out, le, off)
		binary.Write(&out, le, int32(lumps[i].Len()))
		off += int32((lumps[i].Len() + 3) &^ 3)
	}
	for i := range lumps {
		out.Write(lumps[i].Bytes())
		out.Write(make([]byte, (4-lumps[i].Len()%4)%4))
	}
	_, err := w.Write(out.Bytes())
	return err
}
