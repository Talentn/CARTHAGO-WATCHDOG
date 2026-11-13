package dashboard

import (
	"errors"
	"strconv"
	"strings"
)

// A small QR code encoder (ISO/IEC 18004, model 2), enough for the two-factor enrolment
// link: byte mode, error correction level M, versions 1 to 13 (up to 331 bytes). It is
// rendered on the server as SVG, so the secret in the code never goes to another service
// and the page needs no script.

type qrVersion struct {
	total   int // codewords in the symbol
	ecc     int // error correction codewords per block
	blocks  int
	align   []int
	lenBits int // width of the byte-mode length field
}

// Level M block layout per version, from table 9 of the standard.
var qrVersions = [...]qrVersion{
	1:  {26, 10, 1, nil, 8},
	2:  {44, 16, 1, []int{6, 18}, 8},
	3:  {70, 26, 1, []int{6, 22}, 8},
	4:  {100, 18, 2, []int{6, 26}, 8},
	5:  {134, 24, 2, []int{6, 30}, 8},
	6:  {172, 16, 4, []int{6, 34}, 8},
	7:  {196, 18, 4, []int{6, 22, 38}, 8},
	8:  {242, 22, 4, []int{6, 24, 42}, 8},
	9:  {292, 22, 5, []int{6, 26, 46}, 8},
	10: {346, 26, 5, []int{6, 28, 50}, 16},
	11: {404, 30, 5, []int{6, 30, 54}, 16},
	12: {466, 22, 8, []int{6, 32, 58}, 16},
	13: {532, 22, 9, []int{6, 34, 62}, 16},
}

func (v qrVersion) dataCodewords() int { return v.total - v.ecc*v.blocks }

type qrCode struct {
	size     int
	dark     [][]bool
	function [][]bool // finder, timing, alignment and format modules: never masked
}

var errQRTooLong = errors.New("text too long for a QR code")

// qrEncode returns the QR code for text with the mask that scores best. A mask of 0 to 7
// forces that mask (for tests); -1 chooses.
func qrEncode(text string, mask int) (*qrCode, error) {
	ver := 0
	for v := 1; v < len(qrVersions); v++ {
		if 4+qrVersions[v].lenBits+8*len(text) <= 8*qrVersions[v].dataCodewords() {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, errQRTooLong
	}
	v := qrVersions[ver]

	// Byte mode: mode 0100, the length, the bytes, a terminator, then padding.
	var bits []bool
	put := func(val, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, val>>i&1 == 1)
		}
	}
	put(4, 4)
	put(len(text), v.lenBits)
	for i := 0; i < len(text); i++ {
		put(int(text[i]), 8)
	}
	capacity := 8 * v.dataCodewords()
	put(0, min(4, capacity-len(bits)))
	put(0, (8-len(bits)%8)%8)
	for pad := 0xec; len(bits) < capacity; pad ^= 0xec ^ 0x11 {
		put(pad, 8)
	}
	data := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b {
			data[i/8] |= 0x80 >> (i % 8)
		}
	}

	q := &qrCode{size: 17 + 4*ver}
	q.dark = make([][]bool, q.size)
	q.function = make([][]bool, q.size)
	for i := range q.dark {
		q.dark[i], q.function[i] = make([]bool, q.size), make([]bool, q.size)
	}
	q.drawFunctionPatterns(ver, v)
	q.drawCodewords(qrInterleave(data, v))
	if mask < 0 {
		best := -1
		for m := 0; m < 8; m++ {
			q.applyMask(m)
			q.drawFormat(m)
			if p := q.penalty(); best < 0 || p < best {
				best, mask = p, m
			}
			q.applyMask(m) // XOR again undoes it
		}
	}
	q.applyMask(mask)
	q.drawFormat(mask)
	return q, nil
}

func (q *qrCode) set(x, y int, dark bool) {
	q.dark[y][x], q.function[y][x] = dark, true
}

func (q *qrCode) drawFunctionPatterns(ver int, v qrVersion) {
	for i := 0; i < q.size; i++ {
		q.set(6, i, i%2 == 0)
		q.set(i, 6, i%2 == 0)
	}
	// Finder patterns with their light separators, in three corners.
	for _, c := range [][2]int{{3, 3}, {q.size - 4, 3}, {3, q.size - 4}} {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := c[0]+dx, c[1]+dy
				if x < 0 || x >= q.size || y < 0 || y >= q.size {
					continue
				}
				d := max(abs(dx), abs(dy))
				q.set(x, y, d != 2 && d != 4)
			}
		}
	}
	last := len(v.align) - 1
	for i, cx := range v.align {
		for j, cy := range v.align {
			if i == 0 && j == 0 || i == 0 && j == last || i == last && j == 0 {
				continue // a finder pattern is there
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					q.set(cx+dx, cy+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	q.drawFormat(0)
	if ver >= 7 {
		// Version information: the version number with a (18,6) BCH code.
		rem := ver
		for i := 0; i < 12; i++ {
			rem = rem<<1 ^ (rem>>11)*0x1f25
		}
		info := ver<<12 | rem
		for i := 0; i < 18; i++ {
			bit := info>>i&1 == 1
			a, b := q.size-11+i%3, i/3
			q.set(a, b, bit)
			q.set(b, a, bit)
		}
	}
}

// drawFormat writes the format information (level M and the mask, with a (15,5) BCH code)
// in its two places, and the module that is always dark.
func (q *qrCode) drawFormat(mask int) {
	data := 0<<3 | mask // level M is 00
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	info := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return info>>i&1 == 1 }
	for i := 0; i <= 5; i++ {
		q.set(8, i, bit(i))
	}
	q.set(8, 7, bit(6))
	q.set(8, 8, bit(7))
	q.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		q.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		q.set(q.size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		q.set(8, q.size-15+i, bit(i))
	}
	q.set(8, q.size-8, true)
}

// drawCodewords lays the bits out in the zigzag the standard prescribes: two columns at a
// time from the right edge, alternately upwards and downwards, skipping function modules.
func (q *qrCode) drawCodewords(cw []byte) {
	i := 0
	for right := q.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < q.size; vert++ {
			for j := 0; j < 2; j++ {
				x, y := right-j, vert
				if (right+1)&2 == 0 {
					y = q.size - 1 - vert
				}
				if !q.function[y][x] && i < len(cw)*8 {
					q.dark[y][x] = cw[i>>3]>>(7-i&7)&1 == 1
					i++
				}
			}
		}
	}
}

func (q *qrCode) applyMask(mask int) {
	for y := 0; y < q.size; y++ {
		for x := 0; x < q.size; x++ {
			if q.function[y][x] {
				continue
			}
			var flip bool
			switch mask {
			case 0:
				flip = (x+y)%2 == 0
			case 1:
				flip = y%2 == 0
			case 2:
				flip = x%3 == 0
			case 3:
				flip = (x+y)%3 == 0
			case 4:
				flip = (x/3+y/2)%2 == 0
			case 5:
				flip = x*y%2+x*y%3 == 0
			case 6:
				flip = (x*y%2+x*y%3)%2 == 0
			case 7:
				flip = ((x+y)%2+x*y%3)%2 == 0
			}
			if flip {
				q.dark[y][x] = !q.dark[y][x]
			}
		}
	}
}

// penalty scores a masked symbol by the standard's four rules; lower scans better.
func (q *qrCode) penalty() int {
	p, darkCount := 0, 0
	line := make([]bool, q.size)
	score := func() {
		run := 1
		for i := 1; i <= q.size; i++ {
			if i < q.size && line[i] == line[i-1] {
				run++
				continue
			}
			if run >= 5 {
				p += run - 2
			}
			run = 1
		}
		// A finder-like 1:1:3:1:1 run with four light modules on either side.
		for i := 0; i+11 <= q.size; i++ {
			w := line[i : i+11]
			core := func(o int) bool {
				return w[o] && !w[o+1] && w[o+2] && w[o+3] && w[o+4] && !w[o+5] && w[o+6]
			}
			if core(0) && !w[7] && !w[8] && !w[9] && !w[10] || !w[0] && !w[1] && !w[2] && !w[3] && core(4) {
				p += 40
			}
		}
	}
	for y := 0; y < q.size; y++ {
		copy(line, q.dark[y])
		score()
		for x := 0; x < q.size; x++ {
			if q.dark[y][x] {
				darkCount++
			}
			if x+1 < q.size && y+1 < q.size && q.dark[y][x] == q.dark[y][x+1] && q.dark[y][x] == q.dark[y+1][x] && q.dark[y][x] == q.dark[y+1][x+1] {
				p += 3
			}
		}
	}
	for x := 0; x < q.size; x++ {
		for y := 0; y < q.size; y++ {
			line[y] = q.dark[y][x]
		}
		score()
	}
	// Ten points for every 5% the share of dark modules is away from half.
	total := q.size * q.size
	p += abs(darkCount*20-total*10) / total * 10
	return p
}

// qrInterleave splits the data into blocks, appends each block's Reed-Solomon codewords
// and interleaves them, as the standard orders them in the symbol.
func qrInterleave(data []byte, v qrVersion) []byte {
	short := v.blocks - v.total%v.blocks // blocks with one data codeword fewer
	shortLen := v.total/v.blocks - v.ecc
	gen := rsGenerator(v.ecc)
	blocks := make([][]byte, v.blocks)
	eccs := make([][]byte, v.blocks)
	for i, k := 0, 0; i < v.blocks; i++ {
		n := shortLen
		if i >= short {
			n++
		}
		blocks[i] = data[k : k+n]
		eccs[i] = rsRemainder(blocks[i], gen)
		k += n
	}
	out := make([]byte, 0, v.total)
	for i := 0; i <= shortLen; i++ {
		for _, b := range blocks {
			if i < len(b) {
				out = append(out, b[i])
			}
		}
	}
	for i := 0; i < v.ecc; i++ {
		for _, e := range eccs {
			out = append(out, e[i])
		}
	}
	return out
}

// Reed-Solomon over GF(2^8) with the polynomial x^8 + x^4 + x^3 + x^2 + 1.
func gfMul(a, b byte) byte {
	var z int
	for i := 7; i >= 0; i-- {
		z = z<<1 ^ (z>>7)*0x11d
		z ^= int(b>>i&1) * int(a)
	}
	return byte(z)
}

func rsGenerator(degree int) []byte {
	g := make([]byte, degree)
	g[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := 0; j < degree; j++ {
			g[j] = gfMul(g[j], root)
			if j+1 < degree {
				g[j] ^= g[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return g
}

func rsRemainder(data, gen []byte) []byte {
	rem := make([]byte, len(gen))
	for _, b := range data {
		f := b ^ rem[0]
		copy(rem, rem[1:])
		rem[len(rem)-1] = 0
		for i, g := range gen {
			rem[i] ^= gfMul(g, f)
		}
	}
	return rem
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// qrQuiet is the light margin a scanner needs around the symbol, in modules.
const qrQuiet = 4

// svgPath draws the dark modules as one SVG path, a rectangle per horizontal run, in a
// coordinate system of modules that includes the quiet zone. side is the width and height
// of that system.
func (q *qrCode) svgPath() (path string, side int) {
	var b strings.Builder
	for y := 0; y < q.size; y++ {
		for x := 0; x < q.size; x++ {
			if !q.dark[y][x] {
				continue
			}
			run := 1
			for x+run < q.size && q.dark[y][x+run] {
				run++
			}
			b.WriteString("M" + strconv.Itoa(x+qrQuiet) + " " + strconv.Itoa(y+qrQuiet) + "h" + strconv.Itoa(run) + "v1h-" + strconv.Itoa(run) + "z")
			x += run
		}
	}
	return b.String(), q.size + 2*qrQuiet
}
