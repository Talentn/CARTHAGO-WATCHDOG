// Package replay keeps a small top-down recording of a match for the dashboard: where
// every player stood and looked, and who shot at whom.
//
// It is built from what a game server already sends on /v1/ingest when it sends positions
// (GameplayBatch.motion, with aim and shots). A match without positions has no recording
// and everything else works as before. The recording is not evidence and nothing reads it
// back into a rule: it is a picture for a reviewer.
//
// One position per player is kept per Step of match time, whatever the tick rate, with
// the view direction at that moment. A match is cut off at MaxSamples positions and
// MaxShots shots, so a recording stays within a few megabytes however long a match runs.
package replay

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	pb "carthago/backend/gen/carthago/v1"
)

const (
	// StepMs is the match time between two kept positions of a player.
	StepMs = 250
	// MaxSamples is the most positions kept for one match, over all players: ten players
	// for eleven hours, or a hundred for an hour.
	MaxSamples = 400_000
	MaxShots   = 40_000
	MaxPlayers = 256
	// maxBatches bounds the batch clock (Data.Batches).
	maxBatches = 20_000
	// MaxBytes is the largest encoded recording; the caps above keep a match far below it.
	MaxBytes = 6 << 20
	// maxDecoded bounds what Decode inflates.
	maxDecoded = 64 << 20

	defaultTickRate = 64

	// MaxMapID is the longest map name kept with a recording, in bytes.
	MaxMapID = 128
	// gapSteps: a player whose next position is more than this many steps away is not in
	// play in between (dead, left, not spawned). The dashboard's player uses the same.
	gapSteps = 8
)

// Player is one slot of the match. T, X, Y and Yaw are parallel: sample i was taken at
// step T[i] (match time T[i]*StepMs), at X[i], Y[i] centimetres, looking along Yaw[i]
// degrees (0 along +X, 90 along +Y). In the encoded form each list holds its first value
// and then the difference from the previous one.
type Player struct {
	Slot    uint32  `json:"slot"`
	Name    string  `json:"name"`
	Session string  `json:"session,omitempty"`
	Team    uint32  `json:"team"`
	Bot     bool    `json:"bot,omitempty"`
	T       []int32 `json:"t"`
	X       []int32 `json:"x"`
	Y       []int32 `json:"y"`
	Yaw     []int32 `json:"yaw"`
}

// Shot is one shot: match time in milliseconds, the shooter's slot, the slot that was hit
// (-1 for none), 1 for a hit and 1 for a kill.
type Shot [5]int32

// Data is a recording as the dashboard's player reads it.
type Data struct {
	V     int    `json:"v"`
	Match string `json:"match"`
	// Map is the map the game server named for the match (GameplayBatch.map); empty when
	// it named none. The dashboard draws the studio's outline of that map, if it has one.
	Map        string   `json:"map,omitempty"`
	TickRate   uint32   `json:"tick_rate"`
	StepMs     int      `json:"step_ms"`
	DurationMs int64    `json:"duration_ms"`
	Bounds     [4]int32 `json:"bounds"` // min x, min y, max x, max y, centimetres
	Players    []Player `json:"players"`
	Shots      []Shot   `json:"shots"`
	// Batches is the batch clock: batch sequence number, the match time its data reached
	// and when the gateway received it (Unix milliseconds), so evidence that names a batch
	// or only has a wall-clock time can be placed on the timeline.
	Batches   [][3]int64 `json:"batches"`
	Truncated bool       `json:"truncated,omitempty"`
}

// Recorder builds the recording of one match, batch by batch. It is not safe for
// concurrent use.
type Recorder struct {
	match     string
	mapID     string
	tickRate  uint32
	players   map[uint32]*Player
	shots     []Shot
	batches   [][3]int64
	samples   int
	endMs     int64
	truncated bool
}

func NewRecorder(matchID string) *Recorder {
	return &Recorder{match: matchID, players: map[uint32]*Player{}}
}

// Samples is the number of positions recorded so far.
func (r *Recorder) Samples() int { return r.samples }

// DurationMs is the match time of the last thing recorded.
func (r *Recorder) DurationMs() int64 { return r.endMs }

func (r *Recorder) Truncated() bool { return r.truncated }

// SetPlayer names a slot. The caller decides the name: a verified session's player wins
// over what the game server called the slot.
func (r *Recorder) SetPlayer(slot uint32, name, session string, team uint32, bot bool) {
	p := r.player(slot)
	if p == nil {
		return
	}
	p.Name, p.Session, p.Team, p.Bot = name, session, team, bot
}

func (r *Recorder) player(slot uint32) *Player {
	p := r.players[slot]
	if p == nil {
		if len(r.players) >= MaxPlayers {
			r.truncated = true
			return nil
		}
		p = &Player{Slot: slot}
		r.players[slot] = p
	}
	return p
}

func (r *Recorder) ms(tick uint32) int64 { return int64(tick) * 1000 / int64(r.tickRate) }

// Add takes the positions, view angles and shots of one batch, received at the given time.
func (r *Recorder) Add(b *pb.GameplayBatch, at time.Time) {
	if r.mapID == "" {
		if id := b.GetMap().GetMapId(); id != "" && len(id) <= MaxMapID {
			r.mapID = id
		} else if id := b.GetMapGeometry().GetMapId(); id != "" && len(id) <= MaxMapID {
			r.mapID = id
		}
	}
	if r.tickRate == 0 {
		if r.tickRate = b.TickRate; r.tickRate == 0 {
			r.tickRate = defaultTickRate
		}
	}
	end := r.endMs
	for _, m := range b.Motion {
		p := r.player(m.Slot)
		if p == nil {
			continue
		}
		stride := max(m.Stride, 1)
		var x, y int32
		for i := 0; i < len(m.XCm) && i < len(m.YCm); i++ {
			x, y = x+m.XCm[i], y+m.YCm[i]
			t := r.ms(m.FirstTick + uint32(i)*stride)
			end = max(end, t)
			step := int32(t / StepMs)
			if n := len(p.T); n > 0 && p.T[n-1] >= step {
				if p.T[n-1] == step {
					p.X[n-1], p.Y[n-1] = x, y
				}
				continue
			}
			if r.samples >= MaxSamples {
				r.truncated = true
				break
			}
			yaw := int32(0)
			if n := len(p.Yaw); n > 0 {
				yaw = p.Yaw[n-1]
			}
			p.T, p.X, p.Y, p.Yaw = append(p.T, step), append(p.X, x), append(p.Y, y), append(p.Yaw, yaw)
			r.samples++
		}
	}
	for _, a := range b.Aim {
		p := r.players[a.Slot]
		if p == nil || len(p.T) == 0 {
			continue
		}
		for i, yaw := range a.Yaw {
			t := r.ms(a.FirstTick + uint32(i))
			end = max(end, t)
			step := int32(t / StepMs)
			// The view at the last tick of a step stands for the step, and for the steps
			// after it until a newer one is known.
			j := sort.Search(len(p.T), func(k int) bool { return p.T[k] >= step })
			for ; j < len(p.T); j++ {
				p.Yaw[j] = int32(yaw)
			}
		}
	}
	for _, s := range b.Shots {
		t := r.ms(s.Tick)
		end = max(end, t)
		if len(r.shots) >= MaxShots {
			r.truncated = true
			continue
		}
		shot := Shot{int32(t), int32(s.Slot), s.TargetSlot, 0, 0}
		if s.Hit {
			shot[3] = 1
		}
		if s.Kill {
			shot[4] = 1
		}
		r.shots = append(r.shots, shot)
	}
	r.endMs = end
	if len(r.batches) < maxBatches {
		r.batches = append(r.batches, [3]int64{int64(b.BatchSeq), end, at.UnixMilli()})
	}
}

func delta(v []int32) []int32 {
	out := make([]int32, len(v))
	var prev int32
	for i, x := range v {
		out[i], prev = x-prev, x
	}
	return out
}

func undelta(v []int32) {
	var sum int32
	for i, x := range v {
		sum += x
		v[i] = sum
	}
}

// Encode is the recording so far: gzip-compressed JSON, which the dashboard hands to the
// browser as it is.
func (r *Recorder) Encode() ([]byte, error) {
	d := Data{V: 1, Match: r.match, Map: r.mapID, TickRate: r.tickRate, StepMs: StepMs, DurationMs: r.endMs, Shots: r.shots, Batches: r.batches, Truncated: r.truncated}
	if d.Shots == nil {
		d.Shots = []Shot{}
	}
	first := true
	slots := make([]uint32, 0, len(r.players))
	for slot := range r.players {
		slots = append(slots, slot)
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i] < slots[j] })
	for _, slot := range slots {
		p := r.players[slot]
		if len(p.T) == 0 {
			continue
		}
		for i := range p.X {
			if first {
				d.Bounds, first = [4]int32{p.X[i], p.Y[i], p.X[i], p.Y[i]}, false
			}
			d.Bounds[0], d.Bounds[1] = min(d.Bounds[0], p.X[i]), min(d.Bounds[1], p.Y[i])
			d.Bounds[2], d.Bounds[3] = max(d.Bounds[2], p.X[i]), max(d.Bounds[3], p.Y[i])
		}
		c := *p
		c.T, c.X, c.Y, c.Yaw = delta(p.T), delta(p.X), delta(p.Y), delta(p.Yaw)
		d.Players = append(d.Players, c)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > MaxBytes {
		return nil, errors.New("replay: the recording is larger than its size cap")
	}
	return buf.Bytes(), nil
}

// Decode reads an encoded recording, with the players' lists as absolute values.
func Decode(encoded []byte) (*Data, error) {
	zr, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(zr, maxDecoded+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxDecoded {
		return nil, errors.New("replay: the recording is too large to read")
	}
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	for i := range d.Players {
		p := &d.Players[i]
		undelta(p.T)
		undelta(p.X)
		undelta(p.Y)
		undelta(p.Yaw)
	}
	return &d, nil
}

// BatchMs is the match time the batch with this sequence number reached, and whether the
// recording knows the batch.
func (d *Data) BatchMs(seq int64) (int64, bool) {
	i := sort.Search(len(d.Batches), func(k int) bool { return d.Batches[k][0] >= seq })
	if i < len(d.Batches) && d.Batches[i][0] == seq {
		return d.Batches[i][1], true
	}
	return 0, false
}

// WallMs is the match time that had been reached when the gateway's clock showed at, and
// whether at lies within the time the match was being received (with a minute of slack
// after its last batch).
func (d *Data) WallMs(at time.Time) (int64, bool) {
	n := len(d.Batches)
	if n == 0 {
		return 0, false
	}
	w := at.UnixMilli()
	if w < d.Batches[0][2] || w > d.Batches[n-1][2]+60_000 {
		return 0, false
	}
	i := sort.Search(n, func(k int) bool { return d.Batches[k][2] > w })
	return d.Batches[i-1][1], true
}

// TickMs is the match time of a tick.
func (d *Data) TickMs(tick uint32) int64 {
	rate := d.TickRate
	if rate == 0 {
		rate = defaultTickRate
	}
	return int64(tick) * 1000 / int64(rate)
}

// Pose is where the player of a slot stood at a match time, between the two positions
// kept around it, and whether the player was in play then. It is what the dashboard's
// player draws.
func (d *Data) Pose(slot uint32, ms int64) (x, y float64, ok bool) {
	step := d.StepMs
	if step <= 0 {
		step = StepMs
	}
	for i := range d.Players {
		p := &d.Players[i]
		if p.Slot != slot {
			continue
		}
		f := float64(ms) / float64(step)
		n := min(len(p.T), len(p.X), len(p.Y))
		// The first sample after f; the one before it is the last at or before f.
		next := sort.Search(n, func(k int) bool { return float64(p.T[k]) > f })
		at := next - 1
		if at < 0 {
			return 0, 0, false
		}
		if next >= n || p.T[next]-p.T[at] > gapSteps {
			return float64(p.X[at]), float64(p.Y[at]), f-float64(p.T[at]) <= gapSteps
		}
		a := (f - float64(p.T[at])) / float64(p.T[next]-p.T[at])
		return float64(p.X[at]) + float64(p.X[next]-p.X[at])*a, float64(p.Y[at]) + float64(p.Y[next]-p.Y[at])*a, true
	}
	return 0, 0, false
}
