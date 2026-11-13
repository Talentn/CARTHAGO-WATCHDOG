package knowledge

import (
	"fmt"
	"math"
	"sort"

	pb "carthago/backend/gen/carthago/v1"
)

// Config holds the knowledge model's assumptions and the scorer's sampling. Every value
// errs toward crediting the player with more knowledge, because an unexplained leak must
// stay unexplained after the most generous reading of what the player could know.
type Config struct {
	Stride        uint32  // ticks between analysed samples
	FOVDeg        float64 // view cone counted as "could see" (wider than any game's FOV)
	ViewRange     float64 // metres at which an unoccluded enemy counts as seen
	ItemViewRange float64 // metres at which unoccluded loot counts as seen
	FreshSec      float64 // knowledge younger than this explains any aim, wherever the enemy went
	RouteFreshSec float64 // the same for movement, which follows stale information for longer
	SpotMemorySec float64 // a loot spot the team saw empty this recently is not a control
	KnownRadius   float64 // a hidden enemy this close to its last-known position counts as known
	PingRadius    float64 // a location ping reveals enemies and items this close to it
	AlignDeg      float64 // crosshair within this of a target counts as aligned
	ShotAlignDeg  float64
	AimRange      float64 // hidden enemies scored for aim and shots, metres
	RouteRange    float64 // hidden targets scored for movement, metres
	MinSpeed      float64 // movement slower than this is not scored, m/s
	MinItemTier   uint32  // loot below this tier is not scored
	// ShiftsSec are the control offsets: the hidden state at these offsets from "now" is the
	// null model. A player who habitually holds or prefires common angles lines up with where
	// enemies are at other moments just as often as with where they are now; one who sees
	// through walls lines up with "now".
	ShiftsSec []float64
	// Samples are summed in blocks before the z statistic so that correlated
	// neighbouring samples count once. Movement legs last several seconds, so
	// route blocks are longer.
	BlockSec       float64
	RouteBlockSec  float64
	MinBlocks      int // aim blocks needed before the aim feature counts
	MinRouteBlocks int
	MinShots       int // shot samples needed before the shot feature counts
	MaxMoments     int // explanation moments kept per player
	MaxPlayers     int
	Thresholds     map[Segment]Threshold
}

func DefaultConfig() Config {
	return Config{
		Stride: 4, FOVDeg: 120, ViewRange: 90, ItemViewRange: 15,
		FreshSec: 2, RouteFreshSec: 8, SpotMemorySec: 30, KnownRadius: 4, PingRadius: 5,
		AlignDeg: 7, ShotAlignDeg: 5, AimRange: 45, RouteRange: 60, MinSpeed: 1.5, MinItemTier: 2,
		ShiftsSec: []float64{-12, -8, -5, 5, 8, 12}, BlockSec: 4, RouteBlockSec: 10, MinBlocks: 10, MinRouteBlocks: 6, MinShots: 12,
		MaxMoments: 6, MaxPlayers: 128, Thresholds: DefaultThresholds(),
	}
}

const (
	featAim = iota
	featShot
	featRoute
	featLoot
	nFeat
)

var featNames = [nFeat]string{"hidden_aim", "hidden_shots", "hidden_route", "hidden_loot"}
var featLabels = [nFeat]string{
	"Crosshair on enemies the player could not see, hear or be told about",
	"Shots aimed at hidden, unheard enemies",
	"Movement toward hidden, unheard enemies",
	"Movement toward loot the team never saw, against empty spots as close",
}

// eyeToAim lowers the eye position to the point a player aims at (upper chest).
const eyeToAim = 0.3

type sample struct {
	tick     uint32
	pos, vel Vec3
}

type aimSample struct {
	tick       uint32
	yaw, pitch float32
}

type acc struct {
	cur              int64
	curSum           float64
	curN             int
	sumB, sumB2      float64
	blocks, n        int
	sumTrue, sumNull float64
}

func (a *acc) add(block int64, d, t, null float64) {
	if a.curN > 0 && block != a.cur {
		a.flush()
	}
	a.cur = block
	a.curSum += d
	a.curN++
	a.n++
	a.sumTrue += t
	a.sumNull += null
}

func (a *acc) flush() {
	if a.curN == 0 {
		return
	}
	a.sumB += a.curSum
	a.sumB2 += a.curSum * a.curSum
	a.blocks++
	a.curSum, a.curN = 0, 0
}

// z is the self-normalised block sum: about N(0,1) when the behaviour carries no
// information about the hidden state beyond the control offsets.
func (a *acc) z() float64 {
	if a.sumB2 <= 0 {
		return 0
	}
	return a.sumB / math.Sqrt(a.sumB2)
}

type runKind int

const (
	runTrack runKind = iota
	runRouteEnemy
	runRouteItem
)

type run struct {
	start, last         uint32
	n                   int
	errSum              float64
	bearing, rawBearing float64 // unwrapped and last raw bearing to the target, degrees
	bMin, bMax          float64
	startDist, lastDist float64
	known               string
	viewerZone, tgtZone string
}

type pstate struct {
	slot, team uint32
	device     pb.InputDevice
	aimAssist  bool
	motion     []sample
	aim        []aimSample
	feat       [nFeat]acc
	runs       map[[2]uint32]*run // (kind, target)
	moments    []Moment
	shotTicks  map[uint32]uint32 // target -> tick of the last hidden-shot moment
}

type known struct {
	pos  Vec3
	tick uint32
	how  string
}

type item struct {
	pos     Vec3
	tier    uint32
	present bool
}

// Scorer accumulates one match. Feed batches in batch_seq order with Add, then call Finish.
type Scorer struct {
	cfg        Config
	m          *Map
	mode       pb.GameMode
	rate       float64
	players    map[uint32]*pstate
	order      []uint32
	firstTick  uint32
	haveFirst  bool
	maxTick    uint32
	next       uint32
	shiftTicks []int64
	maxShift   uint32
	blockTicks int64
	routeTicks int64

	sounds []*pb.SoundEvent
	team   []*pb.TeamInfo
	items  []*pb.ItemEvent
	vis    []*pb.VisibilityEvent
	shots  []*pb.ShotEvent

	gameVis   map[[2]uint32]bool
	know      map[[2]uint32]*known // (team, enemy)
	itemState map[uint32]*item
	itemKnown map[[2]uint32]bool   // (team, item)
	spotSeen  map[[2]uint32]uint32 // (team, loot spawn index) -> tick last seen
	spotVisit map[uint32]uint32    // loot spawn index -> tick anyone last stood on it
	Dropped   uint64               // samples refused (too many players, out of order)
}

// NewScorer starts a match on a compiled map. mode overrides the map's default when set.
func NewScorer(cfg Config, m *Map, mode pb.GameMode, tickRate uint32) *Scorer {
	if mode == pb.GameMode_GAME_MODE_UNSPECIFIED {
		mode = m.Mode
	}
	if tickRate == 0 {
		tickRate = 64
	}
	if cfg.Stride == 0 {
		cfg.Stride = 1
	}
	s := &Scorer{cfg: cfg, m: m, mode: mode, rate: float64(tickRate), players: map[uint32]*pstate{},
		gameVis: map[[2]uint32]bool{}, know: map[[2]uint32]*known{}, itemState: map[uint32]*item{}, itemKnown: map[[2]uint32]bool{}, spotSeen: map[[2]uint32]uint32{}, spotVisit: map[uint32]uint32{}}
	for _, sh := range cfg.ShiftsSec {
		t := int64(math.Round(sh * s.rate))
		s.shiftTicks = append(s.shiftTicks, t)
		s.maxShift = max(s.maxShift, uint32(abs64(t)))
	}
	s.blockTicks = max(1, int64(cfg.BlockSec*s.rate))
	s.routeTicks = max(1, int64(cfg.RouteBlockSec*s.rate))
	return s
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func (s *Scorer) Map() *Map { return s.m }

// Buffered is the number of motion and aim samples held, which the trim keeps
// to the control window whatever the match length.
func (s *Scorer) Buffered() int {
	n := len(s.sounds) + len(s.team) + len(s.items) + len(s.vis) + len(s.shots)
	for _, p := range s.players {
		n += len(p.motion) + len(p.aim)
	}
	return n
}

func (s *Scorer) Mode() pb.GameMode { return s.mode }

func (s *Scorer) player(slot uint32) *pstate {
	p := s.players[slot]
	if p == nil {
		if len(s.players) >= s.cfg.MaxPlayers {
			return nil
		}
		p = &pstate{slot: slot, team: 1<<20 | slot, runs: map[[2]uint32]*run{}, shotTicks: map[uint32]uint32{}}
		s.players[slot] = p
		s.order = append(s.order, slot)
		sort.Slice(s.order, func(i, j int) bool { return s.order[i] < s.order[j] })
	}
	return p
}

func teamOf(mp *pb.MatchPlayer) uint32 {
	if mp.Team == 0 {
		return 1<<20 | mp.Slot
	}
	return mp.Team
}

// Add folds one batch in and analyses every tick whose control window is complete.
func (s *Scorer) Add(b *pb.GameplayBatch) {
	for _, mp := range b.Players {
		if p := s.player(mp.Slot); p != nil {
			p.team, p.device, p.aimAssist = teamOf(mp), mp.InputDevice, mp.AimAssist
		}
	}
	for _, t := range b.Motion {
		s.addMotion(t)
	}
	for _, t := range b.Aim {
		p := s.player(t.Slot)
		if p == nil {
			s.Dropped++
			continue
		}
		for i := range min(len(t.Yaw), len(t.Pitch)) {
			tick := t.FirstTick + uint32(i)
			if n := len(p.aim); n > 0 && tick <= p.aim[n-1].tick {
				continue
			}
			p.aim = append(p.aim, aimSample{tick, t.Yaw[i], t.Pitch[i]})
		}
	}
	s.sounds = append(s.sounds, b.Sounds...)
	s.team = append(s.team, b.TeamInfo...)
	s.items = append(s.items, b.Items...)
	s.vis = append(s.vis, b.Visibility...)
	s.shots = append(s.shots, b.Shots...)
	for _, q := range [][]uint32{ticksOf(b.Sounds), ticksOf(b.TeamInfo), ticksOf(b.Items)} {
		for _, t := range q {
			s.seeTick(t)
		}
	}
	s.advance(false)
}

type ticked interface{ GetTick() uint32 }

func ticksOf[T ticked](xs []T) []uint32 {
	out := make([]uint32, 0, len(xs))
	for _, x := range xs {
		out = append(out, x.GetTick())
	}
	return out
}

func (s *Scorer) seeTick(t uint32) {
	if !s.haveFirst || t < s.firstTick {
		s.firstTick, s.haveFirst = t, true
		if s.next < t {
			s.next = t - t%s.cfg.Stride
		}
	}
}

func (s *Scorer) addMotion(t *pb.MotionTrack) {
	p := s.player(t.Slot)
	if p == nil {
		s.Dropped++
		return
	}
	stride := max(t.Stride, 1)
	n := min(len(t.XCm), len(t.YCm), len(t.ZCm), len(t.VxCmS), len(t.VyCmS), len(t.VzCmS))
	var x, y, z, vx, vy, vz int64
	for i := range n {
		x, y, z = x+int64(t.XCm[i]), y+int64(t.YCm[i]), z+int64(t.ZCm[i])
		vx, vy, vz = vx+int64(t.VxCmS[i]), vy+int64(t.VyCmS[i]), vz+int64(t.VzCmS[i])
		tick := t.FirstTick + uint32(i)*stride
		if k := len(p.motion); k > 0 && tick <= p.motion[k-1].tick {
			s.Dropped++
			continue
		}
		p.motion = append(p.motion, sample{tick,
			Vec3{float64(x) / 100, float64(y) / 100, float64(z) / 100},
			Vec3{float64(vx) / 100, float64(vy) / 100, float64(vz) / 100}})
		s.seeTick(tick)
		s.maxTick = max(s.maxTick, tick)
	}
}

// Finish analyses the remaining ticks and returns one result per player that moved.
func (s *Scorer) Finish() []Result {
	s.advance(true)
	var out []Result
	for _, slot := range s.order {
		p := s.players[slot]
		for k := range p.runs {
			s.endRun(p, runKind(k[0]), k[1])
		}
		for i := range p.feat {
			p.feat[i].flush()
		}
		if len(p.motion) == 0 && p.feat[featAim].n == 0 {
			continue
		}
		out = append(out, s.result(p))
	}
	return out
}

func (s *Scorer) advance(final bool) {
	if !s.haveFirst {
		return
	}
	for s.next <= s.maxTick && (final || s.next+s.maxShift <= s.maxTick) {
		if s.next >= s.firstTick {
			s.process(s.next)
		}
		s.next += s.cfg.Stride
	}
	s.trim()
}

// trim drops samples older than any control or replay can reach.
func (s *Scorer) trim() {
	keep := int64(s.next) - int64(s.maxShift) - int64(4*s.rate)
	if keep <= 0 {
		return
	}
	for _, p := range s.players {
		i := sort.Search(len(p.motion), func(i int) bool { return int64(p.motion[i].tick) >= keep })
		p.motion = append(p.motion[:0], p.motion[i:]...)
		j := sort.Search(len(p.aim), func(i int) bool { return int64(p.aim[i].tick) >= keep })
		p.aim = append(p.aim[:0], p.aim[j:]...)
	}
}

func (p *pstate) at(t int64, tol int64) (sample, bool) {
	i := sort.Search(len(p.motion), func(i int) bool { return int64(p.motion[i].tick) >= t })
	best, bd := -1, tol+1
	for _, j := range []int{i - 1, i} {
		if j >= 0 && j < len(p.motion) {
			if d := abs64(int64(p.motion[j].tick) - t); d < bd {
				best, bd = j, d
			}
		}
	}
	if best < 0 {
		return sample{}, false
	}
	return p.motion[best], true
}

func (p *pstate) aimAt(t uint32) (Vec3, bool) {
	i := sort.Search(len(p.aim), func(i int) bool { return p.aim[i].tick >= t })
	for _, j := range []int{i, i - 1} {
		if j >= 0 && j < len(p.aim) && abs64(int64(p.aim[j].tick)-int64(t)) <= 2 {
			return dirOf(float64(p.aim[j].yaw), float64(p.aim[j].pitch)), true
		}
	}
	return Vec3{}, false
}

func dirOf(yawDeg, pitchDeg float64) Vec3 {
	y, pt := yawDeg*math.Pi/180, pitchDeg*math.Pi/180
	return Vec3{math.Cos(pt) * math.Cos(y), math.Cos(pt) * math.Sin(y), math.Sin(pt)}
}

// angleTo is the angle in degrees between a unit direction and the vector v.
func angleTo(dir, v Vec3) float64 {
	l := v.Len()
	if l < 1e-9 {
		return 0
	}
	c := dir.Dot(v) / l
	return math.Acos(math.Max(-1, math.Min(1, c))) * 180 / math.Pi
}

func bearingDeg(from, to Vec3) float64 {
	return math.Atan2(to.Y-from.Y, to.X-from.X) * 180 / math.Pi
}

func wrap180(d float64) float64 { return math.Mod(d+540, 360) - 180 }

type live struct {
	p   *pstate
	cur sample
	dir Vec3
	aim bool
}

func aimPoint(eye Vec3) Vec3 { return Vec3{eye.X, eye.Y, eye.Z - eyeToAim} }

// couldSee is the generous sight test: inside a wide cone, in range, and either eye or aim
// point unoccluded.
func (s *Scorer) couldSee(eye, dir, target Vec3) bool {
	v := target.Sub(eye)
	if v.Len() > s.cfg.ViewRange || angleTo(dir, v) > s.cfg.FOVDeg/2 {
		return false
	}
	return s.m.LineOfSight(eye, target) || s.m.LineOfSight(eye, aimPoint(target)) || s.m.bodySight(eye, target)
}

func (s *Scorer) applyEvents(t uint32) {
	take := func(n int, tick func(i int) uint32) int {
		k := 0
		for k < n && tick(k) <= t {
			k++
		}
		return k
	}
	sort.SliceStable(s.vis, func(i, j int) bool { return s.vis[i].Tick < s.vis[j].Tick })
	k := take(len(s.vis), func(i int) uint32 { return s.vis[i].Tick })
	for _, v := range s.vis[:k] {
		s.gameVis[[2]uint32{v.ObserverSlot, v.TargetSlot}] = v.Visible
	}
	s.vis = s.vis[k:]

	sort.SliceStable(s.items, func(i, j int) bool { return s.items[i].Tick < s.items[j].Tick })
	k = take(len(s.items), func(i int) uint32 { return s.items[i].Tick })
	for _, e := range s.items[:k] {
		if e.ItemId == 0 {
			continue
		}
		if len(s.itemState) >= MaxLootSpawns && s.itemState[e.ItemId] == nil {
			continue
		}
		it := &item{pos: Vec3{cm(e.XCm), cm(e.YCm), cm(e.ZCm)}, tier: e.Tier, present: !e.Removed}
		if old := s.itemState[e.ItemId]; old != nil && it.present && (!old.present || old.pos.Dist(it.pos) > 1) {
			// A respawn is a new item as far as anyone's knowledge goes.
			for k := range s.itemKnown {
				if k[1] == e.ItemId {
					delete(s.itemKnown, k)
				}
			}
		}
		s.itemState[e.ItemId] = it
	}
	s.items = s.items[k:]

	sort.SliceStable(s.sounds, func(i, j int) bool { return s.sounds[i].Tick < s.sounds[j].Tick })
	k = take(len(s.sounds), func(i int) uint32 { return s.sounds[i].Tick })
	for _, e := range s.sounds[:k] {
		if e.SourceSlot < 0 {
			continue
		}
		src := s.players[uint32(e.SourceSlot)]
		if src == nil {
			continue
		}
		pos, r := Vec3{cm(e.XCm), cm(e.YCm), cm(e.ZCm)}, float64(e.RadiusCm)/100
		heard := map[uint32]bool{}
		for _, slot := range s.order {
			l := s.players[slot]
			if l.team == src.team || heard[l.team] {
				continue
			}
			if c, ok := l.at(int64(e.Tick), int64(s.cfg.Stride)*2); ok && c.pos.Dist(pos) <= r {
				heard[l.team] = true
				s.know[[2]uint32{l.team, src.slot}] = &known{pos: pos, tick: e.Tick, how: "heard"}
			}
		}
	}
	s.sounds = s.sounds[k:]

	sort.SliceStable(s.team, func(i, j int) bool { return s.team[i].Tick < s.team[j].Tick })
	k = take(len(s.team), func(i int) uint32 { return s.team[i].Tick })
	for _, e := range s.team[:k] {
		team := e.Team
		if team == 0 {
			if e.SourceSlot < 0 {
				continue
			}
			team = 1<<20 | uint32(e.SourceSlot)
		}
		pos := Vec3{cm(e.XCm), cm(e.YCm), cm(e.ZCm)}
		if e.ItemId != 0 {
			s.itemKnown[[2]uint32{team, e.ItemId}] = true
		}
		if e.TargetSlot >= 0 {
			if tp := s.players[uint32(e.TargetSlot)]; tp != nil {
				if c, ok := tp.at(int64(e.Tick), int64(s.cfg.Stride)*2); ok && pos == (Vec3{}) {
					pos = c.pos
				}
			}
			s.know[[2]uint32{team, uint32(e.TargetSlot)}] = &known{pos: pos, tick: e.Tick, how: "spotted for the team"}
			continue
		}
		// A location ping: credit the team with anything near it.
		for _, slot := range s.order {
			tp := s.players[slot]
			if tp.team == team {
				continue
			}
			if c, ok := tp.at(int64(e.Tick), int64(s.cfg.Stride)*2); ok && c.pos.Dist(pos) <= s.cfg.PingRadius {
				s.know[[2]uint32{team, slot}] = &known{pos: c.pos, tick: e.Tick, how: "pinged by a teammate"}
			}
		}
		for id, it := range s.itemState {
			if it.pos.Dist(pos) <= s.cfg.PingRadius {
				s.itemKnown[[2]uint32{team, id}] = true
			}
		}
	}
	s.team = s.team[k:]
}

func (s *Scorer) process(t uint32) {
	s.applyEvents(t)
	tol := int64(s.cfg.Stride) * 2
	lv := make([]live, 0, len(s.order))
	for _, slot := range s.order {
		p := s.players[slot]
		c, ok := p.at(int64(t), tol)
		if !ok {
			continue
		}
		d, aimOK := p.aimAt(t)
		lv = append(lv, live{p: p, cur: c, dir: d, aim: aimOK})
	}

	// What each team could see right now; seeing is shared with the whole team.
	seen := map[[2]uint32]bool{}
	for _, v := range lv {
		for _, e := range lv {
			if e.p.team == v.p.team || seen[[2]uint32{v.p.team, e.p.slot}] {
				continue
			}
			vis := s.gameVis[[2]uint32{v.p.slot, e.p.slot}] || (v.aim && s.couldSee(v.cur.pos, v.dir, e.cur.pos))
			if vis {
				key := [2]uint32{v.p.team, e.p.slot}
				seen[key] = true
				s.know[key] = &known{pos: e.cur.pos, tick: t, how: "seen"}
			}
		}
		if !v.aim {
			continue
		}
		for id, it := range s.itemState {
			key := [2]uint32{v.p.team, id}
			if it.present && !s.itemKnown[key] && s.sees(v, it.pos) {
				s.itemKnown[key] = true
			}
		}
		for i, sp := range s.m.Loot {
			if s.sees(v, sp.Pos) {
				s.spotSeen[[2]uint32{v.p.team, uint32(i)}] = t
			}
			if math.Hypot(sp.Pos.X-v.cur.pos.X, sp.Pos.Y-v.cur.pos.Y) < 2 {
				s.spotVisit[uint32(i)] = t
			}
		}
	}

	block := int64(t) / s.blockTicks
	for _, v := range lv {
		if !v.aim {
			continue
		}
		s.scoreAim(t, block, v, lv, seen)
		s.scoreRoute(t, int64(t)/s.routeTicks, v, lv, seen)
	}
	s.scoreShots(t, block, lv, seen)
}

// sees is the loot sight test: close by, or in view and unoccluded.
func (s *Scorer) sees(v live, p Vec3) bool {
	d := p.Dist(v.cur.pos)
	if d <= 4 {
		return true
	}
	return d <= s.cfg.ItemViewRange && angleTo(v.dir, p.Sub(v.cur.pos)) <= s.cfg.FOVDeg/2 && s.m.LineOfSight(v.cur.pos, p.Add(Vec3{0, 0, 0.3}))
}

// hiddenUnknown: not visible to anyone on the viewer's team and not explained by anything
// the team saw, heard or was told.
func (s *Scorer) hiddenUnknown(t uint32, viewer, enemy *pstate, pos Vec3, seen map[[2]uint32]bool, fresh float64) bool {
	key := [2]uint32{viewer.team, enemy.slot}
	if seen[key] {
		return false
	}
	k := s.know[key]
	if k == nil {
		return true
	}
	if float64(t-min(t, k.tick))/s.rate < fresh {
		return false
	}
	return pos.Dist(k.pos) > s.cfg.KnownRadius
}

func (s *Scorer) knownText(t uint32, viewer, enemy *pstate, pos Vec3) string {
	k := s.know[[2]uint32{viewer.team, enemy.slot}]
	if k == nil {
		return "never seen, heard or reported to the team before this"
	}
	return fmt.Sprintf("last %s %.0f s earlier, %.0f m from where they actually were", k.how, float64(t-min(t, k.tick))/s.rate, pos.Dist(k.pos))
}

// control returns the enemy's position at offset sh if it is a valid control: it must pass
// the same tests as the true position (in range, not visible to the viewer's team now, not
// near where the team last placed that enemy) and be at least minSep from the true
// position. The tests are symmetric in the two positions, so under the null hypothesis a
// control lines up with the player's behaviour exactly as often as the truth does.
func (s *Scorer) control(t uint32, sh int64, v live, e *pstate, truePos Vec3, rng float64, lv []live) (Vec3, bool) {
	c, ok := e.at(int64(t)+sh, int64(s.cfg.Stride)*2)
	if !ok || c.pos.Dist(truePos) < minSep {
		return Vec3{}, false
	}
	d := c.pos.Dist(v.cur.pos)
	if d < 2 || d > rng {
		return Vec3{}, false
	}
	if k := s.know[[2]uint32{v.p.team, e.slot}]; k != nil && c.pos.Dist(k.pos) <= s.cfg.KnownRadius {
		return Vec3{}, false
	}
	for _, m := range lv {
		if m.p.team == v.p.team && m.aim && s.couldSee(m.cur.pos, m.dir, c.pos) {
			return Vec3{}, false
		}
	}
	return c.pos, true
}

// minSep keeps controls distinct from the truth: an enemy standing still gives no evidence
// either way, because habit and knowledge point at the same spot.
const minSep = 3.0

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// scoreAim takes one sample per viewer and tick: is the crosshair on any
// hidden-unknown enemy, against the same question asked of the time-shifted
// controls. A shift only counts when every eligible enemy has a control for it,
// so true and control sets stay the same size.
func (s *Scorer) scoreAim(t uint32, block int64, v live, lv []live, seen map[[2]uint32]bool) {
	var hidden []live
	for _, e := range lv {
		if e.p.team == v.p.team {
			continue
		}
		dist := e.cur.pos.Dist(v.cur.pos)
		if dist < 2 || dist > s.cfg.AimRange || !s.hiddenUnknown(t, v.p, e.p, e.cur.pos, seen, s.cfg.FreshSec) {
			s.endRun(v.p, runTrack, e.p.slot)
			continue
		}
		hidden = append(hidden, e)
	}
	if len(hidden) == 0 {
		return
	}
	hits, n := 0.0, 0
	for _, sh := range s.shiftTicks {
		hit, ok := false, true
		for _, e := range hidden {
			cp, good := s.control(t, sh, v, e.p, e.cur.pos, s.cfg.AimRange, lv)
			if !good {
				ok = false
				break
			}
			hit = hit || angleTo(v.dir, aimPoint(cp).Sub(v.cur.pos)) < s.cfg.AlignDeg
		}
		if ok {
			n++
			hits += b2f(hit)
		}
	}
	anyAligned := false
	for _, e := range hidden {
		errTrue := angleTo(v.dir, aimPoint(e.cur.pos).Sub(v.cur.pos))
		if errTrue >= s.cfg.AlignDeg {
			s.endRun(v.p, runTrack, e.p.slot)
			continue
		}
		anyAligned = true
		r := s.extendRun(v, runTrack, e.p.slot, t, e.cur.pos, e.cur.pos.Dist(v.cur.pos))
		r.errSum += errTrue
		if r.n == 1 {
			r.known = s.knownText(t, v.p, e.p, e.cur.pos)
		}
	}
	if n == 0 {
		return
	}
	null := hits / float64(n)
	v.p.feat[featAim].add(block, b2f(anyAligned)-null, b2f(anyAligned), null)
}

func (s *Scorer) extendRun(v live, kind runKind, target, t uint32, tpos Vec3, dist float64) *run {
	key := [2]uint32{uint32(kind), target}
	r := v.p.runs[key]
	b := bearingDeg(v.cur.pos, tpos)
	if r != nil && t-r.last > 2*s.cfg.Stride {
		s.endRun(v.p, kind, target)
		r = nil
	}
	if r == nil {
		r = &run{start: t, last: t, bearing: b, rawBearing: b, bMin: b, bMax: b, startDist: dist,
			viewerZone: s.m.ZoneName(v.cur.pos), tgtZone: s.m.ZoneName(tpos)}
		v.p.runs[key] = r
	} else {
		r.bearing += wrap180(b - r.rawBearing)
		r.rawBearing = b
		r.bMin, r.bMax = math.Min(r.bMin, r.bearing), math.Max(r.bMax, r.bearing)
	}
	r.last, r.lastDist = t, dist
	r.n++
	return r
}

func (s *Scorer) endRun(p *pstate, kind runKind, target uint32) {
	key := [2]uint32{uint32(kind), target}
	r := p.runs[key]
	if r == nil {
		return
	}
	delete(p.runs, key)
	dur := float64(r.last-r.start+s.cfg.Stride) / s.rate
	var m Moment
	switch kind {
	case runTrack:
		if dur < 0.75 {
			return
		}
		m = Moment{Kind: "tracked_hidden", Tick: r.start, End: r.last, DurationS: dur, TargetSlot: target,
			SweepDeg: r.bMax - r.bMin, MeanErrDeg: r.errSum / float64(r.n), DistanceM: r.startDist,
			ViewerZone: r.viewerZone, TargetZone: r.tgtZone, Known: r.known}
		m.Weight = dur * (1 + m.SweepDeg/30)
	case runRouteEnemy, runRouteItem:
		closed := r.startDist - r.lastDist
		if closed < 10 {
			return
		}
		m = Moment{Kind: "approached_hidden", Tick: r.start, End: r.last, DurationS: dur, DistanceM: r.startDist, ClosedM: closed,
			ViewerZone: r.viewerZone, TargetZone: r.tgtZone, Known: r.known}
		if kind == runRouteItem {
			m.ItemID = target
			m.Kind = "approached_unseen_loot"
		} else {
			m.TargetSlot = target
		}
		m.Weight = closed / 10
	}
	s.keepMoment(p, m)
}

func (s *Scorer) keepMoment(p *pstate, m Moment) {
	if len(p.moments) >= s.cfg.MaxMoments && m.Weight <= p.moments[len(p.moments)-1].Weight {
		return
	}
	m.Replay = s.capture(p, m)
	p.moments = append(p.moments, m)
	sort.SliceStable(p.moments, func(i, j int) bool { return p.moments[i].Weight > p.moments[j].Weight })
	if len(p.moments) > s.cfg.MaxMoments {
		p.moments = p.moments[:s.cfg.MaxMoments]
	}
}

func (s *Scorer) scoreRoute(t uint32, block int64, v live, lv []live, seen map[[2]uint32]bool) {
	vel := Vec3{v.cur.vel.X, v.cur.vel.Y, 0}
	speed := vel.Len()
	if speed < s.cfg.MinSpeed {
		for k := range v.p.runs {
			if runKind(k[0]) != runTrack {
				s.endRun(v.p, runKind(k[0]), k[1])
			}
		}
		return
	}
	heading := vel.Scale(1 / speed)
	closing := func(to Vec3) float64 {
		d := Vec3{to.X - v.cur.pos.X, to.Y - v.cur.pos.Y, 0}
		l := d.Len()
		if l < 1e-6 {
			return 0
		}
		return heading.Dot(d) / l
	}
	for _, e := range lv {
		if e.p.team == v.p.team {
			continue
		}
		dist := e.cur.pos.Dist(v.cur.pos)
		if dist < 3 || dist > s.cfg.RouteRange || !s.hiddenUnknown(t, v.p, e.p, e.cur.pos, seen, s.cfg.RouteFreshSec) {
			s.endRun(v.p, runRouteEnemy, e.p.slot)
			continue
		}
		sum, n := 0.0, 0
		for _, sh := range s.shiftTicks {
			if cp, ok := s.control(t, sh, v, e.p, e.cur.pos, s.cfg.RouteRange, lv); ok {
				sum += closing(cp)
				n++
			}
		}
		if n == 0 {
			continue
		}
		c := closing(e.cur.pos)
		v.p.feat[featRoute].add(block, c-sum/float64(n), c, sum/float64(n))
		if c > 0.8 {
			r := s.extendRun(v, runRouteEnemy, e.p.slot, t, e.cur.pos, dist)
			if r.n == 1 {
				r.known = s.knownText(t, v.p, e.p, e.cur.pos)
			}
		} else {
			s.endRun(v.p, runRouteEnemy, e.p.slot)
		}
	}
	if len(s.itemState) == 0 || len(s.m.Loot) == 0 {
		return
	}
	// Loot: the populated spot against the empty ones the player could equally
	// head for. A spot that still holds loot has usually not been walked over in
	// a while, so the empty controls must not have been either; otherwise they
	// are exactly where players just went.
	var empty []Vec3
	for i, sp := range s.m.Loot {
		if last, ok := s.spotSeen[[2]uint32{v.p.team, uint32(i)}]; ok && float64(t-min(t, last))/s.rate < s.cfg.SpotMemorySec {
			continue
		}
		if last, ok := s.spotVisit[uint32(i)]; ok && float64(t-min(t, last))/s.rate < s.cfg.SpotMemorySec {
			continue
		}
		taken := false
		for _, it := range s.itemState {
			if it.present && it.pos.Dist(sp.Pos) < 2 {
				taken = true
				break
			}
		}
		if d := sp.Pos.Dist(v.cur.pos); !taken && d >= 3 && d <= s.cfg.RouteRange {
			empty = append(empty, sp.Pos)
		}
	}
	ids := make([]uint32, 0, len(s.itemState))
	for id := range s.itemState {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		it := s.itemState[id]
		dist := it.pos.Dist(v.cur.pos)
		if !it.present || it.tier < s.cfg.MinItemTier || s.itemKnown[[2]uint32{v.p.team, id}] || dist < 3 || dist > s.cfg.RouteRange || len(empty) == 0 {
			s.endRun(v.p, runRouteItem, id)
			continue
		}
		sum := 0.0
		for _, e := range empty {
			sum += closing(e)
		}
		null := sum / float64(len(empty))
		c := closing(it.pos)
		v.p.feat[featLoot].add(block, c-null, c, null)
		if c > 0.8 {
			r := s.extendRun(v, runRouteItem, id, t, it.pos, dist)
			if r.n == 1 {
				r.known = fmt.Sprintf("never seen by the team or pinged; %d empty loot spots were as close", len(empty))
			}
		} else {
			s.endRun(v.p, runRouteItem, id)
		}
	}
}

func (s *Scorer) scoreShots(t uint32, block int64, lv []live, seen map[[2]uint32]bool) {
	sort.SliceStable(s.shots, func(i, j int) bool { return s.shots[i].Tick < s.shots[j].Tick })
	k := 0
	for k < len(s.shots) && s.shots[k].Tick <= t {
		k++
	}
	idx := map[uint32]int{}
	for i, v := range lv {
		idx[v.p.slot] = i
	}
	for _, sh := range s.shots[:k] {
		i, ok := idx[sh.Slot]
		if !ok {
			continue
		}
		v := lv[i]
		dir, ok := v.p.aimAt(sh.Tick)
		if !ok {
			continue
		}
		v.dir = dir
		// Shots at someone the team can see are ordinary fighting.
		engaged := false
		var hidden []live
		for _, e := range lv {
			if e.p.team == v.p.team {
				continue
			}
			if seen[[2]uint32{v.p.team, e.p.slot}] {
				if angleTo(dir, aimPoint(e.cur.pos).Sub(v.cur.pos)) < 3*s.cfg.ShotAlignDeg {
					engaged = true
				}
				continue
			}
			if d := e.cur.pos.Dist(v.cur.pos); d >= 2 && d <= s.cfg.AimRange && s.hiddenUnknown(t, v.p, e.p, e.cur.pos, seen, s.cfg.FreshSec) {
				hidden = append(hidden, e)
			}
		}
		if engaged || len(hidden) == 0 {
			continue
		}
		var hitE *live
		for j := range hidden {
			if angleTo(dir, aimPoint(hidden[j].cur.pos).Sub(v.cur.pos)) < s.cfg.ShotAlignDeg {
				hitE = &hidden[j]
				break
			}
		}
		hits, n := 0.0, 0
		for _, off := range s.shiftTicks {
			valid, al := false, false
			for _, e := range hidden {
				cp, ok := s.control(t, off, v, e.p, e.cur.pos, s.cfg.AimRange, lv)
				if !ok {
					continue
				}
				valid = true
				if angleTo(dir, aimPoint(cp).Sub(v.cur.pos)) < s.cfg.ShotAlignDeg {
					al = true
				}
			}
			if valid {
				n++
				hits += b2f(al)
			}
		}
		if n == 0 {
			continue
		}
		null := hits / float64(n)
		v.p.feat[featShot].add(block, b2f(hitE != nil)-null, b2f(hitE != nil), null)
		if hitE != nil {
			last, seenBefore := v.p.shotTicks[hitE.p.slot]
			if seenBefore && sh.Tick-last < uint32(s.rate) {
				continue
			}
			v.p.shotTicks[hitE.p.slot] = sh.Tick
			s.keepMoment(v.p, Moment{Kind: "shot_hidden", Tick: sh.Tick, End: sh.Tick, TargetSlot: hitE.p.slot,
				DistanceM: hitE.cur.pos.Dist(v.cur.pos), MeanErrDeg: angleTo(dir, aimPoint(hitE.cur.pos).Sub(v.cur.pos)),
				ViewerZone: s.m.ZoneName(v.cur.pos), TargetZone: s.m.ZoneName(hitE.cur.pos), Known: s.knownText(t, v.p, hitE.p, hitE.cur.pos),
				Hit: sh.Hit && sh.TargetSlot == int32(hitE.p.slot), Weight: 0.9})
		}
	}
	s.shots = s.shots[k:]
}

// capture records the positions around a moment for the dashboard's top-down view.
func (s *Scorer) capture(p *pstate, m Moment) *Replay {
	step := max(int64(s.rate/4), 1)
	from := int64(m.Tick) - int64(2*s.rate)
	to := int64(m.End) + int64(s.rate)
	r := &Replay{}
	var tgt *pstate
	if m.Kind != "approached_unseen_loot" {
		tgt = s.players[m.TargetSlot]
	}
	for t := from; t <= to; t += step {
		vs, ok := p.at(t, step)
		if !ok {
			continue
		}
		r.Viewer = append(r.Viewer, Vec2{vs.pos.X, vs.pos.Y})
		if t <= int64(m.Tick) || r.EyeZ == 0 {
			r.EyeZ = vs.pos.Z
		}
		if tgt != nil {
			if ts, ok := tgt.at(t, step); ok {
				r.Target = append(r.Target, Vec2{ts.pos.X, ts.pos.Y})
			}
		}
		if t >= int64(m.Tick) && t <= int64(m.End) && (t-int64(m.Tick))%(2*step) == 0 {
			if d, ok := p.aimAt(uint32(t)); ok {
				l := 12.0
				if tgt != nil {
					if ts, ok := tgt.at(t, step); ok {
						l = ts.pos.Dist(vs.pos)
					}
				}
				e := vs.pos.Add(Vec3{d.X, d.Y, 0}.Scale(l / math.Max(math.Hypot(d.X, d.Y), 1e-6)))
				r.Rays = append(r.Rays, [2]Vec2{{vs.pos.X, vs.pos.Y}, {e.X, e.Y}})
			}
		}
	}
	if m.Kind == "approached_unseen_loot" {
		if it := s.itemState[m.ItemID]; it != nil {
			r.Target = []Vec2{{it.pos.X, it.pos.Y}}
			r.TargetIsItem = true
		}
	}
	return r
}

func (s *Scorer) result(p *pstate) Result {
	seg := Segment{Mode: s.mode, Device: p.device}
	th := s.cfg.threshold(seg)
	res := Result{Slot: p.slot, Segment: seg, Calibrated: s.cfg.Calibrated(seg), Threshold: th, AimAssist: p.aimAssist, cfg: s.cfg}
	for i := range p.feat {
		a := &p.feat[i]
		f := FeatureResult{Name: featNames[i], Label: featLabels[i], Z: a.z(), Samples: a.n, Blocks: a.blocks}
		if a.n > 0 {
			f.RateTrue, f.RateNull = a.sumTrue/float64(a.n), a.sumNull/float64(a.n)
		}
		switch i {
		case featShot:
			f.Eligible = a.n >= s.cfg.MinShots
		case featRoute, featLoot:
			f.Eligible = a.blocks >= s.cfg.MinRouteBlocks
		default:
			f.Eligible = a.blocks >= s.cfg.MinBlocks
		}
		res.Features = append(res.Features, f)
	}
	// One test per player-match: the eligible features' z values are combined
	// (Stouffer), which stays N(0,1) under the null instead of taking the
	// maximum of several tests. hidden_loot is reported but not scored: loot
	// that is still there is loot nobody walked to, and empty-spot controls do
	// not yet remove that bias.
	sum, k, excess := 0.0, 0, false
	for i := range res.Features {
		f := &res.Features[i]
		f.Scored = f.Eligible && i != featLoot
		if f.Scored {
			sum += f.Z
			k++
			excess = excess || (f.Z > 0 && f.RateTrue-f.RateNull >= th.MinExcess)
		}
	}
	if k > 0 {
		res.Score = sum / math.Sqrt(float64(k))
	}
	res.Flagged = res.Score >= th.Z && excess
	res.Moments = p.moments
	for i := range res.Moments {
		res.Moments[i].At = s.clock(res.Moments[i].Tick)
	}
	return res
}

func (s *Scorer) clock(t uint32) string {
	sec := int(float64(t-min(t, s.firstTick)) / s.rate)
	return fmt.Sprintf("%02d:%02d", sec/60, sec%60)
}
