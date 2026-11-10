package synth

import (
	"fmt"
	"math"
	"strings"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge"
)

// Role is a simulated player's behaviour.
type Role string

const (
	RoleLegit    Role = "legit"    // roams, holds common angles, fights what it sees
	RolePrefire  Role = "prefire"  // legit, holds and prefires common angles aggressively
	RoleSound    Role = "sound"    // legit, tracks enemies through walls by their footsteps
	RoleTeamCall Role = "teamcall" // legit, tracks enemies through walls that teammates spotted
	RoleInformed Role = "informed" // acts on true hidden positions most of the time
	RoleSubtle   Role = "subtle"   // acts on true hidden positions some of the time, sloppily
)

var Roles = []Role{RoleLegit, RolePrefire, RoleSound, RoleTeamCall, RoleInformed, RoleSubtle}

func ParseRole(s string) (Role, bool) {
	for _, r := range Roles {
		if string(r) == s {
			return r, true
		}
	}
	return "", false
}

// Informed reports whether the role uses ground truth it should not have.
func (r Role) Informed() bool { return r == RoleInformed || r == RoleSubtle }

func (r Role) intentP() float64 {
	switch r {
	case RoleInformed:
		return 0.85
	case RoleSubtle:
		return 0.4
	}
	return 0
}

type PlayerSpec struct {
	Slot       uint32
	Team       uint32
	Role       Role
	Device     pb.InputDevice
	AimAssist  bool
	SessionID  string
	PlayerHash string
	MMR        int32
}

type Spec struct {
	MatchID      string
	Mode         pb.GameMode
	TickRate     uint32
	Seconds      int
	Seed         uint64
	MotionStride uint32
	Players      []PlayerSpec
}

// DefaultPlayers is a 5v5 (shooter) or five teams of two (extraction) with the given roles
// starting at firstSlot. Missing roles are legit.
func DefaultPlayers(mode pb.GameMode, firstSlot uint32, roles []Role) []PlayerSpec {
	var out []PlayerSpec
	for i := range 10 {
		r := RoleLegit
		if i < len(roles) {
			r = roles[i]
		}
		team := uint32(i%2 + 1)
		if mode == pb.GameMode_GAME_MODE_EXTRACTION {
			team = uint32(i/2 + 1)
		}
		out = append(out, PlayerSpec{Slot: firstSlot + uint32(i), Team: team, Role: r, Device: pb.InputDevice_INPUT_DEVICE_MOUSE_KEYBOARD,
			PlayerHash: fmt.Sprintf("synth-%d-%s", firstSlot+uint32(i), r), MMR: 1500})
	}
	return out
}

type PlayerFrame struct {
	Slot       uint32
	Pos, Vel   knowledge.Vec3 // eye position, metres and m/s
	Yaw, Pitch float64
	Commands   uint32
}

type Frame struct {
	Tick    uint32
	Players []PlayerFrame
	Sounds  []*pb.SoundEvent
	Team    []*pb.TeamInfo
	Items   []*pb.ItemEvent
	Vis     []*pb.VisibilityEvent
	Shots   []*pb.ShotEvent
}

// rng is xorshift64*, the same generator gs-stub uses.
type rng struct{ s uint64 }

func (r *rng) next() uint64 {
	r.s ^= r.s >> 12
	r.s ^= r.s << 25
	r.s ^= r.s >> 27
	return r.s * 0x2545_f491_4f6c_dd1d
}
func (r *rng) unit() float64                { return float64(r.next()>>11) / float64(uint64(1)<<53) }
func (r *rng) between(a, b float64) float64 { return a + (b-a)*r.unit() }
func (r *rng) intn(n int) int               { return int(r.next() % uint64(n)) }
func (r *rng) normal() float64 {
	u, v := math.Max(r.unit(), 1e-12), r.unit()
	return math.Sqrt(-2*math.Log(u)) * math.Cos(2*math.Pi*v)
}

type heard struct {
	pos knowledge.Vec3
	at  float64
}

type simPlayer struct {
	spec       PlayerSpec
	pos, vel   knowledge.Vec3
	yaw, pitch float64
	path       []int
	at         int
	running    bool
	hold       float64
	look       *knowledge.Vec3
	lookFor    float64
	glance     float64
	step       float64
	engaged    int
	engageAt   float64
	lostFor    float64
	burst      int
	fireIn     float64
	stopFor    float64
	cooldown   map[uint32]float64
	visible    map[uint32]bool
	heard      map[uint32]heard
	intent     bool
	intentIn   float64
	prefire    int
	visited    []int
	hsRate     float64
}

type simItem struct {
	id      uint32
	node    int
	tier    uint32
	present bool
	respawn float64
}

type sim struct {
	spec    Spec
	m       *knowledge.Map
	r       rng
	dt      float64
	now     float64
	tick    uint32
	ps      []*simPlayer
	bySlot  map[uint32]*simPlayer
	spots   map[[2]uint32]heard // (team, enemy) -> last spotted
	spotOut map[[2]uint32]float64
	items   []*simItem
	frame   *Frame
}

var yardMap = func() *knowledge.Map {
	m, err := knowledge.Compile(YardGeometry())
	if err != nil {
		panic(err)
	}
	return m
}()

// YardMap is the compiled test map.
func YardMap() *knowledge.Map { return yardMap }

func v3(n node, z float64) knowledge.Vec3 { return knowledge.Vec3{X: n.x, Y: n.y, Z: z} }

// Run simulates the match and hands each tick to emit.
func Run(spec Spec, emit func(*Frame)) {
	if spec.TickRate == 0 {
		spec.TickRate = 64
	}
	s := &sim{spec: spec, m: yardMap, r: rng{spec.Seed*0x9e37_79b9_7f4a_7c15 | 1}, dt: 1 / float64(spec.TickRate),
		bySlot: map[uint32]*simPlayer{}, spots: map[[2]uint32]heard{}, spotOut: map[[2]uint32]float64{}}
	for i, ps := range spec.Players {
		p := &simPlayer{spec: ps, engaged: -1, cooldown: map[uint32]float64{}, visible: map[uint32]bool{}, heard: map[uint32]heard{}}
		p.at = s.spawnNode(ps, i)
		p.pos = v3(nodes[p.at], EyeHeight)
		p.yaw = s.r.between(-180, 180)
		p.hold = s.r.between(0.5, 2)
		p.intentIn = s.r.between(0, 3)
		p.hsRate = math.Max(0.08, math.Min(0.45, 0.18+0.12*float64(ps.MMR-1500)/1000))
		s.ps = append(s.ps, p)
		s.bySlot[ps.Slot] = p
	}
	ticks := uint32(spec.Seconds) * spec.TickRate
	for t := uint32(1); t <= ticks; t++ {
		s.tick, s.now = t, float64(t)*s.dt
		s.frame = &Frame{Tick: t}
		if t == 1 && spec.Mode == pb.GameMode_GAME_MODE_EXTRACTION {
			s.initItems()
		}
		s.step()
		emit(s.frame)
	}
}

func (s *sim) spawnNode(ps PlayerSpec, i int) int {
	if s.spec.Mode == pb.GameMode_GAME_MODE_EXTRACTION {
		starts := []int{1, 3, 30, 32, 9, 24, 0, 33, 14, 19}
		return starts[int(ps.Team-1)%len(starts)]
	}
	if ps.Team%2 == 1 {
		return []int{0, 1, 2, 3, 2}[i%5]
	}
	return []int{33, 30, 31, 32, 31}[i%5]
}

func (s *sim) initItems() {
	perm := make([]int, len(lootNodes))
	for i := range perm {
		perm[i] = i
	}
	for i := len(perm) - 1; i > 0; i-- {
		j := s.r.intn(i + 1)
		perm[i], perm[j] = perm[j], perm[i]
	}
	for k := range 7 {
		tier := uint32(3)
		if k >= 4 {
			tier = 1
		}
		it := &simItem{id: uint32(k + 1), node: perm[k], tier: tier, present: true}
		s.items = append(s.items, it)
		s.itemEvent(it)
	}
}

func (s *sim) itemEvent(it *simItem) {
	n := nodes[lootNodes[it.node]]
	s.frame.Items = append(s.frame.Items, &pb.ItemEvent{ItemId: it.id, Tick: s.tick, XCm: cmv(n.x), YCm: cmv(n.y), ZCm: 30, Tier: it.tier, Removed: !it.present})
}

func aimPt(p knowledge.Vec3) knowledge.Vec3 { return knowledge.Vec3{X: p.X, Y: p.Y, Z: p.Z - 0.3} }

func dir(yaw, pitch float64) knowledge.Vec3 {
	y, p := yaw*math.Pi/180, pitch*math.Pi/180
	return knowledge.Vec3{X: math.Cos(p) * math.Cos(y), Y: math.Cos(p) * math.Sin(y), Z: math.Sin(p)}
}

func angles(from, to knowledge.Vec3) (yaw, pitch float64) {
	d := to.Sub(from)
	return math.Atan2(d.Y, d.X) * 180 / math.Pi, math.Atan2(d.Z, math.Hypot(d.X, d.Y)) * 180 / math.Pi
}

func angleBetween(a, b knowledge.Vec3) float64 {
	c := a.Dot(b) / math.Max(a.Len()*b.Len(), 1e-9)
	return math.Acos(math.Max(-1, math.Min(1, c))) * 180 / math.Pi
}

func wrap(d float64) float64 { return math.Mod(d+540, 360) - 180 }

// canSee is the game's own visibility trace: a 100° view cone, 60 m, eye or chest unoccluded.
func (s *sim) canSee(a, b *simPlayer) bool {
	d := b.pos.Sub(a.pos)
	if d.Len() > 60 || angleBetween(dir(a.yaw, a.pitch), d) > 50 {
		return false
	}
	return s.m.LineOfSight(a.pos, b.pos) || s.m.LineOfSight(a.pos, aimPt(b.pos))
}

func (s *sim) enemies(p *simPlayer) []*simPlayer {
	var out []*simPlayer
	for _, q := range s.ps {
		if q.spec.Team != p.spec.Team {
			out = append(out, q)
		}
	}
	return out
}

func (s *sim) step() {
	// Visibility, the game's trace events and automatic team spots.
	for _, p := range s.ps {
		for _, e := range s.enemies(p) {
			vis := s.canSee(p, e)
			if vis != p.visible[e.spec.Slot] {
				p.visible[e.spec.Slot] = vis
				s.frame.Vis = append(s.frame.Vis, &pb.VisibilityEvent{ObserverSlot: p.spec.Slot, TargetSlot: e.spec.Slot, Tick: s.tick, Visible: vis})
			}
			if vis {
				key := [2]uint32{p.spec.Team, e.spec.Slot}
				s.spots[key] = heard{e.pos, s.now}
				if s.now-s.spotOut[key] >= 0.5 {
					s.spotOut[key] = s.now
					s.frame.Team = append(s.frame.Team, &pb.TeamInfo{Tick: s.tick, Team: p.spec.Team, Kind: pb.TeamInfoKind_TEAM_INFO_KIND_SPOTTED,
						SourceSlot: int32(p.spec.Slot), TargetSlot: int32(e.spec.Slot), XCm: cmv(e.pos.X), YCm: cmv(e.pos.Y), ZCm: cmv(e.pos.Z), DurationMs: 2000})
				}
			}
		}
	}
	for _, p := range s.ps {
		s.think(p)
	}
	if len(s.items) > 0 {
		s.loot()
	}
	for _, p := range s.ps {
		s.frame.Players = append(s.frame.Players, PlayerFrame{Slot: p.spec.Slot, Pos: p.pos, Vel: p.vel, Yaw: p.yaw, Pitch: p.pitch, Commands: 1})
	}
}

func (s *sim) nearestVisible(p *simPlayer) *simPlayer {
	var best *simPlayer
	bd := math.Inf(1)
	for _, e := range s.enemies(p) {
		if p.visible[e.spec.Slot] && s.now >= p.cooldown[e.spec.Slot] && e.pos.Dist(p.pos) < 40 {
			if d := e.pos.Dist(p.pos); d < bd {
				best, bd = e, d
			}
		}
	}
	return best
}

// hiddenNearest is the informed player's ground truth: the closest enemy it
// cannot see, preferring one it has not just heard and no teammate sees, since
// that is what the leaked information adds over normal team play.
func (s *sim) hiddenNearest(p *simPlayer, rng float64) *simPlayer {
	var best *simPlayer
	bd := rng
	for _, e := range s.enemies(p) {
		if p.visible[e.spec.Slot] {
			continue
		}
		d := e.pos.Dist(p.pos)
		if h, ok := p.heard[e.spec.Slot]; s.teamSees(p, e) || (ok && s.now-h.at < 2) {
			d += 25
		}
		if d < bd {
			best, bd = e, d
		}
	}
	return best
}

func (s *sim) teamSees(p, e *simPlayer) bool {
	for _, m := range s.ps {
		if m != p && m.spec.Team == p.spec.Team && m.visible[e.spec.Slot] {
			return true
		}
	}
	return false
}

func (s *sim) think(p *simPlayer) {
	role := p.spec.Role
	if p.intentIn -= s.dt; p.intentIn <= 0 {
		p.intentIn = s.r.between(2.5, 4)
		p.intent = s.r.unit() < role.intentP()
	}

	// Engagement with what the player can see.
	if p.engaged >= 0 {
		e := s.bySlot[uint32(p.engaged)]
		if p.visible[uint32(p.engaged)] {
			p.lostFor = 0
		} else if p.lostFor += s.dt; p.lostFor > 0.4 {
			p.engaged = -1
		}
		if e != nil && (p.burst >= 5 || s.now-p.engageAt > 2.5) {
			p.cooldown[e.spec.Slot] = s.now + s.r.between(5, 9)
			p.engaged = -1
		}
	}
	if p.engaged < 0 {
		if e := s.nearestVisible(p); e != nil {
			p.engaged, p.engageAt, p.burst, p.lostFor = int(e.spec.Slot), s.now+s.r.between(0.17, 0.3), 0, 0
			p.fireIn = 0
			p.stopFor = s.r.between(0.8, 1.6)
		}
	}

	var want *knowledge.Vec3
	tau := 0.15
	var tracking *simPlayer
	switch {
	case p.engaged >= 0 && s.now >= p.engageAt:
		e := s.bySlot[uint32(p.engaged)]
		a := aimPt(e.pos)
		want, tau = &a, 0.08
		if p.spec.AimAssist {
			tau = 0.06
		}
	case p.engaged >= 0:
		// Reacting: the crosshair has not started moving yet.
	case role.Informed() && p.intent:
		rngMax := 40.0
		if role == RoleSubtle {
			rngMax = 28
		}
		if e := s.hiddenNearest(p, rngMax); e != nil {
			a := aimPt(e.pos)
			noise := 1.0
			if role == RoleSubtle {
				noise = 3
			}
			a = a.Add(knowledge.Vec3{X: s.r.normal() * noise * 0.1, Y: s.r.normal() * noise * 0.1})
			want, tracking, tau = &a, e, 0.1
		}
	case role == RoleSound:
		var best *heard
		for _, h := range p.heard {
			if s.now-h.at < 2.5 {
				h := h
				if best == nil || h.at > best.at {
					best = &h
				}
			}
		}
		if best != nil {
			a := knowledge.Vec3{X: best.pos.X, Y: best.pos.Y, Z: 1.3}
			want = &a
		}
	case role == RoleTeamCall:
		var best *heard
		for _, e := range s.enemies(p) {
			if h, ok := s.spots[[2]uint32{p.spec.Team, e.spec.Slot}]; ok && s.now-h.at < 3 && !p.visible[e.spec.Slot] && h.pos.Dist(p.pos) < 45 {
				h := h
				if best == nil || h.pos.Dist(p.pos) < best.pos.Dist(p.pos) {
					best = &h
				}
			}
		}
		if best != nil {
			a := aimPt(best.pos)
			want = &a
		}
	}
	moving := p.hold <= 0 && !(p.engaged >= 0 && p.stopFor > 0)
	if want == nil && !(p.engaged >= 0 && s.now < p.engageAt) {
		want = s.habitLook(p, moving)
	}
	if want != nil {
		s.turn(p, *want, tau)
	}
	s.fire(p, tracking)
	s.move(p, moving)
}

// habitLook is where a legit player looks with no enemy information: along the path, glancing
// at doors and corners, or holding one while stopped.
func (s *sim) habitLook(p *simPlayer, moving bool) *knowledge.Vec3 {
	if p.look != nil {
		if p.lookFor -= s.dt; p.lookFor > 0 {
			return p.look
		}
		p.look = nil
	}
	if !moving {
		if a := s.pickAngle(p, 180); a != nil {
			p.look, p.lookFor = a, s.r.between(1.2, 3.5)
			if p.spec.Role == RolePrefire {
				p.lookFor *= 1.4
				if s.r.unit() < 0.6 {
					p.prefire = 2 + s.r.intn(2)
				}
			}
			return p.look
		}
		return nil
	}
	if p.glance -= s.dt; p.glance <= 0 {
		p.glance = s.r.between(1.2, 2.8)
		if a := s.pickAngle(p, 75); a != nil {
			p.look, p.lookFor = a, s.r.between(0.4, 0.9)
			if p.spec.Role == RolePrefire && s.r.unit() < 0.35 {
				p.prefire = 2
			}
			return p.look
		}
	}
	h := math.Hypot(p.vel.X, p.vel.Y)
	if h < 0.1 {
		return nil
	}
	ahead := p.pos.Add(knowledge.Vec3{X: p.vel.X / h * 10, Y: p.vel.Y / h * 10})
	return &ahead
}

func (s *sim) pickAngle(p *simPlayer, within float64) *knowledge.Vec3 {
	head := math.Atan2(p.vel.Y, p.vel.X) * 180 / math.Pi
	if math.Hypot(p.vel.X, p.vel.Y) < 0.1 {
		head = p.yaw
	}
	var opts []knowledge.Vec3
	for _, c := range commonAngles {
		pt := knowledge.Vec3{X: c.x, Y: c.y, Z: 1.3}
		d := pt.Dist(p.pos)
		if d < 3 || d > 35 {
			continue
		}
		y, _ := angles(p.pos, pt)
		if math.Abs(wrap(y-head)) > within {
			continue
		}
		if s.m.LineOfSight(p.pos, pt) {
			opts = append(opts, pt)
		}
	}
	if len(opts) == 0 {
		return nil
	}
	a := opts[s.r.intn(len(opts))]
	return &a
}

func (s *sim) turn(p *simPlayer, want knowledge.Vec3, tau float64) {
	wy, wp := angles(p.pos, want)
	maxStep := 420 * s.dt
	if p.spec.Device == pb.InputDevice_INPUT_DEVICE_CONTROLLER {
		// Sticks turn slower and settle less precisely than a mouse.
		tau *= 1.6
		maxStep = 240 * s.dt
	}
	k := 1 - math.Exp(-s.dt/tau)
	dy := math.Max(-maxStep, math.Min(maxStep, wrap(wy-p.yaw)*k))
	dp := math.Max(-maxStep, math.Min(maxStep, (wp-p.pitch)*k))
	p.yaw = wrap(p.yaw + dy + s.r.normal()*0.12)
	p.pitch = math.Max(-60, math.Min(60, p.pitch+dp+s.r.normal()*0.06))
}

func (s *sim) shoot(p *simPlayer, target int32, hit bool, dist float64) {
	sh := &pb.ShotEvent{Slot: p.spec.Slot, Tick: s.tick, TargetSlot: target, Hit: hit, Weapon: "rifle", DistanceM: float32(dist)}
	if hit {
		sh.Headshot = s.r.unit() < p.hsRate
	}
	s.frame.Shots = append(s.frame.Shots, sh)
	s.sound(p, pb.SoundKind_SOUND_KIND_GUNSHOT, p.pos, 60)
}

func (s *sim) fire(p *simPlayer, tracking *simPlayer) {
	if p.fireIn -= s.dt; p.fireIn > 0 {
		return
	}
	look := dir(p.yaw, p.pitch)
	if p.engaged >= 0 && s.now >= p.engageAt && p.visible[uint32(p.engaged)] {
		e := s.bySlot[uint32(p.engaged)]
		err := angleBetween(look, aimPt(e.pos).Sub(p.pos))
		if err < 4 {
			hit := err < 1.5 && s.r.unit() < 0.75
			s.shoot(p, int32(e.spec.Slot), hit, e.pos.Dist(p.pos))
			p.burst++
			p.fireIn = s.r.between(0.12, 0.17)
		}
		return
	}
	if p.prefire > 0 && p.look != nil && angleBetween(look, p.look.Sub(p.pos)) < 3 {
		s.shoot(p, -1, false, p.look.Dist(p.pos))
		p.prefire--
		p.fireIn = s.r.between(0.11, 0.15)
		return
	}
	if tracking != nil && tracking.pos.Dist(p.pos) < 30 && angleBetween(look, aimPt(tracking.pos).Sub(p.pos)) < 3 && s.r.unit() < 0.012 {
		s.shoot(p, -1, false, tracking.pos.Dist(p.pos))
		p.fireIn = s.r.between(0.3, 0.8)
	}
}

func (s *sim) sound(src *simPlayer, kind pb.SoundKind, at knowledge.Vec3, radius float64) {
	s.frame.Sounds = append(s.frame.Sounds, &pb.SoundEvent{Tick: s.tick, SourceSlot: int32(src.spec.Slot), Kind: kind,
		XCm: cmv(at.X), YCm: cmv(at.Y), ZCm: cmv(at.Z), RadiusCm: uint32(radius * 100)})
	for _, q := range s.ps {
		if q.spec.Team != src.spec.Team && q.pos.Dist(at) <= radius {
			q.heard[src.spec.Slot] = heard{at, s.now}
		}
	}
}

func (s *sim) move(p *simPlayer, moving bool) {
	if p.engaged >= 0 && p.stopFor > 0 {
		p.stopFor -= s.dt
	}
	if !moving {
		if p.hold > 0 {
			p.hold -= s.dt
		}
		p.vel = knowledge.Vec3{}
		if p.hold <= 0 && len(p.path) == 0 && !(p.engaged >= 0 && p.stopFor > 0) {
			s.newGoal(p)
		}
		return
	}
	if len(p.path) == 0 {
		s.newGoal(p)
		if len(p.path) == 0 {
			p.vel = knowledge.Vec3{}
			return
		}
	}
	speed := 2.2
	if p.running {
		speed = 5
	}
	tgt := v3(nodes[p.path[0]], EyeHeight)
	d := tgt.Sub(p.pos)
	l := d.Len()
	stepLen := speed * s.dt
	if l <= stepLen {
		p.pos = tgt
		p.at = p.path[0]
		p.path = p.path[1:]
		if len(p.path) == 0 {
			p.hold = s.r.between(2, 6)
			if p.spec.Role == RolePrefire {
				p.hold += 1.5
			}
		}
		p.vel = d.Scale(1 / s.dt)
	} else {
		p.vel = d.Scale(speed / l)
		p.pos = p.pos.Add(p.vel.Scale(s.dt))
	}
	if p.running {
		if p.step -= s.dt; p.step <= 0 {
			p.step = 0.33
			s.sound(p, pb.SoundKind_SOUND_KIND_FOOTSTEP, knowledge.Vec3{X: p.pos.X, Y: p.pos.Y, Z: 0.05}, 18)
		}
	}
}

func (s *sim) newGoal(p *simPlayer) {
	goal := -1
	informed := p.spec.Role.Informed() && p.intent
	if s.spec.Mode == pb.GameMode_GAME_MODE_EXTRACTION {
		if informed && s.r.unit() < 0.8 {
			bd := math.Inf(1)
			for _, it := range s.items {
				n := lootNodes[it.node]
				if it.present && it.tier >= 2 && n != p.at {
					if d := v3(nodes[n], EyeHeight).Dist(p.pos); d < bd {
						goal, bd = n, d
					}
				}
			}
		}
		if goal < 0 {
			for range 8 {
				g := lootNodes[s.r.intn(len(lootNodes))]
				if g != p.at && !contains(p.visited, g) {
					goal = g
					break
				}
			}
		}
	} else if informed && s.r.unit() < 0.6 {
		if e := s.hiddenNearest(p, 60); e != nil {
			goal = nearestNode(e.pos)
		}
	}
	if goal < 0 || goal == p.at {
		goal = laneNodes[s.r.intn(len(laneNodes))]
	}
	p.path = route(p.at, goal)
	p.running = s.r.unit() < 0.6
	p.visited = append(p.visited, goal)
	if len(p.visited) > 4 {
		p.visited = p.visited[1:]
	}
}

func contains(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func nearestNode(p knowledge.Vec3) int {
	best, bd := 0, math.Inf(1)
	for i, n := range nodes {
		if d := math.Hypot(n.x-p.X, n.y-p.Y); d < bd {
			best, bd = i, d
		}
	}
	return best
}

// route is the shortest node path from a to b (excluding a).
func route(a, b int) []int {
	adj := make([][]int, len(nodes))
	for _, e := range edges {
		adj[e[0]] = append(adj[e[0]], e[1])
		adj[e[1]] = append(adj[e[1]], e[0])
	}
	dist := make([]float64, len(nodes))
	prev := make([]int, len(nodes))
	done := make([]bool, len(nodes))
	for i := range dist {
		dist[i], prev[i] = math.Inf(1), -1
	}
	dist[a] = 0
	for {
		u := -1
		for i := range nodes {
			if !done[i] && (u < 0 || dist[i] < dist[u]) {
				u = i
			}
		}
		if u < 0 || math.IsInf(dist[u], 1) || u == b {
			break
		}
		done[u] = true
		for _, v := range adj[u] {
			if d := dist[u] + math.Hypot(nodes[u].x-nodes[v].x, nodes[u].y-nodes[v].y); d < dist[v] {
				dist[v], prev[v] = d, u
			}
		}
	}
	var out []int
	for v := b; v != a && v >= 0; v = prev[v] {
		out = append(out, v)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *sim) loot() {
	for _, it := range s.items {
		n := nodes[lootNodes[it.node]]
		pos := knowledge.Vec3{X: n.x, Y: n.y, Z: 0.3}
		if !it.present {
			if s.now >= it.respawn {
				// Respawn at a random free spot.
				for range 12 {
					k := s.r.intn(len(lootNodes))
					free := true
					for _, o := range s.items {
						if o.present && o.node == k {
							free = false
						}
					}
					if free {
						it.node, it.present = k, true
						s.itemEvent(it)
						break
					}
				}
			}
			continue
		}
		for _, p := range s.ps {
			if math.Hypot(p.pos.X-pos.X, p.pos.Y-pos.Y) < 1.5 {
				it.present, it.respawn = false, s.now+s.r.between(25, 45)
				s.itemEvent(it)
				s.frame.Sounds = append(s.frame.Sounds, &pb.SoundEvent{Tick: s.tick, SourceSlot: int32(p.spec.Slot), Kind: pb.SoundKind_SOUND_KIND_INTERACT,
					XCm: cmv(pos.X), YCm: cmv(pos.Y), ZCm: cmv(pos.Z), RadiusCm: 1000})
				break
			}
			// Legit players ping loot they see for the team now and then.
			if !p.spec.Role.Informed() && pos.Dist(p.pos) < 30 && s.r.unit() < 0.004 && s.m.LineOfSight(p.pos, pos) &&
				angleBetween(dir(p.yaw, p.pitch), pos.Sub(p.pos)) < 50 {
				s.frame.Team = append(s.frame.Team, &pb.TeamInfo{Tick: s.tick, Team: p.spec.Team, Kind: pb.TeamInfoKind_TEAM_INFO_KIND_PING,
					SourceSlot: int32(p.spec.Slot), TargetSlot: -1, ItemId: it.id, XCm: cmv(pos.X), YCm: cmv(pos.Y), ZCm: cmv(pos.Z), DurationMs: 5000})
			}
		}
	}
}

// ModeName is the scenario-file spelling of a mode.
func ModeName(m pb.GameMode) string {
	switch m {
	case pb.GameMode_GAME_MODE_EXTRACTION:
		return "extraction"
	case pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER:
		return "shooter"
	}
	return "unspecified"
}

func ParseMode(s string) (pb.GameMode, error) {
	switch strings.ToLower(s) {
	case "shooter", "competitive_shooter":
		return pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, nil
	case "extraction":
		return pb.GameMode_GAME_MODE_EXTRACTION, nil
	}
	return 0, fmt.Errorf("unknown mode %q (shooter, extraction)", s)
}
