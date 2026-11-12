package knowledge

import (
	"fmt"
	"math"
	"sort"

	pb "carthago/backend/gen/carthago/v1"
)

// Decoys (detection strategy B1, version 1). A decoy is a fake enemy the game server
// replicated only to chosen players, where none of their team could see or hear it. An
// honest client culls it like any hidden enemy, so nothing on screen or in the audio points
// at it; a client that reads replicated state (ESP, radar, a DMA reader, a network sniffer)
// shows it like a real player. Reactions to decoys are scored with the leak scorer's null
// model: the same decoy's positions at the control offsets, under the same validity tests,
// so a player who habitually holds the angle a decoy walked behind scores nothing.
//
// Decoys never enter the knowledge model: they are not players, so they change no team's
// sight, hearing or last-known positions, and no leak feature looks at them.

const (
	decAim = iota
	decShot
	decRoute
	nDecFeat
)

var decNames = [nDecFeat]string{"decoy_aim", "decoy_shots", "decoy_route"}
var decLabels = [nDecFeat]string{
	"Crosshair snapping to or tracking a decoy only this player was sent",
	"Shots aimed at a decoy",
	"Movement toward a decoy",
}

type decoy struct {
	id         uint32
	team       uint32
	recipients map[uint32]bool
	spawn      uint32 // first replicated tick; 0 = not replicated yet
	despawn    uint32 // first tick no longer replicated; 0 = still replicated
	cloned     int32
	motion     []sample
	lastTick   uint32
}

// aliveAt is the decoy's position at t if it was being replicated then.
func (d *decoy) aliveAt(t uint32, tol int64) (sample, bool) {
	if d.spawn == 0 || t < d.spawn || (d.despawn != 0 && t >= d.despawn) {
		return sample{}, false
	}
	c, ok := atIn(d.motion, int64(t), tol)
	if !ok || c.tick < d.spawn || (d.despawn != 0 && c.tick >= d.despawn) {
		return sample{}, false
	}
	return c, true
}

type decoyState struct {
	feat      [nDecFeat]acc
	moments   []Moment
	received  map[uint32]bool
	reacted   map[uint32]bool
	shotTicks map[uint32]uint32
	samples   int // viewer ticks with at least one live decoy
	exposed   int // decoy samples dropped because the team could have seen the spot
	explained int // dropped because a real enemy or team information was there
}

// DecoyResult is one player's decoy score for a match.
type DecoyResult struct {
	Segment    Segment
	Calibrated bool
	Threshold  Threshold
	Score      float64
	Flagged    bool
	Received   int // decoys replicated to this player
	Reacted    int // distinct decoys with a tracking, shot or approach moment
	Samples    int
	Exposed    int
	Explained  int
	Features   []FeatureResult
	Moments    []Moment
	cfg        Config
}

func (s *Scorer) addDecoy(t *pb.DecoyTrack) {
	if t.DecoyId == 0 {
		s.Dropped++
		return
	}
	d := s.decoys[t.DecoyId]
	if d == nil {
		if len(s.decoys) >= s.cfg.MaxDecoys {
			s.Dropped++
			return
		}
		d = &decoy{id: t.DecoyId, recipients: map[uint32]bool{}, spawn: t.SpawnTick, cloned: t.ClonedFromSlot}
		s.decoys[t.DecoyId] = d
		s.decoyOrder = append(s.decoyOrder, t.DecoyId)
		sort.Slice(s.decoyOrder, func(i, j int) bool { return s.decoyOrder[i] < s.decoyOrder[j] })
	}
	d.team = t.Team
	if t.SpawnTick != 0 && (d.spawn == 0 || t.SpawnTick < d.spawn) {
		d.spawn = t.SpawnTick
	}
	if t.DespawnTick != 0 {
		d.despawn = t.DespawnTick
	}
	for _, slot := range t.Recipients {
		if len(d.recipients) >= s.cfg.MaxPlayers {
			break
		}
		d.recipients[slot] = true
		if p := s.player(slot); p != nil {
			if p.dec == nil {
				p.dec = &decoyState{received: map[uint32]bool{}, reacted: map[uint32]bool{}, shotTicks: map[uint32]uint32{}}
			}
			p.dec.received[d.id] = true
		}
	}
	if t.Track == nil {
		return
	}
	tr := t.Track
	stride := max(tr.Stride, 1)
	n := min(len(tr.XCm), len(tr.YCm), len(tr.ZCm))
	var x, y, z, vx, vy, vz int64
	for i := range n {
		x, y, z = x+int64(tr.XCm[i]), y+int64(tr.YCm[i]), z+int64(tr.ZCm[i])
		if i < len(tr.VxCmS) && i < len(tr.VyCmS) && i < len(tr.VzCmS) {
			vx, vy, vz = vx+int64(tr.VxCmS[i]), vy+int64(tr.VyCmS[i]), vz+int64(tr.VzCmS[i])
		}
		tick := tr.FirstTick + uint32(i)*stride
		if k := len(d.motion); k > 0 && tick <= d.motion[k-1].tick {
			s.Dropped++
			continue
		}
		d.motion = append(d.motion, sample{tick,
			Vec3{float64(x) / 100, float64(y) / 100, float64(z) / 100},
			Vec3{float64(vx) / 100, float64(vy) / 100, float64(vz) / 100}})
		d.lastTick = tick
	}
}

// trimDecoys keeps decoy tracks to the same window as player motion and forgets decoys
// that ended before it; moments already captured keep their own replay.
func (s *Scorer) trimDecoys(keep int64) {
	out := s.decoyOrder[:0]
	for _, id := range s.decoyOrder {
		d := s.decoys[id]
		i := sort.Search(len(d.motion), func(i int) bool { return int64(d.motion[i].tick) >= keep })
		d.motion = append(d.motion[:0], d.motion[i:]...)
		ended := d.despawn != 0 && int64(d.despawn) < keep
		if ended || (len(d.motion) == 0 && int64(d.lastTick) < keep && d.lastTick != 0) {
			delete(s.decoys, id)
			continue
		}
		out = append(out, id)
	}
	s.decoyOrder = out
}

// decoyCheck is why a decoy position does not count for a viewer.
type decoyCheck int

const (
	decoyOK decoyCheck = iota
	decoyRange
	decoyExposed
	decoyExplained
)

// checkDecoy applies the validity tests to a decoy position (the truth or a control). They
// mirror the placement rule, so the truth and its controls are conditioned alike: beyond
// the quiet distance and in range; hidden from every recipient on the viewer's team in any
// direction, with a peek margin so it is never just behind a corner they hold; and no real
// enemy near it or seen by the team within two alignment widths of it, and nothing the team
// was told of in the last few seconds near it, so aim at a real player is not credited to
// a decoy.
func (s *Scorer) checkDecoy(t uint32, v live, d *decoy, pos Vec3, rng float64, lv []live, seen map[[2]uint32]bool) decoyCheck {
	dist := pos.Dist(v.cur.pos)
	if dist < s.cfg.DecoyMinDist || dist > min(rng, s.cfg.DecoyMaxDist) {
		return decoyRange
	}
	for _, m := range lv {
		if m.p.team == v.p.team && d.recipients[m.p.slot] && m.cur.pos.Dist(pos) <= s.cfg.ViewRange && !s.m.HiddenWithMargin(m.cur.pos, pos, eyeToAim, s.cfg.DecoyPeekM) {
			return decoyExposed
		}
	}
	dirD := unit(aimPoint(pos).Sub(v.cur.pos))
	inLine := func(p Vec3) bool { return angleTo(dirD, aimPoint(p).Sub(v.cur.pos)) < 2*s.cfg.AlignDeg }
	for _, e := range lv {
		if e.p.team == v.p.team {
			continue
		}
		if e.cur.pos.Dist(pos) <= s.cfg.DecoyClearance {
			return decoyExplained
		}
		if seen[[2]uint32{v.p.team, e.p.slot}] && inLine(e.cur.pos) {
			return decoyExplained
		}
		if k := s.know[[2]uint32{v.p.team, e.p.slot}]; k != nil {
			age := float64(t-min(t, k.tick)) / s.rate
			if age < s.cfg.RouteFreshSec && k.pos.Dist(pos) <= s.cfg.DecoyClearance {
				return decoyExplained
			}
		}
	}
	return decoyOK
}

// heardInLine reports whether the team learned of an enemy in the decoy's direction in the
// last FreshSec, by a sound or a call. Such samples still count for the rates, since the
// controls are tested the same way, but they never become moments or reactions: a reviewer
// is only shown reactions nothing the player knew could explain.
func (s *Scorer) heardInLine(t uint32, v live, pos Vec3, lv []live) bool {
	dirD := aimPoint(pos).Sub(v.cur.pos)
	for _, e := range lv {
		if e.p.team == v.p.team {
			continue
		}
		k := s.know[[2]uint32{v.p.team, e.p.slot}]
		if k != nil && float64(t-min(t, k.tick))/s.rate < s.cfg.FreshSec && angleTo(unit(dirD), aimPoint(k.pos).Sub(v.cur.pos)) < 2*s.cfg.AlignDeg {
			return true
		}
	}
	return false
}

func unit(v Vec3) Vec3 {
	l := v.Len()
	if l < 1e-9 {
		return v
	}
	return v.Scale(1 / l)
}

type liveDecoy struct {
	d   *decoy
	pos Vec3
}

// liveDecoys are the decoys replicated to v and alive at t that pass checkDecoy.
func (s *Scorer) liveDecoys(t uint32, v live, rng float64, lv []live, seen map[[2]uint32]bool, count bool) []liveDecoy {
	var out []liveDecoy
	alive := false
	for _, id := range s.decoyOrder {
		d := s.decoys[id]
		if !d.recipients[v.p.slot] {
			continue
		}
		c, ok := d.aliveAt(t, int64(s.cfg.Stride)*2)
		if !ok {
			continue
		}
		alive = true
		switch s.checkDecoy(t, v, d, c.pos, rng, lv, seen) {
		case decoyOK:
			out = append(out, liveDecoy{d, c.pos})
		case decoyExposed:
			if count {
				v.p.dec.exposed++
			}
		case decoyExplained:
			if count {
				v.p.dec.explained++
			}
		}
	}
	if alive && count {
		v.p.dec.samples++
	}
	return out
}

// decoyControl is the decoy's position at offset sh, replicated or not (the pre- and
// post-roll exist for this), if that position passes the same tests now and is at least
// minSep from the truth.
func (s *Scorer) decoyControl(t uint32, sh int64, v live, ld liveDecoy, rng float64, lv []live, seen map[[2]uint32]bool) (Vec3, bool) {
	if int64(t)+sh < 0 {
		return Vec3{}, false
	}
	c, ok := atIn(ld.d.motion, int64(t)+sh, int64(s.cfg.Stride)*2)
	if !ok {
		return Vec3{}, false
	}
	// Controls must point somewhere else: two alignment widths of bearing from the truth, a
	// condition symmetric in the two positions like the leak scorer's minSep.
	if c.pos.Dist(ld.pos) < minSep || angleTo(unit(aimPoint(ld.pos).Sub(v.cur.pos)), aimPoint(c.pos).Sub(v.cur.pos)) < 2*s.cfg.AlignDeg {
		return Vec3{}, false
	}
	if r := s.checkDecoy(t, v, ld.d, c.pos, rng, lv, seen); r != decoyOK {
		return Vec3{}, false
	}
	return c.pos, true
}

func (s *Scorer) scoreDecoys(t uint32, block, routeBlock int64, v live, lv []live, seen map[[2]uint32]bool) {
	ds := s.liveDecoys(t, v, s.cfg.AimRange, lv, seen, true)
	live := map[uint32]bool{}
	for _, ld := range ds {
		live[ld.d.id] = true
	}
	for k := range v.p.runs {
		if kind := runKind(k[0]); kind == runDecoyTrack && !live[k[1]] {
			s.endRun(v.p, kind, k[1])
		}
	}
	if len(ds) > 0 {
		hits, n := 0.0, 0
		for _, sh := range s.shiftTicks {
			hit, ok := false, true
			for _, ld := range ds {
				cp, good := s.decoyControl(t, sh, v, ld, s.cfg.AimRange, lv, seen)
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
		aligned := false
		for _, ld := range ds {
			errTrue := angleTo(v.dir, aimPoint(ld.pos).Sub(v.cur.pos))
			if errTrue >= s.cfg.AlignDeg {
				s.endRun(v.p, runDecoyTrack, ld.d.id)
				continue
			}
			aligned = true
			if s.heardInLine(t, v, ld.pos, lv) {
				s.endRun(v.p, runDecoyTrack, ld.d.id)
				continue
			}
			r := s.extendRun(v, runDecoyTrack, ld.d.id, t, ld.pos, ld.pos.Dist(v.cur.pos))
			r.errSum += errTrue
			if r.n == 1 {
				r.snapDeg = s.snapBefore(v, t)
				r.known = s.decoyKnownText(ld.pos, lv, v)
			}
		}
		if n > 0 {
			null := hits / float64(n)
			v.p.dec.feat[decAim].add(block, b2f(aligned)-null, b2f(aligned), null)
		}
	}
	s.scoreDecoyRoute(t, routeBlock, v, lv, seen)
}

// snapBefore is how far the crosshair turned in the half second before t.
func (s *Scorer) snapBefore(v live, t uint32) float64 {
	back := uint32(s.rate / 2)
	if t < back {
		return 0
	}
	d0, ok := v.p.aimAt(t - back)
	if !ok {
		return 0
	}
	return angleTo(d0, v.dir)
}

func (s *Scorer) decoyKnownText(pos Vec3, lv []live, v live) string {
	near := math.Inf(1)
	for _, e := range lv {
		if e.p.team != v.p.team {
			near = math.Min(near, e.cur.pos.Dist(pos))
		}
	}
	if math.IsInf(near, 1) {
		return "no teammate could see it, it made no sound and nobody pinged it"
	}
	return fmt.Sprintf("no teammate could see it, it made no sound and nobody pinged it; the nearest real enemy was %.0f m from it", near)
}

func (s *Scorer) scoreDecoyRoute(t uint32, block int64, v live, lv []live, seen map[[2]uint32]bool) {
	vel := Vec3{v.cur.vel.X, v.cur.vel.Y, 0}
	speed := vel.Len()
	if speed < s.cfg.MinSpeed {
		for k := range v.p.runs {
			if runKind(k[0]) == runDecoyRoute {
				s.endRun(v.p, runDecoyRoute, k[1])
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
	ds := s.liveDecoys(t, v, s.cfg.RouteRange, lv, seen, false)
	live := map[uint32]bool{}
	for _, ld := range ds {
		live[ld.d.id] = true
		if ld.pos.Dist(v.cur.pos) < 3 {
			continue
		}
		sum, n := 0.0, 0
		for _, sh := range s.shiftTicks {
			if cp, ok := s.decoyControl(t, sh, v, ld, s.cfg.RouteRange, lv, seen); ok {
				sum += closing(cp)
				n++
			}
		}
		if n == 0 {
			continue
		}
		c := closing(ld.pos)
		v.p.dec.feat[decRoute].add(block, c-sum/float64(n), c, sum/float64(n))
		if c > 0.8 && !s.heardInLine(t, v, ld.pos, lv) {
			r := s.extendRun(v, runDecoyRoute, ld.d.id, t, ld.pos, ld.pos.Dist(v.cur.pos))
			if r.n == 1 {
				r.known = s.decoyKnownText(ld.pos, lv, v)
			}
		} else {
			s.endRun(v.p, runDecoyRoute, ld.d.id)
		}
	}
	for k := range v.p.runs {
		if runKind(k[0]) == runDecoyRoute && !live[k[1]] {
			s.endRun(v.p, runDecoyRoute, k[1])
		}
	}
}

// decoyShot scores one shot that was not at an enemy the team could see.
func (s *Scorer) decoyShot(t uint32, block int64, v live, sh *pb.ShotEvent, lv []live, seen map[[2]uint32]bool) {
	ds := s.liveDecoys(t, v, s.cfg.AimRange, lv, seen, false)
	if len(ds) == 0 {
		return
	}
	var hit *liveDecoy
	for i := range ds {
		if angleTo(v.dir, aimPoint(ds[i].pos).Sub(v.cur.pos)) < s.cfg.ShotAlignDeg {
			hit = &ds[i]
			break
		}
	}
	hits, n := 0.0, 0
	for _, off := range s.shiftTicks {
		valid, al := false, false
		for _, ld := range ds {
			cp, ok := s.decoyControl(t, off, v, ld, s.cfg.AimRange, lv, seen)
			if !ok {
				continue
			}
			valid = true
			al = al || angleTo(v.dir, aimPoint(cp).Sub(v.cur.pos)) < s.cfg.ShotAlignDeg
		}
		if valid {
			n++
			hits += b2f(al)
		}
	}
	if n == 0 {
		return
	}
	null := hits / float64(n)
	v.p.dec.feat[decShot].add(block, b2f(hit != nil)-null, b2f(hit != nil), null)
	if hit == nil || s.heardInLine(t, v, hit.pos, lv) {
		return
	}
	if last, ok := v.p.dec.shotTicks[hit.d.id]; ok && sh.Tick-last < uint32(s.rate) {
		return
	}
	v.p.dec.shotTicks[hit.d.id] = sh.Tick
	v.p.dec.reacted[hit.d.id] = true
	s.keepDecoyMoment(v.p, Moment{Kind: "shot_decoy", Tick: sh.Tick, End: sh.Tick, DecoyID: hit.d.id,
		DistanceM: hit.pos.Dist(v.cur.pos), MeanErrDeg: angleTo(v.dir, aimPoint(hit.pos).Sub(v.cur.pos)),
		ViewerZone: s.m.ZoneName(v.cur.pos), TargetZone: s.m.ZoneName(hit.pos), Known: s.decoyKnownText(hit.pos, lv, v), Weight: 1.2})
}

func (s *Scorer) endDecoyRun(p *pstate, kind runKind, id uint32, r *run, dur float64) {
	var m Moment
	switch kind {
	case runDecoyTrack:
		if dur < 0.75 {
			return
		}
		m = Moment{Kind: "tracked_decoy", Tick: r.start, End: r.last, DurationS: dur, DecoyID: id,
			SweepDeg: r.bMax - r.bMin, MeanErrDeg: r.errSum / float64(r.n), DistanceM: r.startDist, SnapDeg: r.snapDeg,
			ViewerZone: r.viewerZone, TargetZone: r.tgtZone, Known: r.known}
		m.Weight = dur * (1 + m.SweepDeg/30)
		if r.snapDeg >= 25 {
			m.Kind = "snapped_to_decoy"
			m.Weight += 1
		}
	case runDecoyRoute:
		closed := r.startDist - r.lastDist
		if closed < 10 {
			return
		}
		m = Moment{Kind: "approached_decoy", Tick: r.start, End: r.last, DurationS: dur, DistanceM: r.startDist, ClosedM: closed,
			DecoyID: id, ViewerZone: r.viewerZone, TargetZone: r.tgtZone, Known: r.known, Weight: closed / 10}
	}
	p.dec.reacted[id] = true
	s.keepDecoyMoment(p, m)
}

func (s *Scorer) keepDecoyMoment(p *pstate, m Moment) {
	ms := p.dec.moments
	if len(ms) >= s.cfg.MaxMoments && m.Weight <= ms[len(ms)-1].Weight {
		return
	}
	m.Replay = s.capture(p, m)
	ms = append(ms, m)
	sort.SliceStable(ms, func(i, j int) bool { return ms[i].Weight > ms[j].Weight })
	if len(ms) > s.cfg.MaxMoments {
		ms = ms[:s.cfg.MaxMoments]
	}
	p.dec.moments = ms
}

func (s *Scorer) decoyResult(p *pstate, seg Segment) *DecoyResult {
	ds := p.dec
	th := s.cfg.decoyThreshold(seg)
	res := &DecoyResult{Segment: seg, Calibrated: s.cfg.decoyCalibrated(seg), Threshold: th, Received: len(ds.received),
		Reacted: len(ds.reacted), Samples: ds.samples, Exposed: ds.exposed, Explained: ds.explained, cfg: s.cfg}
	for i := range ds.feat {
		a := &ds.feat[i]
		a.flush()
		f := FeatureResult{Name: decNames[i], Label: decLabels[i], Z: a.z(), Samples: a.n, Blocks: a.blocks}
		if a.n > 0 {
			f.RateTrue, f.RateNull = a.sumTrue/float64(a.n), a.sumNull/float64(a.n)
		}
		switch i {
		case decShot:
			f.Eligible = a.n >= s.cfg.MinDecoyShots
		case decRoute:
			f.Eligible = a.blocks >= s.cfg.MinDecoyRouteBlocks
		default:
			f.Eligible = a.blocks >= s.cfg.MinDecoyBlocks
		}
		// Route is reported with its moments but not combined: a decoy is replicated for
		// a few seconds, too short for a route change to separate from where players go
		// anyway, so it would add noise to the score and no power.
		f.Scored = f.Eligible && i != decRoute
		res.Features = append(res.Features, f)
	}
	sum, k, excess := 0.0, 0, false
	for _, f := range res.Features {
		if f.Scored {
			sum += f.Z
			k++
			excess = excess || (f.Z > 0 && f.RateTrue-f.RateNull >= th.MinExcess)
		}
	}
	if k > 0 {
		res.Score = sum / math.Sqrt(float64(k))
	}
	// One decoy can line up with a habit by chance; reactions to several distinct decoys
	// cannot, which is what the minimum guards on top of the z threshold.
	res.Flagged = res.Score >= th.Z && excess && res.Reacted >= s.cfg.MinDecoyReactions
	res.Moments = ds.moments
	for i := range res.Moments {
		res.Moments[i].At = s.clock(res.Moments[i].Tick)
	}
	return res
}

// Summary is the one-line evidence summary.
func (r *DecoyResult) Summary() string {
	best := FeatureResult{}
	for _, f := range r.Features {
		if f.Eligible && f.Z >= best.Z {
			best = f
		}
	}
	return fmt.Sprintf("reacted to %d of %d decoys only this player was sent: %s z=%.1f (%.0f%% aligned vs %.0f%% by habit), combined z=%.1f, threshold %.1f for %s",
		r.Reacted, r.Received, best.Name, best.Z, 100*best.RateTrue, 100*best.RateNull, r.Score, r.Threshold.Z, r.Segment)
}
