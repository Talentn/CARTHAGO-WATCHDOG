package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/knowledge"
	"carthago/backend/internal/store"
)

// RuleInformationLeak is the evidence rule of the knowledge-aware wallhack scorer.
const RuleInformationLeak = "information_leak"

// RuleDecoyReaction is the evidence rule for reactions to decoys only the player was sent.
// It is its own evidence family: flag-only, never integrity evidence, never a kick.
const RuleDecoyReaction = "decoy_reaction"

// RuleInformationLeakLive is the opt-in live rule's evidence (Config.LeakAlert).
const RuleInformationLeakLive = "information_leak_live"

// A map whose walls contain more than this share of the players' positions is not the map
// being played. Positions are eyes of living players, which the game never puts in a wall.
const (
	maxInSolid        = 0.02
	minSolidPositions = 400
)

// maxCachedMaps bounds compiled maps held in memory; a miss reloads from the store.
const maxCachedMaps = 64

// summaryEvery is how many batches pass between gameplay summary writes while a match runs.
const summaryEvery = 30

type mapKey struct {
	tenant, id string
	version    uint32
}

// v2State is a match's telemetry v2 analysis, owned by the worker.
type v2State struct {
	scorer    *knowledge.Scorer
	ref       *pb.MapRef
	mode      pb.GameMode
	warned    string // the map problem already reported to the game server
	batches   uint64
	dropped   uint64
	summaries map[uint32]*store.GameplaySummary
	results   map[uint32]knowledge.Result // set once, when the match is scored
	mapNote   string                      // where the geometry came from and whether it is pinned
	alerter   *knowledge.Alerter
	positions uint64 // player positions tested against the map's solid world
	inSolid   uint64
	mismatch  bool
}

// v2 handles the telemetry v2 part of a fresh batch: map geometry, raw storage,
// knowledge scoring and the per-slot summary. It returns a warning for the
// game server when part of the batch could not be used.
func (p *Pipeline) v2(ctx context.Context, tenant string, ms *matchState, b *pb.GameplayBatch, at time.Time) (warning string, evs []store.Evidence) {
	if b.SchemaVersion < 2 && b.MapGeometry == nil && len(b.Motion) == 0 {
		return "", nil
	}
	v := ms.v2
	if v == nil {
		v = &v2State{summaries: map[uint32]*store.GameplaySummary{}}
		ms.v2 = v
	}
	v.batches++
	v.dropped += uint64(b.DroppedEvents)
	if b.Mode != pb.GameMode_GAME_MODE_UNSPECIFIED {
		v.mode = b.Mode
	}

	if raw, err := proto.Marshal(b); err == nil {
		if err := p.st.PutGameplayBatch(ctx, &store.GameplayBatchRow{TenantID: tenant, MatchID: b.MatchId, BatchSeq: b.BatchSeq, ReceivedAt: at, Data: raw}); err != nil {
			p.log.Warn("persist gameplay batch", "match", b.MatchId, "err", err)
		}
	}

	if b.MapGeometry != nil {
		if err := p.putMap(ctx, tenant, b.MapGeometry, at); err != nil {
			warning = "map geometry refused: " + err.Error()
			p.log.Warn("map geometry refused", "tenant", tenant, "match", b.MatchId, "map", b.MapGeometry.MapId, "err", err)
		}
		if v.ref == nil {
			v.ref = &pb.MapRef{MapId: b.MapGeometry.MapId, Version: b.MapGeometry.Version}
		}
	}
	if b.Map != nil && b.Map.MapId != "" {
		v.ref = b.Map
	}
	if v.scorer == nil && v.ref != nil {
		m, err := p.loadMap(ctx, tenant, v.ref)
		var note string
		if err == nil {
			note, err = p.mapPin(m)
		}
		switch {
		case err == nil:
			v.scorer, v.mapNote = knowledge.NewScorer(p.cfg.Leak, m, v.mode, b.TickRate), note
			if p.cfg.LeakAlert != nil {
				v.alerter = knowledge.NewAlerter(*p.cfg.LeakAlert, v.scorer)
			}
			p.log.Info("map in use", "match", b.MatchId, "map", m.ID, "version", m.Version, "geometry", m.Describe(), "note", note)
		case warning == "" && v.warned == "" && errors.Is(err, errMapPin):
			warning = err.Error() + "; information-leak scoring is off for this match"
			p.log.Warn("map geometry refused", "tenant", tenant, "match", b.MatchId, "map", v.ref.MapId, "err", err)
		case warning == "" && v.warned == "":
			warning = fmt.Sprintf("map %s v%d unknown: upload its geometry; information-leak scoring is off for this match", v.ref.MapId, v.ref.Version)
		}
	}
	if warning != "" {
		if warning == v.warned {
			warning = ""
		} else {
			v.warned = warning
		}
	}
	if v.scorer != nil {
		if w := p.checkPositions(v, b); w != "" && warning == "" {
			warning = w
		}
		v.scorer.Add(b)
	}
	p.countV2(tenant, ms, v, b, at)

	if v.alerter != nil && !v.mismatch {
		evs = p.leakAlerts(tenant, ms, v, b, at)
	}
	if b.MatchOver && v.scorer != nil {
		evs = append(evs, p.leakEvidence(tenant, ms, v, b, at)...)
	}
	if b.MatchOver || v.batches == 1 || v.batches%summaryEvery == 0 {
		rows := make([]store.GameplaySummary, 0, len(v.summaries))
		for _, s := range v.summaries {
			rows = append(rows, *s)
		}
		if err := p.st.UpsertGameplaySummaries(ctx, rows); err != nil {
			p.log.Warn("persist gameplay summary", "match", b.MatchId, "err", err)
		}
	}
	return warning, evs
}

func (p *Pipeline) countV2(tenant string, ms *matchState, v *v2State, b *pb.GameplayBatch, at time.Time) {
	sum := func(slot uint32) *store.GameplaySummary {
		s := v.summaries[slot]
		if s == nil {
			if len(v.summaries) >= p.cfg.Leak.MaxPlayers {
				return nil
			}
			s = &store.GameplaySummary{TenantID: tenant, MatchID: b.MatchId, Slot: slot, SchemaVersion: b.SchemaVersion}
			v.summaries[slot] = s
		}
		return s
	}
	for _, mp := range b.Players {
		if s := sum(mp.Slot); s != nil {
			s.Team, s.Device, s.AimAssist = mp.Team, knowledge.DeviceName(mp.InputDevice), mp.AimAssist
			s.PlayerHash = mp.PlayerHash
		}
	}
	touched := map[uint32]bool{}
	for _, t := range b.Motion {
		if s := sum(t.Slot); s != nil {
			s.MotionSamples += uint64(len(t.XCm))
			touched[t.Slot] = true
		}
	}
	for _, e := range b.Sounds {
		if e.SourceSlot >= 0 {
			if s := v.summaries[uint32(e.SourceSlot)]; s != nil {
				s.Sounds++
			}
		}
	}
	for _, e := range b.TeamInfo {
		if e.SourceSlot >= 0 {
			if s := v.summaries[uint32(e.SourceSlot)]; s != nil {
				s.TeamInfo++
			}
		}
	}
	for _, e := range b.Shots {
		if s := v.summaries[e.Slot]; s != nil {
			s.Shots++
		}
	}
	for slot, s := range v.summaries {
		if touched[slot] {
			s.Batches++
		}
		if sess, ok := ms.sessions[slot]; ok {
			s.SessionID, s.PlayerHash = sess.SessionID, sess.PlayerHash
		}
		s.Mode = knowledge.ModeName(v.mode)
		if v.ref != nil {
			s.MapID, s.MapVersion = v.ref.MapId, v.ref.Version
		}
		s.SchemaVersion = max(s.SchemaVersion, b.SchemaVersion)
		s.DroppedEvents = v.dropped
		s.UpdatedAt = at
	}
}

// leakEvidence scores the finished match. It runs once, at match_over: testing
// the same player again after every batch would multiply the false-flag rate.
func (p *Pipeline) leakEvidence(tenant string, ms *matchState, v *v2State, b *pb.GameplayBatch, at time.Time) []store.Evidence {
	name := func(slot uint32) string {
		if s, ok := ms.sessions[slot]; ok {
			return s.PlayerHash
		}
		if pl, ok := ms.m.Players[slot]; ok && pl.PlayerHash != "" {
			return pl.PlayerHash
		}
		return fmt.Sprintf("slot %d", slot)
	}
	if v.mismatch {
		p.log.Warn("leak scores withheld: the map geometry does not match where the players were", "match", b.MatchId, "map", v.scorer.Map().ID,
			"positions", v.positions, "inside_walls", v.inSolid)
		return nil
	}
	var evs []store.Evidence
	evidence := func(r knowledge.Result, rule string, z, th float64, summary string, ex knowledge.Explanation) {
		raw, err := json.Marshal(struct {
			Slot     uint32 `json:"slot"`
			BatchSeq uint64 `json:"batch_seq"`
			knowledge.Explanation
		}{r.Slot, b.BatchSeq, ex})
		if err != nil {
			return
		}
		sev := analyzer.SeverityMedium
		if z >= 2*th {
			sev = analyzer.SeverityHigh
		}
		ev := store.Evidence{
			TenantID: tenant, PlayerHash: name(r.Slot), MatchID: b.MatchId, Source: store.SourceGameplay,
			Rule: rule, Severity: int(sev), Score: math.Min(1, z/(2*th)),
			Integrity: false, Summary: summary, Raw: string(raw), ObservedAt: at,
		}
		if s, ok := ms.sessions[r.Slot]; ok {
			ev.SessionID = s.SessionID
		} else if pl, ok := ms.m.Players[r.Slot]; ok {
			ev.Bot = pl.Bot
		}
		evs = append(evs, ev)
	}
	v.results = map[uint32]knowledge.Result{}
	for _, r := range v.scorer.Finish() {
		v.results[r.Slot] = r
		if s := v.summaries[r.Slot]; s != nil {
			s.LeakScored, s.LeakScore, s.LeakFlagged = true, math.Round(r.Score*100)/100, r.Flagged
		}
		_, bound := ms.sessions[r.Slot]
		scored := 0
		for _, f := range r.Features {
			if f.Scored {
				scored++
			}
		}
		live := "off"
		if v.alerter != nil {
			live = fmt.Sprintf("%d/%d", v.alerter.Strong(r.Slot), v.alerter.Windows())
		}
		p.log.Info("leak score", "match", b.MatchId, "slot", r.Slot, "player", name(r.Slot), "bound", bound, "score", math.Round(r.Score*100)/100,
			"flag_at", r.Threshold.Z, "flagged", r.Flagged, "scored_features", scored, "strong_windows", live, "segment", r.Segment.String(), "features", featureText(r))
		if r.Flagged {
			ex := r.Explain(v.scorer.Map(), name)
			ex.MapNote = v.mapNote
			evidence(r, RuleInformationLeak, r.Score, r.Threshold.Z, r.Summary(), ex)
		}
		if d := r.Decoy; d != nil && d.Flagged {
			evidence(r, RuleDecoyReaction, d.Score, d.Threshold.Z, d.Summary(), d.Explain(v.scorer.Map()))
		}
	}
	return evs
}

func featureText(r knowledge.Result) string {
	var parts []string
	for _, f := range r.Features {
		if f.Samples == 0 {
			continue
		}
		scored := ""
		if !f.Scored {
			scored = ", not scored"
		}
		parts = append(parts, fmt.Sprintf("%s z=%.2f true=%.3f control=%.3f blocks=%d%s", f.Name, f.Z, f.RateTrue, f.RateNull, f.Blocks, scored))
	}
	return strings.Join(parts, "; ")
}

// checkPositions counts the batch's player positions that lie inside the map's walls and
// decides, once enough were seen, whether the geometry is the map being played. It returns
// a warning for the game server the first time it is not.
func (p *Pipeline) checkPositions(v *v2State, b *pb.GameplayBatch) string {
	m := v.scorer.Map()
	if !m.HasSolid() {
		return ""
	}
	for _, t := range b.Motion {
		var x, y, z int64
		for i := range min(len(t.XCm), len(t.YCm), len(t.ZCm)) {
			x, y, z = x+int64(t.XCm[i]), y+int64(t.YCm[i]), z+int64(t.ZCm[i])
			v.positions++
			if m.Solid(knowledge.Vec3{X: float64(x) / 100, Y: float64(y) / 100, Z: float64(z) / 100}) {
				v.inSolid++
			}
		}
	}
	was := v.mismatch
	v.mismatch = v.positions >= minSolidPositions && float64(v.inSolid) > maxInSolid*float64(v.positions)
	if v.mismatch && !was {
		return fmt.Sprintf("map %s v%d does not match the match: %d of %d player positions are inside its walls; information-leak scoring is off for this match",
			m.ID, m.Version, v.inSolid, v.positions)
	}
	return ""
}

// leakAlerts runs the opt-in live rule after a batch.
func (p *Pipeline) leakAlerts(tenant string, ms *matchState, v *v2State, b *pb.GameplayBatch, at time.Time) []store.Evidence {
	var evs []store.Evidence
	cfg := *p.cfg.LeakAlert
	for _, h := range v.alerter.Step() {
		var scores []string
		for _, s := range h.Scores {
			scores = append(scores, fmt.Sprintf("%.1f", s))
		}
		summary := fmt.Sprintf("Opt-in live wallhack rule: %d of %d windows of %.0f s were strong (scores %s; a window is strong at %.2f with %.0f%% more alignment than the controls). "+
			"The crosshair or shots followed enemies the player's team could not see, hear or be told about. A behaviour score, not proof.",
			h.Strong, h.Windows, cfg.WindowSec, strings.Join(scores, ", "), cfg.Z, cfg.MinExcess*100)
		raw, _ := json.Marshal(map[string]any{"slot": h.Slot, "batch_seq": b.BatchSeq, "strong_windows": h.Strong, "windows": h.Windows, "window_sec": cfg.WindowSec,
			"window_z": cfg.Z, "window_min_excess": cfg.MinExcess, "scores": h.Scores, "last_window": featureText(h.Last), "map": v.scorer.Map().ID, "map_note": v.mapNote})
		ev := store.Evidence{
			TenantID: tenant, MatchID: b.MatchId, Source: store.SourceGameplay, Rule: RuleInformationLeakLive, Severity: int(analyzer.SeverityHigh),
			Score: 1, Integrity: false, Summary: summary, Raw: string(raw), ObservedAt: at,
		}
		s, bound := ms.sessions[h.Slot]
		switch pl, ok := ms.m.Players[h.Slot]; {
		case bound:
			ev.SessionID, ev.PlayerHash = s.SessionID, s.PlayerHash
		case ok:
			ev.PlayerHash, ev.Bot = pl.PlayerHash, pl.Bot
		}
		if ev.PlayerHash == "" {
			ev.PlayerHash = fmt.Sprintf("slot-%d", h.Slot)
		}
		evs = append(evs, ev)
		if bound && p.cfg.Notices && p.notify != nil {
			p.notify.Notice(s.SessionID, pb.EnforcementCategory_ENFORCEMENT_CATEGORY_VISIBILITY, pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_HIGH)
			p.log.Info("notice raised by", "session", s.SessionID, "rule", RuleInformationLeakLive, "category",
				noticeCategoryName(pb.EnforcementCategory_ENFORCEMENT_CATEGORY_VISIBILITY), "summary", summary)
		}
	}
	return evs
}

var errMapPin = errors.New("map pin")

// mapPin checks a compiled map against the operator's pins and words where it stands.
func (p *Pipeline) mapPin(m *knowledge.Map) (string, error) {
	source := ""
	if m.Source != "" {
		source = ", read by the game server from a map file with SHA-256 " + m.Source
	}
	want, pinned := p.cfg.MapPins[m.ID]
	switch {
	case pinned && !strings.EqualFold(want, m.Hash):
		return "", fmt.Errorf("%w: the geometry sent for %s (hash %s) is not the pinned one (%s)", errMapPin, m.ID, m.Hash, want)
	case pinned:
		return "geometry " + m.Hash + ", pinned by the operator" + source, nil
	case p.cfg.MapPinsRequired:
		return "", fmt.Errorf("%w: %s has no pinned geometry (hash %s) and the gateway accepts pinned maps only", errMapPin, m.ID, m.Hash)
	}
	return "geometry " + m.Hash + ", not pinned: taken as the game server sent it" + source, nil
}

func (p *Pipeline) putMap(ctx context.Context, tenant string, g *pb.MapGeometry, at time.Time) error {
	m, err := knowledge.Compile(g)
	if err != nil {
		return err
	}
	if _, err := p.mapPin(m); err != nil {
		return err
	}
	_, raw, err := knowledge.GeometryHash(g)
	if err != nil {
		return err
	}
	if err := p.st.PutMap(ctx, &store.MapRecord{TenantID: tenant, MapID: m.ID, Version: m.Version, Hash: m.Hash, Geometry: raw, CreatedAt: at}); err != nil {
		if errors.Is(err, store.ErrMapConflict) {
			return fmt.Errorf("%s v%d was uploaded before with different geometry; bump the version", m.ID, m.Version)
		}
		return err
	}
	p.cacheMap(mapKey{tenant, m.ID, m.Version}, m)
	return nil
}

func (p *Pipeline) loadMap(ctx context.Context, tenant string, ref *pb.MapRef) (*knowledge.Map, error) {
	k := mapKey{tenant, ref.MapId, ref.Version}
	if m := p.maps[k]; m != nil {
		return m, nil
	}
	rec, err := p.st.GetMap(ctx, tenant, ref.MapId, ref.Version)
	if err != nil {
		return nil, err
	}
	var g pb.MapGeometry
	if err := proto.Unmarshal(rec.Geometry, &g); err != nil {
		return nil, err
	}
	m, err := knowledge.Compile(&g)
	if err != nil {
		return nil, err
	}
	p.cacheMap(k, m)
	return m, nil
}

func (p *Pipeline) cacheMap(k mapKey, m *knowledge.Map) {
	if len(p.maps) >= maxCachedMaps {
		for old := range p.maps {
			delete(p.maps, old)
			break
		}
	}
	p.maps[k] = m
}
