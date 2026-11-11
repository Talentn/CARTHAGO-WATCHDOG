package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/knowledge"
	"carthago/backend/internal/store"
)

// RuleInformationLeak is the evidence rule of the knowledge-aware wallhack scorer.
const RuleInformationLeak = "information_leak"

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
		switch {
		case err == nil:
			v.scorer = knowledge.NewScorer(p.cfg.Leak, m, v.mode, b.TickRate)
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
		v.scorer.Add(b)
	}
	p.countV2(tenant, ms, v, b, at)

	if b.MatchOver && v.scorer != nil {
		evs = p.leakEvidence(tenant, ms, v, b, at)
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
	var evs []store.Evidence
	for _, r := range v.scorer.Finish() {
		if s := v.summaries[r.Slot]; s != nil {
			s.LeakScored, s.LeakScore, s.LeakFlagged = true, math.Round(r.Score*100)/100, r.Flagged
		}
		if !r.Flagged {
			continue
		}
		ex := r.Explain(v.scorer.Map(), name)
		raw, err := json.Marshal(struct {
			Slot     uint32 `json:"slot"`
			BatchSeq uint64 `json:"batch_seq"`
			knowledge.Explanation
		}{r.Slot, b.BatchSeq, ex})
		if err != nil {
			continue
		}
		sev := analyzer.SeverityMedium
		if r.Score >= 2*r.Threshold.Z {
			sev = analyzer.SeverityHigh
		}
		ev := store.Evidence{
			TenantID: tenant, PlayerHash: name(r.Slot), MatchID: b.MatchId, Source: store.SourceGameplay,
			Rule: RuleInformationLeak, Severity: int(sev), Score: math.Min(1, r.Score/(2*r.Threshold.Z)),
			Integrity: false, Summary: r.Summary(), Raw: string(raw), ObservedAt: at,
		}
		if s, ok := ms.sessions[r.Slot]; ok {
			ev.SessionID = s.SessionID
		}
		evs = append(evs, ev)
	}
	return evs
}

func (p *Pipeline) putMap(ctx context.Context, tenant string, g *pb.MapGeometry, at time.Time) error {
	m, err := knowledge.Compile(g)
	if err != nil {
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
