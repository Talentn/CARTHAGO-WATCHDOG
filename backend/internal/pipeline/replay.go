package pipeline

import (
	"context"
	"fmt"
	"sort"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/replay"
	"carthago/backend/internal/store"
)

// replayState is the recording of a match in progress (internal/replay). A match gets one
// with its first batch that carries player positions; a match without positions never does.
type replayState struct {
	rec     *replay.Recorder
	started time.Time
	saved   time.Time
	dirty   bool
}

// record adds a batch to the match's recording and writes the recording to the store
// every ReplayFlush, so a match in progress can be watched up to about that long ago.
func (p *Pipeline) record(tenant string, ms *matchState, b *pb.GameplayBatch, at time.Time) {
	if p.replays == nil {
		return
	}
	for _, mp := range b.Players {
		if ms.teams == nil {
			ms.teams = map[uint32]uint32{}
		}
		if _, known := ms.teams[mp.Slot]; known || len(ms.teams) < replay.MaxPlayers {
			ms.teams[mp.Slot] = mp.Team
		}
	}
	if ms.replay == nil {
		if len(b.Motion) == 0 {
			return
		}
		ms.replay = &replayState{rec: replay.NewRecorder(b.MatchId), started: at, saved: at}
	}
	ms.replay.rec.Add(b, at)
	ms.replay.dirty = true
	if at.Sub(ms.replay.saved) >= p.cfg.ReplayFlush {
		p.saveReplay(tenant, b.MatchId, ms, at)
	}
}

// saveReplay writes the match's recording if it changed since it was last written.
func (p *Pipeline) saveReplay(tenant, matchID string, ms *matchState, at time.Time) {
	rs := ms.replay
	if p.replays == nil || rs == nil || !rs.dirty {
		return
	}
	rs.dirty, rs.saved = false, at
	row := store.MatchReplay{TenantID: tenant, MatchID: matchID, StartedAt: rs.started, UpdatedAt: at}
	for slot, mp := range ms.m.Players {
		rp := store.ReplayPlayer{Slot: slot, PlayerHash: mp.PlayerHash, Bot: mp.Bot}
		// As for evidence: the verified session wins over what the game server sent.
		if s, ok := ms.sessions[slot]; ok {
			rp.PlayerHash, rp.SessionID, rp.Bot = s.PlayerHash, s.SessionID, false
		}
		if rp.PlayerHash == "" {
			rp.PlayerHash = fmt.Sprintf("slot-%d", slot)
		}
		rs.rec.SetPlayer(slot, rp.PlayerHash, rp.SessionID, ms.teams[slot], rp.Bot)
		row.Players = append(row.Players, rp)
	}
	sort.Slice(row.Players, func(i, j int) bool { return row.Players[i].Slot < row.Players[j].Slot })
	data, err := rs.rec.Encode()
	if err != nil {
		p.log.Warn("encode match replay", "match", matchID, "err", err)
		return
	}
	row.Data, row.DurationMs, row.Samples, row.Truncated = data, rs.rec.DurationMs(), rs.rec.Samples(), rs.rec.Truncated()
	if err := p.replays.PutMatchReplay(context.Background(), &row); err != nil {
		p.log.Warn("persist match replay", "match", matchID, "err", err)
	}
}
