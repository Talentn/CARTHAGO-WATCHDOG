package pipeline

import (
	"context"
	"fmt"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/store"
	"carthago/backend/internal/toxicity"
)

// behaviour runs the behaviour rules (internal/toxicity) on a batch, and once more when
// the match is over, and stores what they find in the toxicity table.
//
// It deliberately does none of what the anti-cheat part of a batch does: it writes no
// evidence, sends no notice, kicks nobody and reaches neither the banner nor the pool.
func (p *Pipeline) behaviour(tenant, matchID string, ms *matchState, b *pb.GameplayBatch, over bool, at time.Time) {
	if p.tox == nil {
		return
	}
	ctx := context.Background()
	if ms.tox == nil {
		stored, err := p.tox.GetToxicityLimits(ctx, tenant)
		lim, perr := toxicity.Parse(stored)
		if err != nil || perr != nil {
			p.log.Warn("behaviour limits unreadable; using the defaults", "tenant", tenant, "err", err, "parse", perr)
			lim = toxicity.Defaults()
		}
		ms.tox = toxicity.NewMatch(lim)
	}
	var found []toxicity.Finding
	if b != nil {
		found = ms.tox.Add(b)
	}
	if over {
		found = append(found, ms.tox.Finish()...)
	}
	if len(found) == 0 {
		return
	}
	rows := make([]store.ToxicityFinding, 0, len(found))
	for _, f := range found {
		r := store.ToxicityFinding{TenantID: tenant, MatchID: matchID, Slot: f.Slot, Kind: f.Kind, Count: f.Count, Summary: f.Summary, ObservedAt: at,
			MatchMs: int64(f.Tick) * 1000 / int64(max(ms.tox.TickRate(), 1))}
		if pl, ok := ms.m.Players[f.Slot]; ok {
			r.PlayerHash, r.Bot = pl.PlayerHash, pl.Bot
		}
		// As for evidence: the verified session wins over what the game server sent.
		if s, ok := ms.sessions[f.Slot]; ok {
			r.PlayerHash, r.SessionID, r.Bot = s.PlayerHash, s.SessionID, false
		}
		if r.PlayerHash == "" {
			r.PlayerHash = fmt.Sprintf("slot-%d", f.Slot)
		}
		rows = append(rows, r)
		p.log.Info("behaviour", "match", matchID, "player", r.PlayerHash, "kind", r.Kind, "summary", r.Summary)
	}
	if err := p.tox.AddToxicityFindings(ctx, rows); err != nil {
		p.log.Warn("persist behaviour findings", "match", matchID, "err", err)
	}
}
