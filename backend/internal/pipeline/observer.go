package pipeline

import (
	"time"

	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/store"
)

// Observer is told what the pipeline has finished working out, after the evidence for it
// is stored: a match that ended, and a session that sent a heartbeat. It exists so a
// scoring engine can work from the same numbers as the rules without the pipeline knowing
// about it.
//
// Both methods run on the pipeline's worker and must return at once; an observer that
// needs to do work queues it. An observer cannot add evidence, change a player's risk or
// kick: the pipeline hands it values and takes nothing back.
type Observer interface {
	MatchFinished(tenant, matchID string, players []MatchPlayer, at time.Time)
	SessionActivity(sess store.Session, newEvidence bool, at time.Time)
}

// MatchPlayer is one slot of a finished match that is bound to a verified session.
type MatchPlayer struct {
	Session store.Session
	Slot    uint32
	Stats   analyzer.PlayerSummary
	// Leak and Decoy are the information-leak and decoy scores with the thresholds they
	// were judged against. Scored is false when the match had no map geometry, or the
	// player's segment has no calibrated threshold.
	Leak  KnowledgeScore
	Decoy KnowledgeScore
}

type KnowledgeScore struct {
	Scored    bool
	Score     float64
	Threshold float64
}

// matchFinished reports a match to the observer once: when it ends or goes idle.
func (p *Pipeline) matchFinished(key [2]string, ms *matchState, at time.Time) {
	if p.cfg.Observer == nil || ms.observed {
		return
	}
	ms.observed = true
	var players []MatchPlayer
	for slot, sess := range ms.sessions {
		stats, ok := ms.m.Summary(slot)
		if !ok {
			continue
		}
		mp := MatchPlayer{Session: sess, Slot: slot, Stats: stats}
		if ms.v2 != nil {
			if r, ok := ms.v2.results[slot]; ok {
				mp.Leak = KnowledgeScore{Scored: r.Calibrated, Score: r.Score, Threshold: r.Threshold.Z}
				if d := r.Decoy; d != nil && d.Calibrated && d.Received > 0 {
					mp.Decoy = KnowledgeScore{Scored: true, Score: d.Score, Threshold: d.Threshold.Z}
				}
			}
		}
		players = append(players, mp)
	}
	if len(players) > 0 {
		p.cfg.Observer.MatchFinished(key[0], key[1], players, at)
	}
}
