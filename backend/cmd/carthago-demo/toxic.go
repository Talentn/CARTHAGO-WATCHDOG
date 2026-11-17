package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge/synth"
	"carthago/backend/internal/sim/localgw"
	"carthago/backend/internal/store"
	"carthago/backend/internal/toxicity"
)

const (
	toxicMatch   = "casual-yard-0002"
	toxicSeconds = 480
	toxicPlayer  = "walid"
)

func (s *story) toxic() error {
	if _, err := s.signIn(toxicPlayer, ""); err != nil {
		return fmt.Errorf("%s signs in: %w", toxicPlayer, err)
	}
	names := append(append([]string{}, cast...), "ilyes", toxicPlayer)
	mode := pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER
	players := synth.DefaultPlayers(mode, 1, nil)
	for i := range players {
		players[i].SessionID, players[i].PlayerHash = s.players[names[i]].SessionID(), names[i]
	}
	me := players[len(players)-1]
	var mates, enemies []uint32
	for _, p := range players[:len(players)-1] {
		if p.Team == me.Team {
			mates = append(mates, p.Slot)
		} else {
			enemies = append(enemies, p.Slot)
		}
	}
	batches := synth.Batches(synth.Spec{MatchID: toxicMatch, Mode: mode, TickRate: 64, Seconds: toxicSeconds, Seed: seed + 7, Players: players})
	synth.Spoil(batches, 64, me.Slot, mates, enemies)
	for _, b := range batches {
		for _, e := range b.Shots {
			if e.Slot == me.Slot && e.Kill && e.TargetSlot > 0 {
				for i := range players {
					if players[i].Slot == uint32(e.TargetSlot) {
						s.teamKilled = names[i]
					}
				}
			}
		}
	}
	if err := s.ingest(batches); err != nil {
		return err
	}
	st := s.gw.Store
	found := func() []store.ToxicityFinding {
		rows, _ := st.ListToxicityFindings(s.ctx, localgw.Tenant, store.ToxicityFilter{MatchID: toxicMatch, Limit: 100})
		return rows
	}
	if !s.wait(20*time.Second, func() bool { return len(found()) >= len(toxicity.Kinds) }) {
		return fmt.Errorf("the behaviour rules found %d kinds in the match, want %d", len(found()), len(toxicity.Kinds))
	}
	rows := found()
	sort.Slice(rows, func(i, j int) bool { return rows[i].MatchMs < rows[j].MatchMs })
	kinds := map[string]bool{}
	for _, r := range rows {
		if r.PlayerHash != toxicPlayer {
			return fmt.Errorf("%s, who played normally, has a behaviour finding: %s", r.PlayerHash, r.Kind)
		}
		kinds[r.Kind] = true
	}
	if len(kinds) != len(toxicity.Kinds) {
		return fmt.Errorf("the behaviour rules found %d of %d kinds", len(kinds), len(toxicity.Kinds))
	}
	// Advice only: no evidence, no risk, no ban, no pool, and the player is told nothing.
	ev, err := st.ListEvidence(s.ctx, localgw.Tenant, store.EvidenceFilter{PlayerHash: toxicPlayer, Limit: 100})
	if err != nil || len(ev) != 0 {
		return fmt.Errorf("%s has %d pieces of anti-cheat evidence, want none (%v)", toxicPlayer, len(ev), err)
	}
	a := s.players[toxicPlayer]
	status, err := s.shadowStatus(toxicPlayer)
	if err != nil {
		return err
	}
	if s.ban(toxicPlayer) != nil || status != "normal" || !a.Online() || a.Seen().Notices != 0 {
		return errors.New("a behaviour finding banned, pooled, ended or told the player")
	}
	lim, _ := toxicity.Parse("")
	s.say("A casual match of ten players, %d minutes. %s runs into the enemy and dies eleven times without a kill,", toxicSeconds/60, toxicPlayer)
	s.say("shoots his own team, stands idle, and leaves with a third of the match to play. No chat is read: the")
	s.say("gateway sees it in the shots, positions and view the game server already sends.")
	for _, r := range rows {
		s.say("- %s at %s: %s", strings.ReplaceAll(r.Kind, "_", " "), clockOf(r.MatchMs), r.Summary)
	}
	s.say("Each studio sets its own limits per match. The defaults, in use here:")
	s.say("%s.", lim.Describe())
	s.say("It is advice for the community team, on the player's page and on the replay: %s/matches/%s?player=%s", s.gw.Dashboard, toxicMatch, toxicPlayer)
	s.say("It is not anti-cheat evidence: %s has no evidence, no risk, no ban, is not in the shadow pool and is told nothing.", toxicPlayer)
	return nil
}

func clockOf(ms int64) string { return fmt.Sprintf("%02d:%02d", ms/60000, ms/1000%60) }
