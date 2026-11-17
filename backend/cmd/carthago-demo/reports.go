package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge/synth"
	"carthago/backend/internal/reports"
	"carthago/backend/internal/sim/localgw"
	"carthago/backend/internal/store"
	"carthago/backend/internal/toxicity"
)

// hit is one player shot by another at a tick of a match.
type hit struct {
	victim string
	tick   uint32
}

// firstHits finds the first n different players a slot shot, a minute or more into the
// match.
func firstHits(batches []*pb.GameplayBatch, slot uint32, players []synth.PlayerSpec, n int) []hit {
	name := map[int32]string{}
	for _, p := range players {
		name[int32(p.Slot)] = p.PlayerHash
	}
	var out []hit
	seen := map[string]bool{}
	for _, b := range batches {
		for _, e := range b.Shots {
			if v := name[e.TargetSlot]; e.Slot == slot && e.Hit && v != "" && !seen[v] && e.Tick > 60*64 && len(out) < n {
				seen[v] = true
				out = append(out, hit{v, e.Tick})
			}
		}
	}
	return out
}

// sendReport is the studio's game server passing a player's report on: POST /v1/reports
// under its server key. It returns the HTTP status and the answer.
func (s *story) sendReport(in reports.Submission) (int, reports.Outcome, error) {
	var out reports.Outcome
	raw, err := json.Marshal(in)
	if err != nil {
		return 0, out, err
	}
	req, err := http.NewRequestWithContext(s.ctx, "POST", s.gw.API+"/v1/reports", bytes.NewReader(raw))
	if err != nil {
		return 0, out, err
	}
	req.Header.Set("Authorization", "Bearer "+localgw.ServerKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, out, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return resp.StatusCode, out, fmt.Errorf("POST /v1/reports: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return resp.StatusCode, out, json.Unmarshal(body, &out)
}

func (s *story) reports() error {
	if len(s.shotBySami) < 2 {
		return errors.New("chapter 2 did not leave two players sami shot in the match")
	}
	st := s.gw.Store
	first, second := s.shotBySami[0], s.shotBySami[1]
	// Where walid killed his second teammate, from chapter 8.
	var teamKill int64 = -1
	found, _ := st.ListToxicityFindings(s.ctx, localgw.Tenant, store.ToxicityFilter{PlayerHash: toxicPlayer, MatchID: toxicMatch})
	for _, f := range found {
		if f.Kind == toxicity.KindTeamKill {
			teamKill = f.MatchMs
		}
	}
	if teamKill < 0 {
		return errors.New("chapter 8 did not leave walid's team kill")
	}
	evidenceBefore, err := st.ListEvidence(s.ctx, localgw.Tenant, store.EvidenceFilter{Limit: 1000})
	if err != nil {
		return err
	}
	bansBefore, _ := st.ListBans(s.ctx, localgw.Tenant, 200)

	// The player who was shot first also reports zied, from an earlier match. zied was
	// banned on the client's own evidence in chapter 3, which confirms the report: that
	// is what gives a reporter weight.
	if code, _, err := s.sendReport(reports.Submission{Reporter: first.victim, Reported: "zied", Match: "ranked-yard-0000", Reason: "cheating"}); err != nil || code != http.StatusCreated {
		return fmt.Errorf("the earlier report about zied: HTTP %d %v", code, err)
	}
	tick := first.tick
	about := reports.Submission{Reporter: first.victim, Reported: "sami", Match: demoMatch, Tick: &tick, TickRate: 64, Reason: "cheating",
		Note: "he was already aiming at the corner before I came round it"}
	code, got, err := s.sendReport(about)
	if err != nil || code != http.StatusCreated || got.Status != reports.StatusAccepted {
		return fmt.Errorf("%s reports sami: HTTP %d %v", first.victim, code, err)
	}
	// The same report again, as an impatient player sends it: counted once.
	code, again, err := s.sendReport(about)
	if err != nil || code != http.StatusOK || again.Status != reports.StatusDuplicate || again.ID != got.ID {
		return fmt.Errorf("the same report sent twice: HTTP %d %+v %v", code, again, err)
	}
	ms := int64(second.tick) * 1000 / 64
	if code, _, err := s.sendReport(reports.Submission{Reporter: second.victim, Reported: "sami", Match: demoMatch, TimeMs: &ms, Reason: "cheating"}); err != nil || code != http.StatusCreated {
		return fmt.Errorf("%s reports sami: HTTP %d %v", second.victim, code, err)
	}
	mate := s.teamKilled
	if mate == "" {
		return errors.New("chapter 8 did not leave the teammate walid killed")
	}
	if code, _, err := s.sendReport(reports.Submission{Reporter: mate, Reported: toxicPlayer, Match: toxicMatch, TimeMs: &teamKill, Reason: "toxic_behaviour",
		Note: "shot his own team at the spawn, then stood there"}); err != nil || code != http.StatusCreated {
		return fmt.Errorf("%s reports %s: HTTP %d %v", mate, toxicPlayer, code, err)
	}
	// A report with a reason outside the list is refused.
	if code, _, err := s.sendReport(reports.Submission{Reporter: mate, Reported: "sami", Match: demoMatch, Reason: "i do not like him"}); err == nil || code != http.StatusBadRequest {
		return fmt.Errorf("a report with a made-up reason: HTTP %d, want 400", code)
	}

	open, err := st.ListPlayerReports(s.ctx, localgw.Tenant, store.ReportFilter{State: store.ReportOpen})
	if err != nil || len(open) != 4 {
		return fmt.Errorf("%d open reports, want 4 (%v)", len(open), err)
	}
	tally, err := st.TallyPlayerReports(s.ctx, localgw.Tenant, open[len(open)-1].CreatedAt)
	if err != nil || tally["sami"] != (store.ReportTally{Reports: 2, Reporters: 2}) {
		return fmt.Errorf("sami's reports: %+v, want 2 from 2 reporters (%v)", tally["sami"], err)
	}
	// Advice only: the reports made no evidence and no ban, pooled nobody, told nobody.
	evidenceAfter, _ := st.ListEvidence(s.ctx, localgw.Tenant, store.EvidenceFilter{Limit: 1000})
	bansAfter, _ := st.ListBans(s.ctx, localgw.Tenant, 200)
	if len(evidenceAfter) != len(evidenceBefore) || len(bansAfter) != len(bansBefore) {
		return errors.New("a report added evidence or a ban")
	}
	for _, n := range []string{"sami", toxicPlayer} {
		status, err := s.shadowStatus(n)
		if err != nil {
			return err
		}
		if s.ban(n) != nil || status != "normal" || !s.players[n].Online() || s.players[n].Seen().Notices != 0 {
			return fmt.Errorf("a report banned, pooled, ended or told %s", n)
		}
	}
	s.say("The game has a report button. The studio's game server passes each report on to the gateway:")
	s.say("- %s, shot by sami at %s, reports him for cheating, with a note. Sent twice by mistake: counted once.", first.victim, clockOf(int64(first.tick)*1000/64))
	s.say("- %s, shot by sami at %s, reports him too: 2 reports from 2 different players in 30 days.", second.victim, clockOf(ms))
	s.say("- %s, killed by his teammate %s at %s in chapter 8, reports him for toxic behaviour.", mate, toxicPlayer, clockOf(teamKill))
	s.say("- %s also reports zied, from an earlier match. zied's ban in chapter 3 confirms that report, so %s's", first.victim, first.victim)
	s.say("  word weighs 0.67; a player with no confirmed or dismissed report yet weighs 0.50.")
	s.say("A reason outside the fixed list is refused.")
	s.say("The reviewer's queue links each report to the replay at that moment: %s/reports", s.gw.Dashboard)
	s.say("A report is advice: no evidence, no ban, nobody in the shadow pool, nobody told, nothing for the Oracle.")
	return nil
}
