package dashboard

import (
	"context"
	"net/url"
	"time"

	"carthago/backend/internal/store"
	"carthago/backend/internal/toxicity"
)

// behaviourWindow is how far back a player's behaviour card looks.
const behaviourWindow = 30 * 24 * time.Hour

var behaviourNames = map[string]string{
	toxicity.KindTeamDamage: "Team damage",
	toxicity.KindTeamKill:   "Team kills",
	toxicity.KindAFK:        "Idle (AFK)",
	toxicity.KindLeftEarly:  "Left early",
	toxicity.KindFeeding:    "Feeding",
}

type behaviourCount struct {
	Label string
	N     int // matches in which the kind was found
}

type behaviourRow struct {
	store.ToxicityFinding
	Label    string
	At       string // mm:ss into the match
	Recorded bool   // the match has a replay
}

// behaviourView is the Behaviour card of a player's page.
type behaviourView struct {
	Total  int
	Counts []behaviourCount
	Rows   []behaviourRow
	More   int // findings in the window that are counted and not listed
	Limits string
}

// maxBehaviourRows is how many findings the card lists; the counts cover all of them.
const maxBehaviourRows = 20

// behaviourFor builds the card for a player, or nil when the last 30 days hold nothing.
func (s *Server) behaviourFor(ctx context.Context, tenant, hash string) (*behaviourView, error) {
	rows, err := s.st.ListToxicityFindings(ctx, tenant, store.ToxicityFilter{PlayerHash: hash, Since: s.now().Add(-behaviourWindow), Limit: 1000})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	v := &behaviourView{Total: len(rows)}
	n := map[string]int{}
	recorded := map[string]bool{}
	for _, r := range rows {
		n[r.Kind]++
		if len(v.Rows) == maxBehaviourRows {
			v.More++
			continue
		}
		has, seen := recorded[r.MatchID]
		if !seen {
			_, err := s.st.GetMatchReplay(ctx, tenant, r.MatchID)
			has = err == nil
			recorded[r.MatchID] = has
		}
		v.Rows = append(v.Rows, behaviourRow{ToxicityFinding: r, Label: behaviourNames[r.Kind], At: clock(r.MatchMs), Recorded: has})
	}
	for _, k := range toxicity.Kinds {
		v.Counts = append(v.Counts, behaviourCount{behaviourNames[k], n[k]})
	}
	stored, err := s.st.GetToxicityLimits(ctx, tenant)
	if err != nil {
		return nil, err
	}
	lim, err := toxicity.Parse(stored)
	if err != nil {
		lim = toxicity.Defaults()
	}
	v.Limits = lim.Describe()
	return v, nil
}

// behaviourMarks are a match's behaviour findings for its replay timeline.
func (s *Server) behaviourMarks(ctx context.Context, tenant, matchID string) ([]matchMark, error) {
	rows, err := s.st.ListToxicityFindings(ctx, tenant, store.ToxicityFilter{MatchID: matchID, Limit: 200})
	if err != nil {
		return nil, err
	}
	marks := make([]matchMark, 0, len(rows))
	for _, r := range rows {
		marks = append(marks, matchMark{Ms: r.MatchMs, Kind: "behaviour", Level: "low", Slot: int(r.Slot), Player: r.PlayerHash, Rule: r.Kind, Text: r.Summary,
			Href: "/players/" + url.PathEscape(r.PlayerHash) + "#behaviour"})
	}
	return marks, nil
}
