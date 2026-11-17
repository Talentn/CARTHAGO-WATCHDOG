package dashboard

import (
	"context"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"carthago/backend/internal/oracle"
	"carthago/backend/internal/store"
)

// The baseline (oracle/baseline.go) is computed here, on read, from the score rows the
// Oracle engine already stores for the tenant: nothing new is written, and a tenant's
// baseline is built from that tenant's rows only. The pages show a player's score, band
// and the names of the signals that stand out. They never show a value, an edge or a
// spread.

// baselineTTL is how long a tenant's computed baseline is reused.
const baselineTTL = time.Minute

type tenantBaseline struct {
	at      time.Time
	base    *oracle.Baseline
	players map[string]oracle.PlayerBaseline
}

type baselineCache struct {
	mu sync.Mutex
	m  map[string]*tenantBaseline
}

// playerBaselineView is one player's place against the tenant's baseline.
type playerBaselineView struct {
	Percent  int
	BandName string
	// Tier is the style of the band, shared with the Oracle's own bands.
	Tier     string
	Sessions int
	Outside  int
	Signals  string
	distance float64
	outside  bool
}

// baselineView is the tenant's baseline as a page shows it.
type baselineView struct {
	// Sessions is how many of the tenant's sessions the baseline has seen, Need how many
	// it wants before it scores anybody.
	Sessions, Need int
	Learning       bool
	Players        map[string]*playerBaselineView
	// Player is set on a player's page.
	Player *playerBaselineView
}

func (s *Server) tenantBaseline(ctx context.Context, tenant string) (*tenantBaseline, error) {
	now := s.now()
	s.baselines.mu.Lock()
	if tb := s.baselines.m[tenant]; tb != nil && now.Sub(tb.at) < baselineTTL && !now.Before(tb.at) {
		s.baselines.mu.Unlock()
		return tb, nil
	}
	s.baselines.mu.Unlock()

	rows, err := s.st.ListOracleScores(ctx, tenant, store.OracleFilter{Limit: store.OracleScoreLimit})
	if err != nil {
		return nil, err
	}
	samples := make([]oracle.BaselineSample, 0, len(rows))
	for i := range rows {
		v, err := oracle.ParseBaselineVector(rows[i].Features)
		if rows[i].FeatureVersion != oracle.FeatureVersion || err != nil {
			continue
		}
		samples = append(samples, oracle.BaselineSample{PlayerHash: rows[i].PlayerHash, Vector: v, At: rows[i].UpdatedAt})
	}
	tb := &tenantBaseline{at: now, base: oracle.LearnBaseline(samples)}
	tb.players = tb.base.Players(samples, now)

	s.baselines.mu.Lock()
	if s.baselines.m == nil {
		s.baselines.m = map[string]*tenantBaseline{}
	}
	s.baselines.m[tenant] = tb
	s.baselines.mu.Unlock()
	return tb, nil
}

func (tb *tenantBaseline) view() *baselineView {
	v := &baselineView{Sessions: tb.base.Sessions, Need: oracle.BaselineMinSessions, Learning: !tb.base.Ready,
		Players: make(map[string]*playerBaselineView, len(tb.players))}
	for hash, p := range tb.players {
		pv := &playerBaselineView{Percent: int(math.Round(100 * p.Score)), Sessions: p.Sessions, Outside: p.Outside,
			distance: p.Distance, outside: p.Band != oracle.BaselineNormal}
		switch p.Band {
		case oracle.BaselineFar:
			pv.BandName, pv.Tier = "far outside", "review"
		case oracle.BaselineOutside:
			pv.BandName, pv.Tier = "outside normal", "watch"
		default:
			pv.BandName, pv.Tier = "normal", "clear"
		}
		var names []string
		for _, sg := range p.Signals {
			if len(names) == 3 {
				break
			}
			names = append(names, sg.Label)
		}
		pv.Signals = strings.Join(names, ", ")
		v.Players[hash] = pv
	}
	return v
}

// playerBaselineFor is the baseline card of a player's page; nil when the tenant has no
// scored session at all (the Oracle engine is off).
func (s *Server) playerBaselineFor(ctx context.Context, tenant, hash string) (*baselineView, error) {
	tb, err := s.tenantBaseline(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if tb.base.Sessions == 0 {
		return nil, nil
	}
	v := tb.view()
	v.Player = v.Players[hash]
	return v, nil
}

// reviewQueue puts the baseline into the players list. Players outside their studio's
// normal play come first, the furthest first; everybody else keeps the order by rule risk.
// The flagged list also takes in players who are outside normal and have no rule evidence
// that would have listed them.
func (s *Server) reviewQueue(ctx context.Context, tenant string, all bool, rows []store.PlayerRow) ([]store.PlayerRow, *baselineView, error) {
	tb, err := s.tenantBaseline(ctx, tenant)
	if err != nil {
		return nil, nil, err
	}
	v := tb.view()
	outside := func(hash string) float64 {
		if p := v.Players[hash]; p != nil && p.outside {
			return p.distance
		}
		return 0
	}
	if !all {
		listed := make(map[string]bool, len(rows))
		missing := 0
		for i := range rows {
			listed[rows[i].PlayerHash] = true
		}
		for hash := range v.Players {
			if outside(hash) > 0 && !listed[hash] {
				missing++
			}
		}
		if missing > 0 {
			everybody, err := s.st.ListPlayers(ctx, tenant, store.PlayerFilter{Limit: 1000})
			if err != nil {
				return nil, nil, err
			}
			for i := range everybody {
				if p := &everybody[i]; !p.Bot && !listed[p.PlayerHash] && outside(p.PlayerHash) > 0 {
					rows = append(rows, *p)
				}
			}
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return outside(rows[i].PlayerHash) > outside(rows[j].PlayerHash) })
	return rows, v, nil
}
