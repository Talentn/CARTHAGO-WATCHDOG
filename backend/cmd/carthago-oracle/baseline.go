package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"carthago/backend/internal/oracle"
	"carthago/backend/internal/oracle/train"
)

func init() {
	commands["baseline"] = command{runBaseline, "measure the per-studio baseline on simulated sessions: what it calls outside normal, with no labels used"}
}

// runBaseline treats the simulated sessions as one studio's history. The baseline is
// learned with the labels hidden and with cheaters among the players, the way it would be
// in production. The labels are used afterwards only to count.
//
// The simulator is built to train a model, so about a third of its sessions cheat. No
// studio looks like that, and a baseline learned from it takes the cheating for normal
// play. The studio measured here keeps every honest session and only as many cheating
// ones as -cheat-share says; then every session is scored. A second pass learns from the
// whole simulated mix, to show what a studio full of cheaters does to the baseline.
func runBaseline(args []string) error {
	fs := flag.NewFlagSet("baseline", flag.ExitOnError)
	data := addDataFlags(fs, 100, 1)
	perPlayer := fs.Int("player-sessions", 5, "sessions grouped into one simulated player for the player score")
	cheatShare := fs.Float64("cheat-share", 0.03, "share of cheating sessions in the studio the baseline learns from")
	fs.Parse(args)
	rows, _, err := data.rows(false)
	if err != nil {
		return err
	}
	honest, cheating := 0, 0
	for i := range rows {
		if !rows[i].InMatch {
			continue
		}
		if rows[i].Cheating {
			cheating++
		} else {
			honest++
		}
	}
	keep := cheating
	if *cheatShare < 1 {
		keep = min(cheating, int(float64(honest)**cheatShare/(1-*cheatShare)+0.5))
	}
	if err := measureBaseline(rows, keep, cheating, *perPlayer, true); err != nil {
		return err
	}
	if keep < cheating {
		return measureBaseline(rows, cheating, cheating, *perPlayer, false)
	}
	return nil
}

// measureBaseline learns from every honest session and keep of the cheating ones, evenly
// picked, and scores all sessions.
func measureBaseline(rows []train.Row, keep, cheating, perPlayer int, table bool) error {
	now := time.Now()
	var samples []oracle.BaselineSample
	seen, kept := 0, 0
	for i := range rows {
		if rows[i].Cheating && rows[i].InMatch {
			seen++
			if kept*cheating >= seen*keep {
				continue
			}
			kept++
		}
		samples = append(samples, oracle.BaselineSample{Vector: rows[i].Vector, At: now})
	}
	b := oracle.LearnBaseline(samples)
	if !b.Ready {
		fmt.Printf("baseline: learning, %d of %d sessions with gameplay; nobody is scored yet\n", b.Sessions, oracle.BaselineMinSessions)
		return nil
	}

	type count struct{ n, outside, far int }
	add := func(c *count, d float64) {
		c.n++
		switch oracle.BaselineBand(d) {
		case oracle.BaselineFar:
			c.far++
			c.outside++
		case oracle.BaselineOutside:
			c.outside++
		}
	}
	sessions, players := map[string]*count{}, map[string]*count{}
	pending := map[string][]float64{}
	at := func(m map[string]*count, k string) *count {
		if m[k] == nil {
			m[k] = &count{}
		}
		return m[k]
	}
	for i := range rows {
		r := &rows[i]
		d, _, ok := b.Distance(r.Vector)
		if !ok {
			continue
		}
		add(at(sessions, r.Profile), d)
		// A simulated player is the next few sessions of one profile: an honest player
		// stays honest and a cheater cheats in every session.
		if pending[r.Profile] = append(pending[r.Profile], d); len(pending[r.Profile]) == perPlayer {
			add(at(players, r.Profile), oracle.PlayerDistance(pending[r.Profile]))
			pending[r.Profile] = nil
		}
	}

	names := make([]string, 0, len(sessions))
	for k := range sessions {
		if k != train.Honest {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	total := func(m map[string]*count) (c count) {
		for _, k := range names {
			if x := m[k]; x != nil {
				c.n, c.outside, c.far = c.n+x.n, c.outside+x.outside, c.far+x.far
			}
		}
		return c
	}
	line := func(name string, s, p *count) {
		if s == nil {
			s = &count{}
		}
		if p == nil {
			p = &count{}
		}
		fmt.Printf("  %-13s sessions %5d  outside %5d (%5.1f%%)  far %5d (%5.1f%%)   players %4d  outside %4d (%5.1f%%)  far %4d (%5.1f%%)\n",
			name, s.n, s.outside, share(s.outside, s.n), s.far, share(s.far, s.n), p.n, p.outside, share(p.outside, p.n), p.far, share(p.far, p.n))
	}
	cs, cp := total(sessions), total(players)
	hs, hp := at(sessions, train.Honest), at(players, train.Honest)
	if !table {
		fmt.Printf("with %.0f%% of the studio cheating: honest players outside normal %d of %d (%.1f%%), cheating players %d of %d (%.1f%%)\n",
			share(kept, b.Sessions), hp.outside, hp.n, share(hp.outside, hp.n), cp.outside, cp.n, share(cp.outside, cp.n))
		return nil
	}
	fmt.Printf("baseline learned from %d simulated sessions, labels hidden (%d of them cheating, %.1f%%); then all %d sessions scored\n",
		b.Sessions, kept, share(kept, b.Sessions), hs.n+cs.n)
	fmt.Printf("a player is %d sessions of one profile; outside = outside normal or further, far = far outside\n", perPlayer)
	line(train.Honest, sessions[train.Honest], players[train.Honest])
	for _, k := range names {
		line(k, sessions[k], players[k])
	}
	line("all cheating", &cs, &cp)
	fmt.Fprintln(os.Stdout)
	fmt.Printf("baseline: honest players outside normal %d of %d (%.1f%%), cheating players %d of %d (%.1f%%); honest sessions %d of %d (%.1f%%), cheating sessions %d of %d (%.1f%%)\n",
		hp.outside, hp.n, share(hp.outside, hp.n), cp.outside, cp.n, share(cp.outside, cp.n),
		hs.outside, hs.n, share(hs.outside, hs.n), cs.outside, cs.n, share(cs.outside, cs.n))
	return nil
}

func share(n, of int) float64 {
	if of == 0 {
		return 0
	}
	return 100 * float64(n) / float64(of)
}
