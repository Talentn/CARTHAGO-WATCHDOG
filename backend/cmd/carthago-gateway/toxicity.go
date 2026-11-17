package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"carthago/backend/internal/store"
	"carthago/backend/internal/toxicity"
)

const toxicityUsage = `usage:
  carthago-gateway toxicity limits -tenant ID [-team-damage N] [-team-kills N] [-afk-seconds N]
                                   [-left-early-percent N] [-feeding-deaths N] [-defaults] [-data DIR]

The limits of a studio's behaviour findings: team damage, team kills, standing idle (AFK),
leaving a match early and feeding, read from what the game server reports. A finding is
advice for the studio's community team. It never counts toward a player's risk, a ban or
the shadow pool.

Without a limit flag the command shows the studio's limits. With one or more it changes
those and keeps the others; 0 turns a kind off; -defaults goes back to the built-in limits.
A change applies to matches that start after it. The command works on the gateway's
database directly, running or not.
`

// toxicityCommand runs "carthago-gateway toxicity ...".
func toxicityCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "limits" {
		fmt.Fprint(stderr, toxicityUsage)
		return 2
	}
	fs := flag.NewFlagSet("toxicity limits", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", "gateway-data", "the gateway's data directory")
	tenant := fs.String("tenant", "", "tenant id of the studio")
	teamDamage := fs.Int("team-damage", 0, "hits on teammates in one match")
	teamKills := fs.Int("team-kills", 0, "teammates killed in one match")
	afk := fs.Int("afk-seconds", 0, "seconds in play without moving or turning")
	left := fs.Int("left-early-percent", 0, "share of the match still to play when the player left")
	feeding := fs.Int("feeding-deaths", 0, "deaths in one match, with next to no kills")
	defaults := fs.Bool("defaults", false, "go back to the built-in limits")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "carthago-gateway toxicity:", err)
		return 1
	}
	if fs.NArg() > 0 {
		fmt.Fprint(stderr, toxicityUsage)
		return 2
	}
	if *tenant == "" {
		return fail(errors.New("-tenant is required"))
	}
	dbPath := filepath.Join(*dataDir, "gateway.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fail(fmt.Errorf("no gateway database at %s: give -data the data directory the gateway runs with", dbPath))
	}
	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		return fail(err)
	}
	defer st.Close()
	ctx := context.Background()
	stored, err := st.GetToxicityLimits(ctx, *tenant)
	if err != nil {
		return fail(err)
	}
	lim, err := toxicity.Parse(stored)
	if err != nil {
		return fail(fmt.Errorf("the stored limits are unreadable (%v); set them again or use -defaults", err))
	}
	changed := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "team-damage":
			lim.TeamDamageHits, changed = *teamDamage, true
		case "team-kills":
			lim.TeamKills, changed = *teamKills, true
		case "afk-seconds":
			lim.AFKSeconds, changed = *afk, true
		case "left-early-percent":
			lim.LeftEarlyPercent, changed = *left, true
		case "feeding-deaths":
			lim.FeedingDeaths, changed = *feeding, true
		}
	})
	switch {
	case *defaults && changed:
		return fail(errors.New("give -defaults alone or the limits to change"))
	case *defaults:
		lim = toxicity.Defaults()
		if err := st.SetToxicityLimits(ctx, *tenant, "", time.Now()); err != nil {
			return fail(err)
		}
	case changed:
		if err := lim.Valid(); err != nil {
			return fail(err)
		}
		if err := st.SetToxicityLimits(ctx, *tenant, lim.Encode(), time.Now()); err != nil {
			return fail(err)
		}
	}
	if changed || *defaults {
		if err := st.AppendAudit(ctx, &store.AuditEntry{TenantID: *tenant, At: time.Now(), Actor: "command line", Action: "toxicity.limits", Target: "behaviour findings", Detail: lim.Describe()}); err != nil {
			return fail(err)
		}
	}
	fmt.Fprintf(stdout, "behaviour limits of %s, per match: %s\n", *tenant, lim.Describe())
	return 0
}
