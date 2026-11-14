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
)

const shadowUsage = `usage:
  carthago-gateway shadow period -tenant ID [-hours N | -days N | -off] [-data DIR]
  carthago-gateway shadow list -tenant ID [-data DIR]

The shadow pool of a studio. With a period set, a player caught on certain evidence is not
banned at once: the player plays on, told nothing, and the ban takes effect when the
period is over. Until then the studio's matchmaking is told who is in the pool
(POST /v1/shadow/status and GET /v1/shadow/pool under the server key) and matches those
players with each other.

period shows the studio's period, or sets it: -hours or -days, at most 90 days; -off is
the default, an automatic ban that takes effect at once. A change applies to players
caught from then on. list shows who is in the pool. Both work on the gateway's database
directly, running or not, and are on the dashboard's Shadow pool page, where a reviewer
also bans a player now or releases one. "carthago-gateway bans lift -ref" releases too.
`

// shadowCommand runs "carthago-gateway shadow ...".
func shadowCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, shadowUsage)
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet("shadow "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", "gateway-data", "the gateway's data directory")
	tenant := fs.String("tenant", "", "tenant id of the studio")
	hours := fs.Int("hours", 0, "period: the shadow period in hours")
	days := fs.Int("days", 0, "period: the shadow period in days")
	off := fs.Bool("off", false, "period: turn the shadow pool off")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "carthago-gateway shadow:", err)
		return 1
	}
	if (cmd != "period" && cmd != "list") || fs.NArg() > 0 {
		fmt.Fprint(stderr, shadowUsage)
		return 2
	}
	if *tenant == "" {
		return fail(errors.New("-tenant is required"))
	}
	set := 0
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "hours" || f.Name == "days" || f.Name == "off" {
			set++
		}
	})
	period := time.Duration(*hours)*time.Hour + time.Duration(*days)*24*time.Hour
	if cmd == "period" && set > 0 {
		switch {
		case set > 1:
			return fail(errors.New("give one of -hours, -days and -off"))
		case !*off && (period <= 0 || period > store.MaxShadowPeriod):
			return fail(fmt.Errorf("the period is from 1 hour to %d days; -off turns the pool off", int(store.MaxShadowPeriod/(24*time.Hour))))
		}
	}
	dbPath := filepath.Join(*dataDir, "gateway.db")
	if _, err := os.Stat(dbPath); err != nil && (cmd == "list" || set == 0) {
		return fail(fmt.Errorf("no gateway database at %s: give -data the data directory the gateway runs with", dbPath))
	}
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return fail(err)
	}
	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		return fail(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now()

	if cmd == "list" {
		pool, err := st.ListShadowBans(ctx, *tenant)
		if err != nil {
			return fail(err)
		}
		n := 0
		for _, b := range pool {
			if !b.InPool(now) {
				continue
			}
			n++
			line := fmt.Sprintf("%s  player %s  rule %s  since %s  ban takes effect %s", b.Ref, b.PlayerHash, orDash(b.Rule),
				b.BannedAt.Local().Format("2006-01-02 15:04"), b.EffectiveAt.Local().Format("2006-01-02 15:04"))
			if b.ShadowOf != "" {
				line += "  another account on the PC of " + b.ShadowOf
			}
			fmt.Fprintln(stdout, line)
		}
		if n == 0 {
			fmt.Fprintln(stdout, "nobody is in the shadow pool")
		}
		return 0
	}

	if set > 0 {
		if err := st.SetShadowPeriod(ctx, *tenant, period); err != nil {
			return fail(err)
		}
		detail := "period set to " + spellPeriod(period)
		if period == 0 {
			detail = "turned off: an automatic ban is immediate again"
		}
		if err := st.AppendAudit(ctx, &store.AuditEntry{TenantID: *tenant, At: now, Actor: "command line", Action: "shadow.period", Target: "shadow pool", Detail: detail}); err != nil {
			return fail(err)
		}
	}
	period, err = st.ShadowPeriod(ctx, *tenant)
	if err != nil {
		return fail(err)
	}
	if period == 0 {
		fmt.Fprintf(stdout, "the shadow pool of %s is off: a player caught on certain evidence is banned at once\n", *tenant)
	} else {
		fmt.Fprintf(stdout, "a player of %s caught on certain evidence plays on in the shadow pool for %s, then the ban takes effect\n", *tenant, spellPeriod(period))
	}
	return 0
}

// spellPeriod writes a shadow period in days when it is whole days, else in hours.
func spellPeriod(d time.Duration) string {
	if n := int(d / (24 * time.Hour)); d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%d %s", n, plural(n, "day", "days"))
	}
	if n := int(d / time.Hour); d%time.Hour == 0 {
		return fmt.Sprintf("%d %s", n, plural(n, "hour", "hours"))
	}
	return d.String()
}
