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

const bansUsage = `usage:
  carthago-gateway bans list -tenant ID [-data DIR]
  carthago-gateway bans lift -tenant ID (-ref REFERENCE | -all) [-note TEXT] [-data DIR]
  carthago-gateway bans delay -tenant ID -minutes N [-data DIR]

Works on the gateway's database directly, running or not. A lifted ban stays in the list as
history. delay sets how long the studio's automatic bans wait before they take effect
(default 0). Both are also on the dashboard's Bans page.
`

// bansCommand runs "carthago-gateway bans ...".
func bansCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, bansUsage)
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet("bans "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", "gateway-data", "the gateway's data directory")
	tenant := fs.String("tenant", "", "tenant id of the studio")
	ref := fs.String("ref", "", "lift: the reference of the ban")
	all := fs.Bool("all", false, "lift: every ban of the tenant that stands")
	note := fs.String("note", "", "lift: why, kept with the ban")
	minutes := fs.Int("minutes", -1, "delay: minutes an automatic ban waits before it takes effect")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "carthago-gateway bans:", err)
		return 1
	}
	if (cmd != "list" && cmd != "lift" && cmd != "delay") || fs.NArg() > 0 {
		fmt.Fprint(stderr, bansUsage)
		return 2
	}
	if *tenant == "" || cmd == "lift" && (*ref == "") == !*all {
		return fail(errors.New("-tenant is required, and lift needs exactly one of -ref and -all"))
	}
	if cmd == "delay" && (*minutes < 0 || time.Duration(*minutes)*time.Minute > store.MaxBanDelay) {
		return fail(fmt.Errorf("-minutes is a number from 0 to %d", int(store.MaxBanDelay/time.Minute)))
	}
	dbPath := filepath.Join(*dataDir, "gateway.db")
	if _, err := os.Stat(dbPath); err != nil {
		if cmd == "lift" && *all {
			fmt.Fprintln(stdout, "no gateway database yet: nobody is banned")
			return 0
		}
		return fail(fmt.Errorf("no gateway database at %s: give -data the data directory the gateway runs with", dbPath))
	}
	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		return fail(err)
	}
	defer st.Close()
	ctx := context.Background()
	if cmd == "delay" {
		if err := st.SetBanDelay(ctx, *tenant, time.Duration(*minutes)*time.Minute); err != nil {
			return fail(err)
		}
		if err := st.AppendAudit(ctx, &store.AuditEntry{TenantID: *tenant, At: time.Now(), Actor: "command line", Action: "ban.delay", Target: "automatic bans",
			Detail: fmt.Sprintf("delay set to %d minutes", *minutes)}); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "automatic bans of %s take effect %d minutes after the detection\n", *tenant, *minutes)
		return 0
	}
	list, err := st.ListBans(ctx, *tenant, 1000)
	if err != nil {
		return fail(err)
	}
	now := time.Now()
	if cmd == "list" {
		for _, b := range list {
			state := "active"
			switch {
			case b.Lifted():
				state = "lifted by " + b.LiftedBy
			case b.Pending(now):
				state = "pending until " + b.EffectiveAt.Local().Format("2006-01-02 15:04")
			}
			fmt.Fprintf(stdout, "%s  %s  player %s  device %s  by %s  rule %s  %s\n", b.Ref, b.BannedAt.Local().Format("2006-01-02 15:04"), b.PlayerHash, orDash(b.DeviceID), b.BannedBy, orDash(b.Rule), state)
		}
		if len(list) == 0 {
			fmt.Fprintln(stdout, "no bans")
		}
		return 0
	}
	lifted := 0
	for _, b := range list {
		if b.Lifted() || !*all && b.Ref != *ref {
			continue
		}
		if _, err := st.LiftBan(ctx, *tenant, b.ID, "command line", *note, now); err != nil {
			return fail(err)
		}
		// The audit log is the dashboard's record of who did what; a lift from the
		// command line belongs in it too.
		if err := st.AppendAudit(ctx, &store.AuditEntry{TenantID: *tenant, At: now, Actor: "command line", Action: "ban.lift", Target: "ban " + b.Ref, Detail: *note}); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "lifted %s (player %s)\n", b.Ref, b.PlayerHash)
		lifted++
	}
	if lifted == 0 {
		if !*all {
			return fail(fmt.Errorf("no standing ban with reference %s", *ref))
		}
		fmt.Fprintln(stdout, "no standing bans")
	}
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
