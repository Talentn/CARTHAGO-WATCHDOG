package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"carthago/backend/internal/learning"
	"carthago/backend/internal/store"
)

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

const cheatsUsage = `usage:
  carthago-gateway cheats list -tenant ID [-data DIR]
  carthago-gateway cheats add -tenant ID (-file PATH | -sha256 HEX) -name NAME [-note TEXT] [-data DIR]
  carthago-gateway cheats remove -tenant ID (-file PATH | -sha256 HEX | -name NAME) [-data DIR]
  carthago-gateway cheats proposed -tenant ID [-data DIR]
  carthago-gateway cheats propose-after -tenant ID -accounts N [-data DIR]

The studio's list of known cheat files, by SHA-256. A module of the game whose file is on
the list is certain evidence (rule known_cheat) whatever the file is called and wherever it
sits, and bans automatically. Works on the gateway's database directly, running or not; an
entry applies to modules reported after it was added. Also on the dashboard's Known cheats
page. The list is never sent to a client.

proposed lists the files that only banned accounts were seen to load: not validly signed,
outside the Windows folder, in at least N distinct banned accounts and in no account that
is not banned. propose-after sets N for the studio (default 2). A proposal is never added
by itself: a reviewer approves or dismisses it on the Known cheats page.
`

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// cheatsCommand runs "carthago-gateway cheats ...".
func cheatsCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, cheatsUsage)
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet("cheats "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", "gateway-data", "the gateway's data directory")
	tenant := fs.String("tenant", "", "tenant id of the studio")
	file := fs.String("file", "", "the cheat's file; its SHA-256 is what is listed")
	sum := fs.String("sha256", "", "the SHA-256 of the cheat's file, 64 hex digits")
	name := fs.String("name", "", "what the cheat is called")
	note := fs.String("note", "", "add: a note kept with the entry")
	accounts := fs.Int("accounts", 0, "propose-after: distinct banned accounts a file must be seen in before it is proposed")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "carthago-gateway cheats:", err)
		return 1
	}
	if (cmd != "list" && cmd != "add" && cmd != "remove" && cmd != "proposed" && cmd != "propose-after") || fs.NArg() > 0 {
		fmt.Fprint(stderr, cheatsUsage)
		return 2
	}
	if *tenant == "" {
		return fail(errors.New("-tenant is required"))
	}
	hash := ""
	switch {
	case cmd == "list" || cmd == "proposed":
	case cmd == "propose-after":
		if *accounts < 1 || *accounts > store.MaxProposalAccounts {
			return fail(fmt.Errorf("-accounts is a number from 1 to %d", store.MaxProposalAccounts))
		}
	case *file != "" && *sum != "":
		return fail(errors.New("give -file or -sha256, not both"))
	case *file != "":
		h, err := fileSHA256(*file)
		if err != nil {
			return fail(err)
		}
		hash = h
	case *sum != "":
		h, ok := store.CleanSHA256(*sum)
		if !ok {
			return fail(errors.New("-sha256 is 64 hex digits"))
		}
		hash = h
	case cmd == "add":
		return fail(errors.New("which file: give -file or -sha256"))
	case *name == "":
		return fail(errors.New("which entry: give -file, -sha256 or -name"))
	}
	if cmd == "add" && strings.TrimSpace(*name) == "" {
		return fail(errors.New("add needs -name: what the cheat is called"))
	}
	dbPath := filepath.Join(*dataDir, "gateway.db")
	if _, err := os.Stat(dbPath); err != nil && cmd != "add" && cmd != "propose-after" {
		if cmd == "list" || cmd == "proposed" {
			fmt.Fprintln(stdout, "no gateway database yet: the list is empty")
			return 0
		}
		return fail(fmt.Errorf("no gateway database at %s: give -data the data directory the gateway runs with", dbPath))
	}
	// add and propose-after also work before the gateway's first run.
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
	audit := func(action string, c store.KnownCheat) error {
		return st.AppendAudit(ctx, &store.AuditEntry{TenantID: *tenant, At: now, Actor: "command line", Action: action, Target: "known cheat " + c.Name, Detail: "SHA-256 " + c.SHA256})
	}
	switch cmd {
	case "propose-after":
		if err := st.SetCheatProposalAccounts(ctx, *tenant, *accounts); err != nil {
			return fail(err)
		}
		if err := st.AppendAudit(ctx, &store.AuditEntry{TenantID: *tenant, At: now, Actor: "command line", Action: "cheat.proposals", Target: "proposed known cheats",
			Detail: fmt.Sprintf("proposed after %d banned accounts", *accounts)}); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "a file is proposed as a known cheat of %s once %d banned %s loaded it and no account that is not banned has\n", *tenant, *accounts, plural(*accounts, "account has", "accounts have"))
		return 0
	case "proposed":
		p, err := learning.FindProposals(ctx, st, *tenant)
		if err != nil {
			return fail(err)
		}
		for _, f := range p.List {
			fmt.Fprintf(stdout, "%s  %s  %s  banned accounts %d  sessions %d  last seen %s\n", f.SHA256, strings.Join(f.Names, ", "), f.Signature, f.BannedAccounts, f.Sessions, f.LastSeen.Local().Format("2006-01-02 15:04"))
		}
		if len(p.List) == 0 {
			fmt.Fprintln(stdout, "nothing is proposed")
		}
		fmt.Fprintf(stdout, "proposed after %d banned %s; compared with %d %s not banned\n", p.MinAccounts, plural(p.MinAccounts, "account", "accounts"), p.Compared, plural(p.Compared, "account that is", "accounts that are"))
		return 0
	case "add":
		c := store.KnownCheat{TenantID: *tenant, SHA256: hash, Name: strings.TrimSpace(*name), Note: strings.TrimSpace(*note), AddedBy: "command line", AddedAt: now}
		err := st.AddKnownCheat(ctx, &c)
		if errors.Is(err, store.ErrDuplicate) {
			have, err := st.KnownCheat(ctx, *tenant, hash)
			if err != nil {
				return fail(err)
			}
			fmt.Fprintf(stdout, "already on the list as %q: %s\n", have.Name, hash)
			return 0
		}
		if err != nil {
			return fail(err)
		}
		if err := audit("cheat.add", c); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "added %q: %s\n", c.Name, hash)
		return 0
	case "list":
		list, err := st.ListKnownCheats(ctx, *tenant)
		if err != nil {
			return fail(err)
		}
		for _, c := range list {
			line := fmt.Sprintf("%s  %s  added %s by %s", c.SHA256, c.Name, c.AddedAt.Local().Format("2006-01-02 15:04"), c.AddedBy)
			if c.Note != "" {
				line += "  (" + c.Note + ")"
			}
			fmt.Fprintln(stdout, line)
		}
		if len(list) == 0 {
			fmt.Fprintln(stdout, "the list is empty")
		}
		return 0
	}
	list, err := st.ListKnownCheats(ctx, *tenant)
	if err != nil {
		return fail(err)
	}
	removed := 0
	for _, c := range list {
		if hash != "" && c.SHA256 != hash || hash == "" && c.Name != *name {
			continue
		}
		if _, err := st.RemoveKnownCheat(ctx, *tenant, c.ID); err != nil {
			return fail(err)
		}
		if err := audit("cheat.remove", c); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "removed %q: %s\n", c.Name, c.SHA256)
		removed++
	}
	if removed == 0 {
		return fail(errors.New("no such entry on the list"))
	}
	return 0
}
