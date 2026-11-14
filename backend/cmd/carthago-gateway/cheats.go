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

	"carthago/backend/internal/store"
)

const cheatsUsage = `usage:
  carthago-gateway cheats list -tenant ID [-data DIR]
  carthago-gateway cheats add -tenant ID (-file PATH | -sha256 HEX) -name NAME [-note TEXT] [-data DIR]
  carthago-gateway cheats remove -tenant ID (-file PATH | -sha256 HEX | -name NAME) [-data DIR]

The studio's list of known cheat files, by SHA-256. A module of the game whose file is on
the list is certain evidence (rule known_cheat) whatever the file is called and wherever it
sits, and bans automatically. Works on the gateway's database directly, running or not; an
entry applies to modules reported after it was added. Also on the dashboard's Known cheats
page. The list is never sent to a client.
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
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "carthago-gateway cheats:", err)
		return 1
	}
	if (cmd != "list" && cmd != "add" && cmd != "remove") || fs.NArg() > 0 {
		fmt.Fprint(stderr, cheatsUsage)
		return 2
	}
	if *tenant == "" {
		return fail(errors.New("-tenant is required"))
	}
	hash := ""
	switch {
	case cmd == "list":
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
	if _, err := os.Stat(dbPath); err != nil && cmd != "add" {
		if cmd == "list" {
			fmt.Fprintln(stdout, "no gateway database yet: the list is empty")
			return 0
		}
		return fail(fmt.Errorf("no gateway database at %s: give -data the data directory the gateway runs with", dbPath))
	}
	// add also works before the gateway's first run, so a list can be prepared.
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
