package main

import (
	"context"
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

const driversUsage = `usage:
  carthago-gateway drivers pool -tenant ID [-on | -off] [-data DIR]
  carthago-gateway drivers show -tenant ID -player P [-data DIR]

The driver list: at its handshake a Windows client sends Windows' own signed list of the
kernel drivers loaded since boot. The gateway verifies it against the session's boot
record, keeps it with the session (the session page shows it) and raises a driver that
has no signer, a PC that accepts test-signed drivers, and a known vulnerable driver for
review. It never bans for it.

pool shows whether the studio's unattested pool is on, or turns it -on or -off (the
default). While it is on, the game-server status call (/v1/shadow/status under the server
key) also answers "attestation": "attested" or "unattested" per player, so the studio's
matchmaking can keep unattested players together. Attested is: the player's latest
session reached trust level 3 (TPM-attested boot with Secure Boot and memory integrity)
and sent a verified, complete driver list with nothing raised in it.

show prints how the list of the player's latest session was read. Both work on the
gateway's database directly, running or not.
`

// driversCommand runs "carthago-gateway drivers ...".
func driversCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, driversUsage)
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet("drivers "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", "gateway-data", "the gateway's data directory")
	tenant := fs.String("tenant", "", "tenant id of the studio")
	player := fs.String("player", "", "show: the player")
	on := fs.Bool("on", false, "pool: turn the unattested pool on")
	off := fs.Bool("off", false, "pool: turn the unattested pool off")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "carthago-gateway drivers:", err)
		return 1
	}
	if (cmd != "pool" && cmd != "show") || fs.NArg() > 0 {
		fmt.Fprint(stderr, driversUsage)
		return 2
	}
	switch {
	case *tenant == "":
		return fail(errors.New("-tenant is required"))
	case cmd == "show" && *player == "":
		return fail(errors.New("-player is required"))
	case *on && *off:
		return fail(errors.New("give one of -on and -off"))
	}
	set := cmd == "pool" && (*on || *off)
	dbPath := filepath.Join(*dataDir, "gateway.db")
	if _, err := os.Stat(dbPath); err != nil && !set {
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

	if cmd == "show" {
		d, err := st.LatestDriverList(ctx, *tenant, *player)
		if errors.Is(err, store.ErrNotFound) {
			fmt.Fprintf(stdout, "DRIVER LIST: no session of %s has been recorded with a driver list\n", *player)
			return 0
		}
		if err != nil {
			return fail(err)
		}
		fmt.Fprintln(stdout, driverListLine(d))
		for _, l := range d.Drivers {
			if len(l.Flags) > 0 {
				fmt.Fprintf(stdout, "  for review: %s (%s) %s %s\n", orDash(l.Name), strings.Join(l.Flags, ", "), l.HashAlg, l.ImageHash)
			}
		}
		return 0
	}

	if set {
		if err := st.SetUnattestedPool(ctx, *tenant, *on); err != nil {
			return fail(err)
		}
		detail := "turned on: the status call answers attested or unattested per player"
		if !*on {
			detail = "turned off: the status call no longer says attested or unattested"
		}
		if err := st.AppendAudit(ctx, &store.AuditEntry{TenantID: *tenant, At: time.Now(), Actor: "command line", Action: "drivers.pool", Target: "unattested pool", Detail: detail}); err != nil {
			return fail(err)
		}
	}
	isOn, err := st.UnattestedPool(ctx, *tenant)
	if err != nil {
		return fail(err)
	}
	if isOn {
		fmt.Fprintf(stdout, "the unattested pool of %s is on: /v1/shadow/status also answers \"attestation\": \"attested\" or \"unattested\" per player\n", *tenant)
	} else {
		fmt.Fprintf(stdout, "the unattested pool of %s is off: /v1/shadow/status does not say attested or unattested\n", *tenant)
	}
	return 0
}

// driverListLine is the one line that says how a session's driver list was read.
func driverListLine(d *store.DriverList) string {
	head := fmt.Sprintf("DRIVER LIST of session %s (trust level %d): ", d.SessionID, d.TrustLevel)
	switch d.Status {
	case store.DriversVerified, store.DriversUnverified:
		s := fmt.Sprintf("%d drivers loaded since boot, signature verified", len(d.Drivers))
		if d.Status == store.DriversUnverified {
			s = fmt.Sprintf("%d drivers loaded since boot, NOT verified (%s)", len(d.Drivers), d.Reason)
		}
		if d.Overflowed {
			s += "; incomplete, Windows' table was full"
		}
		if d.TestSigning {
			s += "; Windows accepts test-signed drivers"
		}
		verdict := "unattested"
		if d.Attested() {
			verdict = "attested"
		}
		return head + s + fmt.Sprintf("; %d raised for review; this session counts as %s", d.Flagged, verdict)
	case store.DriversUnavailable:
		return head + "unavailable: " + d.Reason + "; this session counts as unattested"
	case store.DriversRejected:
		return head + "not accepted: " + d.Reason + "; this session counts as unattested"
	}
	return head + "not sent: " + d.Reason + "; this session counts as unattested"
}
