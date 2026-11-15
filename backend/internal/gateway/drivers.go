package gateway

import (
	"context"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/attest"
	"carthago/backend/internal/store"
)

// The driver list: Windows' own signed list of the kernel drivers loaded since boot, which
// the client fetches in user mode and passes on in Prove. The gateway verifies it against
// the session's boot record, keeps it with the session, and raises what needs a person's
// look. It never refuses, kicks or bans for it: every rule below is of the suspicious
// tier, and a client without a list gets its session like any other.

// DriverLists is where the gateway keeps each session's driver list and what it raised.
type DriverLists interface {
	store.DriverStore
	AddEvidence(ctx context.Context, evs []store.Evidence) error
}

// Attestation answers of the unattested pool.
const (
	StatusAttested   = "attested"
	StatusUnattested = "unattested"
)

// vulnerableDrivers are kernel drivers that are signed and let any administrator read and
// write kernel memory, which is how most kernel cheats get in (BYOVD). By the internal
// name of the image, lower case, without ".sys"; the same names the client's own scan
// knows. Several ship with ordinary tools (RTCore64 with MSI Afterburner, WinRing0 with
// fan and RGB software), so a match is for review.
var vulnerableDrivers = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range []string{
		"asio", "asio64", "asrdrv101", "asrdrv102", "asrdrv104", "asrdrv106", "atillk64", "aswarpot", "bs_def64", "cpuz141_x64", "dbk32", "dbk64",
		"dbutil_2_3", "echo_driver", "ene", "gdrv", "glckio2", "inpoutx64", "iqvw64e", "kprocesshacker", "mhyprot2", "msio64", "nicm", "ntiolib_x64",
		"phymemx64", "procexp152", "rtcore64", "rwdrv", "speedfan", "truesight", "winio64", "winring0x64", "zam64", "zamguard64",
	} {
		m[n] = true
	}
	return m
}()

func vulnerableDriver(name string) bool {
	return vulnerableDrivers[strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".sys")]
}

func driverListUnavailable(dl *pb.DriverList) string {
	switch dl.Unavailable {
	case pb.DriverListUnavailable_DRIVER_LIST_UNAVAILABLE_NO_INTERFACE:
		return "this Windows has no signed driver list (it came with the January 2026 update of Windows 11 24H2 and 25H2)"
	case pb.DriverListUnavailable_DRIVER_LIST_UNAVAILABLE_HVCI_OFF:
		return "memory integrity (HVCI) is off on this PC, so Windows keeps no driver list"
	case pb.DriverListUnavailable_DRIVER_LIST_UNAVAILABLE_VBS_OFF:
		return "virtualization-based security is not running on this PC"
	case pb.DriverListUnavailable_DRIVER_LIST_UNAVAILABLE_FAILED:
		return fmt.Sprintf("Windows refused the request (error %d)", dl.Win32Error)
	}
	return "the client gave no reason"
}

// readDriverList turns what Prove carried into the session's record. boot is the session's
// boot evidence, nil without a TPM quote.
func readDriverList(dl *pb.DriverList, nonce [32]byte, boot *attest.BootResult) *store.DriverList {
	out := &store.DriverList{Status: store.DriversNotSent, Reason: "the client sent no driver list (a build from before it)"}
	if dl == nil {
		return out
	}
	if len(dl.Package) == 0 {
		out.Status, out.Reason = store.DriversUnavailable, driverListUnavailable(dl)
		return out
	}
	verifiedBoot := boot != nil && boot.QuoteOK && boot.Security != nil
	why := "this session has no verified boot record (no TPM quote), so there is no signing key to check the list with"
	var key *rsa.PublicKey
	if verifiedBoot {
		out.TestSigning = boot.Security.TestSigning
		why = "the verified boot record of this session carries no signing key for the list"
		if idks := boot.Security.VBS.IDKS; len(idks) > 0 {
			k, err := attest.IDKSPublicKey(idks)
			if err != nil {
				why = "the signing key in the boot record could not be read: " + err.Error()
			}
			key = k
		}
	} else if boot != nil {
		why = "the boot record of this session did not verify, so there is no signing key to check the list with"
	}
	report, err := attest.CheckDriverPackage(dl.Package, nonce, key)
	if err != nil {
		out.Status, out.Reason = store.DriversRejected, err.Error()
		if errors.Is(err, attest.ErrDriverSignature) {
			out.Reason = "the list's signature does not verify under the signing key of this session's boot record"
		}
		return out
	}
	out.Status, out.Reason, out.Overflowed = store.DriversVerified, "", report.Overflowed
	if !report.Verified {
		out.Status, out.Reason = store.DriversUnverified, why
	}
	for _, d := range report.Drivers {
		l := store.ListedDriver{Name: d.Name, HashAlg: d.HashAlg, ImageHash: hex.EncodeToString(d.ImageHash), Signer: hex.EncodeToString(d.Signer),
			OEM: d.OEM, Loads: d.Loads, Unloaded: d.Unloaded, Boot: d.Boot}
		if d.Signer == nil {
			l.Flags = append(l.Flags, store.DriverFlagUnsigned)
		}
		if vulnerableDriver(d.Name) {
			l.Flags = append(l.Flags, store.DriverFlagVulnerable)
		}
		if len(l.Flags) > 0 {
			out.Flagged++
		}
		out.Drivers = append(out.Drivers, l)
	}
	return out
}

// driverEvidence is what a list raises for review. The list says which images loaded and
// who signed them, not at which signing level, so "test-signed" comes from the boot
// record: Windows was started accepting test-signed drivers.
func driverEvidence(d *store.DriverList) []store.Evidence {
	if d.Status != store.DriversVerified && d.Status != store.DriversUnverified {
		return nil
	}
	trust := "signed list"
	if d.Status == store.DriversUnverified {
		trust = "list not verified"
	}
	named := func(flag string) (names []string, raw string) {
		var hit []store.ListedDriver
		for _, l := range d.Drivers {
			for _, f := range l.Flags {
				if f == flag {
					hit = append(hit, l)
					name := l.Name
					if name == "" {
						name = "(no name) " + l.ImageHash[:min(16, len(l.ImageHash))]
					}
					names = append(names, name)
				}
			}
		}
		b, _ := json.Marshal(hit)
		return names, string(b)
	}
	list := func(names []string) string {
		if len(names) > 6 {
			return strings.Join(names[:6], ", ") + fmt.Sprintf(" and %d more", len(names)-6)
		}
		return strings.Join(names, ", ")
	}
	ev := func(rule string, sev analyzer.Severity, score float64, summary, raw string) store.Evidence {
		return store.Evidence{TenantID: d.TenantID, PlayerHash: d.PlayerHash, SessionID: d.SessionID, Source: store.SourceClient, Rule: rule,
			Severity: int(sev), Score: score, Summary: summary, Raw: raw, ObservedAt: d.ReceivedAt}
	}
	var out []store.Evidence
	if names, raw := named(store.DriverFlagVulnerable); len(names) > 0 {
		out = append(out, ev("driver_vulnerable", analyzer.SeverityLow, 0.5,
			fmt.Sprintf("known-vulnerable kernel driver loaded since boot (%s): %s", trust, list(names)), raw))
	}
	if names, raw := named(store.DriverFlagUnsigned); len(names) > 0 {
		out = append(out, ev("driver_unsigned", analyzer.SeverityMedium, 0.6,
			fmt.Sprintf("kernel driver without a signer loaded since boot (%s): %s", trust, list(names)), raw))
	}
	if d.TestSigning {
		out = append(out, ev("driver_test_signing", analyzer.SeverityMedium, 0.6,
			fmt.Sprintf("Windows was started accepting test-signed kernel drivers (boot record); %d drivers loaded since boot", len(d.Drivers)), ""))
	}
	return out
}

func driverListNote(d *store.DriverList) string {
	switch d.Status {
	case store.DriversVerified:
		return fmt.Sprintf("driver list: verified, %d drivers", len(d.Drivers))
	case store.DriversUnverified:
		return fmt.Sprintf("driver list: %d drivers, not verified: %s", len(d.Drivers), d.Reason)
	case store.DriversUnavailable:
		return "driver list unavailable: " + d.Reason
	case store.DriversRejected:
		return "driver list not accepted: " + d.Reason
	}
	return ""
}

// recordDriverList reads the list of a session that just passed its handshake, stores it
// and what it raised, and returns the note for the client. The note says how the list was
// read and never what was raised in it. A failure here is logged; the session goes on.
func (g *Gateway) recordDriverList(ctx context.Context, sess store.Session, dl *pb.DriverList, nonce [32]byte, boot *attest.BootResult, now time.Time) string {
	if g.cfg.Drivers == nil {
		return ""
	}
	d := readDriverList(dl, nonce, boot)
	d.TenantID, d.SessionID, d.PlayerHash, d.TrustLevel, d.ReceivedAt = sess.TenantID, sess.SessionID, sess.PlayerHash, int(sess.TrustLevel), now
	if err := g.cfg.Drivers.PutDriverList(ctx, d); err != nil {
		g.log.Warn("persist driver list", "session", sess.SessionID, "err", err)
	}
	if evs := driverEvidence(d); len(evs) > 0 {
		if err := g.cfg.Drivers.AddEvidence(ctx, evs); err != nil {
			g.log.Warn("persist driver evidence", "session", sess.SessionID, "err", err)
		}
	}
	g.log.Info("driver list", "session", sess.SessionID, "player", sess.PlayerHash, "status", d.Status, "reason", d.Reason,
		"drivers", len(d.Drivers), "flagged", d.Flagged, "overflowed", d.Overflowed)
	return driverListNote(d)
}

// attestationOf is the unattested pool's answer for a player, "" while the studio has the
// pool off. It reads the player's most recent session and nothing of the shadow pool, so
// it is the same for a player in that pool as for any other.
func (g *Gateway) attestationOf(ctx context.Context, tenant, player string) (string, error) {
	if g.cfg.Drivers == nil {
		return "", nil
	}
	on, err := g.cfg.Drivers.UnattestedPool(ctx, tenant)
	if err != nil || !on {
		return "", err
	}
	d, err := g.cfg.Drivers.LatestDriverList(ctx, tenant, player)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	if d.Attested() {
		return StatusAttested, nil
	}
	return StatusUnattested, nil
}
