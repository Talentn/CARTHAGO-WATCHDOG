// Package analyzer holds the server-side detection rules (plan §8). It is deliberately pure:
// every rule is a function over values the gateway already has, with no I/O and no clock, so
// the thresholds and allowlists all live here (plan §8.6, "the client only observes") and the
// rules are unit-testable without a database or a live match.
//
// Two families live here:
//   - ClassifyFinding turns a client integrity finding (from a heartbeat) into Evidence,
//     applying the overlay/handle allowlist so a Steam or Discord overlay is not treated as a
//     cheat.
//   - The gameplay rules (gameplay.go) turn accumulated match telemetry into Evidence using
//     the statistics in stats.go.
package analyzer

import (
	"fmt"
	"strings"

	pb "carthago/backend/gen/carthago/v1"
)

// Severity orders evidence for the dashboard and for the auto-kick policy.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "unknown"
}

// Evidence is one rule's verdict about one player. Score is a 0..1 confidence used to rank
// within a severity; Integrity marks client-tamper evidence that the auto-kick policy may act
// on (behavioural rules are advisory and never auto-kick, since they can have false positives).
type Evidence struct {
	Rule      string
	Severity  Severity
	Score     float64
	Integrity bool
	Summary   string
}

// Config carries every threshold a rule uses. Defaults() gives values tuned for the Phase 1
// demo; a studio overrides them per title. Everything is here, never on the client.
type Config struct {
	// Overlay/handle allowlist: process image base names (lowercase) that are expected to
	// draw overlays or hold handles to the game, so their findings are downgraded to info.
	OverlayAllow map[string]bool

	SnapDeg       float64 // one-tick angular step counted as a snap
	SnapSettleDeg float64 // the step right after a snap must be below this to count as a lock
	SnapMin       int     // snaps-then-lock events before the player is flagged

	HeadshotMinShots int     // minimum hits before the headshot z-test runs
	HeadshotZ        float64 // z above which the headshot rate is flagged

	TTDMinSamples int     // time-to-damage samples needed, across the match
	TTDZ          float64 // robust-z below which a player reacts implausibly fast

	CmdRatio    float64 // commands-per-tick ratio counted as speedhacking
	CmdMinTicks uint32  // ticks observed before the command-rate rule runs

	TriggerMinPresses int     // trigger presses needed for the macro test
	TriggerMaxCV      float64 // interval coefficient of variation below which it looks scripted

	ClockToleranceRatio float64 // allowed |client/server elapsed - 1| before a clock divergence
	CoverageMinRuns     uint64  // a job completing fewer passes than this is "blind"
}

// Default overlay allowlist: common overlays and capture tools that legitimately inject into or
// draw over the game (plan §8.4). Base names are lowercase.
var defaultOverlayAllow = map[string]bool{
	"gameoverlayrenderer64.dll": true,
	"gameoverlayrenderer.dll":   true,
	"steam.exe":                 true,
	"steamwebhelper.exe":        true,
	"discordhook64.dll":         true,
	"discordhook.dll":           true,
	"overlay.x64.dll":           true,
	"rtsshooks64.dll":           true, // RivaTuner / MSI Afterburner
	"graphics-hook64.dll":       true, // OBS game capture
	"graphics-hook32.dll":       true,
	"nvspcap64.dll":             true, // NVIDIA ShadowPlay
	"nvcamera64.dll":            true,
	"obs64.exe":                 true,
}

func Defaults() Config {
	return Config{
		OverlayAllow:        defaultOverlayAllow,
		SnapDeg:             35,
		SnapSettleDeg:       1.5,
		SnapMin:             4,
		HeadshotMinShots:    40,
		HeadshotZ:           3.5,
		TTDMinSamples:       12,
		TTDZ:                3.5,
		CmdRatio:            1.08,
		CmdMinTicks:         256,
		TriggerMinPresses:   8,
		TriggerMaxCV:        0.02,
		ClockToleranceRatio: 0.02,
		CoverageMinRuns:     1,
	}
}

// ClassifyFinding maps one client finding to Evidence. detail is the finding's text field
// (an image base name for overlay/handle findings). It returns ok=false for findings that
// carry no standalone verdict (e.g. an allowed module load), so the caller can skip them.
func (c Config) ClassifyFinding(code uint32, a, b uint64, detail string) (Evidence, bool) {
	name := strings.ToLower(strings.TrimSpace(detail))
	allowed := c.OverlayAllow[name]
	switch pb.FindingCode(code) {
	case pb.FindingCode_FINDING_CODE_UNBACKED_EXEC:
		// a=base, b=size|flags<<48. Writable+executable private memory is classic manual-map.
		writable := b>>48&uint64(pb.UnbackedFlags_UNBACKED_FLAGS_WRITABLE) != 0
		pe := b>>48&uint64(pb.UnbackedFlags_UNBACKED_FLAGS_PE_SIGNATURE) != 0
		sev := SeverityHigh
		if writable && pe {
			sev = SeverityCritical
		}
		return ev("unbacked_exec", sev, 0.9, true, fmt.Sprintf("executable private memory at %#x", a)), true
	case pb.FindingCode_FINDING_CODE_IMAGE_NOT_IN_LOADER:
		return ev("image_not_in_loader", SeverityHigh, 0.85, true, fmt.Sprintf("mapped image %q not in the loader list", detail)), true
	case pb.FindingCode_FINDING_CODE_MODULE_NOT_IMAGE:
		return ev("module_not_image", SeverityMedium, 0.6, true, "loader module not backed by an image mapping"), true
	case pb.FindingCode_FINDING_CODE_THREAD_START_UNBACKED:
		return ev("thread_start_unbacked", SeverityHigh, 0.85, true, "thread started outside any module"), true
	case pb.FindingCode_FINDING_CODE_API_HOOK:
		return ev("api_hook", SeverityHigh, 0.8, true, fmt.Sprintf("hooked API in %s", detail)), true
	case pb.FindingCode_FINDING_CODE_CODE_PATCH:
		return ev("code_patch", SeverityCritical, 0.9, true, fmt.Sprintf(".text patched: %s", detail)), true
	case pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE:
		if allowed {
			return ev("external_handle", SeverityInfo, 0.1, false, "handle from allowlisted "+detail), true
		}
		return ev("external_handle", SeverityMedium, 0.55, true, fmt.Sprintf("process %s holds a %#x handle to the game", detail, b)), true
	case pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW:
		if allowed {
			return ev("overlay_window", SeverityInfo, 0.1, false, "allowlisted overlay "+detail), true
		}
		return ev("overlay_window", SeverityLow, 0.35, false, "unrecognised topmost overlay "+detail), true
	case pb.FindingCode_FINDING_CODE_DEBUGGER:
		// a = DebugSignal bitmask. A kernel debugger or a debug object is strong; the PEB flag
		// alone is weak and easily spoofed either way.
		strong := a & uint64(pb.DebugSignal_DEBUG_SIGNAL_KERNEL_DEBUGGER|pb.DebugSignal_DEBUG_SIGNAL_DEBUG_OBJECT|pb.DebugSignal_DEBUG_SIGNAL_HARDWARE_BREAKPOINT)
		if strong != 0 {
			return ev("debugger", SeverityHigh, 0.75, true, fmt.Sprintf("debugger present (signals %#x)", a)), true
		}
		return ev("debugger", SeverityLow, 0.3, false, fmt.Sprintf("weak debug signal %#x", a)), true
	case pb.FindingCode_FINDING_CODE_VULNERABLE_DRIVER:
		return ev("vulnerable_driver", SeverityHigh, 0.7, true, "known-vulnerable driver loaded: "+detail), true
	case pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE:
		return classifyModuleSignature(b, detail), true
	case pb.FindingCode_FINDING_CODE_EXTERNAL_EXEC_REGIONS:
		// Seen from outside the process, the engine's own loader (GoldSrc maps hw.dll itself on
		// older builds) and script JITs look the same as foreign code, so this is context for a
		// reviewer and carries no risk until build ground truth exists to compare against.
		return ev("external_exec_regions", SeverityInfo, 0.1, false,
			fmt.Sprintf("%d executable regions without a backing file (%d KB), seen from outside the process", a, b&(1<<48-1)>>10)), true
	case pb.FindingCode_FINDING_CODE_MITIGATIONS, pb.FindingCode_FINDING_CODE_MODULE_LOADED, pb.FindingCode_FINDING_CODE_THREAD_START_LOADER:
		return Evidence{}, false
	}
	return Evidence{}, false
}

// classifyModuleSignature turns a companion's module report into evidence. Everything is
// informational except two cases: an unsigned module loaded from outside the game folder and
// Program Files, and a signed file that was modified after signing. Neither is integrity
// evidence, so neither can kick.
func classifyModuleSignature(b uint64, detail string) Evidence {
	state, class := pb.ModuleSignature(b&0xff), pb.ModulePathClass(b>>8&0xff)
	where := map[pb.ModulePathClass]string{
		pb.ModulePathClass_MODULE_PATH_CLASS_GAME_DIR:      "game folder",
		pb.ModulePathClass_MODULE_PATH_CLASS_PROGRAM_FILES: "Program Files",
		pb.ModulePathClass_MODULE_PATH_CLASS_OTHER:         "outside the game folder",
	}[class]
	if where == "" {
		where = "unknown location"
	}
	what := map[pb.ModuleSignature]string{
		pb.ModuleSignature_MODULE_SIGNATURE_VALID:      "signed, signature valid",
		pb.ModuleSignature_MODULE_SIGNATURE_NONE:       "not signed",
		pb.ModuleSignature_MODULE_SIGNATURE_BAD_DIGEST: "signed, but changed after signing",
		pb.ModuleSignature_MODULE_SIGNATURE_UNTRUSTED:  "signed by an untrusted signer",
		pb.ModuleSignature_MODULE_SIGNATURE_EXPIRED:    "signed with an expired certificate",
		pb.ModuleSignature_MODULE_SIGNATURE_ERROR:      "signature could not be checked",
	}[state]
	if what == "" {
		what = "signature state unknown"
	}
	summary := fmt.Sprintf("module %s (%s): %s", detail, where, what)
	switch {
	case state == pb.ModuleSignature_MODULE_SIGNATURE_BAD_DIGEST:
		return ev("module_signature", SeverityMedium, 0.4, false, summary)
	case class == pb.ModulePathClass_MODULE_PATH_CLASS_OTHER && state != pb.ModuleSignature_MODULE_SIGNATURE_VALID:
		return ev("module_signature", SeverityLow, 0.3, false, summary)
	}
	return ev("module_signature", SeverityInfo, 0.1, false, summary)
}

func ev(rule string, sev Severity, score float64, integrity bool, summary string) Evidence {
	return Evidence{Rule: rule, Severity: sev, Score: score, Integrity: integrity, Summary: summary}
}
