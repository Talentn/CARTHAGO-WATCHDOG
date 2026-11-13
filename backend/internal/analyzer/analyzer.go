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
// The policy kicks on critical integrity evidence only, so a rule may be critical only if no
// legitimate software produces it: today that is a writable executable region with a PE header
// and a clock that runs at a different rate than the kernel's in two consecutive windows.
type Evidence struct {
	Rule      string
	Severity  Severity
	Score     float64
	Integrity bool
	Summary   string

	// Notice is the category under which this evidence may tell the player (an
	// enforcement notice), zero when it is for the dashboard only. It is set by the rules
	// that read a companion's findings; for the older rules the pipeline keeps a list.
	Notice pb.EnforcementCategory
	// NoticeOptIn holds the notice back unless the operator opted in, because the guard
	// named in Held applies. Such evidence need not be integrity evidence.
	NoticeOptIn bool
	Held        string

	// engineCode: code_changed about a library other than the renderer and the client
	// library. See Certain.
	engineCode bool
}

// Config carries every threshold a rule uses. Defaults() gives values tuned for the Phase 1
// demo; a studio overrides them per title. Everything is here, never on the client.
type Config struct {
	// Overlay/handle allowlist: process image base names (lowercase) that are expected to
	// draw overlays or hold handles to the game, so their findings are downgraded to info.
	OverlayAllow map[string]bool

	// AllowRendererLibrary: an unsigned opengl32, d3d9, ddraw or glu32 that the game loads
	// from outside the system directory is excused when the first recorded start of the
	// game had it, as other things of a modified build are. Off by default: such a file is
	// how a wallhack is delivered, and a start profile recorded with it in place would
	// excuse it for good. For a build that ships its own.
	AllowRendererLibrary bool

	SnapDeg       float64 // one-tick angular step counted as a snap
	SnapSettleDeg float64 // the step right after a snap must be below this to count as a lock
	SnapMin       int     // snaps-then-lock events before the player is flagged

	HeadshotMinShots int // minimum hits before the headshot test runs
	// HeadshotZ is the significance of one test, as a one-sided normal z. The test runs again
	// after every batch, so a lucky streak gets many chances: at 4.0 about 1 honest
	// player-match in 5,000 is flagged (simulated), against 1 in 1,000 at 3.5.
	HeadshotZ         float64
	HeadshotMinExcess float64 // the rate must also exceed the baseline by this much (0..1)

	TTDMinOwn     int     // reaction samples needed from the player being judged
	TTDMinSamples int     // reaction samples needed from the rest of the lobby
	TTDMinPlayers int     // other players those samples must come from
	TTDZ          float64 // robust-z below which a player reacts implausibly fast

	CmdRatio    float64 // commands-per-tick ratio counted as speedhacking
	CmdMinTicks uint32  // ticks observed before the command-rate rule runs

	TriggerMinPresses int     // trigger presses needed for the macro test
	TriggerMaxCV      float64 // interval coefficient of variation below which it looks scripted

	ClockToleranceRatio float64 // allowed |client/server elapsed - 1| before a clock divergence
	CoverageMinRuns     uint64  // a job completing fewer passes than this is "blind"
}

// Default overlay allowlist: common overlays and capture tools that legitimately inject into or
// draw over the game (plan §8.4). Base names are lowercase. Matching is by file name only: the
// client does not verify who signed the file, so a cheat that takes one of these names is
// treated like the real thing. Findings about the clocks ignore the list for that reason.
var defaultOverlayAllow = map[string]bool{
	"gameoverlayrenderer64.dll": true,
	"gameoverlayrenderer.dll":   true,
	"steam.exe":                 true,
	"steamwebhelper.exe":        true,
	"discord.exe":               true,
	"discordhook64.dll":         true,
	"discordhook.dll":           true,
	"overlay.x64.dll":           true,
	"rtss.exe":                  true, // RivaTuner / MSI Afterburner
	"rtsshooks64.dll":           true,
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
		HeadshotZ:           4.0,
		HeadshotMinExcess:   0.15,
		TTDMinOwn:           8,
		TTDMinSamples:       12,
		TTDMinPlayers:       3,
		TTDZ:                3.5,
		CmdRatio:            1.08,
		CmdMinTicks:         640,
		TriggerMinPresses:   16,
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
		// a=base, b=size|flags<<48. Executable memory outside any image is what a manually
		// mapped module looks like, but also what every JIT (script engines, browsers embedded
		// in launchers, GPU drivers) and every hooking library's relay page looks like. Only a
		// region that still carries image headers is treated as tamper evidence; the rest is
		// recorded as information so it adds no risk and can never kick.
		flags := b >> 48
		writable := flags&uint64(pb.UnbackedFlags_UNBACKED_FLAGS_WRITABLE) != 0
		pe := flags&uint64(pb.UnbackedFlags_UNBACKED_FLAGS_PE_SIGNATURE) != 0
		mz := flags&uint64(pb.UnbackedFlags_UNBACKED_FLAGS_MZ_HEADER) != 0
		switch {
		case writable && pe:
			return ev("unbacked_exec", SeverityCritical, 0.9, true, fmt.Sprintf("writable executable memory with a PE header at %#x", a)), true
		case pe || mz:
			return ev("unbacked_exec", SeverityHigh, 0.9, true, fmt.Sprintf("executable memory with an image header outside any module at %#x", a)), true
		}
		return ev("unbacked_exec", SeverityInfo, 0.1, false, fmt.Sprintf("executable memory outside any module at %#x (no image header: JIT code or a hook relay)", a)), true
	case pb.FindingCode_FINDING_CODE_IMAGE_NOT_IN_LOADER:
		return ev("image_not_in_loader", SeverityHigh, 0.85, true, fmt.Sprintf("mapped image %q not in the loader list", detail)), true
	case pb.FindingCode_FINDING_CODE_MODULE_NOT_IMAGE:
		return ev("module_not_image", SeverityMedium, 0.6, true, "loader module not backed by an image mapping"), true
	case pb.FindingCode_FINDING_CODE_THREAD_START_UNBACKED:
		return ev("thread_start_unbacked", SeverityHigh, 0.85, true, "thread started outside any module"), true
	case pb.FindingCode_FINDING_CODE_API_HOOK:
		// b = WatchedApi, detail = the module the hook jumps to ("" when it is not a module).
		// Overlays hook the loader APIs to notice graphics DLLs; nothing legitimate hooks the
		// clocks, so the allowlist does not apply to those.
		if allowed && !timingAPI(b) {
			return ev("api_hook", SeverityInfo, 0.1, false, "API hooked by allowlisted "+detail), true
		}
		return ev("api_hook", SeverityHigh, 0.8, true, fmt.Sprintf("hooked API in %s", detail)), true
	case pb.FindingCode_FINDING_CODE_CODE_PATCH:
		// detail = "patched module>module the patch jumps to" ("?" when the target is not a
		// module, "" when the patch is not a jump). The patched modules are the graphics DLLs,
		// which is exactly where overlays and capture tools put their hooks, and a hook that
		// goes through a relay page cannot be attributed. So this is strong evidence for
		// review, but never critical: it must not kick on its own.
		if owner := patchOwner(detail); c.OverlayAllow[owner] {
			return ev("code_patch", SeverityInfo, 0.1, false, "graphics hook by allowlisted "+owner), true
		}
		return ev("code_patch", SeverityHigh, 0.9, true, fmt.Sprintf(".text patched: %s", detail)), true
	case pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE:
		f := &pb.Finding{Code: code, A: a, B: b, Detail: detail}
		if h, ok := HolderOf(f); ok {
			return c.classifyHolder(f, h), true
		}
		if allowed {
			return ev("external_handle", SeverityInfo, 0.1, false, "handle from allowlisted "+detail), true
		}
		// Launchers keep the handle they started the game with, and capture, voice and
		// hardware tools open one; the list above cannot name them all. Low: recorded, and
		// counted with other evidence, but not enough to flag a player by itself.
		return ev("external_handle", SeverityLow, 0.55, false, fmt.Sprintf("process %s holds a %#x handle to the game", detail, b)), true
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
		// Hardware-monitoring, RGB and overclocking tools ship several of these drivers, so a
		// match says something about the machine, not about this player: a note for review
		// that neither flags the player on its own nor counts as tampering.
		return ev("vulnerable_driver", SeverityLow, 0.5, false, "known-vulnerable driver loaded: "+detail), true
	case pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE:
		if b>>16&0xffff != 0 {
			return c.classifyObservedModule(b, detail), true
		}
		return classifyModuleSignature(b, detail), true
	case pb.FindingCode_FINDING_CODE_EXTERNAL_MAPPED_IMAGE:
		return classifyMappedImage(a, b), true
	case pb.FindingCode_FINDING_CODE_EXTERNAL_CODE_CHANGE:
		return classifyCodeChange(a, b, detail), true
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

// patchOwner is the module a code patch jumps to, lowercased, or "" when it is unknown.
func patchOwner(detail string) string {
	_, owner, ok := strings.Cut(detail, ">")
	if !ok {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(owner))
}

func timingAPI(api uint64) bool {
	switch pb.WatchedApi(api) {
	case pb.WatchedApi_WATCHED_API_NTDLL_NT_QUERY_PERFORMANCE_COUNTER, pb.WatchedApi_WATCHED_API_NTDLL_RTL_QUERY_PERFORMANCE_COUNTER,
		pb.WatchedApi_WATCHED_API_KERNEL32_QUERY_PERFORMANCE_COUNTER, pb.WatchedApi_WATCHED_API_KERNELBASE_GET_TICK_COUNT64,
		pb.WatchedApi_WATCHED_API_KERNELBASE_GET_TICK_COUNT, pb.WatchedApi_WATCHED_API_WINMM_TIME_GET_TIME:
		return true
	}
	return false
}

// classifyModuleSignature turns a companion's module report into evidence by the file
// alone, without regard to when the module was seen (classifyObservedModule adds that).
// Everything is informational except two cases: an unsigned module loaded from outside the
// game folder and Program Files, and a signed file that was modified after signing. Neither
// is integrity evidence, so neither can kick.
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
