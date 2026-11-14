package analyzer

import (
	"fmt"

	pb "carthago/backend/gen/carthago/v1"
)

// Tier says what a rule's evidence may do to a player by itself.
type Tier int

const (
	// TierSuspicious evidence is a reason for a person to look: a statistical rule, an
	// advisory score, or a finding that an honest PC or a modified but honest build also
	// produces. It never bans; a reviewer can, from the session page.
	TierSuspicious Tier = iota
	// TierCertain evidence is a hard fact about the game process itself. It bans
	// automatically (Evidence.Certain says when).
	TierCertain
)

func (t Tier) String() string {
	if t == TierCertain {
		return "certain"
	}
	return "suspicious"
}

// ruleTier is the tier of every rule, in one place. A rule that is not listed is
// suspicious, so a new rule cannot ban by being forgotten here.
var ruleTier = map[string]Tier{
	// Seen changing inside the game process by the companion (companion.go).
	"renderer_replaced": TierCertain, // an unsigned renderer library in place of the system's
	"foreign_module":    TierCertain, // an unsigned DLL injected from outside the game folder
	"code_changed":      TierCertain, // rewritten code; only of the renderer or client library, see Certain
	"mapped_image":      TierCertain, // an image mapped by hand, outside the loader
	"external_writer":   TierCertain, // an unsigned outside program with a handle that writes the game's memory
	// A module of the game whose file is on the studio's list of known cheat files.
	RuleKnownCheat: TierCertain,

	// Statistics over how somebody plays.
	"angle_snap": TierSuspicious, "headshot_rate": TierSuspicious, "time_to_damage": TierSuspicious,
	"information_leak": TierSuspicious, "information_leak_live": TierSuspicious, "decoy_reaction": TierSuspicious,
	"macro_interval": TierSuspicious, "command_rate": TierSuspicious, "injected_input": TierSuspicious,
	// The Oracle's score and opinion are advice to a reviewer and are not evidence rules at
	// all; they are named here so that nobody adds them above.
	"oracle_score": TierSuspicious, "oracle_opinion": TierSuspicious,
	// Overlays, readers, tools and debuggers: ordinary programs do these too.
	"overlay_reader": TierSuspicious, "overlay_window": TierSuspicious, "external_reader": TierSuspicious,
	"external_handle": TierSuspicious, "memory_tool": TierSuspicious, "debugger": TierSuspicious,
	// What a patch or a mod of the game also produces.
	"system_library_replaced": TierSuspicious, "system_library_shadowed": TierSuspicious, "game_file_changed": TierSuspicious,
	"new_game_module": TierSuspicious, "module_signature": TierSuspicious,
	// The in-process scanner's findings carry no word on when or from where a change came.
	"code_patch": TierSuspicious, "api_hook": TierSuspicious, "image_not_in_loader": TierSuspicious, "unbacked_exec": TierSuspicious,
	"module_not_image": TierSuspicious, "thread_start_unbacked": TierSuspicious, "external_exec_regions": TierSuspicious,
	"vulnerable_driver": TierSuspicious,
	// Clocks and the health of the scanner.
	"time_source_divergence": TierSuspicious, "clock_drift": TierSuspicious,
	"scanner_stalled": TierSuspicious, "scan_quarantined": TierSuspicious, "scan_coverage": TierSuspicious, "evidence_flood": TierSuspicious,
}

// RuleKnownCheat is the rule of KnownCheat evidence.
const RuleKnownCheat = "known_cheat"

// KnownCheat is the evidence for a module of the game whose file has the SHA-256 of an
// entry of the studio's list of known cheat files. The hash decides: the file's name, its
// folder, its signature and whether an earlier start already had it do not matter.
func KnownCheat(cheat, module, sha256 string) Evidence {
	if module == "" {
		module = "a file"
	}
	e := ev(RuleKnownCheat, SeverityCritical, 1, true,
		fmt.Sprintf("known cheat %q: the game loaded %s, which is on the list of known cheat files (SHA-256 %s)", cheat, module, sha256))
	e.Notice = pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY
	return e
}

// StatisticalRules are the rules that score play or input. None of them may be certain.
var StatisticalRules = []string{
	"angle_snap", "headshot_rate", "time_to_damage", "information_leak", "information_leak_live", "decoy_reaction",
	"macro_interval", "command_rate", "injected_input", "oracle_score", "oracle_opinion",
}

// TierOf is the tier of a rule; suspicious for a rule that is not listed.
func TierOf(rule string) Tier { return ruleTier[rule] }

// Certain reports whether this evidence bans automatically: its rule is of the certain
// tier, and it is the kind of that rule which raises the cheater alert by default. That
// leaves out what the first recorded start of the game already had, what an operator's
// opt-in is needed for, anything below high severity, and rewritten engine code, which a
// listen server's add-ons also produce.
func (e Evidence) Certain() bool {
	return TierOf(e.Rule) == TierCertain && e.Integrity && e.Severity >= SeverityHigh &&
		e.Notice != pb.EnforcementCategory_ENFORCEMENT_CATEGORY_UNSPECIFIED && !e.NoticeOptIn && !e.engineCode
}
