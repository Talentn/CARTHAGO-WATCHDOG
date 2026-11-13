package pipeline

import (
	"fmt"
	"strings"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/analyzer"
)

// Notifier tells a session's client that the session was flagged (gateway.Gateway.Notice).
// It informs the client; it does not end the session.
type Notifier interface {
	Notice(sessionID string, category pb.EnforcementCategory, severity pb.EnforcementSeverity) bool
}

// Which evidence tells the client. The list is short on purpose: a notice puts a "detected"
// screen in front of a player, so only evidence that stands on its own gets one. Everything
// not named here is for the dashboard only, whatever its severity:
//
//   - client evidence: patched game code, a hooked API, an image mapped outside the loader
//     list (game integrity); a debugger attached to the game process itself; the game's
//     clocks disagreeing with each other. Each must be integrity evidence of high or
//     critical severity.
//
//   - gameplay evidence: angle_snap together with headshot_rate or time_to_damage, for the
//     same player in the same match, and only for a slot bound to a verified session.
//
//   - what a companion sees change in a game it watches from outside (analyzer/companion.go,
//     which marks the evidence itself): a renderer or other system library replaced by an
//     unsigned file of the same name, an unsigned module from outside the game folder, an
//     image mapped by hand, rewritten code of the renderer, engine or client library, an
//     unsigned program from outside the game folder with a handle that can write the
//     game's memory, a memory editor with such a handle, and an unsigned program that both
//     reads the game's memory and draws a transparent window over it. Each only when it
//     arrived after the game had finished starting, or was not there at the first recorded
//     start of that game. Renderer findings and the reading overlay carry the visibility
//     category.
//
// Held back unless Config.NoticesOptIn is set, and logged as "notice withheld": anything
// that has been there since the first recorded start of the game, a changed or newly
// loaded file of the game folder, a handle that can only read, engine code rewritten
// while server add-ons are loaded, and a jump into a file of the game folder.
//
//   - information_leak_live, only when the operator turned the live rule on
//     (Config.LeakAlert): a strong information-leak score in several separate windows of
//     one match, for a slot bound to a verified session. Visibility category.
//
// Never on their own or in combination: information_leak (the end-of-match review flag)
// and any other rule that exists to
// flag a player for review (decoy reactions, command rate, input timing), unsigned files
// as such, overlays as such, handles of signed programs, vulnerable drivers, a kernel
// debugger setting, executable memory without a PE header seen from outside, scheduler
// and coverage health.
var noticeClientRules = map[string]pb.EnforcementCategory{
	"code_patch":             pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY,
	"api_hook":               pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY,
	"image_not_in_loader":    pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY,
	"debugger":               pb.EnforcementCategory_ENFORCEMENT_CATEGORY_DEBUGGER,
	"time_source_divergence": pb.EnforcementCategory_ENFORCEMENT_CATEGORY_TIME_MANIPULATION,
}

func noticeCategoryName(c pb.EnforcementCategory) string {
	return strings.ToLower(strings.TrimPrefix(c.String(), "ENFORCEMENT_CATEGORY_"))
}

const noticeAimRule = "angle_snap"

// noticeAimSupport are the rules of which one must accompany angle_snap.
var noticeAimSupport = []string{"headshot_rate", "time_to_damage"}

func noticeSeverity(s analyzer.Severity) pb.EnforcementSeverity {
	if s >= analyzer.SeverityCritical {
		return pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_CRITICAL
	}
	return pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_HIGH
}

// clientNotice decides for one piece of client evidence. f is the finding behind it, nil
// for evidence derived from the heartbeat as a whole. held is set when the evidence would
// have told the player but for a guard that optIn lifts.
func clientNotice(e analyzer.Evidence, f *pb.Finding, optIn bool) (cat pb.EnforcementCategory, sev pb.EnforcementSeverity, send bool, held string) {
	if e.Notice != pb.EnforcementCategory_ENFORCEMENT_CATEGORY_UNSPECIFIED {
		if e.NoticeOptIn && !optIn {
			return e.Notice, 0, false, e.Held
		}
		if !e.NoticeOptIn && (!e.Integrity || e.Severity < analyzer.SeverityHigh) {
			return 0, 0, false, ""
		}
		return e.Notice, noticeSeverity(e.Severity), true, ""
	}
	cat, sev, send = legacyClientNotice(e, f)
	return cat, sev, send, ""
}

func legacyClientNotice(e analyzer.Evidence, f *pb.Finding) (pb.EnforcementCategory, pb.EnforcementSeverity, bool) {
	cat, ok := noticeClientRules[e.Rule]
	if !ok || !e.Integrity || e.Severity < analyzer.SeverityHigh {
		return 0, 0, false
	}
	if cat == pb.EnforcementCategory_ENFORCEMENT_CATEGORY_DEBUGGER {
		// A debug object on the game process is a debugger attached to it. A kernel debugger
		// is a setting of the machine and a hardware breakpoint alone is not enough.
		if f == nil || f.A&uint64(pb.DebugSignal_DEBUG_SIGNAL_DEBUG_OBJECT) == 0 {
			return 0, 0, false
		}
	}
	return cat, noticeSeverity(e.Severity), true
}

// gameplayNotice decides for one slot of a match from the rules reported for it so far.
func gameplayNotice(reported map[string]bool, slot uint32) bool {
	if !reported[fmt.Sprintf("%d|%s", slot, noticeAimRule)] {
		return false
	}
	for _, r := range noticeAimSupport {
		if reported[fmt.Sprintf("%d|%s", slot, r)] {
			return true
		}
	}
	return false
}

func (p *Pipeline) notifyGameplay(ms *matchState) {
	if !p.cfg.Notices || p.notify == nil {
		return
	}
	for slot, s := range ms.sessions {
		if gameplayNotice(ms.reported, slot) {
			p.notify.Notice(s.SessionID, pb.EnforcementCategory_ENFORCEMENT_CATEGORY_AIM_ASSISTANCE, pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_HIGH)
		}
	}
}
