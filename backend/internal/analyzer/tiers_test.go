package analyzer

import (
	"strings"
	"testing"

	pb "carthago/backend/gen/carthago/v1"
)

// The whole policy in one test: no rule that scores play or input can ban by itself, and
// neither can a rule nobody put in the table.
func TestNoStatisticalRuleIsCertain(t *testing.T) {
	for _, r := range StatisticalRules {
		if _, listed := ruleTier[r]; !listed {
			t.Errorf("%s is not in the tier table", r)
		}
		if TierOf(r) != TierSuspicious {
			t.Errorf("%s is statistical and must not be in the certain tier", r)
		}
		if (Evidence{Rule: r, Integrity: true, Severity: SeverityCritical, Notice: integrity}).Certain() {
			t.Errorf("%s evidence would ban automatically", r)
		}
	}
	if TierOf("a_rule_added_later") != TierSuspicious {
		t.Error("a rule that is not listed must be suspicious")
	}
	certain := map[string]bool{"renderer_replaced": true, "foreign_module": true, "code_changed": true, "mapped_image": true, "external_writer": true, RuleKnownCheat: true}
	for r, tier := range ruleTier {
		if (tier == TierCertain) != certain[r] {
			t.Errorf("%s is %s", r, tier)
		}
	}
}

func TestKnownCheatIsCertain(t *testing.T) {
	e := KnownCheat("Wall", "opengl32.dll", "ab12")
	if !e.Certain() || e.Rule != "known_cheat" || !strings.Contains(e.Summary, `known cheat "Wall"`) || !strings.Contains(e.Summary, "opengl32.dll") {
		t.Fatalf("%+v", e)
	}
}

// What bans automatically is exactly what raises the alert by default for the five
// findings of the certain tier.
func TestCertainEvidence(t *testing.T) {
	c := Defaults()
	mod, code, handle, mapped := uint32(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE), uint32(pb.FindingCode_FINDING_CODE_EXTERNAL_CODE_CHANGE),
		uint32(pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE), uint32(pb.FindingCode_FINDING_CODE_EXTERNAL_MAPPED_IMAGE)
	ju, by := pb.CodeChangeKind_CODE_CHANGE_KIND_JUMP_UNBACKED, pb.CodeChangeKind_CODE_CHANGE_KIND_BYTES
	for _, tc := range []struct {
		name    string
		code    uint32
		a, b    uint64
		detail  string
		rule    string
		certain bool
	}{
		{"unsigned renderer library", mod, 1, module(sigNone, clsGame, atStart|shadows|known), "OPENGL32.dll", "renderer_replaced", true},
		{"signed renderer library", mod, 1, module(sigValid, clsGame, atStart|shadows), "OPENGL32.dll", "", false},
		{"unsigned DLL from outside the game folder", mod, 1, module(sigNone, clsOther, after), "hack.dll", "foreign_module", true},
		{"the same, there since the first recorded start", mod, 1, module(sigNone, clsOther, atStart|known), "hack.dll", "foreign_module", false},
		{"unsigned file of the game folder", mod, 1, module(sigNone, clsGame, after), "mp.dll", "", false},
		{"renderer code rewritten", code, 0x5000_1234, codeChange(by, 0, 0, false), "opengl32.dll>", "code_changed", true},
		{"client library hooked from unbacked memory", code, 0x5000_1234, codeChange(ju, 0, 0, true), "client.dll>?", "code_changed", true},
		{"engine code rewritten", code, 0x5000_1234, codeChange(by, 0, 0, false), "hw.dll>", "code_changed", false},
		{"renderer hooked by a signed overlay", code, 0x5000_1234, codeChange(pb.CodeChangeKind_CODE_CHANGE_KIND_JUMP_MODULE, clsOther+1, sigValid, false), "opengl32.dll>discordhook.dll", "code_changed", false},
		{"manual map", mapped, 0x3000000, 0x40000 | after<<32, "0123456789abcdef", "mapped_image", true},
		{"the build's own loader", mapped, 0x3000000, 0x40000 | (atStart|known)<<32, "0123456789abcdef", "mapped_image", false},
		{"unsigned outside program that can write", handle, 4242, holder(0x1fffff, sigNone, clsOther+1, after), "trainer.exe", "external_writer", true},
		{"unsigned outside program that can only read", handle, 4242, holder(0x1410, sigNone, clsOther+1, after), "radar.exe", "external_reader", false},
		{"memory editor with write access", handle, 4242, holder(0x1fffff, sigValid, clsPF+1, after), "cheatengine-x86_64.exe", "memory_tool", false},
	} {
		e, _ := c.ClassifyFinding(tc.code, tc.a, tc.b, tc.detail)
		if tc.rule != "" && e.Rule != tc.rule {
			t.Errorf("%s: rule %s, want %s", tc.name, e.Rule, tc.rule)
		}
		if e.Certain() != tc.certain {
			t.Errorf("%s: certain=%v (%s: %s)", tc.name, e.Certain(), e.Rule, e.Summary)
		}
	}
	h, _ := HolderOf(&pb.Finding{Code: handle, A: 77, B: holder(0x1410, sigNone, clsOther+1, after), Detail: "esp.exe"})
	if e := OverlayReader(h); e.Certain() || e.Notice == none {
		t.Errorf("a reading overlay raises the alert and stays a review flag: certain=%v notice=%v", e.Certain(), e.Notice)
	}
}
