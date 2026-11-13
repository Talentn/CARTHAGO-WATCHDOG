package analyzer

import (
	"strings"
	"testing"

	pb "carthago/backend/gen/carthago/v1"
)

const (
	sigNone    = uint64(pb.ModuleSignature_MODULE_SIGNATURE_NONE)
	sigValid   = uint64(pb.ModuleSignature_MODULE_SIGNATURE_VALID)
	sigError   = uint64(pb.ModuleSignature_MODULE_SIGNATURE_ERROR)
	clsOther   = uint64(pb.ModulePathClass_MODULE_PATH_CLASS_OTHER)
	clsGame    = uint64(pb.ModulePathClass_MODULE_PATH_CLASS_GAME_DIR)
	clsPF      = uint64(pb.ModulePathClass_MODULE_PATH_CLASS_PROGRAM_FILES)
	after      = uint64(pb.ObservedFlags_OBSERVED_FLAGS_AFTER_START)
	atStart    = uint64(pb.ObservedFlags_OBSERVED_FLAGS_AT_START)
	known      = uint64(pb.ObservedFlags_OBSERVED_FLAGS_KNOWN_START)
	shadows    = uint64(pb.ObservedFlags_OBSERVED_FLAGS_SHADOWS_SYSTEM)
	changed    = uint64(pb.ObservedFlags_OBSERVED_FLAGS_FILE_CHANGED)
	newFile    = uint64(pb.ObservedFlags_OBSERVED_FLAGS_NEW_FILE)
	integrity  = pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY
	visibility = pb.EnforcementCategory_ENFORCEMENT_CATEGORY_VISIBILITY
	none       = pb.EnforcementCategory_ENFORCEMENT_CATEGORY_UNSPECIFIED
)

func module(sig, class, flags uint64) uint64 { return sig | class<<8 | flags<<16 | 42<<32 }

type want struct {
	rule   string
	sev    Severity
	notice pb.EnforcementCategory
	optIn  bool
}

func check(t *testing.T, name string, e Evidence, w want) {
	t.Helper()
	if e.Rule != w.rule || e.Severity != w.sev || e.Notice != w.notice || e.NoticeOptIn != w.optIn {
		t.Errorf("%s: got rule=%s severity=%s notice=%v optIn=%v (%s), want %+v", name, e.Rule, e.Severity, e.Notice, e.NoticeOptIn, e.Summary, w)
	}
	if e.NoticeOptIn && e.Held == "" {
		t.Errorf("%s: a held notice must say why", name)
	}
	if e.Notice != none && !e.NoticeOptIn && (!e.Integrity || e.Severity < SeverityHigh) {
		t.Errorf("%s: evidence that tells the player by default must be integrity evidence of high severity", name)
	}
}

func TestModulesByWhenTheyWereSeen(t *testing.T) {
	c := Defaults()
	for _, tc := range []struct {
		name   string
		b      uint64
		detail string
		want   want
	}{
		// The ordinary picture of a modified build: nothing here may tell the player.
		{"unsigned game file at start", module(sigNone, clsGame, atStart|known), "hw.dll", want{"module_signature", SeverityInfo, none, false}},
		{"unsigned game file loaded with the map", module(sigNone, clsGame, after), "mp.dll", want{"module_signature", SeverityInfo, none, false}},
		{"signed overlay arriving late", module(sigValid, clsOther, after), "discordhook.dll", want{"module_signature", SeverityInfo, none, false}},
		{"unsigned tool in Program Files arriving late", module(sigNone, clsPF, after), "rtsshooks.dll", want{"module_signature", SeverityInfo, none, false}},
		{"signature could not be checked", module(sigError, clsOther, after), "odd.dll", want{"module_signature", SeverityLow, none, false}},
		{"redistributable shipped beside the game", module(sigNone, clsGame, atStart|shadows), "dbghelp.dll", want{"system_library_shadowed", SeverityLow, none, false}},
		{"signed replacement renderer", module(sigValid, clsGame, atStart|shadows), "opengl32.dll", want{"module_signature", SeverityInfo, none, false}},

		// The wallhack delivery: a renderer library that is not the Windows one.
		{"renderer proxy, new at this start", module(sigNone, clsGame, atStart|shadows), "OpenGL32.dll", want{"renderer_replaced", SeverityHigh, visibility, false}},
		{"renderer proxy loaded late", module(sigNone, clsGame, after|shadows), "opengl32.dll", want{"renderer_replaced", SeverityHigh, visibility, false}},
		{"renderer proxy the build has always had", module(sigNone, clsGame, atStart|shadows|known), "opengl32.dll", want{"renderer_replaced", SeverityHigh, visibility, false}},
		{"direct3d proxy", module(sigNone, clsGame, atStart|shadows), "d3d9.dll", want{"renderer_replaced", SeverityHigh, visibility, false}},
		{"another search-order spot", module(sigNone, clsGame, atStart|shadows), "winmm.dll", want{"system_library_replaced", SeverityHigh, integrity, false}},
		{"search-order spot the build has always used", module(sigNone, clsGame, after|shadows|known), "dinput.dll", want{"system_library_replaced", SeverityInfo, integrity, true}},

		// An injected library.
		{"unsigned module from elsewhere, after start", module(sigNone, clsOther, after), "hack.dll", want{"foreign_module", SeverityHigh, integrity, false}},
		{"unsigned module from elsewhere, new at start", module(sigNone, clsOther, atStart), "hack.dll", want{"foreign_module", SeverityHigh, integrity, false}},
		{"unsigned module from elsewhere, always there", module(sigNone, clsOther, atStart|known), "ime.dll", want{"foreign_module", SeverityInfo, integrity, true}},

		// Files of the game folder look like the game's own: opt-in only.
		{"game file replaced", module(sigNone, clsGame, atStart|known|changed), "client.dll", want{"game_file_changed", SeverityMedium, integrity, true}},
		{"renderer file replaced", module(sigNone, clsGame, atStart|known|changed|shadows|known), "opengl32.dll", want{"renderer_replaced", SeverityHigh, visibility, false}},
		{"new unsigned game-folder module after start", module(sigNone, clsGame, after|newFile), "extra.dll", want{"new_game_module", SeverityMedium, integrity, true}},
		{"new game-folder module at start", module(sigNone, clsGame, atStart|known|newFile), "extra.dll", want{"module_signature", SeverityInfo, none, false}},
	} {
		e, ok := c.ClassifyFinding(uint32(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE), 0x10000000, tc.b, tc.detail)
		if !ok {
			t.Errorf("%s: no evidence", tc.name)
			continue
		}
		check(t, tc.name, e, tc.want)
	}

	// A report without flags comes from a client that does not say when: unchanged rules.
	e, _ := c.ClassifyFinding(uint32(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE), 1, sigNone|clsOther<<8, "x.dll")
	check(t, "no flags", e, want{"module_signature", SeverityLow, none, false})
}

// An unsigned renderer library in place of the Windows one is a wallhack's way in. It raises
// the notice whenever it is seen: at start, in the first recorded start, and when the
// record of the first start lists it. A signed one is not this evidence at all.
func TestUnsignedRendererLibraryIsNeverExcused(t *testing.T) {
	first := uint64(pb.ObservedFlags_OBSERVED_FLAGS_FIRST_START)
	c := Defaults()
	for _, lib := range []string{"OPENGL32.dll", "d3d9.dll", "ddraw.dll", "glu32.dll"} {
		for name, flags := range map[string]uint64{"new at start": atStart | shadows, "first recorded start": atStart | shadows | known | first, "in the record": atStart | shadows | known, "loaded late": after | shadows} {
			e, _ := c.ClassifyFinding(uint32(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE), 1, module(sigNone, clsGame, flags), lib)
			check(t, lib+", "+name, e, want{"renderer_replaced", SeverityHigh, visibility, false})
			if e.Held != "" || !e.Integrity {
				t.Errorf("%s, %s: held %q integrity %v", lib, name, e.Held, e.Integrity)
			}
		}
		e, _ := c.ClassifyFinding(uint32(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE), 1, module(sigValid, clsGame, atStart|shadows), lib)
		if e.Rule == "renderer_replaced" || e.Notice != none {
			t.Errorf("%s, validly signed: %s notice %v", lib, e.Rule, e.Notice)
		}
	}
	e, _ := c.ClassifyFinding(uint32(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE), 1, module(sigNone, clsGame, atStart|shadows|known|first), "OPENGL32.dll")
	if strings.Contains(e.Summary, "as at the first recorded start") || !strings.Contains(e.Summary, "this run is the first recorded start") {
		t.Errorf("summary: %s", e.Summary)
	}
}

// The opt-out for a build that ships its own renderer library: the record of the first
// start excuses it, as it does other things of a modified build; one that the record does
// not have still raises the notice.
func TestAllowRendererLibrary(t *testing.T) {
	first := uint64(pb.ObservedFlags_OBSERVED_FLAGS_FIRST_START)
	c := Defaults()
	c.AllowRendererLibrary = true
	e, _ := c.ClassifyFinding(uint32(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE), 1, module(sigNone, clsGame, atStart|shadows|known|first), "OPENGL32.dll")
	check(t, "first recorded start", e, want{"renderer_replaced", SeverityInfo, visibility, true})
	if e.Held != heldFirst || !strings.Contains(e.Summary, "this run is the first recorded start") {
		t.Errorf("first recorded start: %s / %s", e.Summary, e.Held)
	}
	e, _ = c.ClassifyFinding(uint32(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE), 1, module(sigNone, clsGame, atStart|shadows|known), "OPENGL32.dll")
	check(t, "in the record", e, want{"renderer_replaced", SeverityInfo, visibility, true})
	if e.Held != heldKnown || !strings.Contains(e.Summary, "as at the first recorded start") {
		t.Errorf("in the record: %s / %s", e.Summary, e.Held)
	}
	e, _ = c.ClassifyFinding(uint32(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE), 1, module(sigNone, clsGame, atStart|shadows), "OPENGL32.dll")
	check(t, "not in the record", e, want{"renderer_replaced", SeverityHigh, visibility, false})
}

func TestMappedImages(t *testing.T) {
	c := Defaults()
	for _, tc := range []struct {
		name  string
		flags uint64
		want  want
	}{
		{"appeared after start", after, want{"mapped_image", SeverityHigh, integrity, false}},
		{"new at this start", atStart, want{"mapped_image", SeverityHigh, integrity, false}},
		{"the build's own loader", atStart | known, want{"mapped_image", SeverityInfo, integrity, true}},
	} {
		e, _ := c.ClassifyFinding(uint32(pb.FindingCode_FINDING_CODE_EXTERNAL_MAPPED_IMAGE), 0x3000000, 0x40000|tc.flags<<32, "0123456789abcdef")
		check(t, tc.name, e, tc.want)
	}
}

func codeChange(kind pb.CodeChangeKind, tclass, tsig uint64, addons bool) uint64 {
	about := uint64(kind) | tclass<<8 | tsig<<16
	if addons {
		about |= 1 << 25
	}
	return 0x7000_1000 | about<<32
}

func TestCodeChanges(t *testing.T) {
	c := Defaults()
	jm, ju, by, bp := pb.CodeChangeKind_CODE_CHANGE_KIND_JUMP_MODULE, pb.CodeChangeKind_CODE_CHANGE_KIND_JUMP_UNBACKED,
		pb.CodeChangeKind_CODE_CHANGE_KIND_BYTES, pb.CodeChangeKind_CODE_CHANGE_KIND_BREAKPOINT
	for _, tc := range []struct {
		name   string
		b      uint64
		detail string
		want   want
	}{
		// Overlays and capture tools hook the renderer after start; they are signed.
		{"signed overlay hooks the renderer", codeChange(jm, clsOther+1, sigValid, false), "opengl32.dll>discordhook.dll", want{"code_changed", SeverityInfo, none, false}},
		{"a Windows library hooks the renderer", codeChange(jm, 0, 0, false), "opengl32.dll>apphelp.dll", want{"code_changed", SeverityInfo, none, false}},
		{"unsigned Program Files tool hooks the renderer", codeChange(jm, clsPF+1, sigNone, false), "opengl32.dll>rtsshooks.dll", want{"code_changed", SeverityMedium, visibility, true}},
		{"target signature unknown", codeChange(jm, clsOther+1, sigError, false), "opengl32.dll>odd.dll", want{"code_changed", SeverityMedium, none, false}},
		{"breakpoint", codeChange(bp, 0, 0, false), "hw.dll>", want{"code_changed", SeverityMedium, none, false}},

		// The renderer: nothing but a signed tool has business rewriting it.
		{"renderer hooked from unbacked memory", codeChange(ju, 0, 0, true), "opengl32.dll>?", want{"code_changed", SeverityHigh, visibility, false}},
		{"renderer hooked by a foreign unsigned module", codeChange(jm, clsOther+1, sigNone, true), "OpenGL32.dll>hack.dll", want{"code_changed", SeverityHigh, visibility, false}},
		{"renderer bytes replaced", codeChange(by, 0, 0, false), "opengl32.dll>", want{"code_changed", SeverityHigh, visibility, false}},
		{"renderer hooked by a game-folder file", codeChange(jm, clsGame+1, sigNone, false), "opengl32.dll>extra.dll", want{"code_changed", SeverityMedium, visibility, true}},

		// The client library.
		{"client library hooked from unbacked memory", codeChange(ju, 0, 0, true), "client.dll>?", want{"code_changed", SeverityHigh, integrity, false}},
		{"client library bytes replaced", codeChange(by, 0, 0, true), "client.dll>", want{"code_changed", SeverityHigh, integrity, false}},

		// The engine also runs the listen server, where add-ons hook it.
		{"engine hooked by an add-on", codeChange(jm, clsGame+1, sigNone, true), "hw.dll>amxmodx_mm.dll", want{"code_changed", SeverityLow, none, false}},
		{"engine hooked by a game-folder file, no add-ons", codeChange(jm, clsGame+1, sigNone, false), "hw.dll>extra.dll", want{"code_changed", SeverityMedium, integrity, true}},
		{"engine hooked from unbacked memory, add-ons loaded", codeChange(ju, 0, 0, true), "hw.dll>?", want{"code_changed", SeverityHigh, integrity, true}},
		{"engine hooked from unbacked memory, no add-ons", codeChange(ju, 0, 0, false), "hw.dll>?", want{"code_changed", SeverityHigh, integrity, false}},
		{"engine bytes replaced, add-ons loaded", codeChange(by, 0, 0, true), "hw.dll>", want{"code_changed", SeverityHigh, integrity, true}},
		{"engine bytes replaced, no add-ons", codeChange(by, 0, 0, false), "hw.dll>", want{"code_changed", SeverityHigh, integrity, false}},
		{"engine hooked by a foreign unsigned module", codeChange(jm, clsOther+1, sigNone, true), "hw.dll>hack.dll", want{"code_changed", SeverityHigh, integrity, false}},
	} {
		e, _ := c.ClassifyFinding(uint32(pb.FindingCode_FINDING_CODE_EXTERNAL_CODE_CHANGE), 0x5000_1234, tc.b, tc.detail)
		check(t, tc.name, e, tc.want)
	}
}

func holder(access, sig, classPlus1, flags uint64) uint64 {
	return access | (sig|classPlus1<<8|uint64(pb.HolderFlags_HOLDER_FLAGS_KNOWN)|flags<<24)<<32
}

func TestHandleHolders(t *testing.T) {
	c := Defaults()
	const all, read = 0x1fffff, 0x1410
	for _, tc := range []struct {
		name   string
		b      uint64
		detail string
		want   want
	}{
		{"a Windows program", holder(all, 0, 0, after), "csrss.exe", want{"external_handle", SeverityInfo, none, false}},
		{"a signed program", holder(all, sigValid, clsOther+1, after), "Recorder.exe", want{"external_handle", SeverityLow, none, false}},
		{"a signed program on the overlay allowlist", holder(all, sigValid, clsOther+1, after), "Discord.exe", want{"external_handle", SeverityInfo, none, false}},
		{"the game's own launcher", holder(all, sigNone, clsGame+1, atStart|known), "launcher.exe", want{"external_handle", SeverityLow, none, false}},
		{"unsigned tool in Program Files", holder(all, sigNone, clsPF+1, after), "tool.exe", want{"external_handle", SeverityMedium, none, false}},

		{"unsigned writer arriving after start", holder(all, sigNone, clsOther+1, after), "trainer.exe", want{"external_writer", SeverityHigh, integrity, false}},
		{"unsigned writer, new at this start", holder(0x38, sigNone, clsOther+1, atStart), "trainer.exe", want{"external_writer", SeverityHigh, integrity, false}},
		{"unsigned writer that has always been there", holder(all, sigNone, clsOther+1, atStart|known), "starter.exe", want{"external_writer", SeverityInfo, integrity, true}},
		{"unsigned reader", holder(read, sigNone, clsOther+1, after), "radar.exe", want{"external_reader", SeverityMedium, integrity, true}},

		// Signed, so named.
		{"memory editor with write access", holder(all, sigValid, clsPF+1, after), "cheatengine-x86_64.exe", want{"memory_tool", SeverityHigh, integrity, false}},
		{"memory editor, read only", holder(read, sigValid, clsPF+1, after), "Cheat Engine.exe", want{"memory_tool", SeverityMedium, integrity, true}},
	} {
		e, _ := c.ClassifyFinding(uint32(pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE), 4242, tc.b, tc.detail)
		check(t, tc.name, e, tc.want)
	}

	// The in-process SDK sends no holder details: the older rule applies.
	e, _ := c.ClassifyFinding(uint32(pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE), 4242, all, "tool.exe")
	check(t, "no holder details", e, want{"external_handle", SeverityLow, none, false})
	e, _ = c.ClassifyFinding(uint32(pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE), 4242, all, "steam.exe")
	check(t, "allowlisted, no holder details", e, want{"external_handle", SeverityInfo, none, false})
}

func TestOverlayReader(t *testing.T) {
	f := &pb.Finding{Code: uint32(pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE), A: 77, B: holder(0x1410, sigNone, clsOther+1, after), Detail: "esp.exe"}
	h, ok := HolderOf(f)
	if !ok || !h.Suspect || h.Known || h.Pid != 77 {
		t.Fatalf("holder %+v ok=%v", h, ok)
	}
	e := OverlayReader(h)
	check(t, "reading overlay", e, want{"overlay_reader", SeverityHigh, visibility, false})
	if !strings.Contains(e.Summary, "esp.exe") {
		t.Errorf("summary %q does not name the program", e.Summary)
	}
	f.B = holder(0x1410, sigNone, clsOther+1, atStart|known)
	h, _ = HolderOf(f)
	check(t, "reading overlay that has always been there", OverlayReader(h), want{"overlay_reader", SeverityInfo, visibility, true})
	f.B = holder(0x1410, sigValid, clsOther+1, after)
	if h, _ = HolderOf(f); h.Suspect {
		t.Error("a signed program with a read handle is not singled out")
	}
	if _, ok := HolderOf(&pb.Finding{Code: f.Code, A: 77, B: 0x1410, Detail: "esp.exe"}); ok {
		t.Error("a finding without holder details has none")
	}
}
