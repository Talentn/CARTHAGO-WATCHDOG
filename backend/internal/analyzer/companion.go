package analyzer

import (
	"fmt"
	"strings"

	pb "carthago/backend/gen/carthago/v1"
)

// Rules for what an out-of-process companion reports about a game the SDK is not built
// into. Such a game has no manifest: a modified build loads its own unsigned files, maps
// code itself and may ship a replacement for a system library. The companion therefore
// says when it first saw each thing (pb.ObservedFlags), and the rules here go by that:
//
//   - what arrives after the game has finished starting is a change;
//   - what is there at start, and was not there at the first recorded start of the same
//     game folder, is new;
//   - what has been there since the first recorded start is taken to be the build. It is
//     recorded as information, carries no risk, and may tell the player only when the
//     operator opts in (Evidence.NoticeOptIn).
//
// A valid signature always excuses a file. A name never does: a file can be called
// anything.

// Libraries a GoldSrc game draws through. A replacement loaded from the game folder sees
// and can change every draw call, which is how a wallhack is usually delivered.
var rendererLibs = map[string]bool{
	"opengl32.dll": true, "glu32.dll": true, "ddraw.dll": true, "d3d8.dll": true, "d3d9.dll": true,
	"d3dim.dll": true, "d3dim700.dll": true, "d3d11.dll": true, "dxgi.dll": true, "gdi32.dll": true,
}

// Other system libraries a GoldSrc game loads by bare name, so that a file of that name
// in the game folder is loaded in place of the system one.
// The renderer libraries a wallhack for an OpenGL or Direct3D 9 game replaces. An unsigned
// one in place of the Windows one is never excused by the record of the first start,
// unless the operator says the build ships its own (Config.AllowRendererLibrary).
var wallhackLibs = map[string]bool{"opengl32.dll": true, "glu32.dll": true, "ddraw.dll": true, "d3d9.dll": true}

var hijackLibs = map[string]bool{
	"wsock32.dll": true, "ws2_32.dll": true, "winmm.dll": true, "dinput.dll": true, "dinput8.dll": true,
	"dsound.dll": true, "version.dll": true, "msacm32.dll": true, "avifil32.dll": true, "msvfw32.dll": true,
	"iphlpapi.dll": true, "winhttp.dll": true, "wininet.dll": true, "user32.dll": true, "kernel32.dll": true,
	"advapi32.dll": true, "shell32.dll": true, "ole32.dll": true, "imm32.dll": true, "winspool.drv": true,
	"mswsock.dll": true, "netapi32.dll": true, "psapi.dll": true, "wintrust.dll": true, "crypt32.dll": true,
	"uxtheme.dll": true, "dwmapi.dll": true, "xinput1_3.dll": true, "xinput9_1_0.dll": true, "hid.dll": true,
}

// Programs whose purpose is to read and write another program's memory. These are named
// because they are validly signed, so the signature rule would excuse them.
var memoryTools = []string{"cheatengine", "artmoney", "tsearch", "squalr", "reclass"}

func isMemoryTool(name string) bool {
	n := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, strings.ToLower(name))
	for _, t := range memoryTools {
		if strings.Contains(n, t) {
			return true
		}
	}
	return false
}

// notValid: the file carries no signature that Windows accepts. A state the companion
// could not establish (unknown, error, expired certificate) is not counted as unsigned.
func notValid(s pb.ModuleSignature) bool {
	return s == pb.ModuleSignature_MODULE_SIGNATURE_NONE || s == pb.ModuleSignature_MODULE_SIGNATURE_BAD_DIGEST ||
		s == pb.ModuleSignature_MODULE_SIGNATURE_UNTRUSTED
}

const (
	heldKnown    = "it was already there at the first recorded start of this game, so it is taken to be part of the build"
	heldFirst    = "this run is the first recorded start of this game, so it has not been compared with anything: whatever is there at start is taken to be part of the build"
	heldGameFile = "a file in the game folder looks like the game's own; an update or a new add-on leaves the same trace"
	heldReader   = "a handle that can only read is also what monitoring tools hold"
	heldAddons   = "server add-ons are loaded in this process, and they rewrite engine code of a listen server for their hooks"
	heldGameJump = "the jump leads into a file of the game folder, which looks like the game's own"
)

func observed(flags uint64, f pb.ObservedFlags) bool { return flags&uint64(f) != 0 }

func whenSeen(flags uint64, secs uint64) string {
	switch {
	case observed(flags, pb.ObservedFlags_OBSERVED_FLAGS_AFTER_START) && secs > 0:
		return fmt.Sprintf("loaded %d s after the game started", secs)
	case observed(flags, pb.ObservedFlags_OBSERVED_FLAGS_AFTER_START):
		return "appeared after the game had finished starting"
	case observed(flags, pb.ObservedFlags_OBSERVED_FLAGS_FIRST_START):
		return "present at start; this run is the first recorded start, so there is nothing to compare it with"
	case observed(flags, pb.ObservedFlags_OBSERVED_FLAGS_KNOWN_START):
		return "present at start, as at the first recorded start"
	}
	return "present at start, but not at the first recorded start of this game"
}

// tell marks evidence that may raise a notice. Something known since the first recorded
// start is information, and needs the operator's opt-in to tell the player.
func tell(e Evidence, cat pb.EnforcementCategory, flags uint64) Evidence {
	e.Notice = cat
	if observed(flags, pb.ObservedFlags_OBSERVED_FLAGS_KNOWN_START) {
		e = partOfBuild(e)
		if observed(flags, pb.ObservedFlags_OBSERVED_FLAGS_FIRST_START) {
			e.Held = heldFirst
		}
	}
	return e
}

func partOfBuild(e Evidence) Evidence {
	e.Severity, e.Score, e.Integrity = SeverityInfo, 0.1, false
	e.NoticeOptIn, e.Held = true, heldKnown
	return e
}

func optIn(e Evidence, cat pb.EnforcementCategory, why string) Evidence {
	e.Notice, e.NoticeOptIn, e.Held = cat, true, why
	return e
}

func integrityOrVisibility(lib string) pb.EnforcementCategory {
	if rendererLibs[lib] {
		return pb.EnforcementCategory_ENFORCEMENT_CATEGORY_VISIBILITY
	}
	return pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY
}

// classifyObservedModule handles a module report that says when the module was seen.
func (c Config) classifyObservedModule(b uint64, detail string) Evidence {
	state, class := pb.ModuleSignature(b&0xff), pb.ModulePathClass(b>>8&0xff)
	flags, secs := b>>16&0xffff, b>>32&0xffff
	name := strings.ToLower(strings.TrimSpace(detail))
	base := classifyModuleSignature(b, detail)
	when := whenSeen(flags, secs)
	switch {
	case observed(flags, pb.ObservedFlags_OBSERVED_FLAGS_SHADOWS_SYSTEM) && notValid(state):
		switch {
		case rendererLibs[name]:
			e := ev("renderer_replaced", SeverityHigh, 0.85, true,
				fmt.Sprintf("renderer library %s is not the Windows one: an unsigned file of that name was loaded from outside the system directory (%s)", detail, when))
			if wallhackLibs[name] && !c.AllowRendererLibrary {
				e.Notice = pb.EnforcementCategory_ENFORCEMENT_CATEGORY_VISIBILITY
				return e
			}
			return tell(e, pb.EnforcementCategory_ENFORCEMENT_CATEGORY_VISIBILITY, flags)
		case hijackLibs[name]:
			e := ev("system_library_replaced", SeverityHigh, 0.8, true,
				fmt.Sprintf("system library %s is not the Windows one: an unsigned file of that name was loaded from outside the system directory (%s)", detail, when))
			return tell(e, pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY, flags)
		}
		return ev("system_library_shadowed", SeverityLow, 0.3, false,
			fmt.Sprintf("%s; a library of this name also exists in the Windows system directory (%s)", base.Summary, when))
	case class == pb.ModulePathClass_MODULE_PATH_CLASS_OTHER && notValid(state):
		e := ev("foreign_module", SeverityHigh, 0.8, true, fmt.Sprintf("%s; %s", base.Summary, when))
		return tell(e, pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY, flags)
	case class == pb.ModulePathClass_MODULE_PATH_CLASS_GAME_DIR && observed(flags, pb.ObservedFlags_OBSERVED_FLAGS_FILE_CHANGED):
		e := ev("game_file_changed", SeverityMedium, 0.5, true,
			fmt.Sprintf("%s; the file is not the one that had this path at the first recorded start (%s)", base.Summary, when))
		return optIn(e, integrityOrVisibility(name), heldGameFile)
	case class == pb.ModulePathClass_MODULE_PATH_CLASS_GAME_DIR && notValid(state) &&
		observed(flags, pb.ObservedFlags_OBSERVED_FLAGS_NEW_FILE) && observed(flags, pb.ObservedFlags_OBSERVED_FLAGS_AFTER_START):
		e := ev("new_game_module", SeverityMedium, 0.5, true,
			fmt.Sprintf("%s; no earlier run loaded a file from this path (%s)", base.Summary, when))
		return optIn(e, integrityOrVisibility(name), heldGameFile)
	}
	if observed(flags, pb.ObservedFlags_OBSERVED_FLAGS_AFTER_START) {
		base.Summary += "; " + when
	}
	return base
}

// classifyMappedImage: a = allocation base, b = size | ObservedFlags << 32.
func classifyMappedImage(a, b uint64) Evidence {
	flags := b >> 32
	e := ev("mapped_image", SeverityHigh, 0.8, true,
		fmt.Sprintf("an image of %d KB was mapped by hand at %#x, outside the Windows loader (%s)", (b&0xffffffff)>>10, a, whenSeen(flags, 0)))
	return tell(e, pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY, flags)
}

// classifyCodeChange: a = address, b = jump target | about << 32, detail = "changed>target".
func classifyCodeChange(a, b uint64, detail string) Evidence {
	about := b >> 32
	kind := pb.CodeChangeKind(about & 0xf)
	tclass, tsig := about>>8&0xff, pb.ModuleSignature(about>>16&0xff)
	tlate, addons := about>>24&1 != 0, about>>25&1 != 0
	changed, target, _ := strings.Cut(strings.ToLower(strings.TrimSpace(detail)), ">")
	cat := integrityOrVisibility(changed)
	// The renderer library and the client library belong to the client alone. The engine
	// also runs a listen server, and server add-ons hook it.
	clientSide := rendererLibs[changed] || changed == "client.dll"
	where := fmt.Sprintf("code of %s was rewritten at %#x after the game had finished starting", changed, a)

	switch kind {
	case pb.CodeChangeKind_CODE_CHANGE_KIND_BREAKPOINT:
		return ev("code_changed", SeverityMedium, 0.5, true, where+": a breakpoint")
	case pb.CodeChangeKind_CODE_CHANGE_KIND_JUMP_MODULE:
		late := ""
		if tlate {
			late = ", itself loaded after start"
		}
		switch {
		case tclass == 0:
			return ev("code_changed", SeverityInfo, 0.1, false, fmt.Sprintf("%s: a jump into %s, a Windows library", where, target))
		case tsig == pb.ModuleSignature_MODULE_SIGNATURE_VALID:
			return ev("code_changed", SeverityInfo, 0.1, false, fmt.Sprintf("%s: a jump into %s, which is validly signed (an overlay or capture tool)", where, target))
		case !notValid(tsig):
			return ev("code_changed", SeverityMedium, 0.5, true, fmt.Sprintf("%s: a jump into %s, whose signature could not be checked", where, target))
		case tclass == uint64(pb.ModulePathClass_MODULE_PATH_CLASS_OTHER)+1:
			e := ev("code_changed", SeverityHigh, 0.9, true, fmt.Sprintf("%s: a jump into %s, an unsigned file from outside the game folder%s", where, target, late))
			e.Notice = cat
			return e
		case !clientSide && addons:
			return ev("code_changed", SeverityLow, 0.3, false, fmt.Sprintf("%s: a jump into %s, an unsigned file of the game folder%s; server add-ons are loaded and hook the engine this way", where, target, late))
		}
		e := ev("code_changed", SeverityMedium, 0.6, true, fmt.Sprintf("%s: a jump into %s, an unsigned file of the game folder or Program Files%s", where, target, late))
		return optIn(e, cat, heldGameJump)
	}
	what := "bytes were replaced, no jump"
	if kind == pb.CodeChangeKind_CODE_CHANGE_KIND_JUMP_UNBACKED {
		what = fmt.Sprintf("a jump to %#x, memory that no file backs", b&0xffffffff)
	}
	e := ev("code_changed", SeverityHigh, 0.9, true, where+": "+what)
	if !clientSide && addons {
		return optIn(e, cat, heldAddons)
	}
	e.Notice = cat
	return e
}

// Holder is what a companion says about a process that holds a handle to the game.
type Holder struct {
	Pid    uint64
	Name   string
	Access uint32
	// Suspect: a memory tool, or an unsigned program from outside the game folder, Program
	// Files and the Windows directory.
	Suspect bool
	// Known: it was already there, with its handle, at the first recorded start.
	Known bool
}

const (
	accessVMOperation  = 0x08
	accessVMRead       = 0x10
	accessVMWrite      = 0x20
	accessCreateThread = 0x02
)

// HolderOf decodes an external-handle finding from a companion; ok is false when the
// finding says nothing about the holder's program (the in-process SDK sends only a name).
func HolderOf(f *pb.Finding) (Holder, bool) {
	about := f.B >> 32
	if pb.FindingCode(f.Code) != pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE || about&uint64(pb.HolderFlags_HOLDER_FLAGS_KNOWN) == 0 {
		return Holder{}, false
	}
	sig, class := pb.ModuleSignature(about&0xff), about>>8&0xff
	h := Holder{Pid: f.A, Name: f.Detail, Access: uint32(f.B)}
	h.Suspect = isMemoryTool(f.Detail) || notValid(sig) && class == uint64(pb.ModulePathClass_MODULE_PATH_CLASS_OTHER)+1
	h.Known = observed(about>>24&0xff, pb.ObservedFlags_OBSERVED_FLAGS_KNOWN_START)
	return h, true
}

func (c Config) classifyHolder(f *pb.Finding, h Holder) Evidence {
	about := f.B >> 32
	sig, class, flags := pb.ModuleSignature(about&0xff), about>>8&0xff, about>>24&0xff
	write := h.Access&(accessVMWrite|accessVMOperation|accessCreateThread) != 0
	can := "read"
	if write {
		can = "read and write"
	}
	when := whenSeen(flags, 0)
	switch {
	case isMemoryTool(h.Name) && write:
		e := ev("memory_tool", SeverityHigh, 0.85, true, fmt.Sprintf("memory editor %s holds a handle that can write the game's memory (access %#x)", h.Name, h.Access))
		e.Notice = pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY
		return e
	case isMemoryTool(h.Name):
		e := ev("memory_tool", SeverityMedium, 0.6, true, fmt.Sprintf("memory editor %s holds a handle that can read the game's memory (access %#x)", h.Name, h.Access))
		return optIn(e, pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY, heldReader)
	case class == 0:
		return ev("external_handle", SeverityInfo, 0.1, false, fmt.Sprintf("handle from %s, a Windows program", h.Name))
	case c.OverlayAllow[strings.ToLower(h.Name)] && !notValid(sig):
		return ev("external_handle", SeverityInfo, 0.1, false, "handle from allowlisted "+h.Name)
	case sig == pb.ModuleSignature_MODULE_SIGNATURE_VALID:
		return ev("external_handle", SeverityLow, 0.2, false, fmt.Sprintf("validly signed program %s holds a %#x handle to the game", h.Name, h.Access))
	case h.Suspect && write:
		e := ev("external_writer", SeverityHigh, 0.8, true,
			fmt.Sprintf("unsigned program %s from outside the game folder holds a handle that can %s the game's memory (access %#x; %s)", h.Name, can, h.Access, when))
		return tell(e, pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY, flags)
	case h.Suspect:
		e := ev("external_reader", SeverityMedium, 0.55, true,
			fmt.Sprintf("unsigned program %s from outside the game folder holds a handle that can read the game's memory (access %#x; %s)", h.Name, h.Access, when))
		return optIn(e, pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY, heldReader)
	case class == uint64(pb.ModulePathClass_MODULE_PATH_CLASS_GAME_DIR)+1:
		return ev("external_handle", SeverityLow, 0.2, false, fmt.Sprintf("program %s of the game folder holds a %#x handle to the game", h.Name, h.Access))
	}
	return ev("external_handle", SeverityMedium, 0.55, true, fmt.Sprintf("process %s holds a %#x handle to the game", h.Name, h.Access))
}

// OverlayReader is the verdict for one program that both holds a handle to the game's
// memory and draws a transparent topmost window over the game: an external ESP. Each
// half alone is ordinary; an unsigned program doing both is not.
func OverlayReader(h Holder) Evidence {
	e := ev("overlay_reader", SeverityHigh, 0.85, true,
		fmt.Sprintf("%s (pid %d) holds a handle that reads the game's memory (access %#x) and draws a transparent topmost window over the game", h.Name, h.Pid, h.Access))
	e.Notice = pb.EnforcementCategory_ENFORCEMENT_CATEGORY_VISIBILITY
	if h.Known {
		return partOfBuild(e)
	}
	return e
}
