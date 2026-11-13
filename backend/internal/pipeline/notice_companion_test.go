package pipeline

import (
	"testing"

	pb "carthago/backend/gen/carthago/v1"
)

// What a companion reports beside a game, as findings.
const (
	obsAfter   = uint64(pb.ObservedFlags_OBSERVED_FLAGS_AFTER_START)
	obsAtStart = uint64(pb.ObservedFlags_OBSERVED_FLAGS_AT_START)
	obsKnown   = uint64(pb.ObservedFlags_OBSERVED_FLAGS_KNOWN_START)
	obsShadow  = uint64(pb.ObservedFlags_OBSERVED_FLAGS_SHADOWS_SYSTEM)
	unsigned   = uint64(pb.ModuleSignature_MODULE_SIGNATURE_NONE)
	inGame     = uint64(pb.ModulePathClass_MODULE_PATH_CLASS_GAME_DIR)
	elsewhere  = uint64(pb.ModulePathClass_MODULE_PATH_CLASS_OTHER)
)

func moduleSeen(sig, class, flags uint64, name string) *pb.Finding {
	return finding(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE, 0x10000000, sig|class<<8|flags<<16|30<<32, name)
}

func handleOf(pid, access, sig, classPlus1, flags uint64, name string) *pb.Finding {
	return finding(pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE, pid, access|(sig|classPlus1<<8|uint64(pb.HolderFlags_HOLDER_FLAGS_KNOWN)|flags<<24)<<32, name)
}

func codeChanged(kind pb.CodeChangeKind, about uint64, detail string) *pb.Finding {
	return finding(pb.FindingCode_FINDING_CODE_EXTERNAL_CODE_CHANGE, 0x5000_1000, 0x3000_0000|(uint64(kind)|about)<<32, detail)
}

var (
	vis   = sentNotice{pb.EnforcementCategory_ENFORCEMENT_CATEGORY_VISIBILITY, pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_HIGH}
	integ = sentNotice{pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY, pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_HIGH}
)

type companionCase struct {
	id     string
	hb     []*pb.Heartbeat
	want   []sentNotice // with the default guards
	strict []sentNotice // with NoticesOptIn
}

func companionCases() []companionCase {
	// A clean start of a modified build, as the companion sees it on every run: its own
	// unsigned files, a Direct3D 8 wrapper it has always shipped, an image its loader
	// maps, its launcher's handle, an overlay, executable memory of a script engine, and
	// add-ons hooking the engine when the map starts.
	clean := hb(
		moduleSeen(unsigned, inGame, obsAtStart|obsKnown, "hw.dll"),
		moduleSeen(unsigned, inGame, obsAtStart|obsKnown, "client.dll"),
		moduleSeen(unsigned, inGame, obsAtStart|obsKnown|obsShadow, "d3d8.dll"),
		moduleSeen(unsigned, inGame, obsAfter, "mp.dll"),
		moduleSeen(unsigned, inGame, obsAfter, "amxmodx_mm.dll"),
		finding(pb.FindingCode_FINDING_CODE_EXTERNAL_MAPPED_IMAGE, 0x1d00000, 0x40000|(obsAtStart|obsKnown)<<32, "aa"),
		finding(pb.FindingCode_FINDING_CODE_EXTERNAL_EXEC_REGIONS, 12, 1<<20, ""),
		handleOf(100, 0x1fffff, unsigned, inGame+1, obsAtStart|obsKnown, "launcher.exe"),
		handleOf(101, 0x1410, uint64(pb.ModuleSignature_MODULE_SIGNATURE_VALID), elsewhere+1, obsAfter, "Discord.exe"),
		finding(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, 101, 0, "Discord.exe"),
		finding(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, 102, 0, "unknown.exe"),
		codeChanged(pb.CodeChangeKind_CODE_CHANGE_KIND_JUMP_MODULE, (inGame+1)<<8|unsigned<<16|1<<24|1<<25, "hw.dll>amxmodx_mm.dll"),
		codeChanged(pb.CodeChangeKind_CODE_CHANGE_KIND_JUMP_MODULE, (elsewhere+1)<<8|uint64(pb.ModuleSignature_MODULE_SIGNATURE_VALID)<<16, "opengl32.dll>discordhook.dll"),
	)
	return []companionCase{
		// The Direct3D 8 wrapper and the mapped image have been there since the first
		// recorded start: only the opt-in tells the player about them.
		{"clean start", []*pb.Heartbeat{clean}, nil, []sentNotice{vis, integ}},
		// An unsigned OpenGL library is a wallhack's way in: the record of the first start
		// does not excuse it.
		{"renderer library that the first recorded start had", []*pb.Heartbeat{hb(moduleSeen(unsigned, inGame, obsAtStart|obsKnown|obsShadow, "OPENGL32.dll"))}, []sentNotice{vis}, []sentNotice{vis}},

		{"renderer proxy dropped into the game folder", []*pb.Heartbeat{hb(moduleSeen(unsigned, inGame, obsAtStart|obsShadow, "opengl32.dll"))}, []sentNotice{vis}, []sentNotice{vis}},
		{"library injected after start", []*pb.Heartbeat{hb(moduleSeen(unsigned, elsewhere, obsAfter, "hack.dll"))}, []sentNotice{integ}, []sentNotice{integ}},
		{"image mapped by hand after start", []*pb.Heartbeat{hb(finding(pb.FindingCode_FINDING_CODE_EXTERNAL_MAPPED_IMAGE, 0x3000000, 0x40000|obsAfter<<32, "bb"))}, []sentNotice{integ}, []sentNotice{integ}},
		{"renderer hooked from unbacked memory", []*pb.Heartbeat{hb(codeChanged(pb.CodeChangeKind_CODE_CHANGE_KIND_JUMP_UNBACKED, 1<<25, "opengl32.dll>?"))}, []sentNotice{vis}, []sentNotice{vis}},
		{"engine patched while add-ons are loaded", []*pb.Heartbeat{hb(codeChanged(pb.CodeChangeKind_CODE_CHANGE_KIND_BYTES, 1<<25, "hw.dll>"))}, nil, []sentNotice{integ}},
		{"unsigned writer", []*pb.Heartbeat{hb(handleOf(200, 0x1fffff, unsigned, elsewhere+1, obsAfter, "trainer.exe"))}, []sentNotice{integ}, []sentNotice{integ}},
		{"unsigned reader", []*pb.Heartbeat{hb(handleOf(201, 0x1410, unsigned, elsewhere+1, obsAfter, "radar.exe"))}, nil, []sentNotice{integ}},
		// The handle and the overlay arrive in different heartbeats, in either order.
		{"reader that draws over the game", []*pb.Heartbeat{
			hb(handleOf(202, 0x1410, unsigned, elsewhere+1, obsAfter, "esp.exe")),
			hb(finding(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, 202, 0, "esp.exe")),
		}, []sentNotice{vis}, []sentNotice{integ, vis}},
		{"overlay first, then its handle", []*pb.Heartbeat{
			hb(finding(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, 203, 0, "esp.exe")),
			hb(handleOf(203, 0x1410, unsigned, elsewhere+1, obsAfter, "esp.exe")),
		}, []sentNotice{vis}, []sentNotice{integ, vis}},
		{"overlay of one program, handle of another", []*pb.Heartbeat{
			hb(finding(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, 204, 0, "overlay.exe"), handleOf(205, 0x1410, uint64(pb.ModuleSignature_MODULE_SIGNATURE_VALID), elsewhere+1, obsAfter, "monitor.exe")),
		}, nil, nil},
		{"reader that later opens the game for writing", []*pb.Heartbeat{
			hb(handleOf(207, 0x1410, unsigned, elsewhere+1, obsAfter, "tool.exe")),
			hb(handleOf(207, 0x1438, unsigned, elsewhere+1, obsAfter, "tool.exe")),
		}, []sentNotice{integ}, []sentNotice{integ, integ}},
		{"memory editor", []*pb.Heartbeat{hb(handleOf(206, 0x1fffff, uint64(pb.ModuleSignature_MODULE_SIGNATURE_VALID), 3, obsAfter, "cheatengine-x86_64.exe"))}, []sentNotice{integ}, []sentNotice{integ}},
	}
}

func TestCompanionEvidenceThatRaisesANotice(t *testing.T) {
	for _, mode := range []struct {
		name  string
		optIn bool
	}{{"default", false}, {"opt-in", true}} {
		p, st, k := newTest(t, Config{Notices: true, NoticesOptIn: mode.optIn})
		n := &notices{}
		p.SetNotifier(n)
		cases := companionCases()
		for _, c := range cases {
			sess := session(st, c.id, "t1", c.id)
			for _, h := range c.hb {
				p.Heartbeat(sess, h)
			}
		}
		flush(p)
		for _, c := range cases {
			want := c.want
			if mode.optIn {
				want = c.strict
			}
			got := n.of(c.id)
			if len(got) != len(want) {
				t.Errorf("%s, %s: notices %v, want %v", mode.name, c.id, got, want)
				continue
			}
			for i := range got {
				if got[i] != want[i] {
					t.Errorf("%s, %s: notice %v, want %v", mode.name, c.id, got[i], want[i])
				}
			}
			if r := k.reason(c.id); r != "" {
				t.Errorf("%s, %s: a notice must not kick, got %q", mode.name, c.id, r)
			}
		}
	}
}
