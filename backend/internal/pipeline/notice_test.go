package pipeline

import (
	"sync"
	"testing"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/store"
)

type sentNotice struct {
	category pb.EnforcementCategory
	severity pb.EnforcementSeverity
}

type notices struct {
	mu  sync.Mutex
	got map[string][]sentNotice
}

func (n *notices) Notice(id string, c pb.EnforcementCategory, s pb.EnforcementSeverity) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.got == nil {
		n.got = map[string][]sentNotice{}
	}
	n.got[id] = append(n.got[id], sentNotice{c, s})
	return true
}

func (n *notices) of(id string) []sentNotice {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.got[id]
}

func hb(f ...*pb.Finding) *pb.Heartbeat { return &pb.Heartbeat{Findings: f} }

func TestClientEvidenceThatRaisesANotice(t *testing.T) {
	p, st, k := newTest(t, Config{Notices: true})
	n := &notices{}
	p.SetNotifier(n)
	object := uint64(pb.DebugSignal_DEBUG_SIGNAL_DEBUG_OBJECT | pb.DebugSignal_DEBUG_SIGNAL_DEBUG_PORT)
	cases := []struct {
		id   string
		hb   *pb.Heartbeat
		want []sentNotice
	}{
		{"patched", hb(finding(pb.FindingCode_FINDING_CODE_CODE_PATCH, 1, 2, "hw.dll>x")),
			[]sentNotice{{pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY, pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_CRITICAL}}},
		{"hooked", hb(finding(pb.FindingCode_FINDING_CODE_API_HOOK, 0x1000, 4, "")),
			[]sentNotice{{pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY, pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_HIGH}}},
		{"debugged", hb(finding(pb.FindingCode_FINDING_CODE_DEBUGGER, object, 0, "")),
			[]sentNotice{{pb.EnforcementCategory_ENFORCEMENT_CATEGORY_DEBUGGER, pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_HIGH}}},
		// Everything a companion reports about an ordinary PC, and the strongest evidence
		// that is still only context: none of it tells the client anything.
		{"ordinary", hb(
			finding(pb.FindingCode_FINDING_CODE_OVERLAY_WINDOW, 1, 0, "unknown.exe"),
			finding(pb.FindingCode_FINDING_CODE_EXTERNAL_HANDLE, 1, 0x1fffff, "tool.exe"),
			finding(pb.FindingCode_FINDING_CODE_VULNERABLE_DRIVER, 1, 0, "winring0.sys"),
			finding(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE, 1, uint64(pb.ModuleSignature_MODULE_SIGNATURE_BAD_DIGEST), "mp.dll"),
			finding(pb.FindingCode_FINDING_CODE_EXTERNAL_EXEC_REGIONS, 9, 1<<20, ""),
			finding(pb.FindingCode_FINDING_CODE_UNBACKED_EXEC, 0x10000, 4096|uint64(pb.UnbackedFlags_UNBACKED_FLAGS_WRITABLE|pb.UnbackedFlags_UNBACKED_FLAGS_PE_SIGNATURE)<<48, ""),
			finding(pb.FindingCode_FINDING_CODE_THREAD_START_UNBACKED, 0x10000, 0, ""),
			finding(pb.FindingCode_FINDING_CODE_DEBUGGER, uint64(pb.DebugSignal_DEBUG_SIGNAL_KERNEL_DEBUGGER), 0, ""),
			finding(pb.FindingCode_FINDING_CODE_DEBUGGER, uint64(pb.DebugSignal_DEBUG_SIGNAL_PEB_BEING_DEBUGGED), 0, ""),
		), nil},
	}
	for _, c := range cases {
		p.Heartbeat(session(st, c.id, "t1", c.id), c.hb)
	}
	flush(p)
	for _, c := range cases {
		got := n.of(c.id)
		if len(got) != len(c.want) {
			t.Errorf("%s: notices %v, want %v", c.id, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: notice %v, want %v", c.id, got[i], c.want[i])
			}
		}
		if r := k.reason(c.id); r != "" {
			t.Errorf("%s: a notice must not kick, got %q", c.id, r)
		}
	}
}

func TestNoticesAreOffUnlessConfigured(t *testing.T) {
	p, st, _ := newTest(t, Config{})
	n := &notices{}
	p.SetNotifier(n)
	p.Heartbeat(session(st, "patched", "t1", "p"), hb(finding(pb.FindingCode_FINDING_CODE_CODE_PATCH, 1, 2, "hw.dll>x")))
	flush(p)
	if got := n.of("patched"); got != nil {
		t.Fatalf("notices %v with Notices off", got)
	}
}

func TestGameplayEvidenceThatRaisesANotice(t *testing.T) {
	rules := func(slot string, names ...string) map[string]bool {
		m := map[string]bool{}
		for _, r := range names {
			m[slot+"|"+r] = true
		}
		return m
	}
	for _, c := range []struct {
		name     string
		reported map[string]bool
		want     bool
	}{
		{"snap with headshot rate", rules("1", "angle_snap", "headshot_rate"), true},
		{"snap with time to damage", rules("1", "angle_snap", "time_to_damage"), true},
		{"snap alone", rules("1", "angle_snap"), false},
		{"statistics without snap", rules("1", "headshot_rate", "time_to_damage"), false},
		{"review rules only", rules("1", RuleInformationLeak, "decoy_reaction", "command_rate", "macro_interval"), false},
		{"snap with review rules", rules("1", "angle_snap", RuleInformationLeak, "decoy_reaction", "command_rate"), false},
		{"another player's rules", rules("2", "angle_snap", "headshot_rate", "time_to_damage"), false},
	} {
		if got := gameplayNotice(c.reported, 1); got != c.want {
			t.Errorf("%s: notice %v, want %v", c.name, got, c.want)
		}
	}

	// Only a slot bound to a verified session has a client to tell: a bot never does.
	p, _, _ := newTest(t, Config{Notices: true})
	n := &notices{}
	p.SetNotifier(n)
	reported := rules("1", "angle_snap", "headshot_rate")
	for k := range rules("2", "angle_snap", "time_to_damage") {
		reported[k] = true
	}
	for k := range rules("3", "angle_snap") {
		reported[k] = true
	}
	ms := &matchState{reported: reported, sessions: map[uint32]store.Session{1: {SessionID: "s1"}, 3: {SessionID: "s3"}}}
	p.notifyGameplay(ms)
	want := sentNotice{pb.EnforcementCategory_ENFORCEMENT_CATEGORY_AIM_ASSISTANCE, pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_HIGH}
	if got := n.of("s1"); len(got) != 1 || got[0] != want {
		t.Errorf("bound slot: notices %v", got)
	}
	if got := n.of("s3"); got != nil {
		t.Errorf("slot with angle_snap only: notices %v", got)
	}
	if len(n.got) != 1 {
		t.Errorf("notices for %d sessions, want 1: %v", len(n.got), n.got)
	}
}
