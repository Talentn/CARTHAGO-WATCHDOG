package pipeline

import (
	"sync"
	"testing"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/analyzer"
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
			[]sentNotice{{pb.EnforcementCategory_ENFORCEMENT_CATEGORY_GAME_INTEGRITY, pb.EnforcementSeverity_ENFORCEMENT_SEVERITY_HIGH}}},
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

// pooled says which players are in a shadow pool, and records what it was asked.
type pooled struct {
	players map[string]bool
	// entering: certain evidence puts a player into the pool.
	entering bool
	asked    []string
}

func (p *pooled) Silent(sess store.Session, certain bool) bool {
	p.asked = append(p.asked, sess.SessionID)
	return p.players[sess.PlayerHash] || certain && p.entering
}

type bansMade struct{ rules []string }

func (b *bansMade) Automatic(_ store.Session, rule, _ string) { b.rules = append(b.rules, rule) }

// A player in the shadow pool gets no notice and no kick, from the client's findings or
// from the gameplay rules, and neither does a player whose evidence is about to put them
// there. The evidence is still recorded and the ban is still asked for.
func TestShadowPoolSilencesNoticesAndKicks(t *testing.T) {
	patch := func(detail string) *pb.Heartbeat {
		return hb(finding(pb.FindingCode_FINDING_CODE_CODE_PATCH, 1, 2, detail))
	}
	newPipeline := func(pool *pooled) (*Pipeline, *store.Memory, *notices, *kicks, *bansMade) {
		p, st, k := newTest(t, Config{Notices: true, AutoKick: true, AutoKickSeverity: analyzer.SeverityHigh})
		n, b := &notices{}, &bansMade{}
		p.SetNotifier(n)
		p.SetBanner(b)
		if pool != nil {
			p.SetPool(pool)
		}
		return p, st, n, k, b
	}

	// Without a pool, and for a player outside it: the notice and the kick, as before.
	for _, pool := range []*pooled{nil, {players: map[string]bool{"somebody-else": true}}} {
		p, st, n, k, _ := newPipeline(pool)
		p.Heartbeat(session(st, "s1", "t1", "p1"), patch("hw.dll>x"))
		flush(p)
		if len(n.of("s1")) != 1 || k.reason("s1") == "" {
			t.Fatalf("pool %+v: notices %v, kicks %v", pool, n.of("s1"), k.got)
		}
	}

	// In the pool.
	pool := &pooled{players: map[string]bool{"p1": true}}
	p, st, n, k, _ := newPipeline(pool)
	p.Heartbeat(session(st, "s1", "t1", "p1"), patch("hw.dll>x"))
	p.Heartbeat(session(st, "clean", "t1", "p9"), hb())
	flush(p)
	if n.of("s1") != nil || len(k.got) != 0 {
		t.Fatalf("in the pool: notices %v, kicks %v", n.of("s1"), k.got)
	}
	if evs, _ := st.ListEvidence(t.Context(), "t1", store.EvidenceFilter{SessionID: "s1", Limit: 10}); len(evs) == 0 {
		t.Fatal("the evidence of a player in the pool was not recorded")
	}
	if len(pool.asked) != 1 {
		t.Fatalf("the pool is asked when there is something to say, not on every heartbeat: %v", pool.asked)
	}
	ms := &matchState{reported: map[string]bool{"1|angle_snap": true, "1|headshot_rate": true, "2|angle_snap": true, "2|headshot_rate": true},
		sessions: map[uint32]store.Session{1: {SessionID: "s1", PlayerHash: "p1"}, 2: {SessionID: "s2", PlayerHash: "p2"}}}
	p.notifyGameplay(ms)
	if n.of("s1") != nil || len(n.of("s2")) != 1 {
		t.Fatalf("gameplay notices: pooled %v, normal %v", n.of("s1"), n.of("s2"))
	}

	// On the way in: certain evidence, with the studio's period on.
	p, st, n, k, b := newPipeline(&pooled{entering: true})
	renderer := finding(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE, 1,
		uint64(pb.ModuleSignature_MODULE_SIGNATURE_NONE)|uint64(pb.ModulePathClass_MODULE_PATH_CLASS_GAME_DIR)<<8|
			uint64(pb.ObservedFlags_OBSERVED_FLAGS_AT_START|pb.ObservedFlags_OBSERVED_FLAGS_SHADOWS_SYSTEM)<<16, "OPENGL32.dll")
	p.Heartbeat(session(st, "s1", "t1", "p1"), hb(renderer))
	p.Heartbeat(session(st, "s2", "t1", "p2"), patch("hw.dll>x"))
	flush(p)
	if n.of("s1") != nil || len(b.rules) != 1 || b.rules[0] != "renderer_replaced" {
		t.Fatalf("on the way in: notices %v, bans %v", n.of("s1"), b.rules)
	}
	if len(n.of("s2")) != 1 || len(k.got) != 1 || k.reason("s2") == "" {
		t.Fatalf("evidence that does not ban: notices %v, kicks %v", n.of("s2"), k.got)
	}
}
