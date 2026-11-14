package learning

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/bans"
	"carthago/backend/internal/store"
)

type fixture struct {
	t    *testing.T
	st   *store.Memory
	bans *bans.Service
	now  time.Time
}

func newFixture(t *testing.T) *fixture {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f := &fixture{t: t, st: store.NewMemory(), now: time.UnixMilli(1_700_000_000_000).UTC()}
	f.bans = bans.New(f.st, log)
	f.bans.Now = func() time.Time { return f.now }
	l := NewLabeler(f.st, log)
	l.Now = func() time.Time { return f.now }
	f.bans.AddHook(l)
	return f
}

func (f *fixture) session(id, player string, age time.Duration) store.Session {
	f.t.Helper()
	s := store.Session{SessionID: id, TenantID: "demo", PlayerHash: player, DeviceID: "dev-" + player, CreatedAt: f.now.Add(-age), ExpiresAt: f.now.Add(time.Hour)}
	if err := f.st.PutSession(context.Background(), &s); err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fixture) label(id string) *store.SessionLabel {
	l, err := f.st.GetSessionLabel(context.Background(), "demo", id)
	if err != nil {
		return nil
	}
	return l
}

// module stores the evidence of one loaded file. bits: signature state, path class << 8.
func (f *fixture) module(session, player, name, sum string, bits int) {
	f.t.Helper()
	raw := fmt.Sprintf(`{"code":"FINDING_CODE_MODULE_SIGNATURE","b":"%#x","detail":%q,"sha256":%q}`, 0x30000|bits, name, sum)
	if err := f.st.AddEvidence(context.Background(), []store.Evidence{{TenantID: "demo", PlayerHash: player, SessionID: session, Source: store.SourceClient,
		Rule: "module", Summary: name, Raw: raw, ObservedAt: f.now}}); err != nil {
		f.t.Fatal(err)
	}
}

// An automatic ban labels the session it was made from and the account's other sessions
// of the last 30 days; a session a reviewer labelled keeps that label; lifting the ban
// removes the ban's labels and nothing else.
func TestBanLabelsFollowTheBan(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.session("old", "max", 40*24*time.Hour)
	f.session("mid", "max", 10*24*time.Hour)
	f.session("reviewed", "max", 5*24*time.Hour)
	now := f.session("now", "max", time.Minute)
	f.session("other", "zed", time.Minute)
	if err := f.st.SetSessionLabel(ctx, &store.SessionLabel{TenantID: "demo", SessionID: "reviewed", PlayerHash: "max", Label: store.LabelCleared, Reviewer: "rev", LabelledAt: f.now}, store.LabelSet, ""); err != nil {
		t.Fatal(err)
	}
	f.bans.Automatic(now, "known_cheat", "known cheat file loaded")
	b, err := f.st.StandingBan(ctx, "demo", "max", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"now", "mid"} {
		l := f.label(id)
		if l == nil || l.Label != store.LabelConfirmedCheat || l.Source != store.LabelSourceBan || l.BanRef != b.Ref || l.CheatType != "client_tampering" || l.Reviewer != "ban "+b.Ref || l.PlayerHash != "max" {
			t.Fatalf("session %s: %+v", id, l)
		}
	}
	if f.label("old") != nil || f.label("other") != nil {
		t.Fatal("a session older than 30 days, or another account's, was labelled")
	}
	if l := f.label("reviewed"); l == nil || l.Label != store.LabelCleared || l.Source != "" {
		t.Fatalf("the reviewer's label: %+v", l)
	}
	// A reviewer changes one of the ban's labels: it is the reviewer's from then on.
	if err := f.st.SetSessionLabel(ctx, &store.SessionLabel{TenantID: "demo", SessionID: "mid", PlayerHash: "max", Label: store.LabelConfirmedCheat, Reviewer: "rev", LabelledAt: f.now}, store.LabelSet, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.bans.Lift(ctx, "demo", b.ID, "ada", "false alarm"); err != nil {
		t.Fatal(err)
	}
	if f.label("now") != nil {
		t.Fatal("the ban's label outlived the ban")
	}
	if f.label("mid") == nil || f.label("reviewed") == nil {
		t.Fatal("lifting the ban removed a reviewer's label")
	}
	trail, _ := f.st.ListLabelAudit(ctx, "demo", "now", 10)
	if len(trail) != 2 || trail[0].Action != store.LabelRemove || trail[1].Action != store.LabelSet || trail[1].Reviewer != "ban "+b.Ref {
		t.Fatalf("label history: %+v", trail)
	}
}

// A person's ban labels only when the session holds certain evidence; the label then has
// the category the person chose. A ban on judgement alone labels nothing.
func TestManualBanLabelsOnCertainEvidenceOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	hunch, proven := f.session("hunch", "ann", time.Minute), f.session("proven", "bob", time.Minute)
	if err := f.st.AddEvidence(ctx, []store.Evidence{
		{TenantID: "demo", PlayerHash: "ann", SessionID: "hunch", Source: store.SourceGameplay, Rule: "aim_snap", Severity: 3, Summary: "snaps", ObservedAt: f.now},
		// A certain rule below high severity is not certain evidence.
		{TenantID: "demo", PlayerHash: "ann", SessionID: "hunch", Source: store.SourceClient, Rule: "foreign_module", Severity: 1, Integrity: true, Summary: "low", ObservedAt: f.now},
		{TenantID: "demo", PlayerHash: "bob", SessionID: "proven", Source: store.SourceClient, Rule: "renderer_replaced", Severity: 3, Integrity: true, Summary: "renderer", ObservedAt: f.now},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.bans.Ban(ctx, bans.Request{Session: hunch, By: "rev", Reason: "looks off", Rule: "aim_assistance"}); err != nil {
		t.Fatal(err)
	}
	if f.label("hunch") != nil {
		t.Fatal("a ban without certain evidence labelled the session")
	}
	if _, _, err := f.bans.Ban(ctx, bans.Request{Session: proven, By: "rev", Rule: "wallhack_information"}); err != nil {
		t.Fatal(err)
	}
	if l := f.label("proven"); l == nil || l.Source != store.LabelSourceBan || l.CheatType != "wallhack_information" {
		t.Fatalf("a ban on certain evidence: %+v", l)
	}
}

// A file is proposed when it is not validly signed, at least the studio's number of
// banned accounts loaded it, and no account that is not banned did. Known and dismissed
// files are not proposed, and a lifted ban no longer counts.
func TestProposals(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	wall, game, signed, solo := strings.Repeat("aa", 32), strings.Repeat("bb", 32), strings.Repeat("cc", 32), strings.Repeat("dd", 32)
	const unsigned, valid, gameDir = 2, 1, 1 << 8
	for _, p := range []string{"max", "nia", "zed"} {
		f.session("s-"+p, p, time.Minute)
	}
	f.module("s-max", "max", "wall.dll", wall, unsigned)
	f.module("s-max2", "max", "wall.dll", wall, unsigned)
	f.module("s-nia", "nia", "d3d9x.dll", wall, unsigned)
	for _, p := range []string{"max", "nia", "zed"} {
		f.module("s-"+p, p, "client.dll", game, unsigned|gameDir)
	}
	f.module("s-max", "max", "overlay.dll", signed, valid)
	f.module("s-nia", "nia", "overlay.dll", signed, valid)
	f.module("s-max", "max", "esp.dll", solo, unsigned)
	list := func() *Proposals {
		t.Helper()
		p, err := FindProposals(ctx, f.st, "demo")
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := list(); len(p.List) != 0 || p.MinAccounts != 2 || p.Compared != 3 {
		t.Fatalf("nobody is banned: %+v", p)
	}
	for _, p := range []string{"max", "nia"} {
		f.bans.Automatic(store.Session{SessionID: "s-" + p, TenantID: "demo", PlayerHash: p}, "known_cheat", "test")
	}
	p := list()
	if len(p.List) != 1 || p.Compared != 1 {
		t.Fatalf("two banned accounts: %+v", p)
	}
	if got := p.List[0]; got.SHA256 != wall || got.BannedAccounts != 2 || got.Sessions != 3 || got.Signature != "not signed" || strings.Join(got.Names, ",") != "wall.dll,d3d9x.dll" {
		t.Fatalf("proposal: %+v", got)
	}
	if p.Proposed(wall) == nil || p.Proposed(game) != nil {
		t.Fatal("Proposed")
	}
	// One PC, one account: with a threshold of 1 the file only max loaded is proposed too.
	f.st.SetCheatProposalAccounts(ctx, "demo", 1)
	if p := list(); len(p.List) != 2 || p.List[0].SHA256 != wall || p.List[1].SHA256 != solo {
		t.Fatalf("threshold 1: %+v", p.List)
	}
	f.st.DismissCheatProposal(ctx, "demo", solo, "rev", f.now)
	f.st.AddKnownCheat(ctx, &store.KnownCheat{TenantID: "demo", SHA256: wall, Name: "Wall", AddedBy: "rev", AddedAt: f.now})
	if p := list(); len(p.List) != 0 {
		t.Fatalf("known and dismissed files are still proposed: %+v", p.List)
	}
	// Another studio's bans and files are its own.
	if p, _ := FindProposals(ctx, f.st, "rival"); len(p.List) != 0 || p.Compared != 0 {
		t.Fatalf("another studio: %+v", p)
	}
	// With nia's ban lifted the game's file is still everybody's, and wall.dll, were it
	// not known by now, would have an account that is not banned.
	b, _ := f.st.StandingBan(ctx, "demo", "nia", "")
	f.bans.Lift(ctx, "demo", b.ID, "ada", "")
	known, _ := f.st.ListKnownCheats(ctx, "demo")
	f.st.RemoveKnownCheat(ctx, "demo", known[0].ID)
	if p := list(); len(p.List) != 0 || p.Compared != 2 {
		t.Fatalf("after a lift: %+v", p)
	}
}
