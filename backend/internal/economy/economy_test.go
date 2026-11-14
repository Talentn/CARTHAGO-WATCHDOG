package economy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"carthago/backend/internal/bans"
	"carthago/backend/internal/store"
)

type fixture struct {
	t    *testing.T
	st   *store.Memory
	bans *bans.Service
	eco  *Service
	now  time.Time
	seq  int
}

func newFixture(t *testing.T, autoBan bool) *fixture {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f := &fixture{t: t, st: store.NewMemory(), now: time.UnixMilli(1_700_000_000_000).UTC()}
	f.bans = bans.New(f.st, log)
	f.bans.Now = func() time.Time { return f.now }
	var banner Banner
	if autoBan {
		banner = f.bans
	}
	f.eco = New(f.st, banner, log)
	f.eco.Now = func() time.Time { return f.now }
	f.bans.SetHook(f.eco)
	return f
}

// ev reports one change a minute after the last and returns the answer.
func (f *fixture) ev(player string, amount int64, source, counterparty string) Result {
	f.t.Helper()
	f.seq++
	f.now = f.now.Add(time.Minute)
	r := f.eco.Record(context.Background(), "demo", []Event{{EventID: fmt.Sprintf("e%d", f.seq), Player: player, Amount: amount, Source: source, Counterparty: counterparty, AtMS: f.now.UnixMilli()}})[0]
	if r.Status != "recorded" {
		f.t.Fatalf("event %d (%s %d %s): %+v", f.seq, player, amount, source, r)
	}
	return r
}

func (f *fixture) snap(player string, balance int64) BalanceResult {
	f.now = f.now.Add(time.Minute)
	return f.eco.Snapshot(context.Background(), "demo", []Balance{{Player: player, Balance: balance, AtMS: f.now.UnixMilli()}})[0]
}

func (f *fixture) banned(player string) *store.Ban {
	b, err := f.st.StandingBan(context.Background(), "demo", player, "")
	if err != nil {
		return nil
	}
	return b
}

func (f *fixture) flags(player string) []store.EconomyFlag {
	l, _ := f.st.ListEconomyFlags(context.Background(), "demo", player, 0)
	return l
}

func (f *fixture) dirty(player string) int64 {
	l, err := f.eco.Dirty(context.Background(), "demo", player)
	if err != nil {
		f.t.Fatal(err)
	}
	var sum int64
	for _, d := range l {
		sum += d.Dirty
	}
	return sum
}

// An honest player: every change is reported with a source the studio has, and the
// balance matches the ledger each time it is reported.
func TestHonestPlayIsLeftAlone(t *testing.T) {
	f := newFixture(t, true)
	if r := f.snap("hana", 500); r.Status != "opened" || r.Ledger != 0 {
		t.Fatalf("first balance: %+v", r)
	}
	f.ev("hana", 200, "job", "")
	f.ev("hana", -150, "purchase", "")
	f.ev("hana", 1000, "robbery", "")
	f.ev("hana", -300, "trade", "fay")
	f.ev("fay", 300, "trade", "hana")
	if r := f.snap("hana", 1250); r.Status != "ok" || r.Ledger != 1250 || len(r.Flags) != 0 {
		t.Fatalf("balance: %+v", r)
	}
	if f.banned("hana") != nil || len(f.flags("")) != 0 || f.dirty("") != 0 {
		t.Fatalf("an honest player was banned, flagged or marked: %+v", f.flags(""))
	}
	// The same event reported again changes nothing.
	if r := f.eco.Record(context.Background(), "demo", []Event{{EventID: "e1", Player: "hana", Amount: 200, Source: "job"}})[0]; r.Status != "duplicate" {
		t.Fatalf("repeat: %+v", r)
	}
	if r := f.snap("hana", 1250); r.Status != "ok" {
		t.Fatalf("balance after a repeated report: %+v", r)
	}
}

// Money in a balance that no report explains bans, beyond the studio's tolerance only.
func TestBalanceAboveTheLedgerBans(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	f.st.SetEconomyTolerance(ctx, "demo", 10)
	f.snap("max", 500)
	f.ev("max", 200, "job", "")
	if r := f.snap("max", 710); r.Status != "ok" || f.banned("max") != nil {
		t.Fatalf("within the tolerance: %+v", r)
	}
	r := f.snap("max", 1_000_700)
	b := f.banned("max")
	if r.Status != "mismatch" || r.Ledger != 700 || len(r.Flags) != 1 || r.Flags[0] != RuleBalanceMismatch || b == nil || r.Banned != b.Ref {
		t.Fatalf("injected money: %+v, ban %+v", r, b)
	}
	if b.Rule != RuleBalanceMismatch || b.BannedBy != store.BanAutomatic || b.Reason != "balance of 1 000 700 money is 1 000 000 above the ledger (700): money that no reported change explains" {
		t.Fatalf("ban: %+v", b)
	}
	if fl := f.flags("max"); len(fl) != 1 || !fl[0].Certain || fl[0].BanRef != b.Ref || fl[0].Amount != 1_000_000 {
		t.Fatalf("flag: %+v", fl)
	}
	// The injected money is dirty in the cheater's own ledger, and the ledger follows the
	// game from here: the same balance is not found again.
	if f.dirty("max") != 1_000_000 {
		t.Fatalf("dirty: %d", f.dirty("max"))
	}
	if r := f.snap("max", 1_000_700); r.Status != "ok" || len(f.flags("max")) != 1 {
		t.Fatalf("the same balance again: %+v", r)
	}
	audit, _ := f.st.ListAudit(ctx, "demo", store.AuditFilter{Limit: 5})
	if len(audit) != 1 || audit[0].Action != "ban.add" || audit[0].Target != "player max" {
		t.Fatalf("audit: %+v", audit)
	}
}

// Money with no source, or from a source the studio does not have, bans. A spend with an
// unknown source creates no money and does not.
func TestMoneyWithoutAKnownSourceBans(t *testing.T) {
	f := newFixture(t, true)
	if r := f.ev("nia", 50_000, "", ""); len(r.Flags) != 1 || r.Flags[0] != RuleNoSource || r.Banned == "" || f.banned("nia") == nil || f.banned("nia").Rule != RuleNoSource {
		t.Fatalf("no source: %+v", r)
	}
	if r := f.ev("oto", 50_000, "console_command", ""); len(r.Flags) != 1 || r.Flags[0] != RuleUnknownSource || f.banned("oto") == nil {
		t.Fatalf("unknown source: %+v", r)
	}
	if r := f.ev("pia", -20, "parking_fee", ""); len(r.Flags) != 0 || f.banned("pia") != nil {
		t.Fatalf("a spend with a new source: %+v", r)
	}
	// A source the studio gave a limit is one of its sources.
	f.st.SetEconomyLimit(context.Background(), store.EconomyLimit{TenantID: "demo", Source: "heist", Currency: "money", PerDay: 100_000})
	if r := f.ev("pia", 5_000, "heist", ""); len(r.Flags) != 0 || f.banned("pia") != nil {
		t.Fatalf("a source the studio listed: %+v", r)
	}
	for _, bad := range []Event{{EventID: "x1", Player: "pia", Amount: 0, Source: "job"}, {EventID: "", Player: "pia", Amount: 5, Source: "job"},
		{EventID: "x2", Player: "pia", Amount: 5, Source: SourceOpening}, {EventID: "x3", Player: "pia", Amount: 5, Source: "trade", Counterparty: "pia"},
		{EventID: "x4", Player: "pia", Amount: 5, Source: "job", AtMS: f.now.Add(time.Hour).UnixMilli()}} {
		if r := f.eco.Record(context.Background(), "demo", []Event{bad})[0]; r.Status != "rejected" || r.Error == "" {
			t.Errorf("%+v was not rejected: %+v", bad, r)
		}
	}
}

// With automatic bans off, what is certain is flagged and marked and nobody is banned.
func TestCertainFlagsWithoutAutomaticBans(t *testing.T) {
	f := newFixture(t, false)
	f.snap("max", 500)
	r := f.snap("max", 9_500)
	if r.Status != "mismatch" || r.Banned != "" || f.banned("max") != nil {
		t.Fatalf("%+v", r)
	}
	if fl := f.flags("max"); len(fl) != 1 || !fl[0].Certain || fl[0].BanRef != "" {
		t.Fatalf("flag: %+v", fl)
	}
}

// Earning over the studio's limit for a source is a flag for review, once per crossing,
// and never a ban.
func TestOverTheLimitIsAFlagOnly(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	f.st.SetEconomyLimit(ctx, store.EconomyLimit{TenantID: "demo", Source: "robbery", Currency: "money", PerHour: 5_000, PerDay: 12_000})
	for i := range 8 {
		r := f.ev("finn", 1_000, "robbery", "")
		if want := i == 5; (len(r.Flags) == 1) != want {
			t.Fatalf("robbery %d: flags %v", i+1, r.Flags)
		}
		f.ev("finn", 1_000, "job", "")
	}
	fl := f.flags("finn")
	if len(fl) != 1 || fl[0].Rule != RuleOverLimit || fl[0].Certain || fl[0].Summary != "6 000 money from robbery in one hour; the studio's limit is 5 000" {
		t.Fatalf("flags: %+v", fl)
	}
	// Two hours later the hour is clear again; the day's limit is crossed further on.
	f.now = f.now.Add(2 * time.Hour)
	for i := range 5 {
		r := f.ev("finn", 1_000, "robbery", "")
		if want := i == 4; (len(r.Flags) == 1) != want {
			t.Fatalf("later robbery %d: flags %v", i+1, r.Flags)
		}
	}
	if fl := f.flags("finn"); len(fl) != 2 || fl[0].Summary != "13 000 money from robbery in one day; the studio's limit is 12 000" {
		t.Fatalf("flags: %+v", fl)
	}
	if f.banned("finn") != nil || f.dirty("") != 0 {
		t.Fatal("farming banned the player or marked money")
	}
}

// What a banned player traded or dropped is dirty on the receivers' entries: what they
// passed on before the ban, and what they pass on after it. The receivers are neither
// flagged nor banned, the studio's removal clears the marks, and lifting the ban does too.
func TestMoneyFromABannedPlayerIsDirty(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	f.snap("max", 500)
	f.ev("max", -300, "trade", "fay")
	if r := f.ev("fay", 300, "trade", "max"); r.Dirty != 0 {
		t.Fatalf("a trade from a player who is not banned: %+v", r)
	}
	f.ev("zoe", 300, "trade", "hana")
	if r := f.snap("max", 90_200); r.Banned == "" {
		t.Fatalf("%+v", r)
	}
	if f.dirty("fay") != 300 || f.dirty("zoe") != 0 {
		t.Fatalf("after the ban: fay %d, zoe %d", f.dirty("fay"), f.dirty("zoe"))
	}
	f.ev("max", -1_000, "drop", "")
	if r := f.ev("bo", 1_000, "drop", "max"); r.Dirty != 1_000 || r.DirtyFrom != "max" || len(r.Flags) != 0 || r.Banned != "" {
		t.Fatalf("picking up what a banned player dropped: %+v", r)
	}
	for _, p := range []string{"fay", "bo"} {
		if f.banned(p) != nil || len(f.flags(p)) != 0 {
			t.Fatalf("%s was banned or flagged for receiving dirty money", p)
		}
	}
	list, _ := f.eco.Dirty(ctx, "demo", "")
	if len(list) != 3 || list[0].Player != "max" || list[0].Dirty != 90_000 || list[1].Player != "bo" || list[2].Player != "fay" || list[2].Entries[0].From != "max" {
		t.Fatalf("dirty list: %+v", list)
	}
	st, err := f.eco.Player(ctx, "demo", "bo")
	if err != nil || st.Banned != "" || len(st.Balances) != 1 || st.Balances[0].Ledger != 1_000 || st.Balances[0].Dirty != 1_000 || len(st.Flags) != 0 {
		t.Fatalf("status of a receiver: %+v %v", st, err)
	}
	// The studio takes 400 back from bo and reports it.
	f.ev("bo", -400, SourceDirtyRemoval, "")
	if f.dirty("bo") != 600 {
		t.Fatalf("after the removal: %d", f.dirty("bo"))
	}
	if _, err := f.bans.Lift(ctx, "demo", f.banned("max").ID, "ada", "false alarm"); err != nil {
		t.Fatal(err)
	}
	if f.dirty("") != 0 {
		t.Fatalf("dirty after the ban was lifted: %d", f.dirty(""))
	}
}

// A balance below the ledger is a spend the game server did not report: a flag, no ban,
// and the ledger follows.
func TestBalanceBelowTheLedger(t *testing.T) {
	f := newFixture(t, true)
	f.snap("kai", 500)
	if r := f.snap("kai", 200); r.Status != "short" || f.banned("kai") != nil {
		t.Fatalf("%+v", r)
	}
	if fl := f.flags("kai"); len(fl) != 1 || fl[0].Rule != RuleBalanceShort || fl[0].Certain {
		t.Fatalf("flags: %+v", fl)
	}
	if r := f.snap("kai", 200); r.Status != "ok" {
		t.Fatalf("again: %+v", r)
	}
}

// A player the ledger first hears of with a history: the first balance is the start,
// whatever was reported before it.
func TestFirstBalanceIsTheStart(t *testing.T) {
	f := newFixture(t, true)
	f.ev("lou", 200, "job", "")
	if r := f.snap("lou", 40_200); r.Status != "opened" || f.banned("lou") != nil {
		t.Fatalf("%+v", r)
	}
	if r := f.snap("lou", 40_200); r.Status != "ok" {
		t.Fatalf("%+v", r)
	}
}

func TestAmount(t *testing.T) {
	for v, want := range map[int64]string{0: "0", 999: "999", 1000: "1 000", -1234567: "-1 234 567"} {
		if got := Amount(v); got != want {
			t.Errorf("%d: %q", v, got)
		}
	}
}
