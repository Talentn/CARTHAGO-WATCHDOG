package review

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/replay"
	"carthago/backend/internal/store"
)

type fixture struct {
	t   *testing.T
	st  *store.Memory
	svc *Service
	now time.Time
	ctx context.Context
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, st: store.NewMemory(), now: time.UnixMilli(1_800_000_000_000).UTC(), ctx: context.Background()}
	f.svc = New(f.st, Config{Key: []byte("a key for the tests, 32 bytes!!!"), Now: func() time.Time { return f.now }})
	return f
}

func (f *fixture) on(tenant string) {
	f.t.Helper()
	set := store.DefaultReviewSettings()
	set.Enabled = true
	if err := f.svc.SetSettings(f.ctx, tenant, set); err != nil {
		f.t.Fatal(err)
	}
}

// match records a match of the named players, slot 1 first. Slot 1 shoots slot 2.
func (f *fixture) match(tenant, id string, players ...string) {
	f.t.Helper()
	d := replay.Data{V: 1, Match: id, Map: "secret-map-name", TickRate: 64, StepMs: 250, DurationMs: 4000, Bounds: [4]int32{0, 0, 1000, 1000}}
	var who []store.ReplayPlayer
	for i, p := range players {
		slot := uint32(i + 1)
		d.Players = append(d.Players, replay.Player{Slot: slot, Name: p, Session: "sess-" + p, Team: uint32(i%2 + 1), T: []int32{0, 16}, X: []int32{int32(100 * i), int32(100 * i)}, Y: []int32{100, 120}, Yaw: []int32{0, 90}})
		who = append(who, store.ReplayPlayer{Slot: slot, PlayerHash: p, SessionID: "sess-" + p})
	}
	d.Shots = []replay.Shot{{1500, 1, 2, 1, 1}, {2500, 1, -1, 0, 0}}
	d.Batches = [][3]int64{{1, 4000, f.now.UnixMilli()}}
	data, err := d.Encode()
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.st.PutMatchReplay(f.ctx, &store.MatchReplay{TenantID: tenant, MatchID: id, StartedAt: f.now, UpdatedAt: f.now, DurationMs: 4000, Data: data, Players: who}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) flag(tenant, match, player string) {
	f.t.Helper()
	if err := f.st.PutOracleScore(f.ctx, &store.OracleScore{TenantID: tenant, SessionID: "sess-" + player + "-" + match, PlayerHash: player, MatchID: match, ModelID: "m", Score: 0.93, Band: store.OracleBandReview, UpdatedAt: f.now}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) calibration(tenant, match, suspect, expected string) *store.ReviewCase {
	f.t.Helper()
	c, err := f.svc.AddCalibration(f.ctx, tenant, match, suspect, expected)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func token(l *Link) string { return strings.TrimPrefix(l.Path, "/review/") }

// vote has the reviewer ask for links and give the verdict on each until one is for a
// real case; calibration cases on the way get the right answer. It returns that link.
func (f *fixture) vote(tenant, reviewer, verdict string) *Link {
	f.t.Helper()
	for i := 0; i < 8; i++ {
		l, err := f.svc.Assign(f.ctx, tenant, reviewer)
		if err != nil {
			f.t.Fatalf("assign %s: %v", reviewer, err)
		}
		v := verdict
		if l.Assignment.Calibration {
			v = VerdictInsufficient
		}
		if err := f.svc.Vote(f.ctx, token(l), v); err != nil {
			f.t.Fatalf("vote %s: %v", reviewer, err)
		}
		if !l.Assignment.Calibration {
			return l
		}
	}
	f.t.Fatalf("%s was never handed a real case", reviewer)
	return nil
}

// footprint is everything community review must leave alone.
func (f *fixture) footprint(tenant string) string {
	f.t.Helper()
	bans, err1 := f.st.ListBans(f.ctx, tenant, 1000)
	shadow, err2 := f.st.ListShadowBans(f.ctx, tenant)
	ev, err3 := f.st.ListEvidence(f.ctx, tenant, store.EvidenceFilter{Limit: 1000})
	labels, err4 := f.st.ListSessionLabels(f.ctx, tenant, store.OracleFilter{Limit: 1000})
	scores, err5 := f.st.ListOracleScores(f.ctx, tenant, store.OracleFilter{Limit: 1000})
	reports, err6 := f.st.ListPlayerReports(f.ctx, tenant, store.ReportFilter{Limit: 1000})
	if err := errors.Join(err1, err2, err3, err4, err5, err6); err != nil {
		f.t.Fatal(err)
	}
	return fmt.Sprintf("bans %+v\nshadow %+v\nevidence %+v\nlabels %+v\nscores %+v\nreports %+v", bans, shadow, ev, labels, scores, reports)
}

func TestOffByDefault(t *testing.T) {
	f := newFixture(t)
	f.match("demo", "m1", "sus", "p2", "p3")
	f.flag("demo", "m1", "sus")
	if n, err := f.svc.Sweep(f.ctx, "demo"); err != nil || n != 0 {
		t.Fatalf("sweep with the feature off: %d %v", n, err)
	}
	if _, err := f.svc.Assign(f.ctx, "demo", "rev1"); !errors.Is(err, ErrOff) {
		t.Fatalf("assign with the feature off: %v", err)
	}
	if cases, _ := f.svc.Cases(f.ctx, "demo", store.ReviewCaseFilter{}); len(cases) != 0 {
		t.Fatalf("cases with the feature off: %+v", cases)
	}
	// A link handed out while the feature was on stops opening when it is turned off.
	f.on("demo")
	l, err := f.svc.Assign(f.ctx, "demo", "rev1")
	if err != nil {
		t.Fatal(err)
	}
	set, _ := f.svc.Settings(f.ctx, "demo")
	set.Enabled = false
	if err := f.svc.SetSettings(f.ctx, "demo", set); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Open(f.ctx, token(l)); !errors.Is(err, ErrBadLink) {
		t.Fatalf("a link of a studio that turned the feature off: %v", err)
	}
}

func TestSweepSources(t *testing.T) {
	f := newFixture(t)
	f.on("demo")
	f.match("demo", "m-oracle", "sus1", "p2", "p3")
	f.match("demo", "m-finding", "sus2", "p2", "p3")
	f.match("demo", "m-reports", "sus3", "p2", "p3")
	f.match("demo", "m-light", "sus4", "p2", "p3")
	f.match("demo", "m-quiet", "sus5", "p2", "p3")
	f.match("rival", "m-oracle", "sus1", "p2")

	f.flag("demo", "m-oracle", "sus1")
	f.flag("demo", "m-not-recorded", "sus1") // no recording: nothing a reviewer could watch
	f.flag("demo", "m-quiet", "stranger")    // not a player of that match
	if err := f.st.PutOracleScore(f.ctx, &store.OracleScore{TenantID: "demo", SessionID: "s-watch", PlayerHash: "sus5", MatchID: "m-quiet", Band: store.OracleBandWatch, UpdatedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.AddEvidence(f.ctx, []store.Evidence{
		{TenantID: "demo", PlayerHash: "sus2", SessionID: "s2", MatchID: "m-finding", Source: store.SourceGameplay, Rule: "aim.snap", Severity: 3, ObservedAt: f.now},
		{TenantID: "demo", PlayerHash: "sus5", SessionID: "s5", MatchID: "m-quiet", Source: store.SourceGameplay, Rule: "aim.snap", Severity: 1, ObservedAt: f.now},
		{TenantID: "demo", PlayerHash: "sus5", SessionID: "s5", MatchID: "m-quiet", Source: store.SourceClient, Rule: "module.unsigned", Severity: 4, ObservedAt: f.now},
		{TenantID: "demo", PlayerHash: "sus5", SessionID: "s5", MatchID: "m-quiet", Source: store.SourceGameplay, Rule: "aim.snap", Severity: 4, Bot: true, ObservedAt: f.now},
	}); err != nil {
		t.Fatal(err)
	}
	report := func(reporter, reported, match string) {
		t.Helper()
		if _, err := f.st.AddPlayerReport(f.ctx, &store.PlayerReport{TenantID: "demo", Reporter: reporter, Reported: reported, MatchID: match, MatchMs: -1, Reason: "cheating", State: store.ReportOpen, CreatedAt: f.now}); err != nil {
			t.Fatal(err)
		}
	}
	// Two new reporters weigh 0.5 each: together they reach the default threshold of 1.
	report("p2", "sus3", "m-reports")
	report("p3", "sus3", "m-reports")
	report("p2", "sus4", "m-light") // one report is not enough

	if n, err := f.svc.Sweep(f.ctx, "demo"); err != nil || n != 3 {
		t.Fatalf("sweep: %d cases, %v", n, err)
	}
	if n, err := f.svc.Sweep(f.ctx, "demo"); err != nil || n != 0 {
		t.Fatalf("a second sweep: %d cases, %v", n, err)
	}
	cases, err := f.svc.Cases(f.ctx, "demo", store.ReviewCaseFilter{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range cases {
		got[c.MatchID+"/"+c.Suspect] = c.Source
	}
	want := map[string]string{"m-oracle/sus1": store.ReviewSourceOracle, "m-finding/sus2": store.ReviewSourceFinding, "m-reports/sus3": store.ReviewSourceReports}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("cases %v, want %v", got, want)
	}
	// The rival studio has the feature off and the same match id: nothing of it is a case.
	if cases, _ := f.svc.Cases(f.ctx, "rival", store.ReviewCaseFilter{}); len(cases) != 0 {
		t.Fatalf("the other studio's cases: %+v", cases)
	}
}

func TestAssignmentRules(t *testing.T) {
	f := newFixture(t)
	f.on("demo")
	f.match("demo", "m1", "sus", "p2", "p3")
	f.match("demo", "m2", "sus", "p4", "p5")
	f.flag("demo", "m1", "sus")
	if err := f.st.AddEvidence(f.ctx, []store.Evidence{{TenantID: "demo", PlayerHash: "sus", SessionID: "s", MatchID: "m2", Source: store.SourceGameplay, Rule: "aim.snap", Severity: 3, ObservedAt: f.now}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.AddPlayerReport(f.ctx, &store.PlayerReport{TenantID: "demo", Reporter: "reporter", Reported: "sus", MatchID: "m9", MatchMs: -1, Reason: "cheating", State: store.ReportOpen, CreatedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	for who, why := range map[string]string{"sus": "the suspect", "p2": "a player of m1 and", "p4": "a player of m2 and", "reporter": "a player who reported the suspect"} {
		_, err := f.svc.Assign(f.ctx, "demo", who)
		if who == "p2" || who == "p4" {
			// They played in one of the two matches; the other match is the same suspect's
			// and they did not play in it, so that one they may get.
			if err != nil {
				t.Fatalf("%s: %v", who, err)
			}
			continue
		}
		if !errors.Is(err, ErrNothing) {
			t.Fatalf("%s was handed a case: %v", why, err)
		}
	}
	p2, _ := f.svc.Assign(f.ctx, "demo", "p2")
	if c, _ := f.st.GetReviewCase(f.ctx, "demo", p2.Assignment.CaseID); c.MatchID != "m2" {
		t.Fatalf("a player of m1 was handed %s", c.MatchID)
	}
	for _, bad := range []string{"", "two words", strings.Repeat("x", 129), "line\nbreak"} {
		var inv *InvalidError
		if _, err := f.svc.Assign(f.ctx, "demo", bad); !errors.As(err, &inv) {
			t.Fatalf("player %q: %v", bad, err)
		}
	}

	// The same link again while the verdict is missing, and never the same suspect twice.
	first, err := f.svc.Assign(f.ctx, "demo", "rev1")
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Minute)
	again, err := f.svc.Assign(f.ctx, "demo", "rev1")
	if err != nil || again.Assignment.ID != first.Assignment.ID || !again.ExpiresAt.After(first.ExpiresAt) {
		t.Fatalf("asking again: %+v %v", again, err)
	}
	if err := f.svc.Vote(f.ctx, token(again), VerdictAim); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Assign(f.ctx, "demo", "rev1"); !errors.Is(err, ErrNothing) {
		t.Fatalf("the same suspect a second time: %v", err)
	}
	// The game server names the player and nothing else: there is no way to ask for a case.
	if l, _ := f.svc.Assign(f.ctx, "demo", "rev2"); l.Assignment.Reviewer != "rev2" || l.Assignment.Suspect != "sus" {
		t.Fatalf("rev2's assignment: %+v", l.Assignment)
	}
}

func TestRateLimit(t *testing.T) {
	f := newFixture(t)
	f.svc = New(f.st, Config{Key: []byte("k"), PerHour: 2, PerDay: 3, Now: func() time.Time { return f.now }})
	f.on("demo")
	for i := 1; i <= 6; i++ {
		m, s := fmt.Sprintf("m%d", i), fmt.Sprintf("sus%d", i)
		f.match("demo", m, s, "p2")
		f.flag("demo", m, s)
	}
	take := func() error {
		l, err := f.svc.Assign(f.ctx, "demo", "rev1")
		if err != nil {
			return err
		}
		return f.svc.Vote(f.ctx, token(l), VerdictInsufficient)
	}
	for i := 0; i < 2; i++ {
		if err := take(); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(time.Minute)
	}
	var rate *RateError
	if err := take(); !errors.As(err, &rate) || rate.RetryAfter <= 0 || rate.RetryAfter > time.Hour {
		t.Fatalf("a third case within the hour: %v", err)
	}
	f.now = f.now.Add(time.Hour)
	if err := take(); err != nil {
		t.Fatalf("after the hour: %v", err)
	}
	if err := take(); !errors.As(err, &rate) || rate.RetryAfter < 20*time.Hour {
		t.Fatalf("a fourth case within the day: %v", err)
	}
	f.now = f.now.Add(24 * time.Hour)
	if err := take(); err != nil {
		t.Fatalf("the next day: %v", err)
	}
}

func TestQuorumDecisionAndStanding(t *testing.T) {
	f := newFixture(t)
	f.on("demo")
	f.match("demo", "m1", "sus", "p2", "p3")
	f.match("demo", "m-cal", "fair", "p2", "p3")
	f.flag("demo", "m1", "sus")
	f.calibration("demo", "m-cal", "fair", ClassInsufficient)
	before := f.footprint("demo")

	// Every reviewer's first case is the calibration case, answered right: weight 2/3 each.
	verdicts := []string{VerdictAim, VerdictAim, VerdictWalls, VerdictAim, VerdictInsufficient}
	var caseID int64
	for i, v := range verdicts {
		l := f.vote("demo", fmt.Sprintf("rev%d", i+1), v)
		caseID = l.Assignment.CaseID
		c, _ := f.st.GetReviewCase(f.ctx, "demo", caseID)
		if open := i < len(verdicts)-1; open != (c.State == store.ReviewOpen) {
			t.Fatalf("after %d verdicts the case is %s", i+1, c.State)
		}
	}
	c, _ := f.st.GetReviewCase(f.ctx, "demo", caseID)
	if c.State != store.ReviewDecided || c.Verdict != ClassCheating || c.Kind != "aim" || c.Agreement < 0.79 || c.Agreement > 0.81 || c.Decision != "" {
		t.Fatalf("the closed case: %+v", c)
	}
	// A sixth reviewer is not handed a closed case.
	if l, err := f.svc.Assign(f.ctx, "demo", "rev6"); err != nil || !l.Assignment.Calibration {
		t.Fatalf("rev6's first: %+v %v", l, err)
	} else if err := f.svc.Vote(f.ctx, token(l), VerdictInsufficient); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Assign(f.ctx, "demo", "rev6"); !errors.Is(err, ErrNothing) {
		t.Fatalf("a closed case was handed out: %v", err)
	}
	// Nothing is scored on the real case until the studio decides.
	st, _ := f.svc.Standing(f.ctx, "demo", "rev1")
	if st.Verdicts != 2 || st.Scored != 1 || st.Correct != 1 || st.Calibration != 1 || st.Level != 1 || len(st.Badges) != 1 {
		t.Fatalf("rev1 before the decision: %+v", st)
	}

	var inv *InvalidError
	if _, err := f.svc.Decide(f.ctx, "demo", caseID, "banned", "ada"); !errors.As(err, &inv) {
		t.Fatalf("a decision that is not one: %v", err)
	}
	if _, err := f.svc.Decide(f.ctx, "rival", caseID, store.ReviewConfirmed, "eve"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another studio decides the case: %v", err)
	}
	if _, err := f.svc.Decide(f.ctx, "demo", caseID, store.ReviewConfirmed, "ada"); err != nil {
		t.Fatal(err)
	}
	c, _ = f.st.GetReviewCase(f.ctx, "demo", caseID)
	if c.Decision != store.ReviewConfirmed || c.DecidedBy != "ada" || !c.DecidedAt.Equal(f.now) {
		t.Fatalf("the decided case: %+v", c)
	}
	for who, want := range map[string]int{"rev1": 2, "rev3": 2, "rev5": 1} {
		st, _ := f.svc.Standing(f.ctx, "demo", who)
		if st.Scored != 2 || st.Correct != want {
			t.Fatalf("%s after the decision: %+v", who, st)
		}
	}
	if st, _ := f.svc.Standing(f.ctx, "demo", "rev5"); st.Weight != 0.5 || !st.Eligible {
		t.Fatalf("rev5's weight: %+v", st)
	}

	// The whole of it changed nothing a ban, a kick, the shadow pool or the Oracle reads.
	if after := f.footprint("demo"); after != before {
		t.Fatalf("community review wrote outside its own tables:\nbefore\n%s\nafter\n%s", before, after)
	}

	// Badges are reported until the game server acknowledges them.
	fresh, err := f.svc.NewBadges(f.ctx, "demo")
	if err != nil || len(fresh) != 6 {
		t.Fatalf("new badges: %+v %v", fresh, err)
	}
	if n, err := f.svc.AckBadges(f.ctx, "demo", "rev1", []string{"first_correct_verdict"}); err != nil || n != 1 {
		t.Fatalf("ack: %d %v", n, err)
	}
	if fresh, _ = f.svc.NewBadges(f.ctx, "demo"); len(fresh) != 5 {
		t.Fatalf("new badges after the ack: %+v", fresh)
	}
	if fresh, _ = f.svc.NewBadges(f.ctx, "rival"); len(fresh) != 0 {
		t.Fatalf("another studio's new badges: %+v", fresh)
	}
}

func TestUndecidedAndDismissed(t *testing.T) {
	f := newFixture(t)
	f.on("demo")
	f.match("demo", "m1", "sus", "p2", "p3")
	f.flag("demo", "m1", "sus")
	var caseID int64
	for i, v := range []string{VerdictAim, VerdictAim, VerdictAim, VerdictToxic, VerdictInsufficient} {
		caseID = f.vote("demo", fmt.Sprintf("rev%d", i+1), v).Assignment.CaseID
	}
	c, _ := f.st.GetReviewCase(f.ctx, "demo", caseID)
	if c.State != store.ReviewUndecided || c.Verdict != "" || c.Agreement < 0.59 || c.Agreement > 0.61 {
		t.Fatalf("three of five: %+v", c)
	}
	var inv *InvalidError
	if _, err := f.svc.Decide(f.ctx, "demo", caseID, store.ReviewConfirmed, "ada"); !errors.As(err, &inv) {
		t.Fatalf("an undecided case was confirmed: %v", err)
	}

	// A dismissed case: those who gave its answer were wrong, "not enough evidence" was right.
	f.match("demo", "m2", "sus2", "p2", "p3")
	f.flag("demo", "m2", "sus2")
	for i, v := range []string{VerdictWalls, VerdictWalls, VerdictWalls, VerdictWalls, VerdictInsufficient} {
		caseID = f.vote("demo", fmt.Sprintf("rev%d", i+1), v).Assignment.CaseID
	}
	if _, err := f.svc.Decide(f.ctx, "demo", caseID, store.ReviewDismissed, "ada"); err != nil {
		t.Fatal(err)
	}
	for who, want := range map[string][2]int{"rev1": {1, 0}, "rev5": {1, 1}} {
		st, _ := f.svc.Standing(f.ctx, "demo", who)
		if st.Scored != want[0] || st.Correct != want[1] {
			t.Fatalf("%s after the dismissal: %+v", who, st)
		}
	}
}

func TestWeightDecidesACase(t *testing.T) {
	// Three verdicts of weight 0.2 against two of weight 0.8: the two carry the case.
	rows := []store.ReviewAssignment{
		{Verdict: VerdictInsufficient, Weight: 0.2}, {Verdict: VerdictInsufficient, Weight: 0.2}, {Verdict: VerdictInsufficient, Weight: 0.2},
		{Verdict: VerdictWalls, Weight: 0.8}, {Verdict: VerdictAim, Weight: 0.8}, {Weight: 0.9},
	}
	tally := TallyOf(rows)
	if tally.Votes != 5 || tally.Lead != ClassCheating || tally.Share < 0.72 || tally.Share > 0.73 || tally.Kind != "aim" || tally.Count[VerdictInsufficient] != 3 {
		t.Fatalf("tally: %+v", tally)
	}
	if empty := TallyOf(nil); empty.Lead != "" || empty.Share != 0 {
		t.Fatalf("empty tally: %+v", empty)
	}
}

func TestCalibrationCatchesACarelessReviewer(t *testing.T) {
	f := newFixture(t)
	f.on("demo")
	f.match("demo", "m1", "sus", "p2", "p3")
	f.flag("demo", "m1", "sus")
	for i := 1; i <= 4; i++ {
		m, s := fmt.Sprintf("cal%d", i), fmt.Sprintf("fair%d", i)
		f.match("demo", m, s, "p2", "p3")
		f.calibration("demo", m, s, ClassInsufficient)
	}
	var inv *InvalidError
	if _, err := f.svc.AddCalibration(f.ctx, "demo", "cal1", "fair1", ClassInsufficient); !errors.As(err, &inv) {
		t.Fatalf("the same calibration case twice: %v", err)
	}
	if _, err := f.svc.AddCalibration(f.ctx, "demo", "cal1", "nobody", ClassCheating); !errors.As(err, &inv) {
		t.Fatalf("a calibration case without the player: %v", err)
	}
	if _, err := f.svc.AddCalibration(f.ctx, "demo", "cal1", "p2", "guilty"); !errors.As(err, &inv) {
		t.Fatalf("a calibration case with an unknown answer: %v", err)
	}

	// The careless reviewer calls everyone a cheater. Wrong once, the weight is below 0.5
	// and every case from then on is a calibration case; wrong three times, no more cases.
	weights := []float64{1.0 / 3, 0.25, 0.2}
	for i, want := range weights {
		l, err := f.svc.Assign(f.ctx, "demo", "careless")
		if err != nil || !l.Assignment.Calibration {
			t.Fatalf("case %d of the careless reviewer: %+v %v", i+1, l, err)
		}
		if err := f.svc.Vote(f.ctx, token(l), VerdictAim); err != nil {
			t.Fatal(err)
		}
		st, _ := f.svc.Standing(f.ctx, "demo", "careless")
		if st.Weight < want-0.001 || st.Weight > want+0.001 || st.Correct != 0 || len(st.Badges) != 0 {
			t.Fatalf("after %d wrong: %+v", i+1, st)
		}
		if eligible := i < 2; st.Eligible != eligible {
			t.Fatalf("after %d wrong, eligible %v", i+1, st.Eligible)
		}
	}
	if _, err := f.svc.Assign(f.ctx, "demo", "careless"); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("a fourth case for the careless reviewer: %v", err)
	}
	// The real case never saw a verdict of theirs, and calibration cases stay open.
	cases, _ := f.svc.Cases(f.ctx, "demo", store.ReviewCaseFilter{})
	for _, c := range cases {
		if c.State != store.ReviewOpen || (!c.Calibration && c.Tally.Votes != 0) {
			t.Fatalf("case %+v", c)
		}
	}
	// A careful reviewer gets a calibration case first and then the real one.
	if l := f.vote("demo", "careful", VerdictAim); l.Assignment.Calibration {
		t.Fatal("no real case for the careful reviewer")
	}
	if st, _ := f.svc.Standing(f.ctx, "demo", "careful"); st.Calibration != 1 || st.CalibrationCorrect != 1 || st.Weight < 0.66 {
		t.Fatalf("the careful reviewer: %+v", st)
	}
}

func TestLinks(t *testing.T) {
	f := newFixture(t)
	f.on("demo")
	f.on("rival")
	f.match("demo", "m1", "sus", "p2", "p3")
	f.flag("demo", "m1", "sus")
	l, err := f.svc.Assign(f.ctx, "demo", "rev1")
	if err != nil {
		t.Fatal(err)
	}
	tok := token(l)
	if sess, err := f.svc.Open(f.ctx, tok); err != nil || sess.Assignment.Reviewer != "rev1" || sess.Case.MatchID != "m1" {
		t.Fatalf("open: %+v %v", sess, err)
	}
	if l.ExpiresAt.Sub(f.now) != DefaultLinkTTL {
		t.Fatalf("link lifetime %s", l.ExpiresAt.Sub(f.now))
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 5 {
		t.Fatalf("token %q", tok)
	}
	swap := func(i int, v string) string {
		p := append([]string(nil), parts...)
		p[i] = v
		return strings.Join(p, ".")
	}
	other := New(f.st, Config{Key: []byte("another gateway's key"), Now: func() time.Time { return f.now }})
	forged := token(other.link(&l.Assignment))
	bad := map[string]string{
		"empty":                      "",
		"garbage":                    "not-a-token",
		"another studio":             swap(1, b64.EncodeToString([]byte("rival"))),
		"another assignment":         swap(2, "2"),
		"a later expiry":             swap(3, "zzzzzzzzz"),
		"a cut signature":            swap(4, parts[4][:len(parts[4])-2]),
		"another version":            swap(0, "v2"),
		"signed with another key":    forged,
		"an extra part":              tok + ".x",
		"an assignment that is gone": token(f.svc.link(&store.ReviewAssignment{TenantID: "demo", ID: 999, ExpiresAt: f.now.Add(time.Minute)})),
	}
	for name, tk := range bad {
		if _, err := f.svc.Open(f.ctx, tk); !errors.Is(err, ErrBadLink) {
			t.Errorf("%s: %v", name, err)
		}
		if err := f.svc.Vote(f.ctx, tk, VerdictAim); !errors.Is(err, ErrBadLink) {
			t.Errorf("vote with %s: %v", name, err)
		}
	}
	var inv *InvalidError
	if err := f.svc.Vote(f.ctx, tok, "guilty"); !errors.As(err, &inv) {
		t.Fatalf("a verdict that is not one: %v", err)
	}
	if err := f.svc.Vote(f.ctx, tok, VerdictToxic); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Vote(f.ctx, tok, VerdictAim); !errors.Is(err, ErrVoted) {
		t.Fatalf("a second verdict: %v", err)
	}
	if a, _ := f.st.GetReviewAssignment(f.ctx, "demo", l.Assignment.ID); a.Verdict != VerdictToxic {
		t.Fatalf("the verdict changed: %+v", a)
	}

	// A link stops working when it expires.
	l2, _ := f.svc.Assign(f.ctx, "demo", "rev2")
	f.now = f.now.Add(DefaultLinkTTL + time.Second)
	if _, err := f.svc.Open(f.ctx, token(l2)); !errors.Is(err, ErrBadLink) {
		t.Fatalf("an expired link: %v", err)
	}
	if err := f.svc.Vote(f.ctx, token(l2), VerdictAim); !errors.Is(err, ErrBadLink) {
		t.Fatalf("a verdict on an expired link: %v", err)
	}
	// A service without a key hands out no links.
	if _, err := New(f.st, Config{}).Assign(f.ctx, "demo", "rev3"); err == nil {
		t.Fatal("a link without a key")
	}
}

func gunzip(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestRecordingHidesWhoPlayed(t *testing.T) {
	f := newFixture(t)
	f.on("demo")
	// The suspect is slot 3 of the game; slot 1 shoots slot 2.
	f.match("demo", "match-id-7781", "acct-alpha", "acct-bravo", "acct-suspect", "acct-delta")
	f.flag("demo", "match-id-7781", "acct-suspect")
	l, err := f.svc.Assign(f.ctx, "demo", "rev1")
	if err != nil {
		t.Fatal(err)
	}
	sess, _ := f.svc.Open(f.ctx, token(l))
	data, err := f.svc.Recording(f.ctx, sess.Case)
	if err != nil {
		t.Fatal(err)
	}
	raw := gunzip(t, data)
	for _, secret := range []string{"acct-", "sess-", "match-id-7781", "secret-map-name", "session", fmt.Sprint(f.now.UnixMilli())} {
		if strings.Contains(raw, secret) {
			t.Errorf("the reviewer's recording holds %q: %s", secret, raw)
		}
	}
	d, err := replay.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Players) != 4 || d.Match != "" || d.Map != "" || len(d.Batches) != 0 {
		t.Fatalf("recording: %+v", d)
	}
	for i, p := range d.Players {
		want := fmt.Sprintf("Player %d", i+1)
		if i == 0 {
			want = "Suspect"
		}
		if p.Slot != uint32(i+1) || p.Name != want || p.Session != "" {
			t.Fatalf("player %d: %+v", i, p)
		}
	}
	// The suspect stood at x=200 in the game's slot 3 and is slot 1 here, on team 1.
	if s := d.Players[0]; s.X[0] != 200 || s.Team != 1 {
		t.Fatalf("the suspect: %+v", s)
	}
	// The shots still join the same two players: the one at x=0 shot the one at x=100.
	at := map[int32]int32{}
	for _, p := range d.Players {
		at[int32(p.Slot)] = p.X[0]
	}
	if len(d.Shots) != 2 || at[d.Shots[0][1]] != 0 || at[d.Shots[0][2]] != 100 || d.Shots[1][2] != -1 {
		t.Fatalf("shots: %+v", d.Shots)
	}
}

func TestReviewPage(t *testing.T) {
	f := newFixture(t)
	f.on("demo")
	f.match("demo", "match-id-7781", "acct-suspect", "acct-bravo", "acct-delta")
	f.flag("demo", "match-id-7781", "acct-suspect")
	if err := f.st.AddEvidence(f.ctx, []store.Evidence{{TenantID: "demo", PlayerHash: "acct-suspect", SessionID: "sess-acct-suspect", MatchID: "match-id-7781", Source: store.SourceGameplay, Rule: "aim.snap", Severity: 4, Summary: "FINDING-TEXT", ObservedAt: f.now}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.AddPlayerReport(f.ctx, &store.PlayerReport{TenantID: "demo", Reporter: "acct-bravo", Reported: "acct-suspect", MatchID: "match-id-7781", MatchMs: -1, Reason: "cheating", Note: "REPORT-TEXT", State: store.ReportOpen, CreatedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	h := f.svc.Handler()
	do := func(method, path string, form url.Values, hdr ...string) *httptest.ResponseRecorder {
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		r := httptest.NewRequest(method, path, body)
		if form != nil {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	l, err := f.svc.Assign(f.ctx, "demo", "rev1")
	if err != nil {
		t.Fatal(err)
	}

	w := do("GET", l.Path, nil)
	page := w.Body.String()
	if w.Code != 200 || !strings.Contains(page, "Suspect") || !strings.Contains(page, `value="cheating_walls"`) || !strings.Contains(page, `value="insufficient"`) {
		t.Fatalf("page: %d %s", w.Code, page)
	}
	for _, secret := range []string{"acct-", "sess-", "match-id-7781", "secret-map-name", "FINDING-TEXT", "REPORT-TEXT", "aim.snap", "0.93", "93%", "rev1", "demo", "oracle", "Oracle"} {
		if strings.Contains(page, secret) {
			t.Errorf("the review page shows %q", secret)
		}
	}
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe") || strings.Contains(page, "<script>") || strings.Contains(page, "style=") || strings.Contains(page, "onclick") {
		t.Errorf("inline script or style: CSP %q", csp)
	}
	if w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
		t.Errorf("headers: %v", w.Header())
	}

	if w := do("GET", l.Path+"/replay.json", nil); w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" || strings.Contains(gunzip(t, w.Body.Bytes()), "acct-") {
		t.Fatalf("recording: %d", w.Code)
	}
	if w := do("GET", l.Path+"/outline.json", nil); w.Code != 404 {
		t.Fatalf("outline of a map without one: %d", w.Code)
	}
	for _, name := range []string{"/review/static/review.css", "/review/static/replay.js"} {
		if w := do("GET", name, nil); w.Code != 200 || w.Body.Len() == 0 {
			t.Fatalf("%s: %d", name, w.Code)
		}
	}

	// Nothing to list and nothing to guess: every other address is the same 404.
	want := do("GET", "/review/not-a-token", nil)
	if want.Code != 404 {
		t.Fatalf("garbage link: %d", want.Code)
	}
	tampered := l.Path[:len(l.Path)-3] + "AAA"
	for _, path := range []string{tampered, "/review/1", "/review/cases", "/review/v1.ZGVtbw.1.zzzz.AAAA"} {
		if w := do("GET", path, nil); w.Code != 404 || w.Body.String() != want.Body.String() {
			t.Errorf("%s: %d, a different answer than for a garbage link", path, w.Code)
		}
	}
	for _, path := range []string{"/review/", "/review", "/review/static/", "/review/cases/1", tampered + "/replay.json", "/review/1/replay.json", "/matches", "/"} {
		if w := do("GET", path, nil); w.Code != 404 && w.Code != 301 {
			t.Errorf("%s: %d", path, w.Code)
		} else if strings.Contains(w.Body.String(), "match-id") {
			t.Errorf("%s names a match", path)
		}
	}

	// The verdict: refused from another site, refused when it is not one, then taken once.
	if w := do("POST", l.Path+"/verdict", url.Values{"verdict": {VerdictAim}}, "Sec-Fetch-Site", "cross-site"); w.Code != 403 {
		t.Fatalf("a cross-site verdict: %d", w.Code)
	}
	if w := do("POST", l.Path+"/verdict", url.Values{"verdict": {"guilty"}}, "Sec-Fetch-Site", "same-origin"); w.Code != 400 {
		t.Fatalf("an unknown verdict: %d", w.Code)
	}
	if w := do("POST", tampered+"/verdict", url.Values{"verdict": {VerdictAim}}); w.Code != 404 {
		t.Fatalf("a verdict on a tampered link: %d", w.Code)
	}
	if a, _ := f.st.GetReviewAssignment(f.ctx, "demo", l.Assignment.ID); a.Verdict != "" {
		t.Fatalf("a refused verdict was recorded: %+v", a)
	}
	if w := do("POST", l.Path+"/verdict", url.Values{"verdict": {VerdictWalls}}, "Sec-Fetch-Site", "same-origin"); w.Code != 200 || !strings.Contains(w.Body.String(), "Your verdict is in") {
		t.Fatalf("verdict: %d %s", w.Code, w.Body.String())
	}
	if w := do("POST", l.Path+"/verdict", url.Values{"verdict": {VerdictInsufficient}}, "Sec-Fetch-Site", "same-origin"); w.Code != http.StatusConflict {
		t.Fatalf("a second verdict: %d", w.Code)
	}
	// A used link shows no replay any more.
	if w := do("GET", l.Path, nil); w.Code != 200 || strings.Contains(w.Body.String(), "replay.js") {
		t.Fatalf("the page of a used link: %d", w.Code)
	}
	if w := do("GET", l.Path+"/replay.json", nil); w.Code != 404 {
		t.Fatalf("the recording of a used link: %d", w.Code)
	}
}
