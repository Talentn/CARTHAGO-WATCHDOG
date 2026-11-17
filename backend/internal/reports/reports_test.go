package reports

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

func u32(v uint32) *uint32 { return &v }
func i64(v int64) *int64   { return &v }

func good() Submission {
	return Submission{Reporter: "amira", Reported: "sami", Match: "m1", Tick: u32(6400), TickRate: 64, Reason: "cheating", Note: "  aimed at me\nthrough the wall "}
}

func TestSubmitValidatesStoresAndDeduplicates(t *testing.T) {
	st := store.NewMemory()
	now := time.UnixMilli(1_800_000_000_000).UTC()
	svc := New(st, func() time.Time { return now })
	ctx := context.Background()

	out, err := svc.Submit(ctx, "t1", good())
	if err != nil || out.Status != StatusAccepted || out.ID == 0 {
		t.Fatalf("a good report: %+v %v", out, err)
	}
	got, err := st.GetPlayerReport(ctx, "t1", out.ID)
	if err != nil || got.Reporter != "amira" || got.Reported != "sami" || got.MatchID != "m1" || got.MatchMs != 100_000 || got.Reason != "cheating" ||
		got.Note != "aimed at me through the wall" || got.State != store.ReportOpen || !got.CreatedAt.Equal(now) {
		t.Fatalf("stored: %+v %v", got, err)
	}
	// The same reporter, player and match again: the first stands, whatever else differs.
	again := good()
	again.Reason, again.Note, again.Tick, again.TickRate, again.TimeMs = "griefing", "another note", nil, 0, i64(5)
	if dup, err := svc.Submit(ctx, "t1", again); err != nil || dup.Status != StatusDuplicate || dup.ID != out.ID {
		t.Fatalf("a repeat: %+v %v", dup, err)
	}
	if got, _ := st.GetPlayerReport(ctx, "t1", out.ID); got.Reason != "cheating" || got.Note != "aimed at me through the wall" {
		t.Fatalf("a repeat changed the report: %+v", got)
	}
	// Another match, another player and another studio are reports of their own.
	for i, other := range []struct {
		tenant string
		change func(*Submission)
	}{
		{"t1", func(s *Submission) { s.Match = "m2" }},
		{"t1", func(s *Submission) { s.Reported = "walid" }},
		{"t2", func(s *Submission) {}},
	} {
		in := good()
		other.change(&in)
		if o, err := svc.Submit(ctx, other.tenant, in); err != nil || o.Status != StatusAccepted {
			t.Fatalf("report %d of its own: %+v %v", i, o, err)
		}
	}
	if n, _ := st.CountPlayerReports(ctx, "t1", store.ReportFilter{}); n != 3 {
		t.Fatalf("t1 has %d reports, want 3", n)
	}
	if _, err := st.GetPlayerReport(ctx, "t2", out.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another studio reads the report: %v", err)
	}

	// The moment: milliseconds, or none.
	in := good()
	in.Match, in.Tick, in.TickRate, in.TimeMs = "m3", nil, 0, i64(61_500)
	o, _ := svc.Submit(ctx, "t1", in)
	if got, _ := st.GetPlayerReport(ctx, "t1", o.ID); got.MatchMs != 61_500 {
		t.Fatalf("time_ms: %+v", got)
	}
	in.Match, in.TimeMs, in.Note = "m4", nil, ""
	o, _ = svc.Submit(ctx, "t1", in)
	if got, _ := st.GetPlayerReport(ctx, "t1", o.ID); got.MatchMs != -1 || got.Note != "" {
		t.Fatalf("no moment, no note: %+v", got)
	}

	before, _ := st.CountPlayerReports(ctx, "t1", store.ReportFilter{})
	for name, change := range map[string]func(*Submission){
		"no reporter":        func(s *Submission) { s.Reporter = "" },
		"no reported":        func(s *Submission) { s.Reported = "" },
		"self report":        func(s *Submission) { s.Reported = s.Reporter },
		"no match":           func(s *Submission) { s.Match = "" },
		"long reporter":      func(s *Submission) { s.Reporter = strings.Repeat("a", MaxID+1) },
		"padded reported":    func(s *Submission) { s.Reported = " sami" },
		"control in match":   func(s *Submission) { s.Match = "m\x00" },
		"no reason":          func(s *Submission) { s.Reason = "" },
		"made-up reason":     func(s *Submission) { s.Reason = "Cheating" },
		"tick without rate":  func(s *Submission) { s.TickRate = 0 },
		"rate without tick":  func(s *Submission) { s.Tick = nil },
		"tick and time":      func(s *Submission) { s.TimeMs = i64(5) },
		"absurd rate":        func(s *Submission) { s.TickRate = 100_000 },
		"negative time":      func(s *Submission) { s.Tick, s.TickRate, s.TimeMs = nil, 0, i64(-5) },
		"time past a day":    func(s *Submission) { s.Tick, s.TickRate, s.TimeMs = nil, 0, i64(MaxMatchMs+1) },
		"long note":          func(s *Submission) { s.Note = strings.Repeat("é", MaxNote+1) },
		"note not UTF-8":     func(s *Submission) { s.Note = "bad \xff" },
		"control in note":    func(s *Submission) { s.Note = "bell \x07" },
		"reporter not UTF-8": func(s *Submission) { s.Reporter = "a\xff" },
	} {
		in := good()
		in.Match = "fresh-" + name
		change(&in)
		var bad *InvalidError
		if _, err := svc.Submit(ctx, "t1", in); !errors.As(err, &bad) || bad.Msg == "" {
			t.Errorf("%s: %v, want an InvalidError", name, err)
		}
	}
	if after, _ := st.CountPlayerReports(ctx, "t1", store.ReportFilter{}); after != before {
		t.Fatalf("a refused report was stored: %d then %d", before, after)
	}
	// A note of exactly the cap is taken.
	in = good()
	in.Match, in.Note = "m5", strings.Repeat("é", MaxNote)
	if _, err := svc.Submit(ctx, "t1", in); err != nil {
		t.Fatalf("a note at the cap: %v", err)
	}
}

func TestSubmitLimitsEachReporter(t *testing.T) {
	st := store.NewMemory()
	now := time.UnixMilli(1_800_000_000_000).UTC()
	svc := New(st, func() time.Time { return now })
	ctx := context.Background()
	send := func(reporter, match string) error {
		_, err := svc.Submit(ctx, "t1", Submission{Reporter: reporter, Reported: "target-" + match, Match: match, Reason: "other"})
		return err
	}
	for i := range MaxPerHour {
		if err := send("spammer", fmt.Sprint("m", i)); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
		now = now.Add(time.Minute)
	}
	var rate *RateError
	if err := send("spammer", "one-more"); !errors.As(err, &rate) || rate.RetryAfter <= 53*time.Minute || rate.RetryAfter > 54*time.Minute {
		t.Fatalf("the report past the hourly limit: %v", err)
	}
	// A repeat of an earlier report is answered, not refused, and does not count.
	if o, err := svc.Submit(ctx, "t1", Submission{Reporter: "spammer", Reported: "target-m0", Match: "m0", Reason: "other"}); err != nil || o.Status != StatusDuplicate {
		t.Fatalf("a repeat while limited: %+v %v", o, err)
	}
	// Another reporter, and the same name in another studio, are not held back.
	if err := send("honest", "m0"); err != nil {
		t.Fatalf("another reporter: %v", err)
	}
	if _, err := svc.Submit(ctx, "t2", Submission{Reporter: "spammer", Reported: "x", Match: "m0", Reason: "other"}); err != nil {
		t.Fatalf("another studio: %v", err)
	}
	// An hour later the reporter may report again, up to the daily limit.
	sent := MaxPerHour
	for sent < MaxPerDay {
		now = now.Add(11 * time.Minute)
		if err := send("spammer", fmt.Sprint("later", sent)); err == nil {
			sent++
		} else if !errors.As(err, &rate) {
			t.Fatal(err)
		}
	}
	now = now.Add(2 * time.Hour)
	if err := send("spammer", "past-the-day"); !errors.As(err, &rate) {
		t.Fatalf("the report past the daily limit: %v", err)
	}
	if n, _ := st.CountPlayerReports(ctx, "t1", store.ReportFilter{Reporter: "spammer"}); n != MaxPerDay {
		t.Fatalf("stored %d reports of the spammer, want %d", n, MaxPerDay)
	}
	now = now.Add(24 * time.Hour)
	if err := send("spammer", "next-day"); err != nil {
		t.Fatalf("the next day: %v", err)
	}
}

func TestOldReportsAreDeleted(t *testing.T) {
	st := store.NewMemory()
	now := time.UnixMilli(1_800_000_000_000).UTC()
	svc := New(st, func() time.Time { return now })
	ctx := context.Background()
	if _, err := svc.Submit(ctx, "t1", good()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(Retention + time.Hour)
	in := good()
	in.Match = "much-later"
	if _, err := svc.Submit(ctx, "t1", in); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.ListPlayerReports(ctx, "t1", store.ReportFilter{})
	if len(rows) != 1 || rows[0].MatchID != "much-later" {
		t.Fatalf("after %v: %+v", Retention, rows)
	}
}

func TestWeight(t *testing.T) {
	banned := func(p string) bool { return p == "zied" || p == "wissem" }
	for _, c := range []struct {
		name  string
		rows  []store.PlayerReport
		want  Weight
		value string
	}{
		{"a new reporter", nil, Weight{}, "0.50"},
		{"only open reports", []store.PlayerReport{{Reported: "sami"}, {Reported: "walid", State: store.ReportReviewed}}, Weight{Pending: 2}, "0.50"},
		{"one confirmed", []store.PlayerReport{{Reported: "zied"}, {Reported: "sami"}}, Weight{Confirmed: 1, Pending: 1}, "0.67"},
		{"two confirmed, one dismissed", []store.PlayerReport{{Reported: "zied"}, {Reported: "wissem", State: store.ReportDismissed}, {Reported: "amira", State: store.ReportDismissed}},
			Weight{Confirmed: 2, Rejected: 1}, "0.60"},
		{"all dismissed", []store.PlayerReport{{Reported: "a", State: store.ReportDismissed}, {Reported: "b", State: store.ReportDismissed}, {Reported: "c", State: store.ReportDismissed}},
			Weight{Rejected: 3}, "0.20"},
	} {
		got := WeightOf(c.rows, banned)
		value := fmt.Sprintf("%.2f", got.Value)
		got.Value = 0
		if got != c.want || value != c.value {
			t.Errorf("%s: %+v %s, want %+v %s", c.name, got, value, c.want, c.value)
		}
	}
}
