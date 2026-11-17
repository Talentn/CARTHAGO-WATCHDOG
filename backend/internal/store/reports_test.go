package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReportStores(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000).UTC()
	ctx := context.Background()
	for name, b := range backends(t) {
		st := b.(ReportStore)
		t.Run(name, func(t *testing.T) {
			add := func(tenant, reporter, reported, match string, at time.Time) *PlayerReport {
				t.Helper()
				r := &PlayerReport{TenantID: tenant, Reporter: reporter, Reported: reported, MatchID: match, MatchMs: 61_000, Reason: "cheating", Note: "a note", CreatedAt: at}
				if added, err := st.AddPlayerReport(ctx, r); err != nil || !added || r.ID == 0 {
					t.Fatalf("add: %v %v %+v", added, err, r)
				}
				return r
			}
			first := add("t1", "amira", "sami", "m1", now.Add(-3*time.Hour))
			add("t1", "bilel", "sami", "m1", now.Add(-2*time.Hour))
			third := add("t1", "amira", "walid", "m2", now.Add(-time.Hour))
			add("t1", "amira", "sami", "m0", now.Add(-40*24*time.Hour))
			rival := add("t2", "amira", "sami", "m1", now)

			// One report per reporter, reported player and match.
			again := &PlayerReport{TenantID: "t1", Reporter: "amira", Reported: "sami", MatchID: "m1", MatchMs: 5, Reason: "other", CreatedAt: now}
			if added, err := st.AddPlayerReport(ctx, again); err != nil || added || again.ID != first.ID {
				t.Fatalf("a second report: %v %v id %d, want the first's %d", added, err, again.ID, first.ID)
			}
			got, err := st.GetPlayerReport(ctx, "t1", first.ID)
			if err != nil || got.Reporter != "amira" || got.Reported != "sami" || got.MatchID != "m1" || got.MatchMs != 61_000 || got.Reason != "cheating" || got.Note != "a note" ||
				got.State != ReportOpen || !got.CreatedAt.Equal(now.Add(-3*time.Hour)) || got.DecidedBy != "" || !got.DecidedAt.IsZero() {
				t.Fatalf("read back: %+v %v", got, err)
			}
			if _, err := st.GetPlayerReport(ctx, "t2", first.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("another studio reads the report: %v", err)
			}

			ids := func(f ReportFilter) int {
				t.Helper()
				rows, err := st.ListPlayerReports(ctx, "t1", f)
				n, err2 := st.CountPlayerReports(ctx, "t1", f)
				if err != nil || err2 != nil || (f.Limit == 0 && n != len(rows)) {
					t.Fatalf("list %+v: %d rows, count %d, %v %v", f, len(rows), n, err, err2)
				}
				for i := 1; i < len(rows); i++ {
					if rows[i].CreatedAt.After(rows[i-1].CreatedAt) {
						t.Fatal("not newest first")
					}
				}
				return len(rows)
			}
			for _, c := range []struct {
				f    ReportFilter
				want int
			}{
				{ReportFilter{}, 4}, {ReportFilter{Reported: "sami"}, 3}, {ReportFilter{Reporter: "amira"}, 3}, {ReportFilter{MatchID: "m1"}, 2},
				{ReportFilter{Reported: "sami", Since: now.Add(-30 * 24 * time.Hour)}, 2}, {ReportFilter{State: ReportOpen}, 4}, {ReportFilter{State: ReportDismissed}, 0},
				{ReportFilter{Limit: 2}, 2}, {ReportFilter{Reporter: "amira", Reported: "sami", MatchID: "m1"}, 1},
			} {
				if got := ids(c.f); got != c.want {
					t.Errorf("%+v: %d reports, want %d", c.f, got, c.want)
				}
			}

			since := now.Add(-30 * 24 * time.Hour)
			tally, err := st.TallyPlayerReports(ctx, "t1", since)
			if err != nil || len(tally) != 2 || tally["sami"] != (ReportTally{Reports: 2, Reporters: 2}) || tally["walid"] != (ReportTally{Reports: 1, Reporters: 1}) {
				t.Fatalf("tally: %+v %v", tally, err)
			}

			// A state is set per studio, and a dismissed report leaves the tally.
			if err := st.SetPlayerReportState(ctx, "t2", third.ID, ReportDismissed, "eve", now); !errors.Is(err, ErrNotFound) {
				t.Fatalf("another studio sets the state: %v", err)
			}
			if err := st.SetPlayerReportState(ctx, "t1", third.ID, ReportDismissed, "ada", now); err != nil {
				t.Fatal(err)
			}
			got, _ = st.GetPlayerReport(ctx, "t1", third.ID)
			if got.State != ReportDismissed || got.DecidedBy != "ada" || !got.DecidedAt.Equal(now) {
				t.Fatalf("dismissed: %+v", got)
			}
			if got := ids(ReportFilter{State: ReportDismissed}); got != 1 {
				t.Fatalf("dismissed reports: %d", got)
			}
			if tally, _ := st.TallyPlayerReports(ctx, "t1", since); len(tally) != 1 || tally["sami"].Reports != 2 {
				t.Fatalf("tally after a dismissal: %+v", tally)
			}
			if r, _ := st.GetPlayerReport(ctx, "t2", rival.ID); r.State != ReportOpen {
				t.Fatalf("the other studio's report changed: %+v", r)
			}

			if n, err := st.PrunePlayerReports(ctx, since); err != nil || n != 1 {
				t.Fatalf("prune: %d %v", n, err)
			}
			if got := ids(ReportFilter{}); got != 3 {
				t.Fatalf("after the prune: %d", got)
			}
		})
	}
}
