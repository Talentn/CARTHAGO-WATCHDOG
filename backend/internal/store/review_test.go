package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReviewStores(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000).UTC()
	ctx := context.Background()
	for name, b := range backends(t) {
		st := b.(ReviewStore)
		t.Run(name, func(t *testing.T) {
			// Off, with the defaults, until a studio sets its own.
			set, err := st.ReviewSettings(ctx, "t1")
			if err != nil || set != DefaultReviewSettings() || set.Enabled {
				t.Fatalf("default settings: %+v %v", set, err)
			}
			want := ReviewSettings{Enabled: true, Quorum: 3, Agreement: 0.6, ReportWeight: 2.5}
			if err := st.PutReviewSettings(ctx, "t1", want, now); err != nil {
				t.Fatal(err)
			}
			if set, _ = st.ReviewSettings(ctx, "t1"); set != want {
				t.Fatalf("settings read back: %+v", set)
			}
			if set, _ = st.ReviewSettings(ctx, "t2"); set.Enabled {
				t.Fatal("one studio's switch turned another's on")
			}

			c := &ReviewCase{TenantID: "t1", MatchID: "m1", Suspect: "sus", Source: ReviewSourceOracle, CreatedAt: now}
			if ok, err := st.AddReviewCase(ctx, c); err != nil || !ok || c.ID == 0 || c.State != ReviewOpen {
				t.Fatalf("add case: %+v %v %v", c, ok, err)
			}
			// One case per studio, match and suspect.
			if ok, err := st.AddReviewCase(ctx, &ReviewCase{TenantID: "t1", MatchID: "m1", Suspect: "sus", Source: ReviewSourceReports, CreatedAt: now}); err != nil || ok {
				t.Fatalf("the same case twice: %v %v", ok, err)
			}
			cal := &ReviewCase{TenantID: "t1", MatchID: "m2", Suspect: "fair", Source: ReviewSourceCalibration, Calibration: true, Expected: "insufficient", CreatedAt: now}
			rival := &ReviewCase{TenantID: "t2", MatchID: "m1", Suspect: "sus", Source: ReviewSourceFinding, CreatedAt: now}
			for _, x := range []*ReviewCase{cal, rival} {
				if ok, err := st.AddReviewCase(ctx, x); err != nil || !ok {
					t.Fatalf("add case: %v %v", ok, err)
				}
			}
			if _, err := st.GetReviewCase(ctx, "t2", c.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("another studio reads the case: %v", err)
			}
			for _, tc := range []struct {
				f    ReviewCaseFilter
				want int
			}{{ReviewCaseFilter{}, 2}, {ReviewCaseFilter{Calibration: 1}, 1}, {ReviewCaseFilter{Calibration: -1}, 1}, {ReviewCaseFilter{State: ReviewDecided}, 0}, {ReviewCaseFilter{State: ReviewOpen, Calibration: -1}, 1}} {
				if list, err := st.ListReviewCases(ctx, "t1", tc.f); err != nil || len(list) != tc.want {
					t.Fatalf("list %+v: %d cases, %v", tc.f, len(list), err)
				}
			}

			a := &ReviewAssignment{TenantID: "t1", CaseID: c.ID, Reviewer: "rev1", Suspect: "sus", AssignedAt: now, ExpiresAt: now.Add(time.Minute)}
			if err := st.AddReviewAssignment(ctx, a); err != nil || a.ID == 0 {
				t.Fatalf("assign: %+v %v", a, err)
			}
			// A reviewer is handed a case once.
			if err := st.AddReviewAssignment(ctx, &ReviewAssignment{TenantID: "t1", CaseID: c.ID, Reviewer: "rev1", Suspect: "sus", AssignedAt: now, ExpiresAt: now}); !errors.Is(err, ErrConflict) {
				t.Fatalf("the same case to the same reviewer: %v", err)
			}
			if _, err := st.GetReviewAssignment(ctx, "t2", a.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("another studio reads the assignment: %v", err)
			}
			if err := st.ExtendReviewAssignment(ctx, "t1", a.ID, now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			// One verdict per assignment: the second is not recorded.
			if ok, err := st.CastReviewVerdict(ctx, "t1", a.ID, "cheating_aim", 0.5, "", now.Add(time.Second)); err != nil || !ok {
				t.Fatalf("verdict: %v %v", ok, err)
			}
			if ok, err := st.CastReviewVerdict(ctx, "t1", a.ID, "insufficient", 0.9, ReviewCorrect, now.Add(2*time.Second)); err != nil || ok {
				t.Fatalf("a second verdict: %v %v", ok, err)
			}
			if ok, err := st.CastReviewVerdict(ctx, "t2", a.ID, "insufficient", 0.9, "", now); (err != nil && !errors.Is(err, ErrNotFound)) || ok {
				t.Fatalf("another studio's verdict: %v %v", ok, err)
			}
			got, err := st.GetReviewAssignment(ctx, "t1", a.ID)
			if err != nil || got.Verdict != "cheating_aim" || got.Weight != 0.5 || got.Outcome != "" || !got.ExpiresAt.Equal(now.Add(time.Hour)) || !got.VotedAt.Equal(now.Add(time.Second)) {
				t.Fatalf("assignment read back: %+v %v", got, err)
			}
			if err := st.SetReviewOutcome(ctx, "t1", a.ID, ReviewCorrect); err != nil {
				t.Fatal(err)
			}
			if list, err := st.ListReviewAssignments(ctx, "t1", ReviewAssignmentFilter{Reviewer: "rev1"}); err != nil || len(list) != 1 || list[0].Outcome != ReviewCorrect {
				t.Fatalf("by reviewer: %+v %v", list, err)
			}
			if list, err := st.ListReviewAssignments(ctx, "t2", ReviewAssignmentFilter{CaseID: c.ID}); err != nil || len(list) != 0 {
				t.Fatalf("another studio lists the assignments: %+v %v", list, err)
			}

			c.State, c.Verdict, c.Kind, c.Agreement, c.ClosedAt = ReviewDecided, "cheating", "aim", 0.8, now
			c.Decision, c.DecidedBy, c.DecidedAt = ReviewConfirmed, "ada", now
			if err := st.UpdateReviewCase(ctx, c); err != nil {
				t.Fatal(err)
			}
			back, err := st.GetReviewCase(ctx, "t1", c.ID)
			if err != nil || back.State != ReviewDecided || back.Verdict != "cheating" || back.Kind != "aim" || back.Agreement != 0.8 || back.Decision != ReviewConfirmed || back.DecidedBy != "ada" || !back.DecidedAt.Equal(now) || back.Source != ReviewSourceOracle {
				t.Fatalf("case read back: %+v %v", back, err)
			}

			if ok, err := st.AddReviewBadge(ctx, "t1", "rev1", "first_correct_verdict", now); err != nil || !ok {
				t.Fatalf("badge: %v %v", ok, err)
			}
			if ok, err := st.AddReviewBadge(ctx, "t1", "rev1", "first_correct_verdict", now.Add(time.Hour)); err != nil || ok {
				t.Fatalf("the same badge twice: %v %v", ok, err)
			}
			if list, _ := st.ListReviewBadges(ctx, "t2", "", true, 0); len(list) != 0 {
				t.Fatalf("another studio lists the badges: %+v", list)
			}
			if list, err := st.ListReviewBadges(ctx, "t1", "", true, 0); err != nil || len(list) != 1 || list[0].Reviewer != "rev1" || !list[0].EarnedAt.Equal(now) {
				t.Fatalf("new badges: %+v %v", list, err)
			}
			if n, err := st.AckReviewBadges(ctx, "t1", "rev1", []string{"first_correct_verdict", "veteran"}, now.Add(time.Minute)); err != nil || n != 1 {
				t.Fatalf("ack: %d %v", n, err)
			}
			if n, err := st.AckReviewBadges(ctx, "t1", "rev1", []string{"first_correct_verdict"}, now.Add(time.Hour)); err != nil || n != 0 {
				t.Fatalf("ack twice: %d %v", n, err)
			}
			if list, _ := st.ListReviewBadges(ctx, "t1", "", true, 0); len(list) != 0 {
				t.Fatalf("an acknowledged badge is still new: %+v", list)
			}
			if list, _ := st.ListReviewBadges(ctx, "t1", "rev1", false, 0); len(list) != 1 || !list[0].DeliveredAt.Equal(now.Add(time.Minute)) {
				t.Fatalf("the reviewer's badges: %+v", list)
			}
		})
	}
}
