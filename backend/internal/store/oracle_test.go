package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestOracleStores(t *testing.T) {
	sq, err := OpenSQLite(filepath.Join(t.TempDir(), "o.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sq.Close()
	for name, st := range map[string]OracleStore{"sqlite": sq, "memory": NewMemory()} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			at := time.UnixMilli(1_700_000_000_000).UTC()

			if s, err := st.GetOracleScore(ctx, "t1", "s1"); !errors.Is(err, ErrNotFound) || s != nil {
				t.Fatalf("missing score: %v %v", s, err)
			}
			sc := &OracleScore{TenantID: "t1", SessionID: "s1", PlayerHash: "p1", MatchID: "m1", ModelID: "cob-1", FeatureVersion: 1,
				Score: 0.25, Band: OracleBandClear, Signals: `[]`, Features: `{}`, UpdatedAt: at}
			if err := st.PutOracleScore(ctx, sc); err != nil {
				t.Fatal(err)
			}
			sc.Score, sc.Band, sc.UpdatedAt = 0.9, OracleBandReview, at.Add(time.Minute)
			if err := st.PutOracleScore(ctx, sc); err != nil {
				t.Fatal(err)
			}
			_ = st.PutOracleScore(ctx, &OracleScore{TenantID: "t1", SessionID: "s2", PlayerHash: "p2", ModelID: "cob-1", Score: 0.1, Band: OracleBandClear, UpdatedAt: at})
			_ = st.PutOracleScore(ctx, &OracleScore{TenantID: "t2", SessionID: "s1", PlayerHash: "p1", ModelID: "cob-1", Score: 0.5, Band: OracleBandWatch, UpdatedAt: at})
			got, err := st.GetOracleScore(ctx, "t1", "s1")
			if err != nil || got == nil || got.Score != 0.9 || got.Band != OracleBandReview || !got.UpdatedAt.Equal(at.Add(time.Minute)) || got.MatchID != "m1" {
				t.Fatalf("score after upsert: %+v %v", got, err)
			}
			if got, _ := st.GetOracleScore(ctx, "t2", "s1"); got == nil || got.Score != 0.5 {
				t.Fatalf("tenant t2 must see its own row: %+v", got)
			}
			if rows, _ := st.ListOracleScores(ctx, "t1", OracleFilter{}); len(rows) != 2 || rows[0].SessionID != "s1" {
				t.Fatalf("list: %+v", rows)
			}
			if rows, _ := st.ListOracleScores(ctx, "t1", OracleFilter{PlayerHash: "p2"}); len(rows) != 1 || rows[0].SessionID != "s2" {
				t.Fatalf("list by player: %+v", rows)
			}
			if rows, _ := st.ListOracleScores(ctx, "t3", OracleFilter{}); len(rows) != 0 {
				t.Fatalf("another tenant sees rows: %+v", rows)
			}

			v := &OracleVerdict{TenantID: "t1", SessionID: "s1", PlayerHash: "p1", CaseHash: "h1", Status: OracleVerdictUnavailable, Reason: "timeout",
				Provider: "local", AnalystModel: "m", PromptVersion: "v1", CaseFile: `{"x":1}`, CreatedAt: at}
			if err := st.PutOracleVerdict(ctx, v); err != nil {
				t.Fatal(err)
			}
			v.CaseHash, v.Status, v.Reason, v.CheatType, v.Confidence, v.Action, v.Summary, v.Cited = "h2", OracleVerdictOK, "", "aim_assistance", 80, "manual_review", "sum", `[{"id":"E1"}]`
			v.LatencyMs, v.TokensIn, v.TokensOut, v.CreatedAt = 1200, 500, 60, at.Add(time.Hour)
			if err := st.PutOracleVerdict(ctx, v); err != nil {
				t.Fatal(err)
			}
			gv, err := st.GetOracleVerdict(ctx, "t1", "s1")
			if err != nil || gv == nil || *gv != *v {
				t.Fatalf("verdict:\n got %+v\nwant %+v (%v)", gv, v, err)
			}
			if gv, err := st.GetOracleVerdict(ctx, "t2", "s1"); !errors.Is(err, ErrNotFound) || gv != nil {
				t.Fatalf("verdict leaked across tenants: %+v", gv)
			}
			if rows, _ := st.ListOracleVerdicts(ctx, "t1", OracleFilter{PlayerHash: "p1"}); len(rows) != 1 {
				t.Fatalf("verdict list: %+v", rows)
			}

			if u, err := st.AddOracleUsage(ctx, "t1", "2026-01-01", 0, 0); err != nil || u != (OracleUsage{}) {
				t.Fatalf("usage read: %+v %v", u, err)
			}
			_, _ = st.AddOracleUsage(ctx, "t1", "2026-01-01", 1, 0)
			_, _ = st.AddOracleUsage(ctx, "t2", "2026-01-01", 5, 5)
			if u, _ := st.AddOracleUsage(ctx, "t1", "2026-01-01", 1, 700); u != (OracleUsage{Cases: 2, Tokens: 700}) {
				t.Fatalf("usage: %+v", u)
			}
			if u, _ := st.AddOracleUsage(ctx, "t1", "2026-01-02", 0, 0); u != (OracleUsage{}) {
				t.Fatalf("usage on another day: %+v", u)
			}

			if l, err := st.GetSessionLabel(ctx, "t1", "s1"); !errors.Is(err, ErrNotFound) || l != nil {
				t.Fatalf("no label yet: %+v %v", l, err)
			}
			l := &SessionLabel{TenantID: "t1", SessionID: "s1", PlayerHash: "p1", Label: LabelUnsure, Note: "first look", Reviewer: "sam", LabelledAt: at}
			if err := st.SetSessionLabel(ctx, l, LabelSet, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			l.Label, l.CheatType, l.Note, l.LabelledAt = LabelConfirmedCheat, "aim_assistance", "watched the demo", at.Add(time.Hour)
			if err := st.SetSessionLabel(ctx, l, LabelAcceptSuggestion, "10.0.0.2"); err != nil {
				t.Fatal(err)
			}
			_ = st.SetSessionLabel(ctx, &SessionLabel{TenantID: "t1", SessionID: "s2", PlayerHash: "p2", Label: LabelCleared, Reviewer: "kim", LabelledAt: at.Add(2 * time.Hour)}, LabelSet, "")
			_ = st.SetSessionLabel(ctx, &SessionLabel{TenantID: "t2", SessionID: "s1", PlayerHash: "p1", Label: LabelCleared, LabelledAt: at}, LabelSet, "")
			got2, err := st.GetSessionLabel(ctx, "t1", "s1")
			if err != nil || *got2 != *l {
				t.Fatalf("label:\n got %+v\nwant %+v (%v)", got2, l, err)
			}
			if ls, _ := st.ListSessionLabels(ctx, "t1", OracleFilter{}); len(ls) != 2 || ls[0].SessionID != "s2" || ls[1].Label != LabelConfirmedCheat {
				t.Fatalf("labels: %+v", ls)
			}
			if ls, _ := st.ListSessionLabels(ctx, "t1", OracleFilter{PlayerHash: "p1"}); len(ls) != 1 || ls[0].SessionID != "s1" {
				t.Fatalf("labels by player: %+v", ls)
			}
			au, err := st.ListLabelAudit(ctx, "t1", "s1", 0)
			if err != nil || len(au) != 2 || au[0].Action != LabelAcceptSuggestion || au[0].Label != LabelConfirmedCheat || au[0].Remote != "10.0.0.2" ||
				au[1].Action != LabelSet || au[1].Label != LabelUnsure || au[1].Reviewer != "sam" || au[1].Note != "first look" || !au[1].At.Equal(at) {
				t.Fatalf("audit: %+v %v", au, err)
			}
			// Removing a label keeps its history.
			if err := st.SetSessionLabel(ctx, &SessionLabel{TenantID: "t1", SessionID: "s1", PlayerHash: "p1", Reviewer: "sam", LabelledAt: at.Add(3 * time.Hour)}, LabelRemove, ""); err != nil {
				t.Fatal(err)
			}
			if _, err := st.GetSessionLabel(ctx, "t1", "s1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("label after removal: %v", err)
			}
			if au, _ := st.ListLabelAudit(ctx, "t1", "s1", 0); len(au) != 3 || au[0].Action != LabelRemove {
				t.Fatalf("audit after removal: %+v", au)
			}
			if got, _ := st.GetSessionLabel(ctx, "t2", "s1"); got == nil || got.Label != LabelCleared {
				t.Fatalf("another tenant's label was touched: %+v", got)
			}
			if au, _ := st.ListLabelAudit(ctx, "t2", "s1", 0); len(au) != 1 {
				t.Fatalf("audit is tenant-scoped: %+v", au)
			}
		})
	}
}
