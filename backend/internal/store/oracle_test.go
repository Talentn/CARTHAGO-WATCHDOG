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

			if cases, _ := st.ListOracleCases(ctx, "t1", true, 0); len(cases) != 0 {
				t.Fatalf("no case is reviewed yet: %+v", cases)
			}
			if cases, _ := st.ListOracleCases(ctx, "t1", false, 0); len(cases) != 1 || cases[0].Review != nil {
				t.Fatalf("cases: %+v", cases)
			}
			rv := &OracleReview{TenantID: "t1", SessionID: "s1", CaseHash: "h2", CheatType: "none", Action: "no_action", Note: "n", ReviewedAt: at.Add(2 * time.Hour)}
			if err := st.PutOracleReview(ctx, rv); err != nil {
				t.Fatal(err)
			}
			cases, err := st.ListOracleCases(ctx, "t1", true, 0)
			if err != nil || len(cases) != 1 || cases[0].Review == nil || *cases[0].Review != *rv || cases[0].Verdict.CaseHash != "h2" {
				t.Fatalf("reviewed cases: %+v %v", cases, err)
			}
			if cases, _ := st.ListOracleCases(ctx, "t2", false, 0); len(cases) != 0 {
				t.Fatalf("cases leaked across tenants: %+v", cases)
			}
		})
	}
}
