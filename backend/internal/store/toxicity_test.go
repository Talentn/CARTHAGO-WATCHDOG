package store

import (
	"context"
	"testing"
	"time"
)

func TestToxicityStores(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000).UTC()
	ctx := context.Background()
	for name, b := range backends(t) {
		st := b.(ToxicityStore)
		t.Run(name, func(t *testing.T) {
			rows := []ToxicityFinding{
				{TenantID: "t1", PlayerHash: "alice", SessionID: "sa", MatchID: "m1", Slot: 3, Kind: "team_kill", Count: 2, MatchMs: 218_000, Summary: "Killed 2 teammates", ObservedAt: now.Add(-2 * time.Hour)},
				{TenantID: "t1", PlayerHash: "alice", SessionID: "sa", MatchID: "m1", Slot: 3, Kind: "afk", Count: 90, MatchMs: 224_000, Summary: "Stood still", ObservedAt: now.Add(-time.Hour)},
				{TenantID: "t1", PlayerHash: "alice", MatchID: "m0", Slot: 1, Kind: "left_early", Count: 40, MatchMs: 100_000, Summary: "Left", ObservedAt: now.Add(-40 * 24 * time.Hour)},
				{TenantID: "t1", PlayerHash: "bot:Hawk", MatchID: "m1", Slot: 7, Kind: "feeding", Count: 12, MatchMs: 170_000, Summary: "Died 12 times", Bot: true, ObservedAt: now},
				{TenantID: "t2", PlayerHash: "alice", MatchID: "m1", Slot: 3, Kind: "team_damage", Count: 6, MatchMs: 1000, Summary: "another studio's", ObservedAt: now},
			}
			if err := st.AddToxicityFindings(ctx, rows); err != nil {
				t.Fatal(err)
			}
			if err := st.AddToxicityFindings(ctx, nil); err != nil {
				t.Fatal(err)
			}
			list := func(tenant string, f ToxicityFilter) []ToxicityFinding {
				t.Helper()
				got, err := st.ListToxicityFindings(ctx, tenant, f)
				if err != nil {
					t.Fatal(err)
				}
				return got
			}
			kinds := func(rows []ToxicityFinding) string {
				s := ""
				for _, r := range rows {
					s += r.Kind + " "
				}
				return s
			}
			all := list("t1", ToxicityFilter{})
			if kinds(all) != "feeding afk team_kill left_early " {
				t.Fatalf("newest first: %q", kinds(all))
			}
			if got := all[2]; got.ID == 0 || got.PlayerHash != "alice" || got.SessionID != "sa" || got.MatchID != "m1" || got.Slot != 3 || got.Count != 2 ||
				got.MatchMs != 218_000 || got.Summary != "Killed 2 teammates" || got.Bot || !got.ObservedAt.Equal(now.Add(-2*time.Hour)) {
				t.Fatalf("a finding read back: %+v", got)
			}
			if !all[0].Bot {
				t.Fatal("the bot flag is lost")
			}
			if got := kinds(list("t1", ToxicityFilter{PlayerHash: "alice", Since: now.Add(-30 * 24 * time.Hour)})); got != "afk team_kill " {
				t.Fatalf("a player's last 30 days: %q", got)
			}
			if got := kinds(list("t1", ToxicityFilter{MatchID: "m1", Limit: 2})); got != "feeding afk " {
				t.Fatalf("a match, limited: %q", got)
			}
			if got := kinds(list("t2", ToxicityFilter{})); got != "team_damage " {
				t.Fatalf("another studio: %q", got)
			}
			if got := list("t3", ToxicityFilter{PlayerHash: "alice"}); len(got) != 0 {
				t.Fatalf("a studio without findings: %+v", got)
			}

			if n, err := st.PruneToxicityFindings(ctx, now.Add(-30*24*time.Hour)); err != nil || n != 1 {
				t.Fatalf("prune: %d %v", n, err)
			}
			if got := kinds(list("t1", ToxicityFilter{PlayerHash: "alice"})); got != "afk team_kill " {
				t.Fatalf("after the prune: %q", got)
			}

			if got, err := st.GetToxicityLimits(ctx, "t1"); err != nil || got != "" {
				t.Fatalf("limits never set: %q %v", got, err)
			}
			if err := st.SetToxicityLimits(ctx, "t1", `{"team_kills":1}`, now); err != nil {
				t.Fatal(err)
			}
			if err := st.SetToxicityLimits(ctx, "t1", `{"team_kills":3}`, now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if got, _ := st.GetToxicityLimits(ctx, "t1"); got != `{"team_kills":3}` {
				t.Fatalf("limits: %q", got)
			}
			if got, _ := st.GetToxicityLimits(ctx, "t2"); got != "" {
				t.Fatalf("another studio reads the limits: %q", got)
			}
			if err := st.SetToxicityLimits(ctx, "t1", "", now); err != nil {
				t.Fatal(err)
			}
			if got, _ := st.GetToxicityLimits(ctx, "t1"); got != "" {
				t.Fatalf("limits after removal: %q", got)
			}
		})
	}
}
