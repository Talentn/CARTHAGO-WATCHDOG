package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type evidenceBackend interface {
	Store
	EvidenceStore
}

func backends(t *testing.T) map[string]evidenceBackend {
	dir := t.TempDir()
	sq, err := OpenSQLite(filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sq.Close() })
	return map[string]evidenceBackend{"sqlite": sq, "memory": NewMemory()}
}

func seed(t *testing.T, st evidenceBackend, now time.Time) {
	ctx := context.Background()
	for _, d := range []string{"dev-a", "dev-b", "dev-x"} {
		if err := st.UpsertDevice(ctx, &Device{DeviceID: d, TenantID: "t1", PublicKey: []byte{1}, FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	sessions := []Session{
		{SessionID: "s1", TenantID: "t1", PlayerHash: "alice", DeviceID: "dev-a", TrustLevel: 3, State: SessionActive, CreatedAt: now.Add(-time.Hour), LastHeartbeat: now},
		{SessionID: "s2", TenantID: "t1", PlayerHash: "bob", DeviceID: "dev-b", TrustLevel: 0, State: SessionActive, CreatedAt: now.Add(-30 * time.Minute), LastHeartbeat: now},
		{SessionID: "s3", TenantID: "t1", PlayerHash: "bob", DeviceID: "dev-b", TrustLevel: 1, State: SessionKicked, CreatedAt: now.Add(-10 * time.Minute), LastHeartbeat: now.Add(-10 * time.Minute)},
		{SessionID: "x1", TenantID: "t2", PlayerHash: "mallory", DeviceID: "dev-x", TrustLevel: 2, State: SessionActive, CreatedAt: now, LastHeartbeat: now},
	}
	for i := range sessions {
		if err := st.PutSession(ctx, &sessions[i]); err != nil {
			t.Fatal(err)
		}
	}
	evs := []Evidence{
		{TenantID: "t1", PlayerHash: "alice", SessionID: "s1", Source: SourceClient, Rule: "overlay_window", Severity: 0, Score: 0.1, Summary: "steam", ObservedAt: now},
		{TenantID: "t1", PlayerHash: "bob", SessionID: "s2", Source: SourceClient, Rule: "code_patch", Severity: 4, Score: 0.9, Integrity: true, Summary: "patched", ObservedAt: now},
		{TenantID: "t1", PlayerHash: "bob", MatchID: "m1", Source: SourceGameplay, Rule: "headshot_rate", Severity: 2, Score: 0.7, Summary: "hs", ObservedAt: now.Add(-time.Minute)},
		{TenantID: "t1", PlayerHash: "carol", MatchID: "m1", Source: SourceGameplay, Rule: "macro_interval", Severity: 1, Score: 0.5, Summary: "low", ObservedAt: now},
		{TenantID: "t2", PlayerHash: "mallory", SessionID: "x1", Source: SourceClient, Rule: "api_hook", Severity: 3, Score: 0.8, Integrity: true, Summary: "other tenant", ObservedAt: now},
	}
	if err := st.AddEvidence(ctx, evs); err != nil {
		t.Fatal(err)
	}
	if evs[4].ID == 0 || evs[4].ID == evs[3].ID {
		t.Fatalf("evidence ids not assigned: %+v", evs)
	}
}

func TestEvidenceStores(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000).UTC()
	for name, st := range backends(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			seed(t, st, now)

			o, err := st.Overview(ctx, "t1", now.Add(-24*time.Hour), now.Add(-2*time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			want := Overview{OnlineSessions: 2, Sessions: 3, Players: 2, FlaggedPlayers: 1, Evidence: 3, TrustLevels: [4]int{1, 1, 0, 1}}
			if o != want {
				t.Fatalf("overview\n got %+v\nwant %+v", o, want)
			}

			players, err := st.ListPlayers(ctx, "t1", PlayerFilter{})
			if err != nil {
				t.Fatal(err)
			}
			if len(players) != 3 || players[0].PlayerHash != "bob" {
				t.Fatalf("players: %+v", players)
			}
			bob := players[0]
			if bob.Sessions != 2 || bob.EvidenceCount != 2 || bob.MaxSeverity != 4 || bob.Integrity != 1 || bob.TopRule != "code_patch" || bob.TrustLevel != 1 {
				t.Fatalf("bob: %+v", bob)
			}
			if wantRisk := 10*0.9 + 3*0.7; bob.Risk < wantRisk-1e-9 || bob.Risk > wantRisk+1e-9 {
				t.Fatalf("bob risk %v want %v", bob.Risk, wantRisk)
			}
			for _, p := range players {
				if p.PlayerHash == "alice" && (p.Risk != 0 || p.EvidenceCount != 0 || p.MaxSeverity != -1) {
					t.Fatalf("info evidence counted against alice: %+v", p)
				}
				if p.PlayerHash == "carol" && p.Sessions != 0 {
					t.Fatalf("carol has gameplay evidence only: %+v", p)
				}
			}
			flagged, _ := st.ListPlayers(ctx, "t1", PlayerFilter{FlaggedOnly: true})
			if len(flagged) != 1 || flagged[0].PlayerHash != "bob" {
				t.Fatalf("flagged: %+v", flagged)
			}

			sess, err := st.ListSessions(ctx, "t1", SessionFilter{})
			if err != nil {
				t.Fatal(err)
			}
			if len(sess) != 3 || sess[0].SessionID != "s3" {
				t.Fatalf("sessions newest first: %+v", sess)
			}
			for _, s := range sess {
				if s.SessionID == "s2" && (s.EvidenceCount != 1 || s.MaxSeverity != 4) {
					t.Fatalf("s2 evidence: %+v", s)
				}
				if s.SessionID == "s1" && (s.EvidenceCount != 0 || s.MaxSeverity != -1) {
					t.Fatalf("s1 evidence: %+v", s)
				}
			}
			bobs, _ := st.ListSessions(ctx, "t1", SessionFilter{PlayerHash: "bob"})
			if len(bobs) != 2 {
				t.Fatalf("bob sessions: %+v", bobs)
			}

			evs, _ := st.ListEvidence(ctx, "t1", EvidenceFilter{MinSeverity: 1})
			if len(evs) != 3 || evs[len(evs)-1].Rule != "headshot_rate" {
				t.Fatalf("evidence: %+v", evs)
			}
			evs, _ = st.ListEvidence(ctx, "t1", EvidenceFilter{SessionID: "s1"})
			if len(evs) != 1 || evs[0].Rule != "overlay_window" {
				t.Fatalf("session evidence incl. info: %+v", evs)
			}

			// Tenant isolation: t1 must never see t2's rows, even by id.
			x, _ := st.ListEvidence(ctx, "t2", EvidenceFilter{})
			if len(x) != 1 {
				t.Fatalf("t2 evidence: %+v", x)
			}
			if _, err := st.GetEvidence(ctx, "t1", x[0].ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("cross-tenant GetEvidence: %v", err)
			}
			if e, err := st.GetEvidence(ctx, "t2", x[0].ID); err != nil || e.Summary != "other tenant" {
				t.Fatalf("own GetEvidence: %v %v", e, err)
			}
			for _, p := range players {
				if p.PlayerHash == "mallory" {
					t.Fatal("other tenant's player listed")
				}
			}

			tel := &Telemetry{SessionID: "x1", UpdatedAt: now, WorkerCPUNs: 123, Coverage: `[{"job":"a"}]`, MitigationsApplied: 3}
			if err := st.PutTelemetry(ctx, tel); err != nil {
				t.Fatal(err)
			}
			tel.WorkerCPUNs = 456
			if err := st.PutTelemetry(ctx, tel); err != nil {
				t.Fatal(err)
			}
			if _, err := st.GetTelemetry(ctx, "t1", "x1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("cross-tenant telemetry: %v", err)
			}
			got, err := st.GetTelemetry(ctx, "t2", "x1")
			if err != nil || got.WorkerCPUNs != 456 || got.Coverage != tel.Coverage || got.MitigationsApplied != 3 {
				t.Fatalf("telemetry: %+v %v", got, err)
			}

			for i, c := range []struct {
				tenant string
				seq    uint64
				fresh  bool
			}{{"t1", 1, true}, {"t1", 1, false}, {"t1", 2, true}, {"t1", 1, false}, {"t2", 1, true}} {
				fresh, err := st.AdvanceMatch(ctx, c.tenant, "m1", c.seq, now, false)
				if err != nil || fresh != c.fresh {
					t.Fatalf("AdvanceMatch #%d %+v: fresh=%v err=%v", i, c, fresh, err)
				}
			}
			o, _ = st.Overview(ctx, "t1", now.Add(-time.Hour), now)
			if o.Matches != 1 {
				t.Fatalf("matches: %d", o.Matches)
			}
		})
	}
}

func TestSQLiteReopenKeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "g.db")
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddEvidence(context.Background(), []Evidence{{TenantID: "t", PlayerHash: "p", Source: SourceClient, Rule: "r", Severity: 2, Score: 1, ObservedAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = OpenSQLite(path)
	if err != nil {
		t.Fatalf("reapplying migrations: %v", err)
	}
	defer st.Close()
	evs, _ := st.ListEvidence(context.Background(), "t", EvidenceFilter{})
	if len(evs) != 1 {
		t.Fatalf("evidence after reopen: %+v", evs)
	}
}
