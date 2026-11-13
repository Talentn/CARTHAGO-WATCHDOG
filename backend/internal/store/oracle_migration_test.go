package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"carthago/backend/migrations"
)

// branchDB builds the database a branch's gateway leaves behind: the closed position-based
// list, then whatever the branch added, with the user_version and rows given.
func branchDB(t *testing.T, version int, extra ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "branch.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range append(append([]string(nil), migrations.SQLite...), append(extra, fmt.Sprintf(`PRAGMA user_version = %d`, version))...) {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func oracleSQL(t *testing.T) string {
	t.Helper()
	for _, m := range migrations.SQLiteNumbered {
		if m.Name == "oracle" {
			if m.Number != 21 || m.Position != 6 || m.Probe != "oracle_scores" {
				t.Fatalf("oracle migration: %+v", m)
			}
			return m.SQL
		}
	}
	t.Fatal("no oracle migration")
	return ""
}

func schemaState(t *testing.T, path string) (version int, numbers string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(`SELECT number FROM schema_migrations ORDER BY number`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ns []string
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		ns = append(ns, fmt.Sprint(n))
	}
	return version, strings.Join(ns, ",")
}

// The position-based list is the same on every branch, so its length is fixed: a branch
// that appends to it gives its own meaning to a user_version another branch also uses.
func TestPositionBasedListIsClosed(t *testing.T) {
	if n := len(migrations.SQLite); n != 5 {
		t.Fatalf("the position-based list has %d migrations; add new ones to SQLiteNumbered", n)
	}
}

// Databases written by each branch's gateway open with the merged gateway, keep their rows
// and end in the same schema state.
func TestUpgradeFromEachBranch(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	score := `INSERT INTO oracle_scores (tenant_id, session_id, player_hash, model_id, feature_version, score, band, signals, features, updated_ms)
		VALUES ('t1', 's1', 'p1', 'cob-test', 1, 0.9, 'review', '[]', '{}', 1)`
	for _, c := range []struct {
		name      string
		version   int
		extra     []string
		wantScore bool
	}{
		{"carthago-dev before the merge and cs16-kit: five migrations", 5, nil, false},
		{"ai-engine: the Oracle as the sixth by position", 6, []string{oracleSQL(t), score}, true},
		{"dashboard-auth: five by position and 0020 by number", 5, []string{createSchemaMigrations, numbered(t, 20).SQL,
			`INSERT INTO schema_migrations (number, name, applied_ms) VALUES (20, 'dashboard_auth', 1)`}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := branchDB(t, c.version, c.extra...)
			for i := range 2 {
				s, err := OpenSQLite(path)
				if err != nil {
					t.Fatalf("open %d: %v", i+1, err)
				}
				sc, err := s.GetOracleScore(ctx, "t1", "s1")
				if c.wantScore && (err != nil || sc.Band != OracleBandReview) {
					t.Fatalf("open %d: the Oracle score written on the branch is gone: %+v %v", i+1, sc, err)
				}
				if i == 0 {
					if err := s.SetSessionLabel(ctx, &SessionLabel{TenantID: "t1", SessionID: "s1", PlayerHash: "p1", Label: LabelCleared, Reviewer: "ala", LabelledAt: now}, LabelSet, "127.0.0.1"); err != nil {
						t.Fatal(err)
					}
					mustUser(t, s, "t1", "ala", RoleAdmin)
				}
				if l, err := s.GetSessionLabel(ctx, "t1", "s1"); err != nil || l.Label != LabelCleared {
					t.Fatalf("open %d: label %+v %v", i+1, l, err)
				}
				if n, _ := s.CountDashUsers(ctx, "t1"); n != 1 {
					t.Fatalf("open %d: %d dashboard users", i+1, n)
				}
				s.Close()
				if v, nums := schemaState(t, path); v != 5 || nums != "20,21" {
					t.Fatalf("open %d: user_version %d, numbered migrations %s; want 5 and 20,21", i+1, v, nums)
				}
			}
		})
	}
}

// A user_version past the closed list that no known migration accounts for is still a
// database from a newer gateway, also when this gateway's own Oracle tables are in it:
// those are recorded by number, so they cannot be what raised the version.
func TestUnknownPositionIsStillRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	// What another branch's gateway does with its own sixth migration.
	if _, err := db.Exec(`CREATE TABLE another_branch (id INTEGER); PRAGMA user_version = 6`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if s, err := OpenSQLite(path); err == nil {
		s.Close()
		t.Fatal("opened a database whose sixth migration is not the Oracle")
	} else if !strings.Contains(err.Error(), "newer than this gateway") {
		t.Fatalf("unexpected error: %v", err)
	}
	if v, nums := schemaState(t, path); v != 6 || nums != "20,21" {
		t.Fatalf("the refused database was changed: user_version %d, numbered %s", v, nums)
	}
}

func numbered(t *testing.T, number int) migrations.Numbered {
	t.Helper()
	for _, m := range migrations.SQLiteNumbered {
		if m.Number == number {
			return m
		}
	}
	t.Fatalf("no migration %d", number)
	return migrations.Numbered{}
}
