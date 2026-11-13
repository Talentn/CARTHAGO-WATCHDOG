package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type authBackend interface {
	Store
	AuthStore
}

func authBackends(t *testing.T) map[string]authBackend {
	sq, err := OpenSQLite(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sq.Close() })
	return map[string]authBackend{"sqlite": sq, "memory": NewMemory()}
}

var authNow = time.UnixMilli(1_800_000_000_000).UTC()

func mustUser(t *testing.T, st AuthStore, tenant, name, role string) *DashUser {
	t.Helper()
	u := &DashUser{TenantID: tenant, Name: name, Role: role, PasswordHash: "hash-of-" + name, CreatedAt: authNow, CreatedBy: "test", PasswordChangedAt: authNow}
	if err := st.CreateDashUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if u.ID == 0 {
		t.Fatal("no id assigned")
	}
	return u
}

func TestDashUsers(t *testing.T) {
	ctx := context.Background()
	for name, st := range authBackends(t) {
		t.Run(name, func(t *testing.T) {
			if n, err := st.CountDashUsers(ctx, "t1"); err != nil || n != 0 {
				t.Fatalf("empty tenant: %d %v", n, err)
			}
			ala := mustUser(t, st, "t1", "ala", RoleAdmin)
			sam := mustUser(t, st, "t1", "sam", RoleReviewer)
			other := mustUser(t, st, "t2", "ala", RoleReadOnly)
			if err := st.CreateDashUser(ctx, &DashUser{TenantID: "t1", Name: "ala", Role: RoleAdmin, PasswordHash: "x", CreatedAt: authNow, PasswordChangedAt: authNow}); !errors.Is(err, ErrConflict) {
				t.Fatalf("duplicate name in a tenant: %v", err)
			}
			if n, _ := st.CountDashUsers(ctx, "t1"); n != 2 {
				t.Fatalf("t1 has %d users", n)
			}
			// Another tenant's id or name never resolves.
			if _, err := st.GetDashUser(ctx, "t1", other.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("t2's user read through t1: %v", err)
			}
			if u, err := st.GetDashUserByName(ctx, "t2", "ala"); err != nil || u.ID != other.ID || u.Role != RoleReadOnly {
				t.Fatalf("t2 ala: %+v %v", u, err)
			}
			if _, err := st.GetDashUserByName(ctx, "t2", "sam"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("sam in t2: %v", err)
			}
			got, err := st.GetDashUser(ctx, "t1", ala.ID)
			if err != nil || got.Name != "ala" || got.Role != RoleAdmin || got.TOTPSecret != nil || !got.LastLoginAt.IsZero() || !got.CreatedAt.Equal(authNow) || got.CreatedBy != "test" {
				t.Fatalf("ala: %+v %v", got, err)
			}
			got.Role, got.PasswordHash, got.TOTPSecret, got.Disabled = RoleReviewer, "new-hash", []byte{1, 2, 3}, true
			got.PasswordChangedAt, got.LastLoginAt = authNow.Add(time.Hour), authNow.Add(2*time.Hour)
			if err := st.UpdateDashUser(ctx, got); err != nil {
				t.Fatal(err)
			}
			again, _ := st.GetDashUser(ctx, "t1", ala.ID)
			if again.Role != RoleReviewer || again.PasswordHash != "new-hash" || string(again.TOTPSecret) != "\x01\x02\x03" || !again.Disabled ||
				!again.PasswordChangedAt.Equal(authNow.Add(time.Hour)) || !again.LastLoginAt.Equal(authNow.Add(2*time.Hour)) {
				t.Fatalf("after update: %+v", again)
			}
			// An update cannot move a user to another tenant or touch one there.
			stray := *again
			stray.TenantID = "t2"
			if err := st.UpdateDashUser(ctx, &stray); !errors.Is(err, ErrNotFound) {
				t.Fatalf("update through the wrong tenant: %v", err)
			}
			list, err := st.ListDashUsers(ctx, "t1")
			if err != nil || len(list) != 2 || list[0].Name != "ala" || list[1].ID != sam.ID {
				t.Fatalf("list: %+v %v", list, err)
			}

			// A time step is accepted once, and never an older one after it.
			for _, c := range []struct {
				step int64
				want bool
			}{{100, true}, {100, false}, {99, false}, {101, true}} {
				if ok, err := st.AdvanceTOTPStep(ctx, sam.ID, c.step); err != nil || ok != c.want {
					t.Errorf("step %d: %v %v, want %v", c.step, ok, err, c.want)
				}
			}
			// UpdateDashUser leaves the step alone, so saving a login time cannot reopen a used code.
			samNow, _ := st.GetDashUser(ctx, "t1", sam.ID)
			samNow.TOTPLastStep = 0
			st.UpdateDashUser(ctx, samNow)
			if ok, _ := st.AdvanceTOTPStep(ctx, sam.ID, 101); ok {
				t.Error("an update reset the used time step")
			}

			if err := st.SetRecoveryCodes(ctx, sam.ID, []string{"h1", "h2", "h3"}); err != nil {
				t.Fatal(err)
			}
			if ok, _ := st.UseRecoveryCode(ctx, ala.ID, "h1"); ok {
				t.Error("another user's recovery code accepted")
			}
			if ok, _ := st.UseRecoveryCode(ctx, sam.ID, "h1"); !ok {
				t.Error("recovery code refused")
			}
			if ok, _ := st.UseRecoveryCode(ctx, sam.ID, "h1"); ok {
				t.Error("recovery code accepted twice")
			}
			if n, _ := st.CountRecoveryCodes(ctx, sam.ID); n != 2 {
				t.Errorf("%d codes left, want 2", n)
			}
			st.SetRecoveryCodes(ctx, sam.ID, []string{"n1"})
			if ok, _ := st.UseRecoveryCode(ctx, sam.ID, "h2"); ok {
				t.Error("a code from the replaced set still works")
			}
			st.SetRecoveryCodes(ctx, sam.ID, nil)
			if n, _ := st.CountRecoveryCodes(ctx, sam.ID); n != 0 {
				t.Errorf("%d codes after clearing", n)
			}
		})
	}
}

func TestDashInvites(t *testing.T) {
	ctx := context.Background()
	for name, st := range authBackends(t) {
		t.Run(name, func(t *testing.T) {
			mk := func(hash, tenant string, ttl time.Duration) {
				t.Helper()
				if err := st.CreateDashInvite(ctx, &DashInvite{TokenHash: hash, TenantID: tenant, Kind: InviteNew, Name: "sam", Role: RoleReviewer, CreatedBy: "ala", CreatedAt: authNow, ExpiresAt: authNow.Add(ttl)}); err != nil {
					t.Fatal(err)
				}
			}
			mk("a", "t1", time.Hour)
			mk("b", "t1", time.Minute)
			mk("c", "t2", time.Hour)
			if v, err := st.GetDashInvite(ctx, "a", authNow); err != nil || v.Name != "sam" || v.Role != RoleReviewer || v.Kind != InviteNew || v.CreatedBy != "ala" || !v.UsedAt.IsZero() {
				t.Fatalf("get: %+v %v", v, err)
			}
			if _, err := st.GetDashInvite(ctx, "b", authNow.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expired link read: %v", err)
			}
			if _, err := st.RedeemDashInvite(ctx, "b", authNow.Add(2*time.Minute)); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expired link redeemed: %v", err)
			}
			if list, _ := st.ListDashInvites(ctx, "t1", authNow); len(list) != 2 {
				t.Fatalf("pending in t1: %+v", list)
			}
			// Of several attempts on one link exactly one wins.
			var wg sync.WaitGroup
			var mu sync.Mutex
			won := 0
			for range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if v, err := st.RedeemDashInvite(ctx, "a", authNow.Add(time.Second)); err == nil && v.TenantID == "t1" && !v.UsedAt.IsZero() {
						mu.Lock()
						won++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			if won != 1 {
				t.Fatalf("link redeemed %d times", won)
			}
			if _, err := st.GetDashInvite(ctx, "a", authNow); !errors.Is(err, ErrNotFound) {
				t.Fatalf("used link still readable: %v", err)
			}
			if err := st.RevokeDashInvite(ctx, "t1", "c"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("t1 revoked t2's link: %v", err)
			}
			if err := st.RevokeDashInvite(ctx, "t2", "c"); err != nil {
				t.Fatal(err)
			}
			if _, err := st.RedeemDashInvite(ctx, "c", authNow); !errors.Is(err, ErrNotFound) {
				t.Fatalf("revoked link redeemed: %v", err)
			}
			if list, _ := st.ListDashInvites(ctx, "t1", authNow); len(list) != 1 || list[0].TokenHash != "b" {
				t.Fatalf("pending after use: %+v", list)
			}
		})
	}
}

func TestDashSessions(t *testing.T) {
	ctx := context.Background()
	for name, st := range authBackends(t) {
		t.Run(name, func(t *testing.T) {
			put := func(id, tenant string, user int64, ttl time.Duration) {
				t.Helper()
				if err := st.PutDashSession(ctx, &DashSession{IDHash: id, TenantID: tenant, UserID: user, Kind: DashSessionFull, CreatedAt: authNow, LastSeenAt: authNow, ExpiresAt: authNow.Add(ttl), IP: "127.0.0.1", UserAgent: "test"}); err != nil {
					t.Fatal(err)
				}
			}
			put("s1", "t1", 1, time.Hour)
			put("s2", "t1", 1, time.Hour)
			put("s3", "t1", 2, time.Hour)
			put("s4", "t2", 1, time.Hour)
			put("old", "t1", 1, time.Minute)
			if x, err := st.GetDashSession(ctx, "s1"); err != nil || x.TenantID != "t1" || x.UserID != 1 || x.Kind != DashSessionFull || x.IP != "127.0.0.1" || !x.ExpiresAt.Equal(authNow.Add(time.Hour)) {
				t.Fatalf("get: %+v %v", x, err)
			}
			st.TouchDashSession(ctx, "s2", authNow.Add(10*time.Minute))
			list, err := st.ListDashSessions(ctx, "t1", 1, authNow.Add(5*time.Minute))
			if err != nil || len(list) != 2 || list[0].IDHash != "s2" || !list[0].LastSeenAt.Equal(authNow.Add(10*time.Minute)) {
				t.Fatalf("list (expired one left out, latest first): %+v %v", list, err)
			}
			if err := st.PruneDashSessions(ctx, authNow.Add(5*time.Minute)); err != nil {
				t.Fatal(err)
			}
			if _, err := st.GetDashSession(ctx, "old"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expired session kept: %v", err)
			}
			// Sign out everywhere else: the user's other sessions go, nobody else's.
			if n, err := st.DeleteDashSessions(ctx, "t1", 1, "s1"); err != nil || n != 1 {
				t.Fatalf("delete others: %d %v", n, err)
			}
			for id, want := range map[string]bool{"s1": true, "s2": false, "s3": true, "s4": true} {
				_, err := st.GetDashSession(ctx, id)
				if (err == nil) != want {
					t.Errorf("session %s present=%v, want %v", id, err == nil, want)
				}
			}
			if n, _ := st.DeleteDashSessions(ctx, "t1", 1, ""); n != 1 {
				t.Errorf("delete all: %d", n)
			}
			st.DeleteDashSession(ctx, "s3")
			if _, err := st.GetDashSession(ctx, "s3"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("deleted session kept: %v", err)
			}
		})
	}
}

func TestTenantSettings(t *testing.T) {
	ctx := context.Background()
	for name, st := range authBackends(t) {
		t.Run(name, func(t *testing.T) {
			if s, err := st.GetTenantSettings(ctx, "t1"); err != nil || s.RequireTOTP {
				t.Fatalf("default: %+v %v", s, err)
			}
			for _, on := range []bool{true, false, true} {
				if err := st.PutTenantSettings(ctx, "t1", TenantSettings{RequireTOTP: on}); err != nil {
					t.Fatal(err)
				}
				if s, _ := st.GetTenantSettings(ctx, "t1"); s.RequireTOTP != on {
					t.Fatalf("require two-factor = %v, want %v", s.RequireTOTP, on)
				}
			}
			if s, _ := st.GetTenantSettings(ctx, "t2"); s.RequireTOTP {
				t.Fatal("one tenant's setting applies to another")
			}
		})
	}
}

func TestAuditLog(t *testing.T) {
	ctx := context.Background()
	for name, st := range authBackends(t) {
		t.Run(name, func(t *testing.T) {
			add := func(tenant, action, target string) *AuditEntry {
				t.Helper()
				e := &AuditEntry{TenantID: tenant, At: authNow, ActorID: 1, Actor: "ala", IP: "127.0.0.1", Action: action, Target: target, Detail: "d"}
				if err := st.AppendAudit(ctx, e); err != nil {
					t.Fatal(err)
				}
				return e
			}
			first := add("t1", "login.ok", "")
			add("t2", "login.ok", "")
			second := add("t1", "user.role", "sam")
			third := add("t1", "login.fail", "sam")
			if first.ID == 0 || first.PrevHash != "" || len(first.Hash) != 64 || second.PrevHash != first.Hash || third.PrevHash != second.Hash {
				t.Fatalf("chain: %+v %+v %+v", first, second, third)
			}
			all, err := st.ListAudit(ctx, "t1", AuditFilter{})
			if err != nil || len(all) != 3 || all[0].ID != third.ID || all[2].ID != first.ID || all[1].Target != "sam" || all[1].Actor != "ala" || !all[1].At.Equal(authNow) {
				t.Fatalf("list newest first: %+v %v", all, err)
			}
			if logins, _ := st.ListAudit(ctx, "t1", AuditFilter{ActionPrefixes: []string{"login."}}); len(logins) != 2 {
				t.Fatalf("filter by action: %+v", logins)
			}
			if page, _ := st.ListAudit(ctx, "t1", AuditFilter{BeforeID: third.ID, Limit: 1}); len(page) != 1 || page[0].ID != second.ID {
				t.Fatalf("paging: %+v", page)
			}
			if other, _ := st.ListAudit(ctx, "t2", AuditFilter{}); len(other) != 1 || other[0].PrevHash != "" {
				t.Fatalf("t2 has its own chain: %+v", other)
			}
			if n, broken, err := st.VerifyAudit(ctx, "t1"); err != nil || n != 3 || broken != 0 {
				t.Fatalf("verify: %d %d %v", n, broken, err)
			}
			if n, broken, _ := st.VerifyAudit(ctx, "nobody"); n != 0 || broken != 0 {
				t.Fatalf("empty log: %d %d", n, broken)
			}
		})
	}
}

// Neither the gateway nor anyone with plain SQL access can change or remove an audit entry
// while the triggers are in place, and an entry changed after removing them is found.
func TestAuditLogIsAppendOnly(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var ids []int64
	for _, action := range []string{"login.ok", "user.role", "user.disable", "logout"} {
		e := &AuditEntry{TenantID: "t1", At: authNow, Actor: "ala", Action: action}
		if err := st.AppendAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID)
	}
	for _, q := range []string{
		`UPDATE dashboard_audit SET actor = 'someone else' WHERE id = ?`,
		`DELETE FROM dashboard_audit WHERE id = ?`,
	} {
		if _, err := st.db.Exec(q, ids[1]); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := st.db.Exec(`DELETE FROM dashboard_audit`); err == nil {
		t.Fatal("the whole log was deleted")
	}
	if n, broken, _ := st.VerifyAudit(ctx, "t1"); n != 4 || broken != 0 {
		t.Fatalf("log changed: %d %d", n, broken)
	}
	// Someone with the database file drops the trigger and rewrites history.
	if _, err := st.db.Exec(`DROP TRIGGER dashboard_audit_no_update; UPDATE dashboard_audit SET action = 'nothing.happened' WHERE id = ?`, ids[1]); err != nil {
		t.Fatal(err)
	}
	if _, broken, _ := st.VerifyAudit(ctx, "t1"); broken != ids[1] {
		t.Fatalf("edited entry: verify reports %d, want %d", broken, ids[1])
	}
	if _, err := st.db.Exec(`DROP TRIGGER dashboard_audit_no_delete; DELETE FROM dashboard_audit WHERE id = ?`, ids[1]); err != nil {
		t.Fatal(err)
	}
	if _, broken, _ := st.VerifyAudit(ctx, "t1"); broken != ids[2] {
		t.Fatalf("removed entry: verify reports %d, want the entry after the gap (%d)", broken, ids[2])
	}
}

// Two gateways' worth of writers (the gateway and the command line share a database file)
// never chain two entries onto the same predecessor.
func TestAuditLogConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	a, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := a
			if i%2 == 1 {
				st = b
			}
			errs <- st.AppendAudit(ctx, &AuditEntry{TenantID: "t1", At: authNow, Actor: "ala", Action: "login.ok"})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n, broken, err := a.VerifyAudit(ctx, "t1"); err != nil || n != 40 || broken != 0 {
		t.Fatalf("verify after concurrent writes: %d %d %v", n, broken, err)
	}
}

// Migrations from 0020 on are recorded by number, so they apply whatever the position-based
// version is, apply once, and a database that has one this gateway does not know is refused.
func TestNumberedMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.db")
	for i := range 2 {
		s, err := OpenSQLite(path)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			mustUser(t, s, "t1", "ala", RoleAdmin)
		}
		if n, _ := s.CountDashUsers(context.Background(), "t1"); n != 1 {
			t.Fatalf("open %d: %d users (reopening must neither rerun the migration nor lose data)", i+1, n)
		}
		var number int
		var name string
		if err := s.db.QueryRow(`SELECT number, name FROM schema_migrations`).Scan(&number, &name); err != nil || number != 20 || name != "dashboard_auth" {
			t.Fatalf("recorded migration: %d %q %v", number, name, err)
		}
		s.Close()
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	// A later position-based migration (another branch's 0006) does not disturb it.
	var v int
	db.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v >= 20 {
		t.Fatalf("user_version %d: the position-based list reached the numbered range", v)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations (number, name, applied_ms) VALUES (21, 'from_the_future', 1)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if s, err := OpenSQLite(path); err == nil {
		s.Close()
		t.Fatal("opened a database with an unknown numbered migration")
	} else if !strings.Contains(err.Error(), "0021_from_the_future") || !strings.Contains(err.Error(), "newer than this gateway") {
		t.Fatalf("unexpected error: %v", err)
	}
}
