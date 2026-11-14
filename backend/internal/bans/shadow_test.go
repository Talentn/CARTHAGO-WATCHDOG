package bans

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

// told records what the hooks hear.
type told struct{ calls []string }

func (h *told) Banned(b *store.Ban) { h.calls = append(h.calls, "banned "+b.PlayerHash) }
func (h *told) Lifted(b *store.Ban) { h.calls = append(h.calls, "lifted "+b.PlayerHash) }
func (h *told) PoolSession(b *store.Ban, sess store.Session) {
	h.calls = append(h.calls, "session "+sess.SessionID+" of "+b.PlayerHash)
}

func (h *told) take() string {
	out := strings.Join(h.calls, ", ")
	h.calls = nil
	return out
}

func audited(t *testing.T, st *store.Memory) string {
	t.Helper()
	list, err := st.ListAudit(context.Background(), "t1", store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(list) - 1; i >= 0; i-- {
		out = append(out, list[i].Action+" by "+list[i].Actor)
	}
	return strings.Join(out, ", ")
}

const period = 48 * time.Hour

func newPool(t *testing.T) (*Service, *store.Memory, *ended, *told, *time.Time) {
	s, st, e, now := newService(t)
	h := &told{}
	s.AddHook(h)
	if err := st.SetShadowPeriod(context.Background(), "t1", period); err != nil {
		t.Fatal(err)
	}
	return s, st, e, h, now
}

func status(t *testing.T, s *Service, player string) string {
	t.Helper()
	b, err := s.Pooled(context.Background(), "t1", player)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		return StatusNormal
	}
	return StatusShadow
}

// With the period off an automatic ban is what it was: immediate, and no pool.
func TestShadowPeriodOffBansAtOnce(t *testing.T) {
	s, st, e, now := newService(t)
	s.Automatic(sess, "mapped_image", "x")
	b, err := st.StandingBan(context.Background(), "t1", "p1", "")
	if err != nil || b.Shadow || !b.Active(*now) || len(e.calls) != 1 || status(t, s, "p1") != StatusNormal {
		t.Fatalf("ban %+v err %v ended %v", b, err, e.calls)
	}
	if s.Silent(sess, true) {
		t.Fatal("silent with the period off")
	}
	if pool, _ := s.Pool(context.Background(), "t1"); len(pool) != 0 {
		t.Fatalf("pool: %+v", pool)
	}
}

// Certain evidence with the period on: the player is in the pool, not refused, no session
// ended, and the ban takes effect by itself at the end of the period.
func TestShadowPoolEntryAndEnd(t *testing.T) {
	ctx := context.Background()
	s, st, e, h, now := newPool(t)
	if !s.Silent(sess, true) || s.Silent(sess, false) {
		t.Fatal("silent: certain evidence is about to pool the player; other evidence is not")
	}
	s.Automatic(sess, "renderer_replaced", "an unsigned renderer")
	b, err := s.Pooled(ctx, "t1", "p1")
	if err != nil || b == nil || !b.Shadow || !b.EffectiveAt.Equal(now.Add(period)) || b.DeviceID != "d1" || b.BannedBy != store.BanAutomatic {
		t.Fatalf("entry: %+v %v", b, err)
	}
	if got, _ := s.Refused(ctx, "t1", "p1", "d1"); got != nil || len(e.calls) != 0 {
		t.Fatalf("a player in the pool was refused or a session ended: %+v %v", got, e.calls)
	}
	if got := h.take(); got != "banned p1" {
		t.Fatalf("hooks: %s", got)
	}
	if !s.Silent(sess, false) || !s.Silent(sess, true) {
		t.Fatal("a player in the pool is not silent")
	}
	// More certain evidence makes no second entry, and another tenant sees nothing.
	s.Automatic(sess, "foreign_module", "again")
	if pool, _ := s.Pool(ctx, "t1"); len(pool) != 1 {
		t.Fatalf("pool: %+v", pool)
	}
	if pool, _ := s.Pool(ctx, "t2"); len(pool) != 0 {
		t.Fatalf("another tenant's pool: %+v", pool)
	}
	// A later session of the player is handed to the hooks.
	s.Connected(ctx, store.Session{SessionID: "s2", TenantID: "t1", PlayerHash: "p1", DeviceID: "d1"})
	if got := h.take(); got != "session s2 of p1" {
		t.Fatalf("hooks: %s", got)
	}

	// One second before the end nothing happens; at the end the ban lands once.
	*now = now.Add(period - time.Second)
	if n := s.Sweep(ctx); n != 0 || status(t, s, "p1") != StatusShadow {
		t.Fatalf("landed early: %d", n)
	}
	*now = now.Add(time.Second)
	if status(t, s, "p1") != StatusNormal {
		t.Fatal("still shadow after the end")
	}
	if got, _ := s.Refused(ctx, "t1", "p1", ""); got == nil || got.Ref != b.Ref {
		t.Fatalf("not refused at the end of the period, before any sweep: %+v", got)
	}
	if n := s.Sweep(ctx); n != 1 || len(e.calls) != 1 || e.calls[0] != "t1/p1/d1/banned" {
		t.Fatalf("sweep: %d, ended %v", n, e.calls)
	}
	s.landDue("t1", b.ID)
	if n := s.Sweep(ctx); n != 0 || len(e.calls) != 1 {
		t.Fatalf("landed twice: %d, ended %v", n, e.calls)
	}
	if got, _ := s.Refused(ctx, "t1", "other", "d1"); got == nil {
		t.Fatal("the device key is not banned")
	}
	if got := audited(t, st); got != "shadow.enter by automatic, shadow.end by automatic" {
		t.Fatalf("audit: %s", got)
	}
	if got := h.take(); got != "" {
		t.Fatalf("hooks at the end: %s", got)
	}
}

// The timer of an entry lands it without a sweep.
func TestShadowPoolTimerLandsTheBan(t *testing.T) {
	ctx := context.Background()
	s, st, e, now := newService(t)
	_ = st.SetShadowPeriod(ctx, "t1", time.Second)
	real := time.Now()
	start := *now
	s.Now = func() time.Time { return start.Add(time.Since(real)) }
	s.Automatic(sess, "renderer_replaced", "x")
	if status(t, s, "p1") != StatusShadow {
		t.Fatal("not in the pool")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		list, _ := st.ListBans(ctx, "t1", 0)
		if len(list) == 1 && !list[0].LandedAt.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the ban did not land: %+v", list)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(e.calls) != 1 {
		t.Fatalf("ended: %v", e.calls)
	}
}

// Another account on the device key of a player in the pool joins with the same end; an
// account on another device key does not.
func TestShadowPoolDeviceJoin(t *testing.T) {
	ctx := context.Background()
	s, st, e, h, now := newPool(t)
	s.Automatic(sess, "renderer_replaced", "x")
	root, _ := s.Pooled(ctx, "t1", "p1")
	h.take()

	*now = now.Add(time.Hour)
	alt := store.Session{SessionID: "a1", TenantID: "t1", PlayerHash: "p2", DeviceID: "d1"}
	s.Connected(ctx, alt)
	s.Connected(ctx, alt)
	s.Connected(ctx, store.Session{SessionID: "c1", TenantID: "t1", PlayerHash: "p3", DeviceID: "d9"})
	s.Connected(ctx, store.Session{SessionID: "c2", TenantID: "t1", PlayerHash: "p4"})
	s.Connected(ctx, store.Session{SessionID: "c3", TenantID: "t2", PlayerHash: "p5", DeviceID: "d1"})
	m, _ := s.Pooled(ctx, "t1", "p2")
	if m == nil || m.ShadowOf != root.Ref || !m.EffectiveAt.Equal(root.EffectiveAt) || m.SessionID != "a1" || m.Ref == root.Ref || m.DeviceID != "" {
		t.Fatalf("alternate account: %+v", m)
	}
	for _, p := range []string{"p3", "p4", "p5"} {
		if status(t, s, p) != StatusNormal {
			t.Fatalf("%s is in the pool", p)
		}
	}
	if pool, _ := s.Pool(ctx, "t1"); len(pool) != 2 {
		t.Fatalf("pool: %+v", pool)
	}
	if got := h.take(); got != "banned p2, session a1 of p2" {
		t.Fatalf("hooks: %s", got)
	}
	if got, _ := s.Refused(ctx, "t1", "p2", "d1"); got != nil {
		t.Fatalf("refused: %+v", got)
	}
	if !s.Silent(alt, false) {
		t.Fatal("the alternate account is not silent")
	}

	// The end of the period bans both accounts and the device key.
	*now = root.EffectiveAt
	if n := s.Sweep(ctx); n != 2 || len(e.calls) != 2 {
		t.Fatalf("sweep: %d, ended %v", n, e.calls)
	}
	for _, c := range [][2]string{{"p1", ""}, {"p2", ""}, {"new", "d1"}} {
		if got, _ := s.Refused(ctx, "t1", c[0], c[1]); got == nil {
			t.Fatalf("%v is not refused", c)
		}
	}
	if got, _ := s.Refused(ctx, "t1", "new", "d2"); got != nil {
		t.Fatalf("a stranger is refused: %+v", got)
	}
	if got := audited(t, st); got != "shadow.enter by automatic, shadow.join by automatic, shadow.end by automatic, shadow.end by automatic" {
		t.Fatalf("audit: %s", got)
	}
}

// Ban now on the player who was caught bans the accounts that joined through the device
// key with it; on such an account it bans that account alone.
func TestShadowPoolBanNow(t *testing.T) {
	ctx := context.Background()
	for _, onRoot := range []bool{true, false} {
		s, _, e, h, now := newPool(t)
		s.Automatic(sess, "renderer_replaced", "x")
		s.Connected(ctx, store.Session{SessionID: "a1", TenantID: "t1", PlayerHash: "p2", DeviceID: "d1"})
		root, _ := s.Pooled(ctx, "t1", "p1")
		m, _ := s.Pooled(ctx, "t1", "p2")
		h.take()
		*now = now.Add(time.Hour)
		if _, _, err := s.BanNow(ctx, "t2", root.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("another tenant: %v", err)
		}
		if onRoot {
			b, with, err := s.BanNow(ctx, "t1", root.ID)
			if err != nil || !b.Active(*now) || !b.EffectiveAt.Equal(*now) || len(with) != 1 || with[0].Ref != m.Ref || len(e.calls) != 2 {
				t.Fatalf("ban now: %+v with %+v err %v ended %v", b, with, err, e.calls)
			}
			if status(t, s, "p1") != StatusNormal || status(t, s, "p2") != StatusNormal {
				t.Fatal("still in the pool")
			}
			if got, _ := s.Refused(ctx, "t1", "p2", ""); got == nil {
				t.Fatal("the alternate account is not banned")
			}
		} else {
			b, with, err := s.BanNow(ctx, "t1", m.ID)
			if err != nil || !b.Active(*now) || len(with) != 0 || len(e.calls) != 1 || e.calls[0] != "t1/p2//banned" {
				t.Fatalf("ban now: %+v with %+v err %v ended %v", b, with, err, e.calls)
			}
			if status(t, s, "p1") != StatusShadow {
				t.Fatal("the caught player left the pool")
			}
			if got, _ := s.Refused(ctx, "t1", "p1", "d1"); got != nil {
				t.Fatalf("the caught player is refused: %+v", got)
			}
		}
		if _, _, err := s.BanNow(ctx, "t1", m.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("banned twice: %v", err)
		}
		if got := h.take(); got != "" {
			t.Fatalf("hooks: %s", got)
		}
	}
}

// A person's ban from the session page is Ban now for a player in the pool.
func TestManualBanEndsThePoolForThePlayer(t *testing.T) {
	ctx := context.Background()
	s, st, e, _, now := newPool(t)
	s.Automatic(sess, "renderer_replaced", "x")
	entry, _ := s.Pooled(ctx, "t1", "p1")
	b, created, err := s.Ban(ctx, Request{Session: sess, By: "ada", Reason: "seen enough"})
	if err != nil || !created || b.ID != entry.ID || !b.Active(*now) || len(e.calls) != 1 {
		t.Fatalf("%+v created=%v err=%v ended=%v", b, created, err, e.calls)
	}
	if list, _ := st.ListBans(ctx, "t1", 0); len(list) != 1 {
		t.Fatalf("a second ban was made: %+v", list)
	}
}

// Release returns the player to normal and tells the hooks, with the accounts that joined
// through the device key. A released alternate account stays out of that entry, until it
// is caught itself.
func TestShadowPoolRelease(t *testing.T) {
	ctx := context.Background()
	s, st, e, h, now := newPool(t)
	s.Automatic(sess, "renderer_replaced", "x")
	alt := store.Session{SessionID: "a1", TenantID: "t1", PlayerHash: "p2", DeviceID: "d1"}
	s.Connected(ctx, alt)
	root, _ := s.Pooled(ctx, "t1", "p1")
	m, _ := s.Pooled(ctx, "t1", "p2")
	h.take()

	// The alternate account alone.
	if _, _, err := s.Release(ctx, "t2", m.ID, "ada", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another tenant: %v", err)
	}
	if _, with, err := s.Release(ctx, "t1", m.ID, "ada", "a brother"); err != nil || len(with) != 0 {
		t.Fatalf("release: %+v %v", with, err)
	}
	if got := h.take(); got != "lifted p2" {
		t.Fatalf("hooks: %s", got)
	}
	s.Connected(ctx, alt)
	if status(t, s, "p2") != StatusNormal || status(t, s, "p1") != StatusShadow || h.take() != "" {
		t.Fatal("the released account is back in the pool, or the caught player left it")
	}
	if s.Silent(alt, false) != true {
		// It plays on a device key of the pool: what is found there stays quiet.
		t.Fatal("a notice would be raised on a device key of the pool")
	}
	// Caught itself, it is in the pool again, with the same end.
	s.Automatic(alt, "foreign_module", "its own evidence")
	again, _ := s.Pooled(ctx, "t1", "p2")
	if again == nil || again.ID == m.ID || again.Rule != "foreign_module" || !again.EffectiveAt.Equal(root.EffectiveAt) || h.take() != "banned p2" {
		t.Fatalf("caught after a release: %+v", again)
	}

	// The caught player: both leave.
	b, with, err := s.Release(ctx, "t1", root.ID, "ada", "false alarm")
	if err != nil || !b.Lifted() || len(with) != 1 || with[0].PlayerHash != "p2" || !with[0].Lifted() {
		t.Fatalf("release: %+v with %+v err %v", b, with, err)
	}
	if got := h.take(); got != "lifted p1, lifted p2" {
		t.Fatalf("hooks: %s", got)
	}
	if pool, _ := s.Pool(ctx, "t1"); len(pool) != 0 {
		t.Fatalf("pool: %+v", pool)
	}
	if _, _, err := s.Release(ctx, "t1", root.ID, "ada", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("released twice: %v", err)
	}
	// Nothing lands later, and the device key pools nobody any more.
	*now = root.EffectiveAt.Add(time.Hour)
	s.Connected(ctx, store.Session{SessionID: "n1", TenantID: "t1", PlayerHash: "p7", DeviceID: "d1"})
	if n := s.Sweep(ctx); n != 0 || len(e.calls) != 0 || status(t, s, "p7") != StatusNormal {
		t.Fatalf("after the release: landed %d, ended %v", n, e.calls)
	}
	for _, p := range []string{"p1", "p2"} {
		if got, _ := s.Refused(ctx, "t1", p, "d1"); got != nil {
			t.Fatalf("%s is refused after the release: %+v", p, got)
		}
	}
	if list, _ := st.ListBans(ctx, "t1", 0); len(list) != 3 {
		t.Fatalf("bans kept as history: %+v", list)
	}
}

// A ban that landed and is lifted later takes the alternate accounts' bans with it.
func TestLiftAfterThePoolLiftsTheAlternateAccounts(t *testing.T) {
	ctx := context.Background()
	s, _, _, _, now := newPool(t)
	s.Automatic(sess, "renderer_replaced", "x")
	s.Connected(ctx, store.Session{SessionID: "a1", TenantID: "t1", PlayerHash: "p2", DeviceID: "d1"})
	root, _ := s.Pooled(ctx, "t1", "p1")
	*now = root.EffectiveAt
	s.Sweep(ctx)
	if _, with, err := s.Lift(ctx, "t1", root.ID, "ada", "appeal"); err != nil || len(with) != 1 {
		t.Fatalf("lift: %+v %v", with, err)
	}
	for _, p := range []string{"p1", "p2"} {
		if got, _ := s.Refused(ctx, "t1", p, "d1"); got != nil {
			t.Fatalf("%s is still refused: %+v", p, got)
		}
	}
}

// Entries keep the end they were made with when the period changes or is turned off.
func TestShadowPeriodChangeKeepsEntries(t *testing.T) {
	ctx := context.Background()
	s, st, _, _, now := newPool(t)
	s.Automatic(sess, "renderer_replaced", "x")
	_ = st.SetShadowPeriod(ctx, "t1", 0)
	b, _ := s.Pooled(ctx, "t1", "p1")
	if b == nil || !b.EffectiveAt.Equal(now.Add(period)) {
		t.Fatalf("entry: %+v", b)
	}
	other := store.Session{SessionID: "s9", TenantID: "t1", PlayerHash: "p9", DeviceID: "d9"}
	s.Automatic(other, "renderer_replaced", "x")
	if got, _ := s.Refused(ctx, "t1", "p9", ""); got == nil || got.Shadow {
		t.Fatalf("with the period off the ban is immediate: %+v", got)
	}
}

// A gateway that was down when a period ended has no timer for it. The player is
// refused from the end on all the same, and the first sweep after the start makes the
// ban take effect: once, with the second account of that PC, and in the audit log.
func TestShadowPoolEndsAfterARestart(t *testing.T) {
	ctx := context.Background()
	s, st, _, _, now := newPool(t)
	s.Automatic(sess, "renderer_replaced", "an unsigned renderer")
	s.Connected(ctx, store.Session{SessionID: "s2", TenantID: "t1", PlayerHash: "p2", DeviceID: "d1"})
	if pool, _ := s.Pool(ctx, "t1"); len(pool) != 2 {
		t.Fatalf("pool before the restart: %+v", pool)
	}

	later := now.Add(period + time.Hour)
	again := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	again.Now = func() time.Time { return later }
	e := &ended{}
	again.SetEnder(e)
	if pool, _ := again.Pool(ctx, "t1"); len(pool) != 0 {
		t.Fatalf("still in the pool after the period: %+v", pool)
	}
	for _, p := range []string{"p1", "p2"} {
		if got, _ := again.Refused(ctx, "t1", p, "d9"); got == nil {
			t.Fatalf("%s is not refused before the sweep", p)
		}
	}
	if n := again.Sweep(ctx); n != 2 || len(e.calls) != 2 {
		t.Fatalf("sweep after the restart: %d, ended %v", n, e.calls)
	}
	if n := again.Sweep(ctx); n != 0 || len(e.calls) != 2 {
		t.Fatalf("second sweep: %d, ended %v", n, e.calls)
	}
	if got := audited(t, st); got != "shadow.enter by automatic, shadow.join by automatic, shadow.end by automatic, shadow.end by automatic" {
		t.Fatalf("audit: %s", got)
	}
	list, _ := st.ListBans(ctx, "t1", 10)
	for _, b := range list {
		if !b.Active(later) || b.LandedAt.IsZero() || b.EffectiveAt.After(later) {
			t.Fatalf("ban after the sweep: %+v", b)
		}
	}
}
