package bans

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

type ended struct{ calls []string }

func (e *ended) EndSessions(tenant, playerHash, deviceID, reason string) int {
	e.calls = append(e.calls, tenant+"/"+playerHash+"/"+deviceID+"/"+reason)
	return 1
}

func newService(t *testing.T) (*Service, *store.Memory, *ended, *time.Time) {
	t.Helper()
	st := store.NewMemory()
	s := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.UnixMilli(1_700_000_000_000).UTC()
	s.Now = func() time.Time { return now }
	e := &ended{}
	s.SetEnder(e)
	return s, st, e, &now
}

var sess = store.Session{SessionID: "s1", TenantID: "t1", PlayerHash: "p1", DeviceID: "d1"}

// A pending ban ends the player's session when it comes due, and not if it was lifted
// before that.
func TestPendingBanIsAppliedWhenDue(t *testing.T) {
	ctx := context.Background()
	for _, lifted := range []bool{false, true} {
		s, st, e, now := newService(t)
		_ = st.SetBanDelay(ctx, "t1", time.Hour)
		s.Automatic(sess, "mapped_image", "an image was mapped by hand")
		list, _ := st.ListBans(ctx, "t1", 0)
		if len(list) != 1 || !list[0].Pending(*now) || list[0].BannedBy != store.BanAutomatic || list[0].Rule != "mapped_image" {
			t.Fatalf("bans: %+v", list)
		}
		b := list[0]
		if !regexp.MustCompile(`^CW-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`).MatchString(b.Ref) {
			t.Fatalf("reference %q", b.Ref)
		}
		if got, _ := s.Refused(ctx, "t1", "p1", "d1"); got != nil || len(e.calls) != 0 {
			t.Fatalf("a pending ban refused the player or ended a session: %+v %v", got, e.calls)
		}
		// More certain evidence in the meantime does not make a second ban.
		s.Automatic(sess, "foreign_module", "again")
		if list, _ := st.ListBans(ctx, "t1", 0); len(list) != 1 {
			t.Fatalf("a second ban was made: %+v", list)
		}
		if lifted {
			if _, err := s.Lift(ctx, "t1", b.ID, "ada", "false alarm"); err != nil {
				t.Fatal(err)
			}
		}
		*now = now.Add(time.Hour)
		s.applyDue("t1", b.ID, "p1", "d1")
		got, _ := s.Refused(ctx, "t1", "p1", "d1")
		if lifted && (got != nil || len(e.calls) != 0) {
			t.Fatalf("a lifted ban was applied: %+v %v", got, e.calls)
		}
		if !lifted && (got == nil || len(e.calls) != 1 || e.calls[0] != "t1/p1/d1/banned") {
			t.Fatalf("the due ban was not applied: %+v %v", got, e.calls)
		}
	}
}

// A person's ban takes effect at once, also over a pending automatic one.
func TestManualBanIsImmediate(t *testing.T) {
	ctx := context.Background()
	s, st, e, now := newService(t)
	_ = st.SetBanDelay(ctx, "t1", time.Hour)
	s.Automatic(sess, "mapped_image", "x")
	b, created, err := s.Ban(ctx, Request{Session: sess, By: "ada", Reason: "confirmed"})
	if err != nil || !created || !b.Active(*now) || b.BannedBy != "ada" || len(e.calls) != 1 {
		t.Fatalf("manual ban: %+v created=%v err=%v ended=%v", b, created, err, e.calls)
	}
	if got, _ := s.Refused(ctx, "t1", "p1", ""); got == nil || got.ID != b.ID {
		t.Fatalf("refused: %+v", got)
	}
	if _, _, err := s.Ban(ctx, Request{Session: store.Session{SessionID: "s2"}, By: "ada"}); err == nil {
		t.Fatal("banned a session without a tenant or a player")
	}
}
