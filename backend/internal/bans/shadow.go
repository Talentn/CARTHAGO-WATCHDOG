package bans

import (
	"context"
	"errors"
	"time"

	"carthago/backend/internal/store"
)

// The shadow pool. While a studio's shadow period is on, certain evidence does not refuse
// the player at once: the ban is made with the end of the period as the time it takes
// effect, and until then the player is in the pool. Nothing the player's client is sent
// differs from a normal player's; the studio's matchmaking asks who is in the pool and
// matches those players with each other. From entry the player's sessions are labelled,
// their files count toward proposed known cheats and money they pass on is marked dirty,
// exactly as for a ban, because the entry is one: Banned and Lifted reach the same hooks.

// StatusNormal and StatusShadow are what a studio's matchmaking is told about a player.
const (
	StatusNormal = "normal"
	StatusShadow = "shadow"
)

// SessionHook is a Hook that is also told when a player in the shadow pool starts another
// session, so what the pool collects covers it.
type SessionHook interface {
	PoolSession(b *store.Ban, sess store.Session)
}

// Pooled returns the ban that keeps an account in the shadow pool now, nil when the
// account is not in it.
func (s *Service) Pooled(ctx context.Context, tenant, playerHash string) (*store.Ban, error) {
	b, err := s.st.StandingBan(ctx, tenant, playerHash, "")
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil || !b.InPool(s.Now()) {
		return nil, err
	}
	return b, nil
}

// Pool lists the tenant's shadow pool, the entry that ends first first.
func (s *Service) Pool(ctx context.Context, tenant string) ([]store.Ban, error) {
	list, err := s.st.ListShadowBans(ctx, tenant)
	if err != nil {
		return nil, err
	}
	now := s.Now()
	out := list[:0]
	for _, b := range list {
		if b.InPool(now) {
			out = append(out, b)
		}
	}
	return out, nil
}

// Silent reports whether nothing may tell this session's player what was found: the
// player is in the shadow pool, or certain is set and this evidence is about to put the
// player there. The detection pipeline asks before it raises a notice or ends a session.
func (s *Service) Silent(sess store.Session, certain bool) bool {
	ctx := context.Background()
	b, err := s.st.StandingBan(ctx, sess.TenantID, sess.PlayerHash, sess.DeviceID)
	switch {
	case err == nil:
		// The account's own entry, or the entry of the device key it plays on. A ban that
		// stands already is not made again, so certain changes nothing here.
		if b.InPool(s.Now()) {
			return true
		}
		own, err := s.Pooled(ctx, sess.TenantID, sess.PlayerHash)
		return err == nil && own != nil
	case !errors.Is(err, store.ErrNotFound):
		s.log.Warn("shadow pool", "session", sess.SessionID, "err", err)
		return false
	case !certain:
		return false
	}
	period, err := s.st.ShadowPeriod(ctx, sess.TenantID)
	if err != nil {
		s.log.Warn("shadow pool", "session", sess.SessionID, "err", err)
	}
	return err == nil && period > 0
}

// Connected is told about every session once its handshake has passed, before the client
// has its answer. The session of a player in the pool is handed to the hooks. An account
// with no ban of its own that connects from the device key of a player in the pool joins
// the pool with the same end, unless a reviewer released it from that entry before.
func (s *Service) Connected(ctx context.Context, sess store.Session) {
	now := s.Now()
	own, err := s.st.StandingBan(ctx, sess.TenantID, sess.PlayerHash, "")
	if err == nil {
		if own.InPool(now) {
			for _, h := range s.hooked() {
				if sh, ok := h.(SessionHook); ok {
					sh.PoolSession(own, sess)
				}
			}
		}
		return
	}
	// The same two lookups for every session, so a handshake takes as long for a player
	// in the pool as for anybody else up to the moment something has to be written.
	var dev *store.Ban
	if errors.Is(err, store.ErrNotFound) && sess.DeviceID != "" {
		dev, err = s.st.StandingBan(ctx, sess.TenantID, "", sess.DeviceID)
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Warn("shadow pool", "session", sess.SessionID, "err", err)
		return
	}
	if dev == nil || !dev.InPool(now) {
		return
	}
	if _, err := s.join(ctx, sess, dev, now, nil); err != nil {
		s.log.Warn("shadow pool: join", "session", sess.SessionID, "of", dev.Ref, "err", err)
	}
}

// join puts the account of a session into the pool through dev, the ban of a player in
// the pool whose device key the session uses. It returns nil when the account has a ban
// of its own already, or when a reviewer released it from this entry before and caught is
// nil; caught is the certain evidence the account itself produced now.
func (s *Service) join(ctx context.Context, sess store.Session, dev *store.Ban, now time.Time, caught *Request) (*store.Ban, error) {
	s.pool.Lock()
	defer s.pool.Unlock()
	if _, err := s.st.StandingBan(ctx, sess.TenantID, sess.PlayerHash, ""); !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	of := dev.Ref
	if dev.ShadowOf != "" {
		of = dev.ShadowOf
	}
	members, err := s.st.ListShadowMembers(ctx, sess.TenantID, of)
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		if m.PlayerHash == sess.PlayerHash && caught == nil {
			// Released from this entry by a reviewer: it stays out.
			return nil, nil
		}
	}
	// The device key is in the ban this one follows, which takes effect at the same time.
	b := &store.Ban{TenantID: sess.TenantID, Ref: newRef(), PlayerHash: sess.PlayerHash, Rule: dev.Rule, SessionID: sess.SessionID,
		Reason: "connected from the device key of " + of, BannedBy: store.BanAutomatic, BannedAt: now, EffectiveAt: dev.EffectiveAt, Shadow: true, ShadowOf: of}
	if caught != nil {
		b.Rule, b.Reason = caught.Rule, caught.Reason
	}
	if err := s.st.AddBan(ctx, b); err != nil {
		return nil, err
	}
	s.log.Info("shadow pool: an account joined through a device key", "ref", b.Ref, "of", of, "tenant", b.TenantID, "player", b.PlayerHash, "device", sess.DeviceID, "ends", b.EffectiveAt)
	s.audit(ctx, b)
	s.made(b, b.EffectiveAt.Sub(now))
	return b, nil
}

// BanNow ends the shadow pool early for one entry: its ban takes effect now. For the
// player who was caught, the accounts that joined through that player's device key are
// banned with it and returned in with. ErrNotFound when the tenant has no such entry.
func (s *Service) BanNow(ctx context.Context, tenant string, id int64) (b *store.Ban, with []store.Ban, err error) {
	return s.finish(ctx, tenant, id, true)
}

func (s *Service) finish(ctx context.Context, tenant string, id int64, early bool) (b *store.Ban, with []store.Ban, err error) {
	if b, err = s.land(ctx, tenant, id, early); err != nil {
		return nil, nil, err
	}
	if b.ShadowOf != "" {
		return b, nil, nil
	}
	members, err := s.st.ListShadowMembers(ctx, tenant, b.Ref)
	if err != nil {
		return b, nil, err
	}
	for _, m := range members {
		got, err := s.land(ctx, tenant, m.ID, early)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return b, with, err
		}
		with = append(with, *got)
	}
	return b, with, nil
}

// land applies one ban of the shadow pool: from now on it refuses the player, and the
// player's live sessions end as for any ban. Only the first caller for a ban gets it.
func (s *Service) land(ctx context.Context, tenant string, id int64, early bool) (*store.Ban, error) {
	now := s.Now()
	b, err := s.st.LandShadowBan(ctx, tenant, id, now)
	if err != nil {
		return nil, err
	}
	s.log.Info("shadow pool: ban in effect", "ref", b.Ref, "tenant", tenant, "player", b.PlayerHash, "device", b.DeviceID, "early", early)
	if !early {
		// What a person does is recorded by the dashboard, with who did it.
		detail := "the shadow period ended: player " + b.PlayerHash + " banned"
		switch {
		case b.DeviceID != "":
			detail += ", with device key " + b.DeviceID
		case b.ShadowOf != "":
			detail += "; the device key is banned by " + b.ShadowOf
		}
		s.record(ctx, &store.AuditEntry{TenantID: tenant, At: now, Actor: store.BanAutomatic, Action: "shadow.end", Target: "ban " + b.Ref, Detail: detail})
	}
	s.endSessions(b)
	return b, nil
}

func (s *Service) landDue(tenant string, id int64) {
	if _, _, err := s.finish(context.Background(), tenant, id, false); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Warn("shadow pool: end of the period", "tenant", tenant, "ban", id, "err", err)
	}
}

// Sweep lands every ban of the shadow pool whose period is over, for all tenants, and
// returns how many. The timer of an entry does this on time while the gateway runs; Sweep
// is for the entries of a gateway that was restarted, and for a period that ended while
// it was down.
func (s *Service) Sweep(ctx context.Context) int {
	list, err := s.st.ListShadowBans(ctx, "")
	if err != nil {
		s.log.Warn("shadow pool: sweep", "err", err)
		return 0
	}
	now, n := s.Now(), 0
	for _, b := range list {
		if b.Pending(now) {
			continue
		}
		if _, err := s.land(ctx, b.TenantID, b.ID, false); err == nil {
			n++
		} else if !errors.Is(err, store.ErrNotFound) {
			s.log.Warn("shadow pool: sweep", "ref", b.Ref, "err", err)
		}
	}
	return n
}

// Run sweeps now and then every interval until ctx is done.
func (s *Service) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		s.Sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Release takes one entry out of the shadow pool: the player is normal again and what the
// entry caused is undone, as when a ban is lifted. The accounts that joined through the
// player's device key are released with it. ErrNotFound when the tenant has no such
// entry in the pool.
func (s *Service) Release(ctx context.Context, tenant string, id int64, by, note string) (b *store.Ban, with []store.Ban, err error) {
	pool, err := s.Pool(ctx, tenant)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range pool {
		if e.ID == id {
			return s.Lift(ctx, tenant, id, by, note)
		}
	}
	return nil, nil, store.ErrNotFound
}
