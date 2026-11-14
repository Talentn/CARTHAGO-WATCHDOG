// Package bans decides who is banned and applies it: the dashboard's "Ban player", the
// gateway's automatic ban on certain evidence, the refusal at the handshake and the end of
// a banned player's live sessions all go through one Service.
package bans

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/store"
)

// Store is what the service needs from the gateway's store.
type Store interface {
	store.BanStore
	GetDevice(ctx context.Context, id string) (*store.Device, error)
}

// Ender ends the live sessions of an account or a device key (gateway.Manager). It
// returns how many it ended.
type Ender interface {
	EndSessions(tenant, playerHash, deviceID, reason string) int
}

type auditor interface {
	AppendAudit(ctx context.Context, e *store.AuditEntry) error
}

// KickReason is what a session ended by a ban is told. Like the refusal, it says nothing
// about what was detected.
const KickReason = "banned"

type Service struct {
	st  Store
	log *slog.Logger
	// Now is the clock; tests replace it.
	Now func() time.Time

	mu   sync.Mutex
	end  Ender
	hook Hook
}

// Hook is told about every ban made and every ban lifted (the economy ledger marks and
// unmarks the money a banned player passed on).
type Hook interface {
	Banned(b *store.Ban)
	Lifted(b *store.Ban)
}

// SetHook names who is told about bans and lifts.
func (s *Service) SetHook(h Hook) {
	s.mu.Lock()
	s.hook = h
	s.mu.Unlock()
}

func (s *Service) hooked() Hook {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hook
}

func New(st Store, log *slog.Logger) *Service {
	return &Service{st: st, log: log, Now: time.Now}
}

// SetEnder names what ends live sessions. Without one a ban still refuses the next
// handshake.
func (s *Service) SetEnder(e Ender) {
	s.mu.Lock()
	s.end = e
	s.mu.Unlock()
}

// Request is one ban to make from a session.
type Request struct {
	Session store.Session
	By      string // a dashboard account's name; empty for an automatic ban
	Reason  string
	Rule    string
}

// Ban bans the session's account and the device key the session used. created is false
// when a ban already stands for either, which is then returned unchanged. A ban made by a
// person takes effect at once; an automatic one after the tenant's delay.
func (s *Service) Ban(ctx context.Context, r Request) (b *store.Ban, created bool, err error) {
	sess := r.Session
	if sess.TenantID == "" || sess.PlayerHash == "" {
		return nil, false, errors.New("bans: a session without a tenant or a player")
	}
	automatic := r.By == ""
	now := s.Now()
	standing, err := s.st.StandingBan(ctx, sess.TenantID, sess.PlayerHash, sess.DeviceID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, false, err
	}
	// A person's ban is still made when the one that stands is only pending.
	if err == nil && (automatic || standing.Active(now)) {
		return standing, false, nil
	}
	b = &store.Ban{TenantID: sess.TenantID, Ref: newRef(), PlayerHash: sess.PlayerHash, DeviceID: sess.DeviceID,
		Reason: r.Reason, Rule: r.Rule, SessionID: sess.SessionID, BannedBy: r.By, BannedAt: now, EffectiveAt: now}
	if sess.DeviceID != "" {
		if d, err := s.st.GetDevice(ctx, sess.DeviceID); err == nil {
			b.DeviceTPM = d.KeyAlg == int32(pb.DeviceKeyAlg_DEVICE_KEY_ALG_ECDSA_P256_TPM)
		}
	}
	if automatic {
		b.BannedBy = store.BanAutomatic
		delay, err := s.st.BanDelay(ctx, sess.TenantID)
		if err != nil {
			return nil, false, err
		}
		b.EffectiveAt = now.Add(delay)
	}
	if err := s.st.AddBan(ctx, b); err != nil {
		return nil, false, err
	}
	pending := b.EffectiveAt.Sub(now)
	s.log.Info("ban", "ref", b.Ref, "tenant", b.TenantID, "player", b.PlayerHash, "device", b.DeviceID, "device_tpm", b.DeviceTPM,
		"by", b.BannedBy, "rule", b.Rule, "session", b.SessionID, "effective_in", pending.String())
	if automatic {
		s.audit(ctx, b)
	}
	if pending > 0 {
		time.AfterFunc(pending, func() { s.applyDue(b.TenantID, b.ID, b.PlayerHash, b.DeviceID) })
	} else {
		s.endSessions(b)
	}
	if h := s.hooked(); h != nil {
		h.Banned(b)
	}
	return b, true, nil
}

// Automatic bans a session on evidence of the certain tier (analyzer.Evidence.Certain). It
// is what the detection pipeline calls; failures are logged.
func (s *Service) Automatic(sess store.Session, rule, summary string) {
	if len(summary) > 280 {
		summary = summary[:280]
	}
	if _, _, err := s.Ban(context.Background(), Request{Session: sess, Reason: summary, Rule: rule}); err != nil {
		s.log.Warn("automatic ban", "session", sess.SessionID, "rule", rule, "err", err)
	}
}

func (s *Service) audit(ctx context.Context, b *store.Ban) {
	au, ok := s.st.(auditor)
	if !ok {
		return
	}
	detail := fmt.Sprintf("ban %s, rule %s, device key %s", b.Ref, b.Rule, orNone(b.DeviceID))
	if b.EffectiveAt.After(b.BannedAt) {
		detail += ", pending until " + b.EffectiveAt.UTC().Format(time.RFC3339)
	}
	target := "session " + b.SessionID
	if b.SessionID == "" {
		// A ban from the economy ledger is about an account, not a session.
		target = "player " + b.PlayerHash
	}
	e := &store.AuditEntry{TenantID: b.TenantID, At: b.BannedAt, Actor: store.BanAutomatic, Action: "ban.add", Target: target, Detail: detail}
	if err := au.AppendAudit(ctx, e); err != nil {
		s.log.Warn("audit automatic ban", "ref", b.Ref, "err", err)
	}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// applyDue ends the live sessions of a pending ban that has come due, unless it was
// lifted in the meantime.
func (s *Service) applyDue(tenant string, id int64, playerHash, deviceID string) {
	b, err := s.st.StandingBan(context.Background(), tenant, playerHash, deviceID)
	if err != nil || !b.Active(s.Now()) {
		return
	}
	s.log.Info("pending ban applied", "ref", b.Ref, "tenant", tenant, "player", playerHash, "ban", id)
	s.endSessions(b)
}

func (s *Service) endSessions(b *store.Ban) {
	s.mu.Lock()
	end := s.end
	s.mu.Unlock()
	if end == nil {
		return
	}
	if n := end.EndSessions(b.TenantID, b.PlayerHash, b.DeviceID, KickReason); n > 0 {
		s.log.Info("sessions ended by ban", "ref", b.Ref, "sessions", n)
	}
}

// Lift ends a standing ban, pending or active.
func (s *Service) Lift(ctx context.Context, tenant string, id int64, by, note string) (*store.Ban, error) {
	b, err := s.st.LiftBan(ctx, tenant, id, by, note, s.Now())
	if err == nil {
		s.log.Info("ban lifted", "ref", b.Ref, "tenant", tenant, "player", b.PlayerHash, "by", by)
		if h := s.hooked(); h != nil {
			h.Lifted(b)
		}
	}
	return b, err
}

// Refused returns the ban that refuses this account or device key now, nil when there is
// none. A pending ban refuses nobody.
func (s *Service) Refused(ctx context.Context, tenant, playerHash, deviceID string) (*store.Ban, error) {
	b, err := s.st.StandingBan(ctx, tenant, playerHash, deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil || !b.Active(s.Now()) {
		return nil, err
	}
	return b, nil
}

// refAlphabet leaves out the characters that are mistaken for each other when read aloud
// or typed from a screenshot.
const refAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// newRef is the reference a banned player sees: random, so it tells nothing about how
// many bans there are or when this one was made.
func newRef() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err)
	}
	out := []byte("CW-0000-0000")
	for i, r := range raw {
		pos := 3 + i
		if i >= 4 {
			pos++
		}
		out[pos] = refAlphabet[int(r)%len(refAlphabet)]
	}
	return string(out)
}
