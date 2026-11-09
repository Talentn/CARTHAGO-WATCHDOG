package gateway

import (
	"context"
	"log/slog"
	"sync"
	"time"

	pb "sentinel/backend/gen/sentinel/v1"
	"sentinel/backend/internal/store"
)

// Manager owns live sessions and their heartbeat deadlines. A missed deadline marks the
// session kicked and pushes a Kick to every game server watching it (plan §5.3: the game
// server enforces, the client never decides its own fate).
type Manager struct {
	store store.Store
	log   *slog.Logger
	now   func() time.Time

	mu       sync.Mutex
	sessions map[string]*liveSession
	watchers map[string]map[*gsConn]struct{}
}

type liveSession struct {
	rec     store.Session
	timeout time.Duration
	timer   *time.Timer
	// onKick notifies the client connection, if one is still attached.
	onKick func(reason string)
}

func NewManager(st store.Store, log *slog.Logger, now func() time.Time) *Manager {
	return &Manager{store: st, log: log, now: now, sessions: map[string]*liveSession{}, watchers: map[string]map[*gsConn]struct{}{}}
}

// Start registers an active session and arms its heartbeat deadline.
func (m *Manager) Start(rec store.Session, timeout time.Duration) error {
	rec.State = store.SessionActive
	if err := m.store.PutSession(context.Background(), &rec); err != nil {
		return err
	}
	ls := &liveSession{rec: rec, timeout: timeout}
	m.mu.Lock()
	m.sessions[rec.SessionID] = ls
	ls.timer = time.AfterFunc(timeout, func() { m.Kick(rec.SessionID, "heartbeat_timeout") })
	m.mu.Unlock()
	return nil
}

// Heartbeat pushes the deadline out. It returns false if the session is no longer active.
func (m *Manager) Heartbeat(id string, newExpiry time.Time) bool {
	m.mu.Lock()
	ls, ok := m.sessions[id]
	if !ok || ls.rec.State != store.SessionActive {
		m.mu.Unlock()
		return false
	}
	ls.timer.Reset(ls.timeout)
	ls.rec.LastHeartbeat = m.now()
	ls.rec.Heartbeats++
	if !newExpiry.IsZero() {
		ls.rec.ExpiresAt = newExpiry
	}
	rec := ls.rec
	m.mu.Unlock()
	if err := m.store.PutSession(context.Background(), &rec); err != nil {
		m.log.Warn("persist heartbeat", "session", id, "err", err)
	}
	return true
}

// Attach sets the client connection's kick callback; false if the session is not active.
func (m *Manager) Attach(id string, onKick func(reason string)) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	ls, ok := m.sessions[id]
	if !ok || ls.rec.State != store.SessionActive {
		return false
	}
	ls.onKick = onKick
	return true
}

// Detach drops the client callback when its connection ends; the deadline keeps running.
func (m *Manager) Detach(id string) {
	m.mu.Lock()
	if ls, ok := m.sessions[id]; ok {
		ls.onKick = nil
	}
	m.mu.Unlock()
}

func (m *Manager) Kick(id, reason string) {
	m.mu.Lock()
	ls, ok := m.sessions[id]
	if !ok || ls.rec.State != store.SessionActive {
		m.mu.Unlock()
		return
	}
	ls.timer.Stop()
	ls.rec.State, ls.rec.KickReason = store.SessionKicked, reason
	rec, notify := ls.rec, ls.onKick
	ls.onKick = nil
	var targets []*gsConn
	for c := range m.watchers[id] {
		targets = append(targets, c)
	}
	m.mu.Unlock()

	if err := m.store.PutSession(context.Background(), &rec); err != nil {
		m.log.Warn("persist kick", "session", id, "err", err)
	}
	m.log.Info("session kicked", "session", id, "reason", reason, "player", rec.PlayerHash, "game_servers_notified", len(targets),
		"heartbeats", rec.Heartbeats, "since_last_heartbeat", m.now().Sub(rec.LastHeartbeat).Round(time.Millisecond))
	kick := kickMsg(&rec, m.now())
	for _, c := range targets {
		c.send(&pb.GsServerMsg{Body: &pb.GsServerMsg_Kick{Kick: kick}})
	}
	if notify != nil {
		notify(reason)
	}
}

func kickMsg(rec *store.Session, now time.Time) *pb.Kick {
	return &pb.Kick{SessionId: rec.SessionID, Reason: rec.KickReason, AtMs: uint64(now.UnixMilli()), PlayerHash: rec.PlayerHash}
}

// Watch subscribes a game server to a session's kicks. A session that was already kicked
// produces its Kick immediately, so a late watcher cannot miss it.
func (m *Manager) Watch(c *gsConn, id string) (known bool, kick *pb.Kick) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ls, ok := m.sessions[id]
	if !ok || ls.rec.TenantID != c.tenant {
		return false, nil
	}
	if m.watchers[id] == nil {
		m.watchers[id] = map[*gsConn]struct{}{}
	}
	m.watchers[id][c] = struct{}{}
	if ls.rec.State == store.SessionKicked {
		return true, kickMsg(&ls.rec, m.now())
	}
	return true, nil
}

func (m *Manager) Unwatch(c *gsConn, id string) {
	m.mu.Lock()
	delete(m.watchers[id], c)
	m.mu.Unlock()
}

func (m *Manager) DropConn(c *gsConn) {
	m.mu.Lock()
	for id, w := range m.watchers {
		delete(w, c)
		if len(w) == 0 {
			delete(m.watchers, id)
		}
	}
	m.mu.Unlock()
}

// Prune forgets ended sessions older than keep (they stay in the store).
func (m *Manager) Prune(keep time.Duration) {
	cutoff := m.now().Add(-keep)
	m.mu.Lock()
	for id, ls := range m.sessions {
		if ls.rec.State != store.SessionActive && ls.rec.LastHeartbeat.Before(cutoff) {
			delete(m.sessions, id)
			delete(m.watchers, id)
		}
	}
	m.mu.Unlock()
}

func (m *Manager) Get(id string) (store.Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ls, ok := m.sessions[id]
	if !ok {
		return store.Session{}, false
	}
	return ls.rec, true
}
