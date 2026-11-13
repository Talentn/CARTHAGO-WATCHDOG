// Package gateway terminates client WebSockets: Hello/Challenge/Prove handshake, TPM
// attestation, session tokens and heartbeat deadlines (plan §5.2-5.4), plus the game-server
// control channel that delivers kicks.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/attest/ekroots"
	"carthago/backend/internal/protocol"
	"carthago/backend/internal/store"
)

type Config struct {
	// Tenants maps tenant id to the server API key its game servers authenticate with.
	Tenants map[string]string

	HeartbeatInterval time.Duration
	HeartbeatTimeout  time.Duration
	TokenTTL          time.Duration
	// RenewBefore: a heartbeat ack carries a fresh token once the current one is this close to expiry.
	RenewBefore time.Duration
	// HelloTimeout bounds the wait for Hello; ProveTimeout the wait for Prove (TPM work
	// on first contact includes AK creation, which takes seconds).
	HelloTimeout time.Duration
	ProveTimeout time.Duration
	// FetchEKCerts allows contacting TPM manufacturer services for EK certificates not in NV
	// and following AIA URLs for missing EK chain intermediates.
	FetchEKCerts bool
	// EKRoots are the trusted TPM manufacturer CAs; nil means the embedded bundle.
	EKRoots *ekroots.Bundle

	// MaxHandshakes and MaxHandshakesPerIP bound client handshakes in progress, in total
	// and per remote address; further connections get HTTP 503. Raise the per-address
	// limit when clients reach the gateway through a proxy that hides their address.
	MaxHandshakes      int
	MaxHandshakesPerIP int

	// Detections receives every accepted heartbeat and serves /v1/ingest; nil disables both.
	Detections Detections

	// Bans, when set, is asked at every handshake whether the account or the device key is
	// banned (internal/bans). Nil: nobody is refused for a ban.
	Bans BanChecker
	// TestNoticeAfter sends every session an enforcement notice of category TEST this long
	// after its client connected, to try a game's alert screen. Zero disables it.
	TestNoticeAfter time.Duration

	Now func() time.Time
}

// BanChecker returns the ban that refuses an account or a device key now, nil for none.
type BanChecker interface {
	Refused(ctx context.Context, tenant, playerHash, deviceID string) (*store.Ban, error)
}

// Detections is the analysis pipeline (internal/pipeline). Heartbeat must not block.
type Detections interface {
	Heartbeat(sess store.Session, hb *pb.Heartbeat)
	Gameplay(ctx context.Context, tenant string, b *pb.GameplayBatch) (accepted bool, warning string, err error)
}

func (c *Config) defaults() {
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = 15 * time.Second
	}
	if c.HeartbeatTimeout == 0 {
		c.HeartbeatTimeout = 3 * c.HeartbeatInterval
	}
	if c.TokenTTL == 0 {
		c.TokenTTL = 15 * time.Minute
	}
	if c.RenewBefore == 0 {
		c.RenewBefore = c.TokenTTL / 3
	}
	if c.HelloTimeout == 0 {
		c.HelloTimeout = 10 * time.Second
	}
	if c.ProveTimeout == 0 {
		c.ProveTimeout = 60 * time.Second
	}
	if c.MaxHandshakes <= 0 {
		c.MaxHandshakes = defaultMaxHandshakes
	}
	if c.MaxHandshakesPerIP <= 0 {
		c.MaxHandshakesPerIP = defaultMaxHandshakesPerIP
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.EKRoots == nil {
		b, err := ekroots.Default()
		if err != nil {
			panic(err) // the embedded bundle is checked by ekroots tests
		}
		c.EKRoots = b
	}
}

type Gateway struct {
	cfg        Config
	keys       *Keys
	store      store.Store
	sessions   *Manager
	log        *slog.Logger
	handshakes *handshakeGate
}

func New(cfg Config, keys *Keys, st store.Store, log *slog.Logger) *Gateway {
	cfg.defaults()
	return &Gateway{cfg: cfg, keys: keys, store: st, sessions: NewManager(st, log, cfg.Now), log: log, handshakes: newHandshakeGate(cfg.MaxHandshakes, cfg.MaxHandshakesPerIP)}
}

func (g *Gateway) Sessions() *Manager { return g.sessions }

// Notice tells the client of an active session that the session was flagged: a signed
// EnforcementNotice carrying a category and a severity, nothing about the rule behind it.
// It informs only; the session stays up. A session gets at most one notice per category.
func (g *Gateway) Notice(sessionID string, category pb.EnforcementCategory, severity pb.EnforcementSeverity) bool {
	sid, err := hex.DecodeString(sessionID)
	if err != nil || len(sid) != protocol.SessionIDLen {
		return false
	}
	id := make([]byte, protocol.NoticeIDLen)
	if _, err := rand.Read(id); err != nil {
		return false
	}
	issued, delivered, err := g.sessions.Notify(sessionID, uint32(category), func(rec store.Session) (*pb.EnforcementNotice, error) {
		return protocol.SignNotice(g.keys.Identity, g.keys.IdentityKID, &pb.EnforcementNoticeBody{
			NoticeId: id, SessionId: sid, TenantId: rec.TenantID, PlayerIdHash: rec.PlayerHash,
			IssuedAtMs: uint64(g.cfg.Now().UnixMilli()), Category: uint32(category), Severity: uint32(severity),
		})
	})
	if err != nil {
		g.log.Warn("enforcement notice", "session", sessionID, "err", err)
		return false
	}
	if issued {
		g.log.Info("enforcement notice", "session", sessionID, "notice", hex.EncodeToString(id), "category", noticeName(category.String(), "ENFORCEMENT_CATEGORY_"),
			"severity", noticeName(severity.String(), "ENFORCEMENT_SEVERITY_"), "delivered", delivered)
	}
	return issued
}

func noticeName(s, prefix string) string { return strings.ToLower(strings.TrimPrefix(s, prefix)) }

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/client", g.handleClient)
	mux.HandleFunc("GET /v1/gs", g.handleGameServer)
	if g.cfg.Detections != nil {
		mux.HandleFunc("GET /v1/ingest", g.handleIngest)
	}
	mux.HandleFunc("GET /v1/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g.keys.Public())
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	return mux
}
