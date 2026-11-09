// Package gateway terminates client WebSockets: Hello/Challenge/Prove handshake, TPM
// attestation, session tokens and heartbeat deadlines (plan §5.2-5.4), plus the game-server
// control channel that delivers kicks.
package gateway

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"sentinel/backend/internal/store"
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
	// FetchEKCerts allows contacting TPM manufacturer services for EK certificates not in NV.
	FetchEKCerts bool

	Now func() time.Time
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
	if c.Now == nil {
		c.Now = time.Now
	}
}

type Gateway struct {
	cfg      Config
	keys     *Keys
	store    store.Store
	sessions *Manager
	log      *slog.Logger
}

func New(cfg Config, keys *Keys, st store.Store, log *slog.Logger) *Gateway {
	cfg.defaults()
	return &Gateway{cfg: cfg, keys: keys, store: st, sessions: NewManager(st, log, cfg.Now), log: log}
}

func (g *Gateway) Sessions() *Manager { return g.sessions }

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/client", g.handleClient)
	mux.HandleFunc("GET /v1/gs", g.handleGameServer)
	mux.HandleFunc("GET /v1/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g.keys.Public())
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	return mux
}
