// Package localgw starts a complete Carthago gateway inside a demo tool: the real
// handshake with TPM attestation, the detection pipeline, the ban service with the shadow
// pool, the known-cheat list, the economy ledger, the Oracle when it is given a bundle,
// the game-server API and the dashboard, over a SQLite database in a folder the tool
// chooses. It is wired the way cmd/carthago-gateway wires it, with client notices and
// automatic bans on, and listens on loopback only.
package localgw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/attest/ekroots"
	"carthago/backend/internal/bans"
	"carthago/backend/internal/dashboard"
	"carthago/backend/internal/economy"
	"carthago/backend/internal/gateway"
	"carthago/backend/internal/learning"
	"carthago/backend/internal/oracle"
	"carthago/backend/internal/oracle/analyst"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/store"
)

const (
	Tenant       = "demo"
	ServerKey    = "demo-server-key"
	DashboardKey = "demo-dashboard-key"
)

type Config struct {
	// Dir holds the database and the gateway's keys.
	Dir string
	// Listen and DashboardListen are loopback addresses.
	Listen, DashboardListen string
	// HeartbeatInterval is what the gateway asks of its clients. Default 1 s, so a demo
	// does not wait.
	HeartbeatInterval time.Duration
	// OracleDir, when set, holds an Oracle bundle: sessions are scored, and the built-in
	// analyst without a language model writes the opinions.
	OracleDir string
	// Log receives the gateway's own log lines. Default: none.
	Log io.Writer
}

// Gateway is the running gateway and what a demo needs to look inside it.
type Gateway struct {
	Store    *store.SQLite
	Bans     *bans.Service
	Oracle   *oracle.Engine
	Bundle   *oracle.Bundle
	Identity ed25519.PublicKey
	// API is http://host:port of the client and game-server API, Dashboard of the dashboard.
	API, Dashboard string

	stop []func()
}

type kickFunc func(id, reason string)

func (f kickFunc) Kick(id, reason string) { f(id, reason) }

// Start opens the database, starts the gateway and serves both listeners.
func Start(ctx context.Context, cfg Config) (*Gateway, error) {
	out := cfg.Log
	if out == nil {
		out = io.Discard
	}
	log := slog.New(slog.NewTextHandler(out, nil))
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = time.Second
	}
	for _, addr := range []string{cfg.Listen, cfg.DashboardListen} {
		if !gateway.IsLoopbackListen(addr) {
			return nil, fmt.Errorf("%s is not a loopback address: the demo keys must not be reachable from other machines", addr)
		}
	}
	st, err := store.OpenSQLite(filepath.Join(cfg.Dir, "gateway.db"))
	if err != nil {
		return nil, err
	}
	g := &Gateway{Store: st}
	ok := false
	defer func() {
		if !ok {
			g.Close()
		}
	}()
	keys, err := gateway.LoadOrCreateKeys(cfg.Dir)
	if err != nil {
		return nil, err
	}
	if err := keys.WritePublic(filepath.Join(cfg.Dir, "public-keys.json")); err != nil {
		return nil, err
	}
	g.Identity = keys.Identity.Public().(ed25519.PublicKey)
	roots, err := ekroots.Default()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	g.stop = append(g.stop, cancel)

	var info *dashboard.OracleInfo
	var observer pipeline.Observer
	if cfg.OracleDir != "" {
		if g.Bundle, err = oracle.LoadBundle(cfg.OracleDir); err != nil {
			return nil, err
		}
		an, err := analyst.New(analyst.Config{Provider: analyst.Stub{},
			Prompts: analyst.Prompts{Version: g.Bundle.Manifest.Analyst.PromptVersion, System: g.Bundle.SystemPrompt, Case: g.Bundle.CasePrompt}, Usage: st})
		if err != nil {
			return nil, err
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		// A demo's sessions are reviewed while they are still connected and without the
		// usual wait for a burst of findings to settle.
		if g.Oracle, err = oracle.New(oracle.Config{Bundle: g.Bundle, Analyst: an, PseudonymKey: key, ReviewLive: true, Settle: time.Second}, st, log); err != nil {
			return nil, err
		}
		go g.Oracle.Run(ctx)
		s := g.Oracle.Status()
		info = &dashboard.OracleInfo{BundleID: s.BundleID, ModelID: s.ModelID, Analyst: s.Analyst, AnalystModel: s.AnalystModel, PromptVersion: s.PromptVersion}
		observer = g.Oracle
	}

	var gw *gateway.Gateway
	pcfg := pipeline.Config{Notices: true, Rules: analyzer.Defaults()}
	if observer != nil {
		pcfg.Observer = observer
	}
	detections := pipeline.New(pcfg, st, st, kickFunc(func(id, reason string) { gw.Sessions().Kick(id, reason) }), log)
	g.stop = append(g.stop, detections.Close)
	g.Bans = bans.New(st, log)
	detections.SetBanner(g.Bans)
	detections.SetKnownCheats(st)
	detections.SetPool(g.Bans)
	ledger := economy.New(st, g.Bans, log)
	g.Bans.AddHook(ledger)
	g.Bans.AddHook(learning.NewLabeler(st, log))
	gw = gateway.New(gateway.Config{
		Tenants: map[string]string{Tenant: ServerKey}, HeartbeatInterval: cfg.HeartbeatInterval, HeartbeatTimeout: 30 * time.Second, EKRoots: roots,
		Detections: detections, Bans: g.Bans, Pool: g.Bans, Drivers: st, Economy: ledger,
	}, keys, st, log)
	detections.SetNotifier(gw)
	g.Bans.SetEnder(gw.Sessions())
	go g.Bans.Run(ctx, time.Second)

	d, err := dashboard.New(dashboard.Config{Keys: map[string]string{Tenant: DashboardKey}, AllowedHosts: []string{"localhost", "127.0.0.1", "::1"}, Oracle: info, Bans: g.Bans}, st, log)
	if err != nil {
		return nil, err
	}
	if err := d.ConfigureAuth(dashboard.AuthConfig{Loopback: true}); err != nil {
		return nil, err
	}
	var addrs []string
	for _, s := range []struct {
		addr string
		h    http.Handler
	}{{cfg.Listen, gw.Handler()}, {cfg.DashboardListen, d.Handler()}} {
		ln, err := net.Listen("tcp", s.addr)
		if err != nil {
			return nil, fmt.Errorf("%w (another run may still be open: close it, or pick other ports with -listen and -dashboard-listen)", err)
		}
		srv := &http.Server{Handler: s.h, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		g.stop = append(g.stop, func() { _ = srv.Close() })
		addrs = append(addrs, ln.Addr().String())
	}
	g.API, g.Dashboard = "http://"+addrs[0], "http://"+addrs[1]
	ok = true
	return g, nil
}

// ClientURL is what a client SDK is given as its gateway.
func (g *Gateway) ClientURL() string { return "ws" + g.API[len("http"):] + "/v1/client" }

// IdentityHex is the gateway identity key a client pins.
func (g *Gateway) IdentityHex() string { return hex.EncodeToString(g.Identity) }

// AdminInvite is a one-time link that creates an admin account on the dashboard. Once an
// admin exists the shared demo key no longer signs in.
func (g *Gateway) AdminInvite(ctx context.Context) (string, error) {
	token, _, err := dashboard.Bootstrap{Store: g.Store}.InviteAdmin(ctx, Tenant, "admin")
	if err != nil {
		return "", err
	}
	return g.Dashboard + "/invite/" + token, nil
}

func (g *Gateway) Close() {
	for i := len(g.stop) - 1; i >= 0; i-- {
		g.stop[i]()
	}
	_ = g.Store.Close()
}
