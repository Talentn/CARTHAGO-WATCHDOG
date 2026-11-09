// Command gateway is the Sentinel client gateway (plan §4): WebSocket handshake, TPM
// attestation, session tokens, heartbeat deadlines and game-server kicks.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"sentinel/backend/internal/gateway"
	"sentinel/backend/internal/store"
)

type tenantFlag map[string]string

func (t tenantFlag) String() string { return fmt.Sprint(map[string]string(t)) }
func (t tenantFlag) Set(v string) error {
	id, key, ok := strings.Cut(v, "=")
	if !ok || id == "" || key == "" {
		return errors.New("want tenant=server-key")
	}
	t[id] = key
	return nil
}

func main() {
	tenants := tenantFlag{}
	listen := flag.String("listen", "127.0.0.1:8750", "listen address")
	dataDir := flag.String("data", "gateway-data", "directory for keys, public-keys.json and the SQLite database")
	storeKind := flag.String("store", "sqlite", "sqlite | memory")
	flag.Var(tenants, "tenant", "tenant=server-key (repeatable); default demo=demo-server-key")
	hbInterval := flag.Duration("hb-interval", 15*time.Second, "client heartbeat interval")
	hbTimeout := flag.Duration("hb-timeout", 45*time.Second, "heartbeat deadline before a kick")
	ttl := flag.Duration("token-ttl", 15*time.Minute, "session token lifetime")
	fetchEK := flag.Bool("fetch-ek", false, "fetch EK certificates from TPM manufacturer services when not in NV")
	verbose := flag.Bool("v", false, "debug logging (per-heartbeat lines)")
	flag.Parse()
	if len(tenants) == 0 {
		tenants["demo"] = "demo-server-key"
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	keys, err := gateway.LoadOrCreateKeys(*dataDir)
	if err != nil {
		log.Error("keys", "err", err)
		os.Exit(1)
	}
	pubPath := filepath.Join(*dataDir, "public-keys.json")
	if err := keys.WritePublic(pubPath); err != nil {
		log.Error("write public keys", "err", err)
		os.Exit(1)
	}
	var st store.Store = store.NewMemory()
	if *storeKind == "sqlite" {
		if st, err = store.OpenSQLite(filepath.Join(*dataDir, "gateway.db")); err != nil {
			log.Error("sqlite", "err", err)
			os.Exit(1)
		}
	}
	defer st.Close()

	gw := gateway.New(gateway.Config{
		Tenants: tenants, HeartbeatInterval: *hbInterval, HeartbeatTimeout: *hbTimeout, TokenTTL: *ttl, FetchEKCerts: *fetchEK,
	}, keys, st, log)
	srv := &http.Server{Addr: *listen, Handler: gw.Handler(), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				gw.Sessions().Prune(10 * time.Minute)
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("gateway listening", "addr", *listen, "store", *storeKind, "public_keys", pubPath,
		"identity_kid", keys.IdentityKID, "token_kid", keys.TokenKID, "tenants", len(tenants), "hb_interval", *hbInterval, "hb_timeout", *hbTimeout)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}
