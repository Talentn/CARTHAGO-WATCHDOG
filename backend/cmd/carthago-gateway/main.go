// Command carthago-gateway is the Carthago Gateway (plan §4): WebSocket handshake, TPM
// attestation, session tokens, heartbeat deadlines and game-server kicks.
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"carthago/backend/internal/attest/ekroots"
	"carthago/backend/internal/dashboard"
	"carthago/backend/internal/gateway"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/store"
)

// evidenceStore is what the detection pipeline and the dashboard need from the store.
type evidenceStore interface {
	store.Store
	store.EvidenceStore
	store.OracleStore
}

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
	fetchEK := flag.Bool("fetch-ek", false, "fetch EK certificates from TPM manufacturer services when not in NV, and missing EK chain intermediates via AIA")
	ekRootsDir := flag.String("ek-roots-dir", "", "directory of extra trusted EK root CA certificates (PEM or DER), e.g. a development swtpm CA")
	tlsCert := flag.String("tls-cert", "", "TLS certificate chain (PEM); with -tls-key serves wss://")
	tlsKey := flag.String("tls-key", "", "TLS private key (PEM)")
	tlsDev := flag.Bool("tls-dev-cert", false, "serve wss:// with a self-signed certificate kept in -data (created on first use)")
	tlsBackup := flag.String("tls-backup-pin", "", "comma-separated hex SPKI SHA-256 pins of the next TLS keys, published for rotation")
	verbose := flag.Bool("v", false, "debug logging (per-heartbeat lines)")
	dashListen := flag.String("dashboard-listen", "127.0.0.1:8751", "Carthago Watchdog dashboard listen address (empty disables)")
	dashKeys := tenantFlag{}
	flag.Var(dashKeys, "dashboard-key", "tenant=dashboard-login-key (repeatable); default demo=demo-dashboard-key with the default tenant")
	dashSecure := flag.Bool("dashboard-secure-cookie", false, "mark the dashboard cookie Secure (when served over HTTPS)")
	maxHandshakes := flag.Int("max-handshakes", 0, "client handshakes allowed in progress at once (0 = default 1024)")
	maxHandshakesIP := flag.Int("max-handshakes-per-ip", 0, "client handshakes allowed in progress per remote address (0 = default 32; raise behind a proxy)")
	autoKick := flag.Bool("auto-kick", false, "kick sessions on critical client integrity evidence (behavioural evidence never kicks)")
	dashHosts := flag.String("dashboard-host", "", "comma-separated host names the dashboard answers to, besides localhost when it listens on loopback (e.g. the name a reverse proxy forwards)")
	oracleCfg := oracleFlagSet(flag.CommandLine)
	flag.Parse()
	if len(tenants) == 0 {
		tenants["demo"] = demoServerKey
		if len(dashKeys) == 0 {
			dashKeys["demo"] = demoDashboardKey
		}
	}
	if err := checkExposure(*listen, *dashListen, tenants, dashKeys, *dashSecure); err != nil {
		fmt.Fprintln(os.Stderr, "carthago-gateway:", err)
		os.Exit(2)
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
	tlsCfg, err := loadTLS(*tlsCert, *tlsKey, *tlsDev, *dataDir)
	if err != nil {
		log.Error("tls", "err", err)
		os.Exit(1)
	}
	if tlsCfg != nil {
		pin, err := gateway.SPKIPin(tlsCfg.Certificates[0])
		if err != nil {
			log.Error("tls pin", "err", err)
			os.Exit(1)
		}
		backups, err := splitPins(*tlsBackup)
		if err != nil {
			log.Error("tls-backup-pin", "err", err)
			os.Exit(1)
		}
		keys.TLSPins = append([]string{pin}, backups...)
	} else if !gateway.IsLoopbackListen(*listen) {
		log.Error("refusing plaintext on a non-loopback address; use -tls-cert/-tls-key or -tls-dev-cert", "addr", *listen)
		os.Exit(1)
	}
	pubPath := filepath.Join(*dataDir, "public-keys.json")
	if err := keys.WritePublic(pubPath); err != nil {
		log.Error("write public keys", "err", err)
		os.Exit(1)
	}
	var st evidenceStore = store.NewMemory()
	if *storeKind == "sqlite" {
		if st, err = store.OpenSQLite(filepath.Join(*dataDir, "gateway.db")); err != nil {
			log.Error("sqlite", "err", err)
			os.Exit(1)
		}
	}
	defer st.Close()

	roots, err := loadEKRoots(*ekRootsDir)
	if err != nil {
		log.Error("ek roots", "err", err)
		os.Exit(1)
	}
	anchors, inters := roots.Counts()
	log.Info("EK roots loaded", "bundle", roots.Version, "anchors", anchors, "intermediates", inters, "extra_dir", *ekRootsDir)
	if w := extraRootsWarning(*ekRootsDir, *listen); w != "" {
		log.Warn(w, "dir", *ekRootsDir)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	orc, err := startOracle(ctx, oracleCfg, *dataDir, st, log)
	if err != nil {
		log.Error("oracle", "err", err)
		os.Exit(1)
	}
	defer orc.close()

	var gw *gateway.Gateway
	kick := kickFunc(func(id, reason string) { gw.Sessions().Kick(id, reason) })
	detections := pipeline.New(pipeline.Config{AutoKick: *autoKick, Observer: orc.observer}, st, st, kick, log)
	defer detections.Close()
	gw = gateway.New(gateway.Config{
		Tenants: tenants, HeartbeatInterval: *hbInterval, HeartbeatTimeout: *hbTimeout, TokenTTL: *ttl, FetchEKCerts: *fetchEK, EKRoots: roots,
		Detections: detections, MaxHandshakes: *maxHandshakes, MaxHandshakesPerIP: *maxHandshakesIP,
	}, keys, st, log)
	srv := &http.Server{Addr: *listen, Handler: gw.Handler(), ReadHeaderTimeout: 10 * time.Second, TLSConfig: tlsCfg}
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
	if *dashListen != "" {
		if err := serveDashboard(ctx, *dashListen, dashKeys, *dashSecure, dashboardHosts(*dashListen, *dashHosts), orc.info, st, log); err != nil {
			log.Error("dashboard", "err", err)
			os.Exit(1)
		}
	}
	scheme := "ws"
	if tlsCfg != nil {
		scheme = "wss"
	}
	log.Info("Carthago Gateway listening", "addr", *listen, "scheme", scheme, "tls_spki_sha256", strings.Join(keys.TLSPins, ","), "store", *storeKind, "public_keys", pubPath,
		"identity_kid", keys.IdentityKID, "token_kid", keys.TokenKID, "tenants", len(tenants), "hb_interval", *hbInterval, "hb_timeout", *hbTimeout)
	if tlsCfg != nil {
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}

// extraRootsWarning: certificates in -ek-roots-dir are trusted exactly like the bundled
// manufacturer roots, so whoever holds one of their keys can give an emulated TPM trust
// level 2 and 3. That is what a development swtpm CA is for, and not something to leave
// configured on a gateway that players reach.
func extraRootsWarning(dir, listen string) string {
	if dir == "" || gateway.IsLoopbackListen(listen) {
		return ""
	}
	return "extra EK roots are trusted like manufacturer roots on a non-loopback gateway: a TPM certified by any of them reaches trust level 2 and 3"
}

func loadEKRoots(dir string) (*ekroots.Bundle, error) {
	b, err := ekroots.Default()
	if err != nil || dir == "" {
		return b, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		files[e.Name()] = data
	}
	return b.WithExtraRoots(files)
}

func loadTLS(certFile, keyFile string, dev bool, dataDir string) (*tls.Config, error) {
	switch {
	case certFile != "" || keyFile != "":
		if certFile == "" || keyFile == "" || dev {
			return nil, errors.New("use -tls-cert with -tls-key, or -tls-dev-cert alone")
		}
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return gateway.TLSConfig(c), nil
	case dev:
		c, err := gateway.LoadOrCreateDevCert(dataDir)
		if err != nil {
			return nil, err
		}
		return gateway.TLSConfig(c), nil
	}
	return nil, nil
}

func splitPins(s string) ([]string, error) {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if b, err := hex.DecodeString(p); err != nil || len(b) != 32 {
			return nil, fmt.Errorf("pin %q: want 64 hex characters (SHA-256 of the SPKI)", p)
		}
		out = append(out, strings.ToLower(p))
	}
	return out, nil
}

const (
	demoServerKey    = "demo-server-key"
	demoDashboardKey = "demo-dashboard-key"
	// minExposedKeyLen is the shortest key accepted on a listener that is not loopback.
	minExposedKeyLen = 16
)

// checkExposure refuses configurations that are only acceptable on a developer machine:
// the built-in demo keys or short keys on a listener reachable from other hosts, a
// dashboard served in plaintext to other hosts, and tenants sharing a server key (the
// key is what selects the tenant).
func checkExposure(listen, dashListen string, tenants, dashKeys map[string]string, dashSecure bool) error {
	byKey := map[string]string{}
	for tenant, key := range tenants {
		if other, dup := byKey[key]; dup {
			return fmt.Errorf("tenants %q and %q share a server key; each tenant needs its own", other, tenant)
		}
		byKey[key] = tenant
	}
	if !gateway.IsLoopbackListen(listen) {
		for tenant, key := range tenants {
			if key == demoServerKey || len(key) < minExposedKeyLen {
				return fmt.Errorf("refusing to listen on %s with the demo or a short server key for tenant %q; set -tenant %s=<at least %d random characters>", listen, tenant, tenant, minExposedKeyLen)
			}
		}
	}
	if dashListen != "" && !gateway.IsLoopbackListen(dashListen) {
		for tenant, key := range dashKeys {
			if key == demoDashboardKey || len(key) < minExposedKeyLen {
				return fmt.Errorf("refusing to serve the dashboard on %s with the demo or a short key for tenant %q; set -dashboard-key %s=<at least %d random characters>", dashListen, tenant, tenant, minExposedKeyLen)
			}
		}
		if !dashSecure {
			return fmt.Errorf("refusing to serve the dashboard on %s without -dashboard-secure-cookie: it speaks plain HTTP, so off loopback it must sit behind a TLS-terminating proxy", dashListen)
		}
	}
	return nil
}

// dashboardHosts returns the Host names the dashboard answers to: the loopback names for a
// loopback listener plus any configured ones. An empty result disables the check (a
// non-loopback listener without -dashboard-host).
func dashboardHosts(dashListen, extra string) []string {
	var hosts []string
	if gateway.IsLoopbackListen(dashListen) {
		hosts = append(hosts, "localhost", "127.0.0.1", "::1")
	}
	for _, h := range strings.FieldsFunc(extra, func(r rune) bool { return r == ',' || r == ' ' }) {
		hosts = append(hosts, h)
	}
	return hosts
}

type kickFunc func(id, reason string)

func (f kickFunc) Kick(id, reason string) { f(id, reason) }

// serveDashboard runs the Carthago Watchdog dashboard on its own listener, so it can stay on
// loopback (or behind a VPN or proxy) while the client gateway faces the internet.
func serveDashboard(ctx context.Context, addr string, keys map[string]string, secure bool, hosts []string, orc *dashboard.OracleInfo, st evidenceStore, log *slog.Logger) error {
	if len(keys) == 0 {
		log.Warn("dashboard has no -dashboard-key entries; nobody can sign in")
	}
	d, err := dashboard.New(dashboard.Config{Keys: keys, SecureCookie: secure, AllowedHosts: hosts, Oracle: orc}, st, log)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	ds := &http.Server{Handler: d.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = ds.Shutdown(sctx)
	}()
	go func() {
		log.Info("Carthago Watchdog dashboard listening", "addr", "http://"+addr, "tenants", len(keys))
		if err := ds.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("dashboard listen", "err", err)
		}
	}()
	return nil
}
