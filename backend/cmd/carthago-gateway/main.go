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

	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/attest/ekroots"
	"carthago/backend/internal/dashboard"
	"carthago/backend/internal/gateway"
	"carthago/backend/internal/knowledge"
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
	if len(os.Args) > 1 && os.Args[1] == "dashboard-user" {
		os.Exit(dashboardUserCommand(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
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
	flag.Var(dashKeys, "dashboard-key", "tenant=shared-demo-key (repeatable): the demo login, for a loopback dashboard only and only until that tenant has a user account; default demo=demo-dashboard-key with the default tenant")
	dashSecure := flag.Bool("dashboard-secure-cookie", false, "the dashboard sits behind a TLS-terminating proxy: mark its cookies Secure and send HSTS")
	dashAuthOpts := dashAuthFlagSet(flag.CommandLine)
	maxHandshakes := flag.Int("max-handshakes", 0, "client handshakes allowed in progress at once (0 = default 1024)")
	maxHandshakesIP := flag.Int("max-handshakes-per-ip", 0, "client handshakes allowed in progress per remote address (0 = default 32; raise behind a proxy)")
	autoKick := flag.Bool("auto-kick", false, "kick sessions on critical client integrity evidence (behavioural evidence never kicks)")
	dashHosts := flag.String("dashboard-host", "", "comma-separated host names the dashboard answers to, besides localhost when it listens on loopback (e.g. the name a reverse proxy forwards)")
	clientNotices := flag.Bool("client-notices", false, "tell a client when its session is flagged by evidence that stands on its own (a signed notice with a category and a severity; it never kicks)")
	allowRendererLibrary := flag.Bool("allow-renderer-library", false, "for a game build that ships its own renderer library: an unsigned opengl32, d3d9, ddraw or glu32 loaded from outside the system directory is excused when the first recorded start of the game had it. By default it always counts as a replaced renderer (a wallhack) and raises the notice")
	clientNoticesStrict := flag.Bool("client-notices-strict", false, "with -client-notices: also send the notices that are held back by default because an honest, modified game build can produce the same evidence (things present since the first recorded start of a game, changed or new files of the game folder, read-only handles, engine code rewritten while server add-ons are loaded)")
	mapPins := flag.String("map-pins", "", "file of trusted map geometries, one `map_id sha256` per line (the line carthago-cs16-bridge map-hash prints); a geometry uploaded for a listed map with another hash is refused and that match is not scored for information leaks")
	mapPinsRequired := flag.Bool("map-pins-required", false, "with -map-pins: also refuse geometry for maps the file does not list")
	leakAlert := flag.Bool("leak-alert", false, "opt-in live wallhack rule: a player whose information-leak score is strong in two separate windows of one match gets information_leak_live evidence during the match and, with -client-notices, a notice of the visibility category when the slot is bound to a verified session. Off, information_leak is evidence for review at the end of a match and never tells the player")
	testNotice := flag.Duration("test-notice-after", 0, "development: send every session a notice of category test this long after its client connected (0 = never)")
	oracleCfg := oracleFlagSet(flag.CommandLine)
	flag.Parse()
	if len(tenants) == 0 {
		tenants["demo"] = demoServerKey
		if len(dashKeys) == 0 && *dashListen != "" && gateway.IsLoopbackListen(*dashListen) {
			dashKeys["demo"] = demoDashboardKey
		}
	}
	// A dashboard that serves HTTPS itself is as good as one behind a TLS proxy.
	*dashSecure = *dashSecure || dashAuthOpts.tls()
	dashAuthOpts.dataDir, dashAuthOpts.memory = *dataDir, *storeKind != "sqlite"
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
	pcfg := pipeline.Config{AutoKick: *autoKick, Notices: *clientNotices, NoticesOptIn: *clientNoticesStrict, MapPinsRequired: *mapPinsRequired, Observer: orc.observer}
	pcfg.Rules = analyzer.Defaults()
	pcfg.Rules.AllowRendererLibrary = *allowRendererLibrary
	if *mapPins != "" {
		if pcfg.MapPins, err = loadMapPins(*mapPins); err != nil {
			log.Error("map-pins", "err", err)
			os.Exit(1)
		}
		log.Info("map pins loaded", "file", *mapPins, "maps", len(pcfg.MapPins), "required", *mapPinsRequired)
	}
	if *leakAlert {
		a := knowledge.DefaultAlert()
		pcfg.LeakAlert = &a
		log.Info("live information-leak rule on (opt-in)", "window_s", a.WindowSec, "window_z", a.Z, "min_excess", a.MinExcess, "windows", a.Windows, "tells_the_player", *clientNotices)
	}
	detections := pipeline.New(pcfg, st, st, kick, log)
	defer detections.Close()
	gw = gateway.New(gateway.Config{
		Tenants: tenants, HeartbeatInterval: *hbInterval, HeartbeatTimeout: *hbTimeout, TokenTTL: *ttl, FetchEKCerts: *fetchEK, EKRoots: roots,
		Detections: detections, MaxHandshakes: *maxHandshakes, MaxHandshakesPerIP: *maxHandshakesIP, TestNoticeAfter: *testNotice,
	}, keys, st, log)
	detections.SetNotifier(gw)
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

// loadMapPins reads `map_id sha256` lines; '#' starts a comment.
func loadMapPins(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pins := map[string]string{}
	for i, line := range strings.Split(string(raw), "\n") {
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 {
			return nil, fmt.Errorf("%s line %d: want `map_id sha256`", path, i+1)
		}
		if b, err := hex.DecodeString(f[1]); err != nil || len(b) != 32 {
			return nil, fmt.Errorf("%s line %d: %q is not a SHA-256 in hex", path, i+1, f[1])
		}
		if old, dup := pins[f[0]]; dup && !strings.EqualFold(old, f[1]) {
			return nil, fmt.Errorf("%s line %d: %s is pinned twice with different hashes", path, i+1, f[0])
		}
		pins[f[0]] = strings.ToLower(f[1])
	}
	return pins, nil
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
// dashboard served in plaintext to other hosts or given a shared login key there, and
// tenants sharing a server key (the key is what selects the tenant). dashSecure means the
// dashboard is reached over TLS: its own, or a proxy's in front of it.
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
		if !dashSecure {
			return fmt.Errorf("refusing to serve the dashboard on %s in plain HTTP: give it -dashboard-tls-cert and -dashboard-tls-key, or put it behind a TLS-terminating proxy and say so with -dashboard-secure-cookie", dashListen)
		}
		for tenant := range dashKeys {
			return fmt.Errorf("refusing to serve the dashboard on %s with a shared login key for tenant %q: -dashboard-key is the demo login and works on loopback only; remove it and create an admin with: carthago-gateway dashboard-user add-admin -tenant %s -name <name>", dashListen, tenant, tenant)
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
		log.Info("dashboard has no shared demo key: people sign in with accounts; the first admin of a studio is created with: carthago-gateway dashboard-user add-admin")
	}
	d, err := dashboard.New(dashboard.Config{Keys: keys, SecureCookie: secure, AllowedHosts: hosts, Oracle: orc}, st, log)
	if err != nil {
		return err
	}
	if err := dashAuth.configure(d, addr); err != nil {
		return err
	}
	dashTLS, err := dashAuth.tlsConfig()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	ds := &http.Server{Handler: d.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10, TLSConfig: dashTLS}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = ds.Shutdown(sctx)
	}()
	go func() {
		var err error
		if dashTLS != nil {
			log.Info("Carthago Watchdog dashboard listening", "addr", "https://"+addr, "demo_keys", len(keys))
			err = ds.ServeTLS(ln, "", "")
		} else {
			log.Info("Carthago Watchdog dashboard listening", "addr", "http://"+addr, "demo_keys", len(keys))
			err = ds.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("dashboard listen", "err", err)
		}
	}()
	return nil
}
