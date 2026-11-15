// carthago-shadow-sim plays a studio's matchmaker against the shadow pool of a Carthago
// gateway: simulated players sign in over the real client protocol, the matchmaker asks
// the real game-server API who is in the pool, and five short scenes show what follows.
// It starts a gateway of its own on this PC, with a dashboard to look at the result.
// The players are simulated clients that send reports; there is no game and no cheat in
// it.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"carthago/backend/internal/bans"
	"carthago/backend/internal/dashboard"
	"carthago/backend/internal/gateway"
	"carthago/backend/internal/learning"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/store"
)

const (
	demoTenant       = "demo"
	demoServerKey    = "demo-server-key"
	demoDashboardKey = "demo-dashboard-key"
	// The period the players caught for the dashboard are left with.
	dashboardPeriod = 48 * time.Hour
	minPeriod       = 10 * time.Second
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8770", "where the tool's gateway listens")
	dash := flag.String("dashboard-listen", "127.0.0.1:8771", "where the tool's dashboard listens")
	period := flag.Duration("period", 20*time.Second, "the shadow period of the run, so the ban is seen to take effect (a studio sets hours or days)")
	exit := flag.Bool("exit", false, "stop after the scenes instead of keeping the dashboard up")
	admin := flag.Bool("admin", false, "also print a one-time link that creates an admin account on the tool's dashboard, to try the period setting (the demo key is a reviewer, and stops signing in once an admin exists)")
	flag.Parse()
	os.Exit(run(*listen, *dash, *period, *exit, *admin, os.Stdout))
}

func run(listen, dash string, period time.Duration, exit, admin bool, out io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fail := func(err error) int {
		fmt.Fprintln(out, "ERROR:", err)
		return 2
	}
	if period < minPeriod {
		return fail(fmt.Errorf("-period is at least %s: the scenes need that long before the ban takes effect", minPeriod))
	}
	fmt.Fprintln(out, "Carthago shadow pool: simulated matchmaker")
	dir, err := os.MkdirTemp("", "carthago-shadow-sim-")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(dir)
	l, err := newLocal(ctx, dir)
	if err != nil {
		return fail(err)
	}
	defer l.close()
	var addrs []string
	for _, s := range []struct {
		addr string
		h    http.Handler
	}{{listen, l.api}, {dash, l.dash}} {
		ln, err := net.Listen("tcp", s.addr)
		if err != nil {
			fmt.Fprintf(out, "ERROR: %v\nAnother run of this tool may still be open; close it, or pick other ports with -listen and -dashboard-listen.\n", err)
			return 2
		}
		srv := &http.Server{Handler: s.h, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		defer srv.Close()
		addrs = append(addrs, ln.Addr().String())
	}
	dashURL, invite := "http://"+addrs[1], ""
	if admin {
		token, _, err := dashboard.Bootstrap{Store: l.st}.InviteAdmin(ctx, demoTenant, "admin")
		if err != nil {
			return fail(err)
		}
		invite = dashURL + "/invite/" + token
	}
	if err := l.setPeriod(ctx, period); err != nil {
		return fail(err)
	}
	fmt.Fprintf(out, "gateway    http://%s, started by this tool; client notices on, automatic bans on\n", addrs[0])
	fmt.Fprintf(out, "period     %s for this run, so you see the ban take effect (a studio sets hours or days)\n", period)

	s := &sim{ctx: ctx, out: out, local: l, api: "http://" + addrs[0], ws: "ws://" + addrs[0] + "/v1/client", key: demoServerKey, period: period}
	passed, total := s.scenes()
	fmt.Fprintf(out, "\nRESULT: %d of %d scenes passed\n", passed, total)
	code := 0
	if passed != total {
		code = 1
	}
	if err := s.leaveSome(); err != nil {
		fmt.Fprintln(out, "ERROR:", err)
		code = 2
	}
	if !exit && code != 2 {
		if invite != "" {
			fmt.Fprintf(out, "\nDashboard: open this one-time link, choose a password, sign in as admin of studio %s, page Shadow pool:\n  %s\n", demoTenant, invite)
		} else {
			fmt.Fprintf(out, "\nDashboard: %s  (studio %s, key %s), page Shadow pool.\n", dashURL, demoTenant, demoDashboardKey)
		}
		fmt.Fprintln(out, "Press Ctrl+C to stop; nothing is kept.")
		<-ctx.Done()
	}
	return code
}

// local is a gateway inside this tool: the real handshake, detection pipeline, ban
// service, game-server API and dashboard over a database in a scratch folder.
type local struct {
	api, dash http.Handler
	st        *store.SQLite
	bans      *bans.Service
	identity  ed25519.PublicKey
	stop      func()
}

func (l *local) close() {
	l.stop()
	_ = l.st.Close()
}

type kickFunc func(id, reason string)

func (f kickFunc) Kick(id, reason string) { f(id, reason) }

func newLocal(ctx context.Context, dir string) (*local, error) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		return nil, err
	}
	keys, err := gateway.LoadOrCreateKeys(dir)
	if err != nil {
		return nil, err
	}
	banning := bans.New(st, log)
	banning.AddHook(learning.NewLabeler(st, log))
	var gw *gateway.Gateway
	detections := pipeline.New(pipeline.Config{Notices: true}, st, st, kickFunc(func(id, reason string) { gw.Sessions().Kick(id, reason) }), log)
	detections.SetBanner(banning)
	detections.SetKnownCheats(st)
	detections.SetPool(banning)
	gw = gateway.New(gateway.Config{
		Tenants: map[string]string{demoTenant: demoServerKey}, HeartbeatInterval: 500 * time.Millisecond, HeartbeatTimeout: 15 * time.Second,
		Detections: detections, Bans: banning, Pool: banning, Drivers: st,
	}, keys, st, log)
	detections.SetNotifier(gw)
	banning.SetEnder(gw.Sessions())
	ctx, cancel := context.WithCancel(ctx)
	go banning.Run(ctx, time.Second)
	d, err := dashboard.New(dashboard.Config{Keys: map[string]string{demoTenant: demoDashboardKey}, Bans: banning}, st, log)
	if err != nil {
		cancel()
		return nil, err
	}
	if err := d.ConfigureAuth(dashboard.AuthConfig{Loopback: true}); err != nil {
		cancel()
		return nil, err
	}
	return &local{api: gw.Handler(), dash: d.Handler(), st: st, bans: banning, identity: keys.Identity.Public().(ed25519.PublicKey), stop: func() {
		cancel()
		detections.Close()
	}}, nil
}

// setPeriod is the admin's period setting. The dashboard and the command line take hours
// or days; the run sets seconds, straight in the store, so the end can be watched.
func (l *local) setPeriod(ctx context.Context, d time.Duration) error {
	if err := l.st.SetShadowPeriod(ctx, demoTenant, d); err != nil {
		return err
	}
	return l.st.AppendAudit(ctx, &store.AuditEntry{TenantID: demoTenant, At: time.Now(), Actor: "simulation", Action: "shadow.period", Target: "shadow pool", Detail: "period set to " + d.String()})
}
