// carthago-econ-sim plays a studio's game server against the economy ledger of a
// Carthago gateway: four short scenarios over the real game-server API, each with its
// outcome. With no flags it starts a gateway of its own on this PC, with a dashboard to
// look at the result. It simulates reports only; there is no game and no cheat in it.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"time"

	"carthago/backend/internal/bans"
	"carthago/backend/internal/dashboard"
	"carthago/backend/internal/economy"
	"carthago/backend/internal/gateway"
	"carthago/backend/internal/store"
)

const (
	demoTenant       = "demo"
	demoServerKey    = "demo-server-key"
	demoDashboardKey = "demo-dashboard-key"
	// The limit the farming scenario runs into.
	robberyPerHour, robberyPerDay = 5_000, 20_000
)

func main() {
	remote := flag.String("gateway", "", "URL of a gateway that is already running, e.g. https://127.0.0.1:8443 (default: start one inside this tool)")
	key := flag.String("key", demoServerKey, "the tenant's server key")
	listen := flag.String("listen", "127.0.0.1:8760", "where the tool's own gateway listens")
	dash := flag.String("dashboard-listen", "127.0.0.1:8761", "where the tool's own dashboard listens")
	exit := flag.Bool("exit", false, "stop after the scenarios instead of keeping the dashboard up")
	flag.Parse()
	os.Exit(run(*remote, *key, *listen, *dash, *exit, os.Stdout))
}

func run(remote, key, listen, dash string, exit bool, out io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Fprintln(out, "Carthago economy ledger: simulated game server")
	base, dashURL := remote, ""
	if remote == "" {
		dir, err := os.MkdirTemp("", "carthago-econ-sim-")
		if err != nil {
			fmt.Fprintln(out, "ERROR:", err)
			return 2
		}
		defer os.RemoveAll(dir)
		l, err := newLocal(dir)
		if err != nil {
			fmt.Fprintln(out, "ERROR:", err)
			return 2
		}
		defer l.close()
		for addr, h := range map[string]http.Handler{listen: l.api, dash: l.dash} {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				fmt.Fprintf(out, "ERROR: %v\nAnother run of this tool may still be open; close it, or pick other ports with -listen and -dashboard-listen.\n", err)
				return 2
			}
			srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
			go func() { _ = srv.Serve(ln) }()
			defer srv.Close()
		}
		base, dashURL, key = "http://"+listen, "http://"+dash, demoServerKey
		fmt.Fprintf(out, "gateway    %s, started by this tool (robbery limit: %s per hour, %s per day)\n", base, economy.Amount(robberyPerHour), economy.Amount(robberyPerDay))
	} else {
		fmt.Fprintf(out, "gateway    %s (set a limit for robbery of %s per hour on its Economy page first)\n", base, economy.Amount(robberyPerHour))
	}
	passed, total := scenarios(newGameServer(base, key), out)
	fmt.Fprintf(out, "\nRESULT: %d of %d scenarios passed\n", passed, total)
	code := 0
	if passed != total {
		code = 1
	}
	if dashURL != "" && !exit {
		fmt.Fprintf(out, "\nDashboard: %s  (studio %s, key %s), page Economy.\nPress Ctrl+C to stop; nothing is kept.\n", dashURL, demoTenant, demoDashboardKey)
		<-ctx.Done()
	}
	return code
}

// local is a gateway inside this tool: the real ledger, ban service, game-server API and
// dashboard over a database in a scratch folder.
type local struct {
	api, dash http.Handler
	st        *store.SQLite
}

func (l *local) close() { _ = l.st.Close() }

func newLocal(dir string) (*local, error) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		return nil, err
	}
	keys, err := gateway.LoadOrCreateKeys(dir)
	if err != nil {
		return nil, err
	}
	if err := st.SetEconomyLimit(context.Background(), store.EconomyLimit{TenantID: demoTenant, Source: "robbery", Currency: economy.DefaultCurrency, PerHour: robberyPerHour, PerDay: robberyPerDay}); err != nil {
		return nil, err
	}
	banning := bans.New(st, log)
	ledger := economy.New(st, banning, log)
	banning.SetHook(ledger)
	gw := gateway.New(gateway.Config{Tenants: map[string]string{demoTenant: demoServerKey}, Bans: banning, Economy: ledger}, keys, st, log)
	banning.SetEnder(gw.Sessions())
	d, err := dashboard.New(dashboard.Config{Keys: map[string]string{demoTenant: demoDashboardKey}, Bans: banning}, st, log)
	if err != nil {
		return nil, err
	}
	if err := d.ConfigureAuth(dashboard.AuthConfig{Loopback: true}); err != nil {
		return nil, err
	}
	return &local{api: gw.Handler(), dash: d.Handler(), st: st}, nil
}

func runID() string { return strconv.FormatInt(time.Now().UnixMilli()%(36*36*36*36), 36) }
