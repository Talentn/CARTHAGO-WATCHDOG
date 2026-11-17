// carthago-demo is the buyer demo: one command that starts a gateway for a demo studio
// and plays one story against it, with no game. Simulated game clients sign in over the
// real client protocol and report; a simulated game server reports money over the real
// game-server API; the Oracle scores simulated matches. Everything that follows (evidence,
// bans, the shadow pool, the ledger's flags, the Oracle's ordering) is the gateway's own
// doing, and the dashboard shows it.
//
// Nothing in it is a cheat or touches a game or this PC: what a "cheater" does here is a
// report a simulated client sends.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"carthago/backend/internal/sim/localgw"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8790", "where the demo's gateway listens")
	dash := flag.String("dashboard-listen", "127.0.0.1:8791", "where the demo's dashboard listens")
	matches := flag.Int("matches", 34, "simulated matches the Oracle learns the studio's normal play from (10 players each; fewer than 30 leaves it learning)")
	exit := flag.Bool("exit", false, "stop after the story instead of keeping the dashboard up")
	admin := flag.Bool("admin", false, "also print a one-time link that creates an admin account, for the Users and Audit log pages and the settings (the demo key is a reviewer, and stops signing in once an admin exists)")
	flag.Parse()
	os.Exit(run(*listen, *dash, *matches, *exit, *admin, os.Stdout))
}

func run(listen, dash string, matches int, exit, admin bool, out io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fail := func(err error) int {
		fmt.Fprintln(out, "ERROR:", err)
		fmt.Fprintln(out, "RESULT: the demo did not run")
		return 2
	}
	fmt.Fprintln(out, "Carthago Watchdog: buyer demo")
	fmt.Fprintln(out, "No game is needed. The players are simulated clients on the real client protocol, the game server is")
	fmt.Fprintln(out, "simulated on the real server API, and the gateway, its rules, its bans and its dashboard are the product.")
	dir, err := os.MkdirTemp("", "carthago-demo-")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(dir)

	fmt.Fprintf(out, "\nPreparing: %d simulated matches for the Oracle (a quarter of a minute)...\n", matches)
	history, err := prepareOracle(filepath.Join(dir, "oracle"), matches)
	if err != nil {
		return fail(err)
	}
	gw, err := localgw.Start(ctx, localgw.Config{Dir: dir, Listen: listen, DashboardListen: dash, OracleDir: filepath.Join(dir, "oracle")})
	if err != nil {
		return fail(err)
	}
	defer gw.Close()
	fmt.Fprintf(out, "Gateway %s and dashboard %s started for studio %q; client notices on, automatic bans on.\n", gw.API, gw.Dashboard, localgw.Tenant)

	s := &story{ctx: ctx, out: out, gw: gw, history: history, pcs: map[string]pc{}}
	passed, total := s.play()
	pagesOK, pages := s.pages()

	invite := ""
	if admin {
		if invite, err = gw.AdminInvite(ctx); err != nil {
			return fail(err)
		}
	}
	fmt.Fprintf(out, "\nDashboard: %s   studio: %s   key: %s   (the \"Demo login\" box of the sign-in page)\n", gw.Dashboard, localgw.Tenant, localgw.DashboardKey)
	if invite != "" {
		fmt.Fprintf(out, "Admin: open this one-time link instead, choose a password and sign in as admin: %s\n", invite)
	}
	if !exit {
		fmt.Fprintln(out, "It stays up until you press Ctrl+C; nothing is kept afterwards.")
	}
	code := 0
	verdict := "PASS"
	if passed != total || pagesOK != pages {
		code, verdict = 1, "FAIL"
	}
	fmt.Fprintf(out, "RESULT: %s, %d of %d chapters as expected, %d of %d dashboard pages show data\n", verdict, passed, total, pagesOK, pages)
	if !exit {
		<-ctx.Done()
	}
	return code
}

// say prints one line of the narration.
func (s *story) say(format string, a ...any) { fmt.Fprintf(s.out, "   "+format+"\n", a...) }

// wait polls ok for up to d.
func (s *story) wait(d time.Duration, ok func() bool) bool {
	deadline := time.Now().Add(d)
	for {
		if ok() {
			return true
		}
		if time.Now().After(deadline) || s.ctx.Err() != nil {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func list(names []string) string {
	switch len(names) {
	case 0:
		return "nobody"
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}
