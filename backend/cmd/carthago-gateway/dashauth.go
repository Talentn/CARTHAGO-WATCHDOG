package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"carthago/backend/internal/dashboard"
	"carthago/backend/internal/gateway"
	"carthago/backend/internal/store"
)

// dashAuthOptions are the gateway flags about signing in to the dashboard.
type dashAuthOptions struct {
	tlsCert, tlsKey string
	sessionTTL      time.Duration
	idleTimeout     time.Duration
	trustedProxies  string
	// dataDir and memory are copied from -data and -store once the flags are parsed.
	dataDir string
	memory  bool
}

// dashAuth is read by serveDashboard.
var dashAuth = &dashAuthOptions{}

func dashAuthFlagSet(fs *flag.FlagSet) *dashAuthOptions {
	o := dashAuth
	fs.StringVar(&o.tlsCert, "dashboard-tls-cert", "", "TLS certificate chain (PEM) for the dashboard; with -dashboard-tls-key the dashboard serves HTTPS itself")
	fs.StringVar(&o.tlsKey, "dashboard-tls-key", "", "TLS private key (PEM) for the dashboard")
	fs.DurationVar(&o.sessionTTL, "dashboard-session-ttl", 12*time.Hour, "a dashboard sign-in ends this long after it started, whatever happens")
	fs.DurationVar(&o.idleTimeout, "dashboard-idle-timeout", 30*time.Minute, "a dashboard sign-in ends after this long without a request")
	fs.StringVar(&o.trustedProxies, "dashboard-trusted-proxy", "", "comma-separated addresses or CIDR ranges of reverse proxies whose X-Forwarded-For header names the real client (for sign-in limits and the audit log)")
	return o
}

// tls reports whether the dashboard serves HTTPS itself.
func (o *dashAuthOptions) tls() bool { return o.tlsCert != "" || o.tlsKey != "" }

func (o *dashAuthOptions) tlsConfig() (*tls.Config, error) {
	if !o.tls() {
		return nil, nil
	}
	if o.tlsCert == "" || o.tlsKey == "" {
		return nil, errors.New("use -dashboard-tls-cert together with -dashboard-tls-key")
	}
	c, err := tls.LoadX509KeyPair(o.tlsCert, o.tlsKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12}, nil
}

func parseProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("-dashboard-trusted-proxy %q: want an address or a CIDR range", f)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

const dashboardKeyFile = "dashboard-secret.key"

// loadOrCreateDashboardKey reads the key that seals two-factor secrets and keys the
// recovery-code hashes, creating it on first use. It lives in the data directory, next to
// the database it protects and with the gateway's other keys. Losing it means every user
// has to enrol their authenticator app again.
func loadOrCreateDashboardKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, dashboardKeyFile)
	if b, err := os.ReadFile(path); err == nil {
		key, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(key) < 32 {
			return nil, fmt.Errorf("%s: want at least 64 hex characters", path)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
		f.Close()
		return nil, err
	}
	return key, f.Close()
}

// configure applies the sign-in options to a dashboard listening on addr.
func (o *dashAuthOptions) configure(d *dashboard.Server, addr string) error {
	proxies, err := parseProxies(o.trustedProxies)
	if err != nil {
		return err
	}
	c := dashboard.AuthConfig{Loopback: gateway.IsLoopbackListen(addr), SessionTTL: o.sessionTTL, IdleTimeout: o.idleTimeout, TrustedProxies: proxies}
	if !o.memory && o.dataDir != "" {
		if c.SecretKey, err = loadOrCreateDashboardKey(o.dataDir); err != nil {
			return err
		}
		if abs, err := filepath.Abs(o.dataDir); err == nil {
			c.DataDir = abs
		}
	}
	return d.ConfigureAuth(c)
}

const dashboardUserUsage = `Manage dashboard accounts on the gateway PC.

  carthago-gateway dashboard-user add-admin        -tenant ID -name NAME [-data DIR] [-url URL] [-password-stdin]
  carthago-gateway dashboard-user reset-password   -tenant ID -name NAME [-data DIR] [-url URL]
  carthago-gateway dashboard-user reset-two-factor -tenant ID -name NAME [-data DIR]
  carthago-gateway dashboard-user list             -tenant ID [-data DIR]

add-admin prints a one-time link. Whoever opens it in a browser chooses the password and
becomes an admin of that studio. Further users are invited by an admin in the dashboard.
With -password-stdin the account is created at once with the password read from standard
input, for scripted installs. The gateway can stay running while these commands are used.
`

// dashboardUserCommand runs "carthago-gateway dashboard-user ...". It works on the SQLite
// database in the data directory; the gateway does not need to be stopped.
func dashboardUserCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "-help" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, dashboardUserUsage)
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet("dashboard-user "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data", "gateway-data", "the gateway's data directory")
	tenant := fs.String("tenant", "", "tenant id of the studio")
	name := fs.String("name", "", "user name")
	base := fs.String("url", "http://127.0.0.1:8751", "address the dashboard is opened at, for the printed link")
	pwStdin := fs.Bool("password-stdin", false, "add-admin: read the password from standard input and create the account at once")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "carthago-gateway dashboard-user:", err)
		return 1
	}
	if fs.NArg() > 0 {
		return fail(fmt.Errorf("unexpected argument %q", fs.Arg(0)))
	}
	switch cmd {
	case "add-admin", "reset-password", "reset-two-factor", "list":
	default:
		fmt.Fprint(stderr, dashboardUserUsage)
		return 2
	}
	if *tenant == "" || (*name == "" && cmd != "list") {
		return fail(errors.New("-tenant and -name are required (list needs only -tenant)"))
	}
	// The usual mistake is the wrong directory, and a new empty database there would take
	// the account without a word while the running dashboard never sees it.
	dbPath := filepath.Join(*dataDir, "gateway.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fail(fmt.Errorf("no gateway database at %s: give -data the data directory the gateway runs with (it creates the database at its first start)", dbPath))
	}
	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		return fail(err)
	}
	defer st.Close()
	ctx := context.Background()
	b := dashboard.Bootstrap{Store: st}
	link := func(token string, expires time.Time, what string) {
		fmt.Fprintf(stdout, "%s\n\n  %s/invite/%s\n\nThe link works once and until %s. Anyone who has it can use it, so do not paste it anywhere.\n",
			what, strings.TrimRight(*base, "/"), token, expires.Local().Format("2006-01-02 15:04 MST"))
	}
	switch cmd {
	case "add-admin":
		if *pwStdin {
			line, err := bufio.NewReader(io.LimitReader(stdin, 4096)).ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return fail(err)
			}
			if err := b.CreateAdmin(ctx, *tenant, *name, strings.TrimRight(line, "\r\n")); err != nil {
				return fail(err)
			}
			fmt.Fprintf(stdout, "Admin %q created for tenant %q. The shared demo key no longer signs in to that studio.\n", strings.ToLower(*name), *tenant)
			return 0
		}
		token, expires, err := b.InviteAdmin(ctx, *tenant, *name)
		if err != nil {
			return fail(err)
		}
		link(token, expires, fmt.Sprintf("Open this link in a browser on this PC to choose the password for admin %q of tenant %q:", strings.ToLower(*name), *tenant))
	case "reset-password":
		token, expires, err := b.ResetPassword(ctx, *tenant, *name)
		if err != nil {
			return fail(err)
		}
		link(token, expires, fmt.Sprintf("Open this link in a browser to choose a new password for %q of tenant %q:", strings.ToLower(*name), *tenant))
	case "reset-two-factor":
		if err := b.ResetTwoFactor(ctx, *tenant, *name); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "Two-factor sign-in removed for %q of tenant %q, and the account was signed out everywhere.\n", strings.ToLower(*name), *tenant)
	case "list":
		users, err := b.List(ctx, *tenant)
		if err != nil {
			return fail(err)
		}
		if len(users) == 0 {
			fmt.Fprintf(stdout, "Tenant %q has no dashboard accounts.\n", *tenant)
			return 0
		}
		fmt.Fprintf(stdout, "%-32s  %-9s  %-10s  %-8s  %s\n", "USER", "ROLE", "TWO-FACTOR", "STATUS", "LAST SIGN-IN")
		for _, u := range users {
			twoFactor, status, last := "off", "active", "never"
			if u.TwoFactor {
				twoFactor = "on"
			}
			if u.Disabled {
				status = "disabled"
			}
			if !u.LastLogin.IsZero() {
				last = u.LastLogin.Local().Format("2006-01-02 15:04 MST")
			}
			fmt.Fprintf(stdout, "%-32s  %-9s  %-10s  %-8s  %s\n", u.Name, u.Role, twoFactor, status, last)
		}
	}
	return 0
}
