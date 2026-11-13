package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/store"
)

func dashUser(t *testing.T, stdin string, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = dashboardUserCommand(args, strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

func TestDashboardUserCommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gateway-data")
	ctx := context.Background()
	open := func() *store.SQLite {
		st, err := store.OpenSQLite(filepath.Join(dir, "gateway.db"))
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	// Without the gateway's database in that directory nothing is created there.
	if code, out, errOut := dashUser(t, "", "add-admin", "-data", dir, "-tenant", "demo", "-name", "ala"); code != 1 || out != "" || !strings.Contains(errOut, "no gateway database at") {
		t.Fatalf("add-admin in a directory without a database: %d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("the command created the directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	open().Close() // what the gateway's first start does

	// add-admin prints a one-time link and creates no account by itself.
	code, out, errOut := dashUser(t, "", "add-admin", "-data", dir, "-tenant", "demo", "-name", "Ala")
	link := regexp.MustCompile(`(?m)^  http://127\.0\.0\.1:8751/invite/([A-Za-z0-9_-]{43})$`).FindStringSubmatch(out)
	if code != 0 || link == nil || !strings.Contains(out, `admin "ala" of tenant "demo"`) || !strings.Contains(out, "works once") {
		t.Fatalf("add-admin: %d\n%s\n%s", code, out, errOut)
	}
	st := open()
	if n, _ := st.CountDashUsers(ctx, "demo"); n != 0 {
		t.Errorf("add-admin created %d accounts before the link was opened", n)
	}
	invites, _ := st.ListDashInvites(ctx, "demo", time.Now())
	if len(invites) != 1 || invites[0].Name != "ala" || invites[0].Role != store.RoleAdmin || strings.Contains(invites[0].TokenHash, link[1]) {
		t.Errorf("stored invite: %+v", invites)
	}
	st.Close()
	// -url is where the dashboard is reached.
	_, out, _ = dashUser(t, "", "add-admin", "-data", dir, "-tenant", "rival", "-name", "rex", "-url", "https://dash.studio.example/")
	if !strings.Contains(out, "  https://dash.studio.example/invite/") {
		t.Errorf("-url: %s", out)
	}

	// Scripted installs: the password on standard input. The policy applies.
	for _, weak := range []string{"short\n", "password123456\n", "bea-bea-bea-bea\n", "\n", ""} {
		if code, out, errOut := dashUser(t, weak, "add-admin", "-data", dir, "-tenant", "demo", "-name", "bea", "-password-stdin"); code != 1 || out != "" || !strings.Contains(errOut, "dashboard-user:") {
			t.Errorf("weak password %q: %d %q %q", weak, code, out, errOut)
		}
	}
	code, out, errOut = dashUser(t, "plum-kettle-orbit-97\r\n", "add-admin", "-data", dir, "-tenant", "demo", "-name", "bea", "-password-stdin")
	if code != 0 || !strings.Contains(out, `Admin "bea" created`) || strings.Contains(out+errOut, "plum-kettle") {
		t.Fatalf("add-admin -password-stdin: %d %s %s", code, out, errOut)
	}
	st = open()
	u, err := st.GetDashUserByName(ctx, "demo", "bea")
	if err != nil || u.Role != store.RoleAdmin || !strings.HasPrefix(u.PasswordHash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("created admin: %+v %v", u, err)
	}
	log, _ := st.ListAudit(ctx, "demo", store.AuditFilter{Limit: 10})
	if len(log) != 2 || log[0].Action != "user.create" || log[0].Actor != "command line" || log[0].IP != "local" || log[1].Action != "user.invite" {
		t.Errorf("audit log after the commands: %+v", log)
	}
	st.Close()
	if code, _, errOut := dashUser(t, "plum-kettle-orbit-97\n", "add-admin", "-data", dir, "-tenant", "demo", "-name", "bea", "-password-stdin"); code != 1 || !strings.Contains(errOut, "already") {
		t.Errorf("the same admin twice: %d %s", code, errOut)
	}

	code, out, _ = dashUser(t, "", "list", "-data", dir, "-tenant", "demo")
	if code != 0 || !regexp.MustCompile(`(?m)^bea +Admin +off +active +never$`).MatchString(out) || strings.Contains(out, "argon2") {
		t.Errorf("list: %d\n%s", code, out)
	}
	if _, out, _ := dashUser(t, "", "list", "-data", dir, "-tenant", "nobody-home"); !strings.Contains(out, "no dashboard accounts") {
		t.Errorf("list of an empty tenant: %s", out)
	}

	code, out, _ = dashUser(t, "", "reset-password", "-data", dir, "-tenant", "demo", "-name", "bea")
	if code != 0 || !regexp.MustCompile(`/invite/[A-Za-z0-9_-]{43}\n`).MatchString(out) || !strings.Contains(out, "new password") {
		t.Errorf("reset-password: %d %s", code, out)
	}
	if code, _, errOut := dashUser(t, "", "reset-password", "-data", dir, "-tenant", "demo", "-name", "nobody"); code != 1 || errOut == "" {
		t.Errorf("reset-password for nobody: %d", code)
	}
	st = open()
	secret := []byte("sealed")
	if err := st.UpdateDashUser(ctx, "demo", u.ID, store.DashUserChange{TOTPSecret: &secret}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, out, _ := dashUser(t, "", "list", "-data", dir, "-tenant", "demo"); !regexp.MustCompile(`(?m)^bea +Admin +on `).MatchString(out) {
		t.Errorf("list with two-factor on: %s", out)
	}
	if code, out, _ := dashUser(t, "", "reset-two-factor", "-data", dir, "-tenant", "demo", "-name", "bea"); code != 0 || !strings.Contains(out, "Two-factor sign-in removed") {
		t.Errorf("reset-two-factor: %d %s", code, out)
	}
	st = open()
	if u, _ := st.GetDashUserByName(ctx, "demo", "bea"); u.TOTPSecret != nil {
		t.Error("two-factor secret left after reset-two-factor")
	}
	st.Close()

	// Mistakes get the usage or a plain error, and exit non-zero.
	for _, args := range [][]string{
		{}, {"help"}, {"delete-everything", "-tenant", "demo"}, {"add-admin"}, {"add-admin", "-tenant", "demo"}, {"add-admin", "-name", "ala"},
		{"add-admin", "-data", dir, "-tenant", "demo", "-name", "a b"}, {"add-admin", "-data", dir, "-tenant", "demo", "-name", "ala", "extra"}, {"list", "-nope"},
	} {
		if code, out, errOut := dashUser(t, "", args...); code == 0 || out != "" || errOut == "" {
			t.Errorf("dashboard-user %v: exit %d, stdout %q", args, code, out)
		}
	}
}

func TestDashboardKeyFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	key, err := loadOrCreateDashboardKey(dir)
	if err != nil || len(key) != 32 {
		t.Fatalf("create: %d bytes, %v", len(key), err)
	}
	path := filepath.Join(dir, dashboardKeyFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v", info.Mode().Perm())
	}
	again, err := loadOrCreateDashboardKey(dir)
	if err != nil || !bytes.Equal(again, key) {
		t.Errorf("the key changed between starts: %v", err)
	}
	other, _ := loadOrCreateDashboardKey(filepath.Join(t.TempDir(), "other"))
	if bytes.Equal(other, key) {
		t.Error("two installs got the same key")
	}
	// A damaged file is an error, not a silent new key: a new key would lock every
	// account with two-factor sign-in out.
	for _, bad := range []string{"", "not hex", "abcd"} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrCreateDashboardKey(dir); err == nil {
			t.Errorf("key file %q accepted", bad)
		}
	}
}

func TestParseProxies(t *testing.T) {
	got, err := parseProxies("10.0.0.5, 192.168.0.0/16 ::1,fd00::/8")
	if err != nil || len(got) != 4 || got[0].String() != "10.0.0.5/32" || got[1].String() != "192.168.0.0/16" || got[2].String() != "::1/128" || got[3].String() != "fd00::/8" {
		t.Errorf("parseProxies: %v %v", got, err)
	}
	if got, err := parseProxies(""); err != nil || len(got) != 0 {
		t.Errorf("empty: %v %v", got, err)
	}
	for _, bad := range []string{"proxy.example", "10.0.0.0/33", "10.0.0.1,x"} {
		if _, err := parseProxies(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDashboardTLSOptions(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	saved := *dashAuth
	defer func() { *dashAuth = saved }()
	o := dashAuthFlagSet(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if o.tls() || o.sessionTTL != 12*time.Hour || o.idleTimeout != 30*time.Minute {
		t.Errorf("defaults: %+v", o)
	}
	if c, err := o.tlsConfig(); c != nil || err != nil {
		t.Errorf("no TLS flags: %v %v", c, err)
	}
	o.tlsCert = "only-the-cert.pem"
	if _, err := o.tlsConfig(); err == nil || !strings.Contains(err.Error(), "together") {
		t.Errorf("certificate without key: %v", err)
	}
	// A real pair loads, and nothing older than TLS 1.2 is offered.
	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dash.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"dash.test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	o.tlsCert, o.tlsKey = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(o.tlsCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(o.tlsKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	c, err := o.tlsConfig()
	if err != nil || c == nil || len(c.Certificates) != 1 || c.MinVersion < 0x0303 {
		t.Errorf("TLS config: %+v %v", c, err)
	}
}
