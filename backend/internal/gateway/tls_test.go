package gateway

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"

	"carthago/backend/internal/protocol"
	"carthago/backend/internal/store"
)

func TestDevCertPersistsAndPinIsSPKIHash(t *testing.T) {
	dir := t.TempDir()
	c1, err := LoadOrCreateDevCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := LoadOrCreateDevCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	p1, _ := SPKIPin(c1)
	p2, _ := SPKIPin(c2)
	if p1 != p2 {
		t.Fatalf("pin changed across restarts: %s %s", p1, p2)
	}
	leaf, _ := x509.ParseCertificate(c1.Certificate[0])
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if p1 != hex.EncodeToString(sum[:]) || leaf.Subject.CommonName != "Carthago Gateway (development)" {
		t.Errorf("pin %s cn %q", p1, leaf.Subject.CommonName)
	}
}

// pinnedClient trusts exactly one SPKI pin, the way carthago-net does.
func pinnedClient(pin string, maxVersion uint16) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // replaced by the pin check below
		MaxVersion:         maxVersion,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
			if hex.EncodeToString(sum[:]) != pin {
				return errors.New("pin mismatch")
			}
			return nil
		},
	}}}
}

func newTLSEnv(t *testing.T) (*env, string) {
	keys, err := LoadOrCreateKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadOrCreateDevCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := SPKIPin(cert)
	keys.TLSPins = []string{pin}
	st := store.NewMemory()
	gw := New(Config{Tenants: map[string]string{"demo": serverKey}, HeartbeatInterval: time.Second, TokenTTL: time.Minute},
		keys, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewUnstartedServer(gw.Handler())
	srv.TLS = TLSConfig(cert)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &env{gw: gw, srv: srv, keys: keys, st: st, dial: &websocket.DialOptions{HTTPClient: pinnedClient(pin, 0)}}, pin
}

func TestHandshakeOverPinnedTLS13(t *testing.T) {
	e, pin := newTLSEnv(t)
	c, err := handshake(t, e, softwareKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.VerifyToken(tokenKeys(e), c.session.SessionToken, time.Now(), protocol.DefaultLeeway); err != nil {
		t.Fatal(err)
	}
	resp, err := pinnedClient(pin, 0).Get(e.srv.URL + "/v1/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 || !bytes.Contains(body, []byte(`"tls_spki_sha256":["`+pin+`"]`)) {
		t.Errorf("TLS %+v keys %s", resp.TLS, body)
	}
}

func TestTLS12ClientRejected(t *testing.T) {
	e, pin := newTLSEnv(t)
	if _, err := pinnedClient(pin, tls.VersionTLS12).Get(e.srv.URL + "/healthz"); err == nil {
		t.Fatal("a TLS 1.2 client connected")
	}
}

func TestIsLoopbackListen(t *testing.T) {
	for addr, want := range map[string]bool{"127.0.0.1:8750": true, "[::1]:8750": true, "localhost:1": true, "0.0.0.0:8750": false, ":8750": false, "10.0.0.5:443": false} {
		if IsLoopbackListen(addr) != want {
			t.Errorf("%s: want %v", addr, want)
		}
	}
}
