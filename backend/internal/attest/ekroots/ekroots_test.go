package ekroots

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

var vendors = []string{"intel", "amd", "infineon", "stmicro", "nuvoton"}

func TestEmbeddedBundleCoversVendors(t *testing.T) {
	b, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Skipped) != 0 {
		t.Errorf("unparseable bundle entries: %v", b.Skipped)
	}
	a, i := b.Counts()
	t.Logf("bundle %q: %d anchors, %d intermediates", b.Version, a, i)
	perVendor := map[string]int{}
	for _, es := range b.bySubject {
		for _, e := range es {
			if e.anchor {
				perVendor[e.vendor]++
			}
		}
	}
	for _, v := range vendors {
		if perVendor[v] == 0 {
			t.Errorf("no %s anchors", v)
		}
	}
}

// Every vendor has intermediates that verify to one of its own anchors through the real
// vendor signatures (RSA and ECDSA, SHA-1 and SHA-2), including STMicro's EK CAs whose
// padded serial needs the lenient parser.
func TestBundledIntermediatesChainToVendorRoots(t *testing.T) {
	b, _ := Default()
	now := time.Now()
	ok, other := map[string]int{}, map[string][]string{}
	for _, es := range b.bySubject {
		for _, e := range es {
			if e.anchor {
				continue
			}
			r := b.Verify(e.cert, nil, now)
			if r.Status == StatusVerified && r.Vendor == e.vendor {
				ok[e.vendor]++
			} else {
				other[e.vendor] = append(other[e.vendor], e.name+": "+string(r.Status)+" "+r.Detail)
			}
		}
	}
	for _, v := range vendors {
		if ok[v] == 0 {
			t.Errorf("%s: no intermediate verifies to a %s root", v, v)
		}
		t.Logf("%s: %d intermediates verify to %s roots", v, ok[v], v)
		for _, o := range other[v] {
			t.Errorf("%s intermediate does not verify: %s", v, o)
		}
	}
	var stm *entry
	for _, es := range b.bySubject {
		for _, e := range es {
			if e.name == "STM TPM EK Intermediate CA 01.crt" {
				stm = e
			}
		}
	}
	if stm == nil {
		t.Fatal("STM TPM EK Intermediate CA 01 missing from the bundle")
	}
	if r := b.Verify(stm.cert, nil, now); r.Status != StatusVerified || r.Vendor != "stmicro" {
		t.Errorf("STM EK intermediate: %+v", r)
	}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func issue(t *testing.T, parent *testCA, cn string, isCA bool) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn, Organization: []string{"Carthago Watchdog test"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	signer, signerKey := tmpl, k
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &k.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{c, k}
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func TestVerifyOutcomes(t *testing.T) {
	base, _ := Default()
	root := issue(t, nil, "Test TPM Root", true)
	inter := issue(t, root, "Test TPM Intermediate", true)
	leaf := issue(t, inter, "Test EK", false)
	b, err := base.WithExtraRoots(map[string][]byte{"test-root.pem": pemOf(root.cert)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	if r := b.Verify(leaf.cert, []*x509.Certificate{inter.cert}, now); r.Status != StatusVerified || r.Vendor != "custom" || len(r.Chain) != 3 {
		t.Errorf("full chain: %+v", r)
	}
	if r := b.Verify(leaf.cert, nil, now); r.Status != StatusUnknownVendor {
		t.Errorf("missing intermediate: %+v", r)
	}
	if r := base.Verify(leaf.cert, []*x509.Certificate{inter.cert}, now); r.Status != StatusUnknownVendor {
		t.Errorf("root not bundled (swtpm-style): %+v", r)
	}
	self := issue(t, nil, "swtpm self-issued EK", false)
	if r := base.Verify(self.cert, nil, now); r.Status != StatusUnknownVendor {
		t.Errorf("self-issued: %+v", r)
	}
	if r := b.Verify(nil, nil, now); r.Status != StatusNoCert {
		t.Errorf("nil leaf: %+v", r)
	}

	forged := *leaf.cert
	forged.Signature = append([]byte(nil), leaf.cert.Signature...)
	forged.Signature[len(forged.Signature)-3] ^= 0x40
	if r := b.Verify(&forged, []*x509.Certificate{inter.cert}, now); r.Status != StatusInvalid || !strings.Contains(r.Detail, "signature") {
		t.Errorf("bad leaf signature: %+v", r)
	}

	notCA := issue(t, root, "Test TPM Intermediate", false)
	leaf2 := issue(t, notCA, "Test EK 2", false)
	if r := b.Verify(leaf2.cert, []*x509.Certificate{notCA.cert}, now); r.Status != StatusInvalid || !strings.Contains(r.Detail, "not a CA") {
		t.Errorf("non-CA intermediate: %+v", r)
	}
}

func TestParseCertificateNormalizesPaddedSerial(t *testing.T) {
	root := issue(t, nil, "Padded Root", true)
	der := root.cert.Raw
	// Re-encode the serial with a redundant leading zero byte, the STMicro quirk. Lengths
	// grow by one at each enclosing level, all short or 2-byte forms in this certificate.
	padded, ok := padSerial(der)
	if !ok {
		t.Skip("test certificate layout not supported by padSerial")
	}
	if _, err := x509.ParseCertificate(padded); err == nil {
		t.Fatal("strict parser accepted a padded serial; test is not exercising the quirk")
	}
	c, err := ParseCertificate(padded)
	if err != nil {
		t.Fatal(err)
	}
	if c.SerialNumber.Cmp(root.cert.SerialNumber) != 0 || string(c.Raw) != string(padded) {
		t.Errorf("serial %v raw kept %v", c.SerialNumber, string(c.Raw) == string(padded))
	}
}

// padSerial inserts 0x00 before the serial's content in a DER certificate whose outer
// SEQUENCE and TBS SEQUENCE use 2-byte long-form lengths (0x82).
func padSerial(der []byte) ([]byte, bool) {
	if len(der) < 20 || der[0] != 0x30 || der[1] != 0x82 || der[4] != 0x30 || der[5] != 0x82 {
		return nil, false
	}
	i := 8
	if der[i] == 0xa0 { // [0] version
		i += 2 + int(der[i+1])
	}
	if der[i] != 0x02 || der[i+1] >= 0x7f {
		return nil, false
	}
	n := int(der[i+1])
	out := append([]byte(nil), der[:i]...)
	out = append(out, 0x02, byte(n+1), 0x00)
	out = append(out, der[i+2:]...)
	bump := func(at int) {
		l := int(out[at])<<8 | int(out[at+1])
		l++
		out[at], out[at+1] = byte(l>>8), byte(l)
	}
	bump(2)
	bump(6)
	return out, true
}
