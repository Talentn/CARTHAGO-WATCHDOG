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
			// TPM 1.2-era CAs that have since expired are checked just before they expired.
			at := now
			if now.After(e.cert.NotAfter) {
				at = e.cert.NotAfter.Add(-24 * time.Hour)
			}
			r := b.Verify(e.cert, nil, at)
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
	return issueAt(t, parent, cn, isCA, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func issueAt(t *testing.T, parent *testCA, cn string, isCA bool, notBefore, notAfter time.Time) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn, Organization: []string{"Carthago Watchdog test"}},
		NotBefore: notBefore, NotAfter: notAfter,
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

func TestVerifyEnforcesValidity(t *testing.T) {
	base, _ := Default()
	now := time.Now()
	past, future := now.Add(-48*time.Hour), now.Add(48*time.Hour)
	root := issueAt(t, nil, "Validity Root", true, past, future)
	b, err := base.WithExtraRoots(map[string][]byte{"root.pem": pemOf(root.cert)})
	if err != nil {
		t.Fatal(err)
	}

	expiredCA := issueAt(t, root, "Validity Intermediate", true, past, now.Add(-time.Hour))
	leaf := issueAt(t, expiredCA, "Validity EK", false, past, future)
	if r := b.Verify(leaf.cert, []*x509.Certificate{expiredCA.cert}, now); r.Status != StatusInvalid || !strings.Contains(r.Detail, "expired") {
		t.Errorf("expired intermediate: %+v", r)
	}
	if r := b.Verify(leaf.cert, []*x509.Certificate{expiredCA.cert}, now.Add(-2*time.Hour)); r.Status != StatusVerified {
		t.Errorf("same chain while the intermediate was valid: %+v", r)
	}

	// A re-issued intermediate with the same key and name lets the path through.
	renewed := *expiredCA.cert
	renewedDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: expiredCA.cert.Subject, NotBefore: past, NotAfter: future,
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: expiredCA.cert.SubjectKeyId,
	}, root.cert, &expiredCA.key.PublicKey, root.key)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := x509.ParseCertificate(renewedDER); err == nil {
		renewed = *c
	}
	if r := b.Verify(leaf.cert, []*x509.Certificate{expiredCA.cert, &renewed}, now); r.Status != StatusVerified {
		t.Errorf("expired and current issuer supplied: %+v", r)
	}

	inter := issueAt(t, root, "Validity Intermediate 2", true, past, future)
	expiredLeaf := issueAt(t, inter, "Expired EK", false, past, now.Add(-time.Minute))
	if r := b.Verify(expiredLeaf.cert, []*x509.Certificate{inter.cert}, now); r.Status != StatusInvalid || !strings.Contains(r.Detail, "EK certificate") {
		t.Errorf("expired EK certificate: %+v", r)
	}
	earlyLeaf := issueAt(t, inter, "Future EK", false, now.Add(time.Hour), future)
	if r := b.Verify(earlyLeaf.cert, []*x509.Certificate{inter.cert}, now); r.Status != StatusInvalid || !strings.Contains(r.Detail, "not valid before") {
		t.Errorf("not yet valid EK certificate: %+v", r)
	}
	noExpiry := issueAt(t, inter, "No-expiry EK", false, past, time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC))
	if r := b.Verify(noExpiry.cert, []*x509.Certificate{inter.cert}, now); r.Status != StatusVerified {
		t.Errorf("99991231235959Z EK certificate: %+v", r)
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

// Mutually cross-signed CA certificates with one name and key make every ordering of them
// a candidate path. The search must give up after a bounded number of signature checks
// instead of trying them all (12 such certificates are about 2e7 orderings at depth 8).
func TestVerifyBoundsPathSearch(t *testing.T) {
	base, _ := Default()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	name := pkix.Name{CommonName: "Looping CA"}
	var cas []*x509.Certificate
	for i := 0; i < 12; i++ {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: name, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		cas = append(cas, c)
	}
	leaf := issue(t, &testCA{cas[0], k}, "Looping EK", false)
	start := time.Now()
	r := base.Verify(leaf.cert, cas, time.Now())
	if r.Status != StatusInvalid || !strings.Contains(r.Detail, "signature checks") {
		t.Errorf("want the search budget to end the walk, got %+v", r)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("path search took %s", d)
	}
}

func TestVerifyEnforcesPathLength(t *testing.T) {
	base, _ := Default()
	root := issue(t, nil, "PathLen Root", true)
	b, err := base.WithExtraRoots(map[string][]byte{"root.pem": pemOf(root.cert)})
	if err != nil {
		t.Fatal(err)
	}
	ca := func(parent *testCA, cn string, pathLenZero bool) *testCA {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: pathLenZero}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &k.PublicKey, parent.key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return &testCA{c, k}
	}
	limited := ca(root, "PathLen 0 CA", true)
	if r := b.Verify(issue(t, limited, "EK under pathLen 0", false).cert, []*x509.Certificate{limited.cert}, time.Now()); r.Status != StatusVerified {
		t.Errorf("EK directly under a pathLen 0 CA: %+v", r)
	}
	sub := ca(limited, "CA under pathLen 0", false)
	leaf := issue(t, sub, "EK under a forbidden sub-CA", false)
	if r := b.Verify(leaf.cert, []*x509.Certificate{limited.cert, sub.cert}, time.Now()); r.Status != StatusInvalid || !strings.Contains(r.Detail, "allows 0 CA") {
		t.Errorf("sub-CA below a pathLen 0 CA: %+v", r)
	}
}
