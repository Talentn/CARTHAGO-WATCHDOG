package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"carthago/backend/internal/attest/ekroots"
)

func bcryptRSABlob(k *rsa.PublicKey) []byte {
	e := big.NewInt(int64(k.E)).Bytes()
	n := k.N.Bytes()
	b := make([]byte, 24, 24+len(e)+len(n))
	binary.LittleEndian.PutUint32(b[0:], 0x31415352)
	binary.LittleEndian.PutUint32(b[4:], uint32(k.N.BitLen()))
	binary.LittleEndian.PutUint32(b[8:], uint32(len(e)))
	binary.LittleEndian.PutUint32(b[12:], uint32(len(n)))
	return append(append(b, e...), n...)
}

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, cn string, parent *ca) *ca {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	signer, sk := tmpl, k
	if parent != nil {
		signer, sk = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &k.PublicKey, sk)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &ca{c, k}
}

func ekCert(t *testing.T, issuer *ca, ek *rsa.PublicKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		Subject: pkix.Name{CommonName: "test EK"}, KeyUsage: x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.cert, ek, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCheckEKChainOutcomes(t *testing.T) {
	ekKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek := &ekKey.PublicKey
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	root := newCA(t, "Test TPM Vendor Root", nil)
	inter := newCA(t, "Test TPM Vendor EK CA", root)
	leaf := ekCert(t, inter, ek)

	base, err := ekroots.Default()
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := base.WithExtraRoots(map[string][]byte{"root.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw})})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, c := range []struct {
		name    string
		certs   [][]byte
		roots   *ekroots.Bundle
		want    ekroots.Status
		matches bool
	}{
		{"leaf and intermediate from NV, root bundled", [][]byte{leaf, inter.cert.Raw}, trusted, ekroots.StatusVerified, true},
		{"intermediate first in NV", [][]byte{inter.cert.Raw, leaf}, trusted, ekroots.StatusVerified, true},
		{"vendor root not bundled (emulated TPM)", [][]byte{leaf, inter.cert.Raw}, base, ekroots.StatusUnknownVendor, true},
		{"intermediate missing", [][]byte{leaf}, trusted, ekroots.StatusUnknownVendor, true},
		{"no certificate", nil, trusted, ekroots.StatusNoCert, false},
		{"certificate for another key only", [][]byte{ekCert(t, inter, &other.PublicKey)}, trusted, ekroots.StatusNoCert, false},
	} {
		rep := CheckEK(ek, c.certs, nil, "INTC", false, c.roots, now)
		if rep.ChainStatus != c.want || rep.CertMatchesEK != c.matches {
			t.Errorf("%s: status %s matches %v, want %s %v (notes %v)", c.name, rep.ChainStatus, rep.CertMatchesEK, c.want, c.matches, rep.Notes)
		}
		if c.want == ekroots.StatusVerified && (rep.RootVendor != "custom" || len(rep.Chain) != 3) {
			t.Errorf("%s: vendor %q chain %d", c.name, rep.RootVendor, len(rep.Chain))
		}
	}

	// An impostor CA with the vendor CA's name has a different key id: no known issuer.
	impostor := ekCert(t, newCA(t, "Test TPM Vendor EK CA", nil), ek)
	if rep := CheckEK(ek, [][]byte{impostor, inter.cert.Raw}, nil, "INTC", false, trusted, now); rep.ChainStatus != ekroots.StatusUnknownVendor {
		t.Errorf("impostor issuer: %s %v", rep.ChainStatus, rep.Notes)
	}
	tampered := append([]byte(nil), leaf...)
	tampered[len(tampered)-2] ^= 0x01 // inside the signature value
	if rep := CheckEK(ek, [][]byte{tampered, inter.cert.Raw}, nil, "INTC", false, trusted, now); rep.ChainStatus != ekroots.StatusInvalid {
		t.Errorf("tampered signature: %s %v", rep.ChainStatus, rep.Notes)
	}
}

func TestRecheckEKRejectsADifferentEK(t *testing.T) {
	a, _ := rsa.GenerateKey(rand.Reader, 2048)
	b, _ := rsa.GenerateKey(rand.Reader, 2048)
	roots, _ := ekroots.Default()
	bound := CheckEK(&a.PublicKey, nil, nil, "", false, roots, time.Now()).PublicSHA256
	if _, err := RecheckEK(bcryptRSABlob(&a.PublicKey), nil, nil, "", false, roots, time.Now(), bound); err != nil {
		t.Errorf("same EK: %v", err)
	}
	if _, err := RecheckEK(bcryptRSABlob(&b.PublicKey), nil, nil, "", false, roots, time.Now(), bound); err == nil {
		t.Error("a different EK was accepted for a bound AK")
	}
}

// Intel PTT (11th gen Core and later): EK -> per-device "CSME <p> PTT 01SVN" -> "CSME <p>
// SVN01 Kernel CA" -> "CSME <p> ROM CA" -> public On-Die issuing CA -> On-Die root. The
// three device CAs come only from the TPM's EK certificate chain NV indices.
func TestCheckEKIntelPTTChainFromNV(t *testing.T) {
	ekKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek := &ekKey.PublicKey
	root := newCA(t, "Test OnDie CA Root", nil)
	issuing := newCA(t, "Test On Die CSME P_TGL Issuing CA", root)
	rom := newCA(t, "CSME TGL ROM CA", issuing)
	kernel := newCA(t, "CSME TGL SVN01 Kernel CA", rom)
	ptt := newCA(t, "CSME TGL PTT 01SVN", kernel)
	leaf := ekCert(t, ptt, ek)
	base, _ := ekroots.Default()
	roots, err := base.WithExtraRoots(map[string][]byte{"root.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw})})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	chain := [][]byte{ptt.cert.Raw, kernel.cert.Raw, rom.cert.Raw, issuing.cert.Raw}

	rep := CheckEK(ek, [][]byte{leaf}, chain, "INTC", false, roots, now)
	if rep.ChainStatus != ekroots.StatusVerified || len(rep.Chain) != 6 {
		t.Fatalf("PTT chain from NV: %s chain %d %v", rep.ChainStatus, len(rep.Chain), rep.Notes)
	}
	if rep.Chain[0].Source != "tpm-nv" || rep.Chain[1].Source != "supplied" || rep.Chain[5].Source != "bundle" {
		t.Errorf("sources: %+v", rep.Chain)
	}
	if rep := CheckEK(ek, [][]byte{leaf}, nil, "INTC", false, roots, now); rep.ChainStatus != ekroots.StatusUnknownVendor {
		t.Errorf("without the NV chain: %s", rep.ChainStatus)
	}
	if rep := CheckEK(ek, [][]byte{leaf}, [][]byte{issuing.cert.Raw, rom.cert.Raw, ptt.cert.Raw}, "INTC", false, roots, now); rep.ChainStatus != ekroots.StatusUnknownVendor {
		t.Errorf("Kernel CA missing: %s", rep.ChainStatus)
	}
	// Chain certificates never stand in for the EK certificate itself.
	if rep := CheckEK(ek, nil, append([][]byte{leaf}, chain...), "INTC", false, roots, now); rep.ChainStatus != ekroots.StatusNoCert || rep.CertMatchesEK {
		t.Errorf("EK certificate only in the chain indices: %s matches %v", rep.ChainStatus, rep.CertMatchesEK)
	}
	// Supplied chain certificates cannot become anchors: without the bundled root the
	// path stops at the supplied self-signed root.
	if rep := CheckEK(ek, [][]byte{leaf}, append(chain, root.cert.Raw), "INTC", false, base, now); rep.ChainStatus != ekroots.StatusUnknownVendor {
		t.Errorf("self-signed root supplied in the chain: %s", rep.ChainStatus)
	}
	if rep := CheckEK(ek, [][]byte{leaf}, chain, "INTC", false, roots, ptt.cert.NotAfter.Add(time.Minute)); rep.ChainStatus != ekroots.StatusInvalid {
		t.Errorf("after the device CAs expired: %s %v", rep.ChainStatus, rep.Notes)
	}
	junk := make([][]byte, MaxEKChainCerts+4)
	for i := range junk {
		junk[i] = []byte{0x30, 0x03, 0x02, 0x01, byte(i)}
	}
	if rep := CheckEK(ek, [][]byte{leaf}, append(junk, chain...), "INTC", false, roots, now); rep.ChainStatus != ekroots.StatusUnknownVendor {
		t.Errorf("chain beyond MaxEKChainCerts was used: %s", rep.ChainStatus)
	}
}

// A certificate for the EK's key that is a CA certificate, or is limited to another use,
// is not an EK certificate even if it chains to a trusted root.
func TestCheckEKRejectsNonEKLeaf(t *testing.T) {
	ekKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek := &ekKey.PublicKey
	root := newCA(t, "Leaf Check Root", nil)
	base, _ := ekroots.Default()
	trusted, err := base.WithExtraRoots(map[string][]byte{"root.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw})})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(mod func(*x509.Certificate)) []byte {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			Subject: pkix.Name{CommonName: "leaf"}, KeyUsage: x509.KeyUsageKeyEncipherment}
		mod(tmpl)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, ek, root.key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	now := time.Now()
	for name, c := range map[string]struct {
		der  []byte
		want ekroots.Status
	}{
		"no EKU": {mk(func(*x509.Certificate) {}), ekroots.StatusVerified},
		"EK EKU": {mk(func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidEKCertificate} }), ekroots.StatusVerified},
		"CA": {mk(func(c *x509.Certificate) {
			c.IsCA, c.BasicConstraintsValid, c.KeyUsage = true, true, x509.KeyUsageCertSign
		}), ekroots.StatusInvalid},
		"TLS EKU only": {mk(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }), ekroots.StatusInvalid},
	} {
		rep := CheckEK(ek, [][]byte{c.der}, nil, "", false, trusted, now)
		if rep.ChainStatus != c.want {
			t.Errorf("%s: %s, want %s (%v)", name, rep.ChainStatus, c.want, rep.Notes)
		}
	}
}

func TestCheckEKCapsSuppliedCertificates(t *testing.T) {
	ekKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	root := newCA(t, "Cap Root", nil)
	base, _ := ekroots.Default()
	var nv [][]byte
	for i := 0; i < MaxEKNVCerts+5; i++ {
		nv = append(nv, root.cert.Raw)
	}
	// The EK certificate sits behind more filler than the cap admits, so it is not used.
	nv = append(nv, ekCert(t, root, &ekKey.PublicKey))
	rep := CheckEK(&ekKey.PublicKey, nv, nil, "", false, base, time.Now())
	if rep.ChainStatus != ekroots.StatusNoCert || len(rep.Notes) == 0 {
		t.Errorf("status %s notes %v", rep.ChainStatus, rep.Notes)
	}
}

// With fetching enabled, AIA URLs come from a client-supplied certificate. They must not
// make the gateway request anything but the known manufacturer hosts, and the reason a
// fetch failed must not be reported back to the client.
func TestFetchIsLimitedToManufacturerHosts(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	for _, u := range []string{
		srv.URL + "/issuer.cer",
		"http://169.254.169.254/latest/meta-data/",
		"http://localhost:8751/",
		"file:///etc/passwd",
		"https://ekop.intel.com.evil.example/x",
		"https://user@ekop.intel.com/x",
		"https://ekop.intel.com:8443/x",
		"gopher://ftpm.amd.com/",
	} {
		if err := checkFetchURL(u); err == nil {
			t.Errorf("%s allowed", u)
		}
		if _, err := fetch(u); err == nil {
			t.Errorf("%s fetched", u)
		}
	}
	for _, u := range []string{"https://ekop.intel.com/ekcertservice/abc", "http://pki.infineon.com/OptigaRsaMfrCA036/OptigaRsaMfrCA036.crt", "https://FTPM.AMD.COM/pki/aia/00"} {
		if err := checkFetchURL(u); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	// Even an allowed name must not reach a non-public address (DNS pointing inwards).
	for _, a := range []string{"127.0.0.1:80", "10.1.2.3:443", "192.168.0.1:80", "169.254.169.254:80", "[::1]:80", "[fd00::1]:443", "[::ffff:127.0.0.1]:80", "0.0.0.0:80"} {
		if err := publicAddressOnly("tcp", a, nil); err == nil {
			t.Errorf("dial to %s allowed", a)
		}
	}
	if err := publicAddressOnly("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("public address refused: %v", err)
	}

	// End to end: an EK certificate whose AIA points at an internal server.
	ekKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer := newCA(t, "Unknown EK CA", nil)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		Subject: pkix.Name{CommonName: "EK with internal AIA"}, IssuingCertificateURL: []string{srv.URL + "/secret"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.cert, &ekKey.PublicKey, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	roots, _ := ekroots.Default()
	rep := CheckEK(&ekKey.PublicKey, [][]byte{der}, nil, "", true, roots, time.Now())
	if hits.Load() != 0 {
		t.Errorf("gateway requested the internal URL %d times", hits.Load())
	}
	if rep.ChainStatus != ekroots.StatusUnknownVendor {
		t.Errorf("status %s", rep.ChainStatus)
	}
	for _, n := range rep.Notes {
		if strings.Contains(n, srv.URL) || strings.Contains(n, "127.0.0.1") {
			t.Errorf("note leaks the fetch target: %q", n)
		}
	}
}

func TestDecodeBCryptRSAPublicRejectsDegenerateKeys(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := DecodeBCryptRSAPublic(bcryptRSABlob(&k.PublicKey)); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	even := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}
	for name, pub := range map[string]*rsa.PublicKey{
		"1024-bit modulus": &small.PublicKey,
		"even modulus":     even,
		"exponent 1":       {N: k.N, E: 1},
		"even exponent":    {N: k.N, E: 65536},
	} {
		if _, err := DecodeBCryptRSAPublic(bcryptRSABlob(pub)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	zeroExp := bcryptRSABlob(&k.PublicKey)
	binary.LittleEndian.PutUint32(zeroExp[8:], 0)
	if _, err := DecodeBCryptRSAPublic(zeroExp); err == nil {
		t.Error("blob without an exponent accepted")
	}
}
