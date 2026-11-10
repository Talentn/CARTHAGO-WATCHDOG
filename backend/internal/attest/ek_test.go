package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"sentinel/backend/internal/attest/ekroots"
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
		rep := CheckEK(ek, c.certs, "INTC", false, c.roots, now)
		if rep.ChainStatus != c.want || rep.CertMatchesEK != c.matches {
			t.Errorf("%s: status %s matches %v, want %s %v (notes %v)", c.name, rep.ChainStatus, rep.CertMatchesEK, c.want, c.matches, rep.Notes)
		}
		if c.want == ekroots.StatusVerified && (rep.RootVendor != "custom" || len(rep.Chain) != 3) {
			t.Errorf("%s: vendor %q chain %d", c.name, rep.RootVendor, len(rep.Chain))
		}
	}

	// An impostor CA with the vendor CA's name has a different key id: no known issuer.
	impostor := ekCert(t, newCA(t, "Test TPM Vendor EK CA", nil), ek)
	if rep := CheckEK(ek, [][]byte{impostor, inter.cert.Raw}, "INTC", false, trusted, now); rep.ChainStatus != ekroots.StatusUnknownVendor {
		t.Errorf("impostor issuer: %s %v", rep.ChainStatus, rep.Notes)
	}
	tampered := append([]byte(nil), leaf...)
	tampered[len(tampered)-2] ^= 0x01 // inside the signature value
	if rep := CheckEK(ek, [][]byte{tampered, inter.cert.Raw}, "INTC", false, trusted, now); rep.ChainStatus != ekroots.StatusInvalid {
		t.Errorf("tampered signature: %s %v", rep.ChainStatus, rep.Notes)
	}
}

func TestRecheckEKRejectsADifferentEK(t *testing.T) {
	a, _ := rsa.GenerateKey(rand.Reader, 2048)
	b, _ := rsa.GenerateKey(rand.Reader, 2048)
	roots, _ := ekroots.Default()
	bound := CheckEK(&a.PublicKey, nil, "", false, roots, time.Now()).PublicSHA256
	if _, err := RecheckEK(bcryptRSABlob(&a.PublicKey), nil, "", false, roots, time.Now(), bound); err != nil {
		t.Errorf("same EK: %v", err)
	}
	if _, err := RecheckEK(bcryptRSABlob(&b.PublicKey), nil, "", false, roots, time.Now(), bound); err == nil {
		t.Error("a different EK was accepted for a bound AK")
	}
}
