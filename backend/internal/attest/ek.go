package attest

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"

	goattest "github.com/google/go-attestation/attest"

	"carthago/backend/internal/attest/ekroots"
)

// DecodeBCryptRSAPublic decodes a Windows BCRYPT_RSAKEY_BLOB ("RSA1") public key.
func DecodeBCryptRSAPublic(b []byte) (*rsa.PublicKey, error) {
	if len(b) < 24 {
		return nil, errors.New("RSA blob too short")
	}
	magic := binary.LittleEndian.Uint32(b[0:4])
	if magic != 0x31415352 {
		return nil, fmt.Errorf("unexpected RSA blob magic 0x%08x", magic)
	}
	expLen := int(binary.LittleEndian.Uint32(b[8:12]))
	modLen := int(binary.LittleEndian.Uint32(b[12:16]))
	if expLen > 8 || 24+expLen+modLen > len(b) {
		return nil, errors.New("RSA blob lengths out of range")
	}
	e := new(big.Int).SetBytes(b[24 : 24+expLen])
	n := new(big.Int).SetBytes(b[24+expLen : 24+expLen+modLen])
	// An EK is RSA-2048 or larger with a small odd exponent; anything else is not a key the
	// EK challenge should be wrapped to.
	if n.BitLen() < 2048 || n.BitLen() > 4096 || n.Bit(0) == 0 {
		return nil, fmt.Errorf("RSA modulus of %d bits is not a usable EK", n.BitLen())
	}
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || e.Bit(0) == 0 {
		return nil, errors.New("RSA public exponent out of range")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// CertInfo summarises one certificate in the EK chain.
type CertInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Source    string    `json:"source"`
}

// EKReport describes what could be established about the endorsement key.
type EKReport struct {
	PublicSHA256  string     `json:"public_sha256"`
	CertSource    string     `json:"cert_source"`
	CertURL       string     `json:"cert_url,omitempty"`
	CertMatchesEK bool       `json:"cert_matches_ek"`
	Chain         []CertInfo `json:"chain"`
	// ChainStatus is the outcome of verification against the bundled manufacturer roots.
	ChainStatus ekroots.Status `json:"chain_status"`
	RootVendor  string         `json:"root_vendor,omitempty"`
	Root        string         `json:"root,omitempty"`
	Notes       []string       `json:"notes,omitempty"`
}

// fetchHosts are the only hosts EK certificates and missing issuers are fetched from. The
// URLs come from the EK certificate, which the client supplies, so without this list the
// gateway could be made to request arbitrary (internal) URLs.
var fetchHosts = map[string]bool{
	"ekop.intel.com":            true, // Intel EK certificate service
	"tsci.intel.com":            true, // Intel On-Die CA
	"trustedservices.intel.com": true, // Intel PTT EK CAs
	"upgrades.intel.com":        true, // Intel PTT EK CAs (older AIA URLs)
	"ftpm.amd.com":              true, // AMD fTPM
	"pki.infineon.com":          true,
	"secure.globalsign.com":     true, // STMicro's chain is issued under GlobalSign
	"sw-center.st.com":          true,
	"www.nuvoton.com":           true,
}

// checkFetchURL allows http(s) URLs on a default port of a host in fetchHosts.
func checkFetchURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("unparseable URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("scheme %q not allowed", u.Scheme)
	}
	if u.User != nil {
		return errors.New("URL with credentials not allowed")
	}
	if p := u.Port(); p != "" && p != "80" && p != "443" {
		return fmt.Errorf("port %s not allowed", p)
	}
	if host := strings.ToLower(u.Hostname()); !fetchHosts[host] {
		return fmt.Errorf("host %q is not a known TPM manufacturer host", host)
	}
	return nil
}

// publicAddressOnly refuses connections to loopback, private, link-local and other
// non-global addresses, whatever name they were resolved from.
func publicAddressOnly(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("fetch: %v", err)
	}
	ip := ap.Addr().Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("fetch: %s is not a public address", ip)
	}
	return nil
}

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, Control: publicAddressOnly}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many redirects")
		}
		return checkFetchURL(req.URL.String())
	},
}

func fetch(u string) ([]byte, error) {
	if err := checkFetchURL(u); err != nil {
		return nil, err
	}
	resp, err := httpClient.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func parseAnyCert(b []byte) (*x509.Certificate, error) {
	if c, err := goattest.ParseEKCertificate(b); err == nil {
		return c, nil
	}
	if blk, _ := pem.Decode(b); blk != nil {
		return x509.ParseCertificate(blk.Bytes)
	}
	// Intel's EK service answers with JSON carrying a base64url DER certificate.
	var j struct {
		Certificate string `json:"certificate"`
	}
	if json.Unmarshal(b, &j) == nil && j.Certificate != "" {
		for _, enc := range []*base64.Encoding{base64.URLEncoding, base64.RawURLEncoding, base64.StdEncoding} {
			if der, err := enc.DecodeString(j.Certificate); err == nil {
				return goattest.ParseEKCertificate(der)
			}
		}
	}
	return nil, errors.New("unrecognised certificate encoding")
}

// ekCertURL mirrors go-attestation's (unexported) manufacturer EK-certificate service URLs
// for firmware TPMs that do not provision the certificate into NV.
func ekCertURL(pub *rsa.PublicKey, manufacturer string) string {
	switch strings.TrimSpace(manufacturer) {
	case "INTC":
		h := sha256.New()
		h.Write(pub.N.Bytes())
		h.Write([]byte{0x1, 0x00, 0x01})
		return "https://ekop.intel.com/ekcertservice/" + url.QueryEscape(base64.URLEncoding.EncodeToString(h.Sum(nil)))
	case "AMD":
		h := sha256.New()
		h.Write([]byte{0x00, 0x00, 0x22, 0x22})
		e := make([]byte, 4)
		binary.BigEndian.PutUint32(e, uint32(pub.E))
		h.Write(e)
		h.Write(pub.N.Bytes())
		return "https://ftpm.amd.com/pki/aia/" + url.QueryEscape(fmt.Sprintf("%X", h.Sum(nil)[0:16]))
	}
	return ""
}

func info(c *x509.Certificate, source string) CertInfo {
	return CertInfo{Subject: c.Subject.String(), Issuer: c.Issuer.String(), NotBefore: c.NotBefore, NotAfter: c.NotAfter, Source: source}
}

func parseSuppliedCert(der []byte) (*x509.Certificate, error) {
	if c, err := goattest.ParseEKCertificate(der); err == nil {
		return c, nil
	}
	return ekroots.ParseCertificate(der)
}

// tcg-kp-EKCertificate (TCG EK Credential Profile).
var oidEKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 1}

// notAnEKCertificate says why leaf cannot be an EK certificate, or returns "". A CA
// certificate is never one, and a certificate that restricts its use with an extended key
// usage must name the EK usage.
func notAnEKCertificate(leaf *x509.Certificate) string {
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return fmt.Sprintf("%q is a CA certificate, not an EK certificate", leaf.Subject.String())
	}
	if len(leaf.ExtKeyUsage) == 0 && len(leaf.UnknownExtKeyUsage) == 0 {
		return ""
	}
	if slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return ""
	}
	for _, oid := range leaf.UnknownExtKeyUsage {
		if oid.Equal(oidEKCertificate) {
			return ""
		}
	}
	return fmt.Sprintf("%q has an extended key usage that does not include tcg-kp-EKCertificate", leaf.Subject.String())
}

// MaxEKChainCerts bounds the EK chain certificates taken from one handshake.
const MaxEKChainCerts = 16

// MaxEKNVCerts bounds the EK certificates taken from one handshake (a TPM holds one per EK
// template: RSA and ECC, low and high range).
const MaxEKNVCerts = 8

// CheckEK finds an EK certificate (NV first, then the manufacturer service when allowed),
// confirms it certifies the EK used for the AK binding, and verifies its chain against the
// bundled manufacturer roots. chainCerts (from the TPM's EK certificate chain NV indices)
// and the other EK certificates (for example ECC EK certificates) are used only as
// untrusted intermediates; with allowFetch, missing issuers are also fetched from AIA URLs.
func CheckEK(ekPub *rsa.PublicKey, nvCerts, chainCerts [][]byte, manufacturer string, allowFetch bool, roots *ekroots.Bundle, now time.Time) EKReport {
	sum := sha256.Sum256(x509.MarshalPKCS1PublicKey(ekPub))
	rep := EKReport{PublicSHA256: fmt.Sprintf("%x", sum), CertSource: "none", ChainStatus: ekroots.StatusNoCert}

	var leaf *x509.Certificate
	var extra []*x509.Certificate
	if len(nvCerts) > MaxEKNVCerts {
		rep.Notes = append(rep.Notes, fmt.Sprintf("EK certificates: %d supplied, using the first %d", len(nvCerts), MaxEKNVCerts))
		nvCerts = nvCerts[:MaxEKNVCerts]
	}
	for i, der := range nvCerts {
		c, err := parseSuppliedCert(der)
		if err != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("NV cert %d unparseable: %v", i, err))
			continue
		}
		if k, ok := c.PublicKey.(*rsa.PublicKey); ok && k.Equal(ekPub) && leaf == nil {
			leaf, rep.CertSource = c, "tpm-nv"
			continue
		}
		extra = append(extra, c)
	}
	if len(chainCerts) > MaxEKChainCerts {
		rep.Notes = append(rep.Notes, fmt.Sprintf("EK chain: %d certificates supplied, using the first %d", len(chainCerts), MaxEKChainCerts))
		chainCerts = chainCerts[:MaxEKChainCerts]
	}
	for i, der := range chainCerts {
		c, err := parseSuppliedCert(der)
		if err != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("EK chain cert %d unparseable: %v", i, err))
			continue
		}
		extra = append(extra, c)
	}
	if leaf == nil {
		rep.CertURL = ekCertURL(ekPub, manufacturer)
		switch {
		case rep.CertURL == "":
			rep.Notes = append(rep.Notes, "no EK cert in NV and no known manufacturer service for "+manufacturer)
		case !allowFetch:
			rep.Notes = append(rep.Notes, "EK cert fetch disabled")
		default:
			body, err := fetch(rep.CertURL)
			if err == nil {
				leaf, err = parseAnyCert(body)
			}
			if err != nil {
				slog.Warn("EK certificate fetch failed", "url", rep.CertURL, "err", err)
				rep.Notes = append(rep.Notes, "manufacturer EK cert fetch failed")
			} else {
				rep.CertSource = "manufacturer-service"
			}
		}
	}
	if leaf == nil {
		return rep
	}
	if k, ok := leaf.PublicKey.(*rsa.PublicKey); !ok || !k.Equal(ekPub) {
		rep.ChainStatus = ekroots.StatusInvalid
		rep.Chain = []CertInfo{info(leaf, rep.CertSource)}
		rep.Notes = append(rep.Notes, "EK certificate does not certify this EK")
		return rep
	}
	rep.CertMatchesEK = true
	if msg := notAnEKCertificate(leaf); msg != "" {
		rep.ChainStatus = ekroots.StatusInvalid
		rep.Chain = []CertInfo{info(leaf, rep.CertSource)}
		rep.Notes = append(rep.Notes, "EK chain: "+msg)
		return rep
	}
	if allowFetch {
		extra = append(extra, fetchIssuers(leaf, roots, extra, &rep)...)
	}
	// EK certs often carry critical TPM-specific extensions, so the chain is built and
	// signatures checked by ekroots rather than x509.Verify.
	res := roots.Verify(leaf, extra, now)
	rep.ChainStatus, rep.RootVendor, rep.Root = res.Status, res.Vendor, res.Root
	if res.Detail != "" {
		rep.Notes = append(rep.Notes, "EK chain: "+res.Detail)
	}
	rep.Notes = append(rep.Notes, res.Notes...)
	if res.Status == ekroots.StatusVerified {
		rep.Chain = rep.Chain[:0]
		for i, c := range res.Chain {
			src := "bundle"
			switch {
			case i == 0:
				src = rep.CertSource
			case !roots.Contains(c):
				src = "supplied"
			}
			rep.Chain = append(rep.Chain, info(c, src))
		}
	} else {
		rep.Chain = []CertInfo{info(leaf, rep.CertSource)}
	}
	if m := strings.TrimSpace(manufacturer); res.Vendor != "" && res.Vendor != "custom" && vendorForManufacturer[m] != "" && vendorForManufacturer[m] != res.Vendor {
		rep.Notes = append(rep.Notes, fmt.Sprintf("TPM reports manufacturer %q but the EK chains to a %s root", m, res.Vendor))
	}
	return rep
}

// vendorForManufacturer maps TPM_PT_MANUFACTURER IDs to bundle vendors.
var vendorForManufacturer = map[string]string{"INTC": "intel", "AMD": "amd", "IFX": "infineon", "STM": "stmicro", "NTC": "nuvoton"}

// fetchIssuers follows AIA URLs upward from leaf while no known issuer exists.
func fetchIssuers(leaf *x509.Certificate, roots *ekroots.Bundle, have []*x509.Certificate, rep *EKReport) []*x509.Certificate {
	var got []*x509.Certificate
	known := func(c *x509.Certificate) bool {
		if roots.HasIssuer(c) {
			return true
		}
		for _, h := range append(have, got...) {
			if bytes.Equal(h.RawSubject, c.RawIssuer) {
				return true
			}
		}
		return false
	}
	cur := leaf
	for depth := 0; depth < 6 && !known(cur) && !bytes.Equal(cur.RawIssuer, cur.RawSubject); depth++ {
		var parent *x509.Certificate
		var lastErr error
		for _, u := range cur.IssuingCertificateURL {
			body, err := fetch(u)
			if err == nil {
				parent, err = parseAnyCert(body)
			}
			if err == nil {
				break
			}
			lastErr = err
			// Not echoed to the client: the notes go back in the Session message and the
			// URL is attacker-chosen, so the error would describe what the gateway can reach.
			slog.Warn("EK issuer fetch failed", "url", u, "err", err)
		}
		if parent == nil {
			if lastErr == nil {
				rep.Notes = append(rep.Notes, "AIA fetch stopped: no AIA issuer URL")
			} else {
				rep.Notes = append(rep.Notes, "AIA fetch stopped: issuer could not be fetched")
			}
			break
		}
		got = append(got, parent)
		cur = parent
	}
	return got
}
