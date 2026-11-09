package attest

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	goattest "github.com/google/go-attestation/attest"
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
	PublicSHA256    string     `json:"public_sha256"`
	CertSource      string     `json:"cert_source"`
	CertURL         string     `json:"cert_url,omitempty"`
	CertMatchesEK   bool       `json:"cert_matches_ek"`
	Chain           []CertInfo `json:"chain"`
	ChainSignatures bool       `json:"chain_signatures_valid"`
	ChainEndsAtRoot bool       `json:"chain_ends_at_self_signed_root"`
	Notes           []string   `json:"notes,omitempty"`
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

func fetch(u string) ([]byte, error) {
	resp, err := httpClient.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
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

// CheckEK finds an EK certificate (NV first, then the manufacturer service when allowed),
// confirms it certifies the EK used for credential activation, and walks the AIA chain.
// Roots are not pinned in this spike; the report only says where the chain ends.
func CheckEK(ekPub *rsa.PublicKey, nvCerts [][]byte, manufacturer string, allowFetch bool) EKReport {
	sum := sha256.Sum256(x509.MarshalPKCS1PublicKey(ekPub))
	rep := EKReport{PublicSHA256: fmt.Sprintf("%x", sum), CertSource: "none"}

	var leaf *x509.Certificate
	for i, der := range nvCerts {
		c, err := goattest.ParseEKCertificate(der)
		if err != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("NV cert %d unparseable: %v", i, err))
			continue
		}
		if k, ok := c.PublicKey.(*rsa.PublicKey); ok && k.Equal(ekPub) {
			leaf, rep.CertSource = c, "tpm-nv"
			break
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf("NV cert %d (%s) is not for the RSA EK", i, c.Subject))
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
				rep.Notes = append(rep.Notes, "manufacturer EK cert fetch failed: "+err.Error())
			} else {
				rep.CertSource = "manufacturer-service"
			}
		}
	}
	if leaf == nil {
		return rep
	}
	if k, ok := leaf.PublicKey.(*rsa.PublicKey); ok && k.Equal(ekPub) {
		rep.CertMatchesEK = true
	}
	rep.Chain = append(rep.Chain, info(leaf, rep.CertSource))

	rep.ChainSignatures = true
	cur := leaf
	for depth := 0; depth < 6; depth++ {
		if bytes.Equal(cur.RawIssuer, cur.RawSubject) && cur.CheckSignature(cur.SignatureAlgorithm, cur.RawTBSCertificate, cur.Signature) == nil {
			rep.ChainEndsAtRoot = true
			break
		}
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
			lastErr = fmt.Errorf("%s: %w", u, err)
		}
		if parent == nil {
			if lastErr == nil {
				lastErr = errors.New("no AIA issuer URL")
			}
			rep.Notes = append(rep.Notes, "chain walk stopped: "+lastErr.Error())
			break
		}
		// EK certs often carry critical TPM-specific extensions, so check signatures
		// directly instead of using x509.Verify.
		if err := parent.CheckSignature(cur.SignatureAlgorithm, cur.RawTBSCertificate, cur.Signature); err != nil {
			rep.ChainSignatures = false
			rep.Notes = append(rep.Notes, fmt.Sprintf("signature on %q does not verify under %q: %v", cur.Subject, parent.Subject, err))
		}
		rep.Chain = append(rep.Chain, info(parent, "aia"))
		cur = parent
	}
	if !rep.ChainEndsAtRoot {
		rep.ChainSignatures = false
	}
	return rep
}
