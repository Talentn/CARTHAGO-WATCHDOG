// Package ekroots holds the bundled TPM manufacturer CA certificates (Intel PTT/fTPM, AMD
// fTPM, Infineon, STMicro, Nuvoton) and builds EK certificate chains to them.
//
// The bundle is generated from Microsoft's TrustedTpm.cab by tools/carthago-update-ek-roots.sh.
// As on Windows, every certificate in a vendor's RootCA folder is a trust anchor, and
// IntermediateCA certificates are untrusted path-building candidates.
package ekroots

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

//go:embed certs/*.pem certs/VERSION
var embedded embed.FS

// Status is the outcome of EK certificate chain verification.
type Status string

const (
	// StatusVerified: the EK certificate chains to a bundled manufacturer root.
	StatusVerified Status = "verified"
	// StatusUnknownVendor: an EK certificate exists but no issuer path reaches a bundled
	// root (vendor not bundled, self-issued as by swtpm, or an intermediate is missing).
	StatusUnknownVendor Status = "unknown_vendor"
	// StatusInvalid: a candidate path exists but a signature or CA constraint fails, or the
	// certificate does not certify this EK.
	StatusInvalid Status = "invalid"
	// StatusNoCert: no EK certificate for this EK was available.
	StatusNoCert Status = "no_cert"
)

const maxDepth = 8

type entry struct {
	cert   *x509.Certificate
	vendor string
	name   string
	anchor bool
}

// Bundle is an immutable set of trust anchors and intermediates.
type Bundle struct {
	Version   string
	bySubject map[string][]*entry
	// byName and bySKID find issuers whose subject is encoded differently from the
	// child's issuer field (e.g. PrintableString vs UTF8String); signatures still decide.
	byName  map[string][]*entry
	bySKID  map[string][]*entry
	anchors int
	inter   int
	// Skipped lists bundle entries that could not be parsed at all.
	Skipped []string
}

var (
	defaultOnce   sync.Once
	defaultBundle *Bundle
	defaultErr    error
)

// Default returns the embedded bundle.
func Default() (*Bundle, error) {
	defaultOnce.Do(func() {
		sub, err := fs.Sub(embedded, "certs")
		if err != nil {
			defaultErr = err
			return
		}
		defaultBundle, defaultErr = Load(sub)
	})
	return defaultBundle, defaultErr
}

// Load reads <vendor>-roots.pem and <vendor>-intermediates.pem files (and an optional
// VERSION file) from fsys.
func Load(fsys fs.FS) (*Bundle, error) {
	b := newBundle()
	if v, err := fs.ReadFile(fsys, "VERSION"); err == nil {
		b.Version = strings.TrimSpace(string(v))
	}
	names, err := fs.Glob(fsys, "*.pem")
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		base := strings.TrimSuffix(path.Base(n), ".pem")
		vendor, kind, ok := strings.Cut(base, "-")
		if !ok || (kind != "roots" && kind != "intermediates") {
			continue
		}
		data, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, err
		}
		b.addPEM(data, vendor, kind == "roots", n)
	}
	if b.anchors == 0 {
		return nil, errors.New("ekroots: bundle has no trust anchors")
	}
	return b, nil
}

// WithExtraRoots returns a copy of b that also trusts the given PEM or DER certificates as
// anchors (vendor "custom"), e.g. a development swtpm CA.
func (b *Bundle) WithExtraRoots(files map[string][]byte) (*Bundle, error) {
	nb := newBundle()
	nb.Version, nb.Skipped = b.Version, b.Skipped
	for _, es := range b.bySubject {
		for _, e := range es {
			nb.add(e)
		}
	}
	for name, data := range files {
		before := nb.anchors
		if bytes.Contains(data, []byte("-----BEGIN")) {
			nb.addPEM(data, "custom", true, name)
		} else if c, err := ParseCertificate(data); err == nil {
			nb.add(&entry{cert: c, vendor: "custom", name: name, anchor: true})
		}
		if nb.anchors == before {
			return nil, fmt.Errorf("ekroots: no certificate in %s", name)
		}
	}
	return nb, nil
}

func (b *Bundle) addPEM(data []byte, vendor string, anchor bool, file string) {
	label := ""
	for len(data) > 0 {
		line, rest, _ := bytes.Cut(data, []byte("\n"))
		if l := strings.TrimSpace(string(line)); strings.HasPrefix(l, "# ") {
			label = strings.TrimPrefix(l, "# ")
			data = rest
			continue
		}
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := ParseCertificate(blk.Bytes)
		if err != nil {
			b.Skipped = append(b.Skipped, fmt.Sprintf("%s: %s: %v", file, label, err))
			continue
		}
		b.add(&entry{cert: c, vendor: vendor, name: label, anchor: anchor})
	}
}

func (b *Bundle) add(e *entry) {
	if e.anchor {
		b.anchors++
	} else {
		b.inter++
	}
	b.index(e)
}

func newBundle() *Bundle {
	return &Bundle{bySubject: map[string][]*entry{}, byName: map[string][]*entry{}, bySKID: map[string][]*entry{}}
}

func (b *Bundle) index(e *entry) {
	k := string(e.cert.RawSubject)
	b.bySubject[k] = append(b.bySubject[k], e)
	n := e.cert.Subject.String()
	b.byName[n] = append(b.byName[n], e)
	if len(e.cert.SubjectKeyId) > 0 {
		s := string(e.cert.SubjectKeyId)
		b.bySKID[s] = append(b.bySKID[s], e)
	}
}

// issuers returns the distinct candidate issuers of c.
func (b *Bundle) issuers(c *x509.Certificate) []*entry {
	var out []*entry
	seen := map[*entry]bool{}
	for _, es := range [][]*entry{b.bySubject[string(c.RawIssuer)], b.byName[c.Issuer.String()], b.bySKID[string(c.AuthorityKeyId)]} {
		for _, e := range es {
			if !seen[e] {
				seen[e] = true
				out = append(out, e)
			}
		}
	}
	return out
}

// Counts returns the number of anchors and intermediates in the bundle.
func (b *Bundle) Counts() (anchors, intermediates int) { return b.anchors, b.inter }

// Contains reports whether c itself is in the bundle.
func (b *Bundle) Contains(c *x509.Certificate) bool {
	for _, e := range b.bySubject[string(c.RawSubject)] {
		if bytes.Equal(e.cert.Raw, c.Raw) {
			return true
		}
	}
	return false
}

// HasIssuer reports whether the bundle holds a candidate issuer for c.
func (b *Bundle) HasIssuer(c *x509.Certificate) bool { return len(b.issuers(c)) > 0 }

// ParseCertificate parses DER strictly, then retries with the TBS serial number
// re-encoded minimally (some vendor CAs use a padded INTEGER). The returned certificate
// keeps the original Raw, RawTBSCertificate and Signature, so signatures made over and by
// it verify against the original bytes.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	c, err := x509.ParseCertificate(der)
	if err == nil {
		return c, nil
	}
	fixed, tbs, sig, ok := normalizeSerial(der)
	if !ok {
		return nil, err
	}
	c, err2 := x509.ParseCertificate(fixed)
	if err2 != nil {
		return nil, err
	}
	c.Raw, c.RawTBSCertificate, c.Signature = der, tbs, sig
	return c, nil
}

// normalizeSerial rewrites a certificate with a non-minimal serial INTEGER into minimal
// form. It returns the rewritten DER plus the original TBS bytes and signature value.
func normalizeSerial(der []byte) (fixed, origTBS, sig []byte, ok bool) {
	in := cryptobyte.String(der)
	var cert, tbs cryptobyte.String
	if !in.ReadASN1(&cert, cbasn1.SEQUENCE) || !in.Empty() {
		return nil, nil, nil, false
	}
	rest := cert
	var tbsFull cryptobyte.String
	if !rest.ReadASN1Element(&tbsFull, cbasn1.SEQUENCE) {
		return nil, nil, nil, false
	}
	tail := []byte(rest) // signatureAlgorithm || signatureValue
	{
		r := rest
		var alg, bits cryptobyte.String
		if !r.ReadASN1Element(&alg, cbasn1.SEQUENCE) || !r.ReadASN1(&bits, cbasn1.BIT_STRING) || len(bits) == 0 || bits[0] != 0 {
			return nil, nil, nil, false
		}
		sig = []byte(bits[1:])
	}
	t := tbsFull
	if !t.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		return nil, nil, nil, false
	}
	var version cryptobyte.String
	hasVersion := tbs.PeekASN1Tag(cbasn1.Tag(0).Constructed().ContextSpecific())
	if hasVersion && !tbs.ReadASN1Element(&version, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, nil, nil, false
	}
	var serial cryptobyte.String
	if !tbs.ReadASN1(&serial, cbasn1.INTEGER) || len(serial) == 0 {
		return nil, nil, nil, false
	}
	s := []byte(serial)
	for len(s) > 1 && ((s[0] == 0x00 && s[1]&0x80 == 0) || (s[0] == 0xff && s[1]&0x80 != 0)) {
		s = s[1:]
	}
	if len(s) == len(serial) {
		return nil, nil, nil, false
	}
	var nb cryptobyte.Builder
	nb.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		c.AddASN1(cbasn1.SEQUENCE, func(t *cryptobyte.Builder) {
			t.AddBytes(version)
			t.AddASN1(cbasn1.INTEGER, func(i *cryptobyte.Builder) { i.AddBytes(s) })
			t.AddBytes(tbs)
		})
		c.AddBytes(tail)
	})
	out, err := nb.Bytes()
	if err != nil {
		return nil, nil, nil, false
	}
	return out, []byte(tbsFull), sig, true
}

// Result describes a chain verification.
type Result struct {
	Status Status
	// Vendor is the bundle vendor of the anchor reached (intel, amd, infineon, stmicro,
	// nuvoton, custom); empty unless verified.
	Vendor string
	// Root is the anchor's subject; Chain runs from the leaf to the anchor.
	Root   string
	Chain  []*x509.Certificate
	Detail string
	Notes  []string
}

// Verify builds a path from leaf to a bundled anchor. extra holds untrusted candidate
// intermediates (from the TPM's NV, the client, or AIA fetches).
//
// Every certificate on the path, the EK certificate and the anchor included, must be
// within its validity period at now; when several issuers match, an out-of-date one is
// skipped in favour of a current one. EK certificates and vendor CAs are issued with long
// lifetimes (Intel On-Die CAs and PTT EKs run to 2049; RFC 5280's 99991231235959Z means no
// expiry and is honoured as such), so an expired certificate means the vendor no longer
// vouches for the path. A path that fails only on dates is StatusInvalid, which caps
// trust like an unknown vendor does.
func (b *Bundle) Verify(leaf *x509.Certificate, extra []*x509.Certificate, now time.Time) Result {
	if leaf == nil {
		return Result{Status: StatusNoCert}
	}
	extras := newBundle()
	for _, c := range extra {
		if c != nil && !bytes.Equal(c.Raw, leaf.Raw) {
			extras.index(&entry{cert: c, name: "supplied"})
		}
	}
	v := &verifier{b: b, extras: extras, now: now, seen: map[[32]byte]bool{}, budget: maxSignatureChecks}
	path, anchor := v.walk(leaf, 0)
	if anchor == nil {
		if v.budget <= 0 {
			return Result{Status: StatusInvalid, Detail: fmt.Sprintf("no issuer path found within %d signature checks", maxSignatureChecks)}
		}
		if v.failure != "" {
			return Result{Status: StatusInvalid, Detail: v.failure}
		}
		return Result{Status: StatusUnknownVendor, Detail: fmt.Sprintf("no bundled issuer path for %q", leaf.Issuer.String())}
	}
	if msg := outsideValidity(leaf, now); msg != "" {
		return Result{Status: StatusInvalid, Detail: "EK certificate " + msg}
	}
	return Result{Status: StatusVerified, Vendor: anchor.vendor, Root: anchor.cert.Subject.String(), Chain: append([]*x509.Certificate{leaf}, path...)}
}

// outsideValidity describes why c is not valid at now, or returns "".
func outsideValidity(c *x509.Certificate, now time.Time) string {
	switch {
	case now.Before(c.NotBefore):
		return fmt.Sprintf("%q is not valid before %s", c.Subject.String(), c.NotBefore.UTC().Format(time.RFC3339))
	case now.After(c.NotAfter):
		return fmt.Sprintf("%q expired %s", c.Subject.String(), c.NotAfter.UTC().Format(time.RFC3339))
	}
	return ""
}

// maxSignatureChecks bounds the path search of one Verify call. The supplied intermediates
// are attacker-controlled: a handful of mutually cross-signed CA certificates with one name
// would otherwise make the depth-first search try every ordering of them. Real EK chains
// have at most a few candidates per level.
const maxSignatureChecks = 128

type verifier struct {
	b       *Bundle
	extras  *Bundle
	now     time.Time
	seen    map[[32]byte]bool
	failure string
	budget  int
}

// walk returns the issuer path above child (child excluded) ending at an anchor.
func (v *verifier) walk(child *x509.Certificate, depth int) ([]*x509.Certificate, *entry) {
	if depth >= maxDepth {
		return nil, nil
	}
	key := sha256.Sum256(child.Raw)
	if v.seen[key] {
		return nil, nil
	}
	v.seen[key] = true
	defer delete(v.seen, key)

	for _, p := range append(v.b.issuers(child), v.extras.issuers(child)...) {
		pc := p.cert
		if len(child.AuthorityKeyId) > 0 && len(pc.SubjectKeyId) > 0 && !bytes.Equal(child.AuthorityKeyId, pc.SubjectKeyId) {
			continue
		}
		if v.budget <= 0 {
			return nil, nil
		}
		v.budget--
		if err := pc.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature); err != nil {
			v.fail(fmt.Sprintf("signature on %q does not verify under %q: %v", child.Subject.String(), pc.Subject.String(), err))
			continue
		}
		if !p.anchor {
			if !pc.BasicConstraintsValid || !pc.IsCA {
				v.fail(fmt.Sprintf("issuer %q is not a CA", pc.Subject.String()))
				continue
			}
		}
		// depth counts the CA certificates between pc and the EK certificate.
		if pc.BasicConstraintsValid && (pc.MaxPathLen > 0 || pc.MaxPathLenZero) && depth > pc.MaxPathLen {
			v.fail(fmt.Sprintf("issuer %q allows %d CA certificates below it, the path has %d", pc.Subject.String(), pc.MaxPathLen, depth))
			continue
		}
		if pc.KeyUsage != 0 && pc.KeyUsage&x509.KeyUsageCertSign == 0 {
			v.fail(fmt.Sprintf("issuer %q lacks keyCertSign", pc.Subject.String()))
			continue
		}
		if msg := outsideValidity(pc, v.now); msg != "" {
			v.fail("issuer " + msg)
			continue
		}
		if p.anchor {
			return []*x509.Certificate{pc}, p
		}
		if rest, a := v.walk(pc, depth+1); a != nil {
			return append([]*x509.Certificate{pc}, rest...), a
		}
	}
	return nil, nil
}

func (v *verifier) fail(msg string) {
	if v.failure == "" {
		v.failure = msg
	}
}
