package attest

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"
)

// The runtime driver list of Windows 11: GetRuntimeAttestationReport returns a "Runtime
// Report Package" in which the Secure Kernel lists every kernel driver image it has
// validated since boot, unloaded ones included, and signs it. The structures are those of
// winnt.h (RUNTIME_REPORT_PACKAGE_HEADER, RUNTIME_REPORT_DIGEST_HEADER,
// DRIVER_RUNTIME_REPORT, DRIVER_INFO_ENTRY), all little-endian and packed:
//
//	0x00  package header, 40 bytes: magic "RTRP", version 1, number of reports, report
//	      bitmap, package size, digest type (CALG_SHA_512), size of the digest headers,
//	      signature scheme (1: RSA-PSS with SHA-512), signature size, size of the reports
//	0x28  the caller's nonce, 32 bytes
//	0x48  one digest header per report, 68 bytes: report type and the SHA-512 of the report
//	...   the signature, over the SHA-512 of everything before it
//	...   the reports; the driver report is a 12-byte header, 56-byte entries in load
//	      order, then the hashes and names the entries point at
//
// Microsoft documents the function and the structures; which key signs is described by
// the engineer who built it (Allievi, 2026) and traced in an independent analysis: the
// Secure Kernel's identity signing key, whose public half the boot loader measures into
// PCR 12 as SIPAEVENT_VSM_IDKS_INFO. Nothing here was checked against a package from a
// real PC.
const (
	driverPackageMagic    = 0x52545250
	driverPackageHeader   = 40
	driverNonceLen        = 32
	driverDigestHeader    = 68
	driverReportHeader    = 12
	driverEntrySize       = 56
	driverNameLen         = 32
	calgSHA1              = 0x8004
	calgSHA256            = 0x800c
	calgSHA384            = 0x800d
	calgSHA512            = 0x800e
	schemePSSSHA512       = 1
	runtimeReportDriver   = 0
	driverFlagUnloaded    = 1 << 0
	driverFlagBoot        = 1 << 1
	driverFlagHotPatch    = 1 << 2
	reportFlagOverflowed  = 1 << 0
	reportFlagPartial     = 1 << 1
	reportFlagBootDrivers = 1 << 2

	// MaxDriverPackage bounds what the gateway reads. Windows records at most 384 images,
	// which is some tens of kilobytes.
	MaxDriverPackage = 512 << 10
)

// ListedDriver is one kernel driver image of the list.
type ListedDriver struct {
	// Name is the InternalName of the image's version resource, cut to 32 bytes by
	// Windows; a label, not an identity. It can be empty.
	Name string
	// HashAlg and ImageHash are the Authenticode hash of the image, which is what
	// identifies it.
	HashAlg   string
	ImageHash []byte
	// Signer is the SHA-1 thumbprint of the leaf certificate that validated the image,
	// nil when the entry carries none.
	Signer []byte
	// OEM is the program name of the signature; inbox Windows drivers have none.
	OEM   string
	Loads int
	// Unloaded: unloaded at least once since boot. It does not mean the driver is not
	// loaded now.
	Unloaded, Boot, HotPatch bool
}

// DriverReport is a driver list that parsed and matched its digest and nonce.
type DriverReport struct {
	Drivers []ListedDriver
	// Overflowed: Windows' table was full, so later drivers are missing.
	Overflowed bool
	// Partial and BootDrivers are the report's other two flags, as sent.
	Partial, BootDrivers bool
	// Verified: the signature was checked with the signing key of a verified boot record.
	// Unverified says why not, when it was not.
	Verified   bool
	Unverified string
}

// ErrDriverSignature: the package's signature does not verify under the signing key of
// the session's verified boot record.
var ErrDriverSignature = errors.New("the signature does not verify under the signing key of the boot record")

// IDKSPublicKey parses the payload of SIPAEVENT_VSM_IDKS_INFO: key algorithm 1 (RSA), bit
// length, exponent size and modulus size as 32-bit integers, then exponent and modulus,
// big-endian.
func IDKSPublicKey(payload []byte) (*rsa.PublicKey, error) {
	if len(payload) < 16 {
		return nil, errors.New("signing key event too short")
	}
	alg, bits := binary.LittleEndian.Uint32(payload[0:]), binary.LittleEndian.Uint32(payload[4:])
	elen, mlen := int(binary.LittleEndian.Uint32(payload[8:])), int(binary.LittleEndian.Uint32(payload[12:]))
	if alg != 1 {
		return nil, fmt.Errorf("signing key algorithm %d, want 1 (RSA)", alg)
	}
	if elen < 1 || elen > 8 || mlen < 256 || mlen > 1024 || len(payload) != 16+elen+mlen || int(bits) != mlen*8 {
		return nil, fmt.Errorf("signing key event of %d bytes does not hold a %d-bit RSA key", len(payload), bits)
	}
	e := new(big.Int).SetBytes(payload[16 : 16+elen])
	n := new(big.Int).SetBytes(payload[16+elen:])
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || e.Bit(0) == 0 || n.BitLen() != mlen*8 {
		return nil, errors.New("signing key event holds no usable RSA key")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// CheckDriverPackage reads a Runtime Report Package that was asked for with nonce.
//
// A package that is not exactly the documented layout, carries another nonce, whose
// driver report does not match the signed digest, or that lists no driver is an error: a
// list that does not parse is malformed, never empty. With key, the signing key of the
// session's verified boot record, the signature is checked too and a bad one is
// ErrDriverSignature. Without key the list is returned with Verified false.
func CheckDriverPackage(pkg []byte, nonce [32]byte, key *rsa.PublicKey) (*DriverReport, error) {
	if len(pkg) > MaxDriverPackage {
		return nil, fmt.Errorf("package of %d bytes is larger than any driver list", len(pkg))
	}
	if len(pkg) < driverPackageHeader+driverNonceLen {
		return nil, errors.New("package too short")
	}
	le16 := func(off int) int { return int(binary.LittleEndian.Uint16(pkg[off:])) }
	le32 := func(off int) int { return int(binary.LittleEndian.Uint32(pkg[off:])) }
	if uint32(le32(0)) != driverPackageMagic {
		return nil, errors.New("not a Runtime Report Package (magic)")
	}
	if v := le16(4); v != 1 {
		return nil, fmt.Errorf("package version %d, want 1", v)
	}
	reports, bitmap := le16(6), binary.LittleEndian.Uint64(pkg[8:])
	size, digestType, digestsSize := le32(16), le16(20), le16(22)
	scheme, sigSize, reportsSize := le16(26), le32(28), le32(32)
	switch {
	case size != len(pkg):
		return nil, fmt.Errorf("package says %d bytes and is %d", size, len(pkg))
	case reports < 1 || bitmap&1 == 0:
		return nil, errors.New("package holds no driver report")
	case digestType != calgSHA512 || digestsSize != reports*driverDigestHeader:
		return nil, errors.New("package digests are not SHA-512 digest headers")
	case scheme != schemePSSSHA512:
		return nil, fmt.Errorf("signature scheme %d, want 1 (RSA-PSS with SHA-512)", scheme)
	case sigSize < 256 || sigSize > 1024:
		return nil, fmt.Errorf("signature of %d bytes", sigSize)
	}
	signedLen := driverPackageHeader + driverNonceLen + digestsSize
	reportsAt := signedLen + sigSize
	if reportsAt+reportsSize != len(pkg) {
		return nil, errors.New("package sections do not add up to its size")
	}
	if !bytes.Equal(pkg[driverPackageHeader:driverPackageHeader+driverNonceLen], nonce[:]) {
		return nil, errors.New("the package was not made for this handshake (nonce)")
	}

	// Walk the reports next to their digest headers. Every byte after the signature must
	// belong to a report whose digest is in the signed part.
	var drivers []byte
	at := reportsAt
	for i := 0; i < reports; i++ {
		dh := pkg[driverPackageHeader+driverNonceLen+i*driverDigestHeader:][:driverDigestHeader]
		if len(pkg)-at < 8 {
			return nil, errors.New("truncated report header")
		}
		typ, rsize := le16(at), le32(at+4)
		if rsize < 8 || rsize > len(pkg)-at {
			return nil, fmt.Errorf("report %d has an invalid size", i)
		}
		if int(binary.LittleEndian.Uint16(dh)) != typ {
			return nil, fmt.Errorf("report %d is of another type than its digest", i)
		}
		sum := sha512.Sum512(pkg[at : at+rsize])
		if !bytes.Equal(sum[:], dh[4:]) {
			return nil, fmt.Errorf("report %d does not match its signed digest", i)
		}
		if typ == runtimeReportDriver {
			if drivers != nil {
				return nil, errors.New("two driver reports")
			}
			drivers = pkg[at : at+rsize]
		}
		at += rsize
	}
	if at != len(pkg) {
		return nil, errors.New("bytes after the last report")
	}
	if drivers == nil {
		return nil, errors.New("package holds no driver report")
	}
	out, err := parseDriverReport(drivers)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return out, nil
	}
	digest := sha512.Sum512(pkg[:signedLen])
	if err := rsa.VerifyPSS(key, crypto.SHA512, digest[:], pkg[signedLen:reportsAt], &rsa.PSSOptions{SaltLength: sha512.Size, Hash: crypto.SHA512}); err != nil {
		return nil, ErrDriverSignature
	}
	out.Verified = true
	return out, nil
}

func parseDriverReport(r []byte) (*DriverReport, error) {
	if len(r) < driverReportHeader {
		return nil, errors.New("driver report shorter than its header")
	}
	n, flags := int(binary.LittleEndian.Uint16(r[8:])), binary.LittleEndian.Uint16(r[10:])
	if n == 0 {
		// Only the first builds that had the function signed an empty list; a current
		// Windows always has drivers to list.
		return nil, errors.New("the driver report lists no driver")
	}
	if driverReportHeader+n*driverEntrySize > len(r) {
		return nil, errors.New("driver entries do not fit in the report")
	}
	out := &DriverReport{Overflowed: flags&reportFlagOverflowed != 0, Partial: flags&reportFlagPartial != 0, BootDrivers: flags&reportFlagBootDrivers != 0}
	blob := func(off, size int) ([]byte, bool) {
		if size == 0 {
			return nil, true
		}
		if off < driverReportHeader+n*driverEntrySize || off > len(r) || size > len(r)-off {
			return nil, false
		}
		return r[off : off+size], true
	}
	for i := 0; i < n; i++ {
		e := r[driverReportHeader+i*driverEntrySize:][:driverEntrySize]
		d := ListedDriver{Name: cleanDriverText(e[:driverNameLen])}
		hashAlg, signerAlg := binary.LittleEndian.Uint16(e[32:]), binary.LittleEndian.Uint16(e[34:])
		hashOff, signerOff := int(binary.LittleEndian.Uint32(e[36:])), int(binary.LittleEndian.Uint32(e[40:]))
		d.Loads = int(binary.LittleEndian.Uint16(e[44:]))
		oemSize, oemOff := int(binary.LittleEndian.Uint16(e[46:])), int(binary.LittleEndian.Uint32(e[48:]))
		eflags := binary.LittleEndian.Uint16(e[52:])
		d.Unloaded, d.Boot, d.HotPatch = eflags&driverFlagUnloaded != 0, eflags&driverFlagBoot != 0, eflags&driverFlagHotPatch != 0

		var hashLen int
		d.HashAlg, hashLen = driverHash(hashAlg)
		hash, ok := blob(hashOff, hashLen)
		if !ok || hashLen == 0 {
			return nil, fmt.Errorf("driver %d has no image hash the report holds", i)
		}
		d.ImageHash = append([]byte{}, hash...)
		if signerOff != 0 {
			_, signerLen := driverHash(signerAlg)
			signer, ok := blob(signerOff, signerLen)
			if !ok {
				return nil, fmt.Errorf("driver %d points outside the report", i)
			}
			if len(signer) > 0 && !allZero(signer) {
				d.Signer = append([]byte{}, signer...)
			}
		}
		oem, ok := blob(oemOff, oemSize)
		if !ok {
			return nil, fmt.Errorf("driver %d points outside the report", i)
		}
		d.OEM = cleanDriverText(oem)
		out.Drivers = append(out.Drivers, d)
	}
	return out, nil
}

func driverHash(alg uint16) (string, int) {
	switch alg {
	case calgSHA1:
		return "sha1", 20
	case calgSHA256:
		return "sha256", 32
	case calgSHA384:
		return "sha384", 48
	case calgSHA512:
		return "sha512", 64
	}
	return "", 0
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// cleanDriverText turns a fixed or counted UTF-8 field into text that is safe to store
// and show: up to the first NUL, valid UTF-8, no control characters.
func cleanDriverText(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	s := strings.ToValidUTF8(string(b), "")
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
}
