// Package driverlisttest builds Runtime Report Packages the way Windows lays them out,
// for tests and the simulators. Nothing in it runs on a player's PC.
package driverlisttest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"

	"carthago/backend/internal/attest"
)

// ReportOverflowed is the driver report flag for a full table.
const ReportOverflowed = 1

// DriverReport lays out a driver report: header, entries, then the hashes and names.
func DriverReport(drivers []attest.ListedDriver, flags uint16) []byte {
	const header, entry = 12, 56
	r := make([]byte, header+entry*len(drivers))
	binary.LittleEndian.PutUint16(r[8:], uint16(len(drivers)))
	binary.LittleEndian.PutUint16(r[10:], flags)
	algs := map[string]uint16{"sha1": 0x8004, "sha256": 0x800c, "sha384": 0x800d, "sha512": 0x800e}
	for i, d := range drivers {
		e := r[header+entry*i:][:entry]
		copy(e[:32], d.Name)
		binary.LittleEndian.PutUint16(e[32:], algs[d.HashAlg])
		binary.LittleEndian.PutUint16(e[34:], 0x8004)
		binary.LittleEndian.PutUint32(e[36:], uint32(len(r)))
		r = append(r, d.ImageHash...)
		e = r[header+entry*i:][:entry]
		if d.Signer != nil {
			binary.LittleEndian.PutUint32(e[40:], uint32(len(r)))
			r = append(r, d.Signer...)
			e = r[header+entry*i:][:entry]
		}
		binary.LittleEndian.PutUint16(e[44:], uint16(d.Loads))
		binary.LittleEndian.PutUint16(e[46:], uint16(len(d.OEM)))
		if d.OEM != "" {
			binary.LittleEndian.PutUint32(e[48:], uint32(len(r)))
			r = append(r, d.OEM...)
			r = append(r, 0)
			e = r[header+entry*i:][:entry]
		}
		var f uint16
		if d.Unloaded {
			f |= 1
		}
		if d.Boot {
			f |= 2
		}
		if d.HotPatch {
			f |= 4
		}
		binary.LittleEndian.PutUint16(e[52:], f)
	}
	binary.LittleEndian.PutUint32(r[4:], uint32(len(r)))
	return r
}

// Package wraps a driver report in a package for nonce, signed by key.
func Package(report []byte, nonce [32]byte, key *rsa.PrivateKey) []byte {
	const header, digest = 40, 68
	sigSize := key.Size()
	p := make([]byte, header, header+32+digest+sigSize+len(report))
	binary.LittleEndian.PutUint32(p[0:], 0x52545250)
	binary.LittleEndian.PutUint16(p[4:], 1)
	binary.LittleEndian.PutUint16(p[6:], 1)
	binary.LittleEndian.PutUint64(p[8:], 1)
	binary.LittleEndian.PutUint32(p[16:], uint32(header+32+digest+sigSize+len(report)))
	binary.LittleEndian.PutUint16(p[20:], 0x800e)
	binary.LittleEndian.PutUint16(p[22:], digest)
	binary.LittleEndian.PutUint16(p[26:], 1)
	binary.LittleEndian.PutUint32(p[28:], uint32(sigSize))
	binary.LittleEndian.PutUint32(p[32:], uint32(len(report)))
	p = append(p, nonce[:]...)
	sum := sha512.Sum512(report)
	p = append(p, 0, 0, 0, 0)
	p = append(p, sum[:]...)
	signed := sha512.Sum512(p)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA512, signed[:], &rsa.PSSOptions{SaltLength: sha512.Size, Hash: crypto.SHA512})
	if err != nil {
		panic(err)
	}
	p = append(p, sig...)
	return append(p, report...)
}

// IDKSEvent is the payload of the boot log event that carries the signing key.
func IDKSEvent(pub *rsa.PublicKey) []byte {
	e := []byte{byte(pub.E >> 16), byte(pub.E >> 8), byte(pub.E)}
	n := pub.N.Bytes()
	b := make([]byte, 16, 16+len(e)+len(n))
	binary.LittleEndian.PutUint32(b[0:], 1)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(n)*8))
	binary.LittleEndian.PutUint32(b[8:], uint32(len(e)))
	binary.LittleEndian.PutUint32(b[12:], uint32(len(n)))
	return append(append(b, e...), n...)
}
