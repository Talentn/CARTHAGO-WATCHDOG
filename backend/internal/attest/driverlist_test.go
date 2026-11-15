package attest_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"carthago/backend/internal/attest"
	"carthago/backend/internal/attest/driverlisttest"
)

var driverKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

func sampleDrivers() []attest.ListedDriver {
	h := func(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }
	return []attest.ListedDriver{
		{Name: "ntfs.sys", HashAlg: "sha256", ImageHash: h("ntfs"), Signer: h("ms")[:20], Loads: 1, Boot: true},
		{Name: "vgk.sys", HashAlg: "sha256", ImageHash: h("vgk"), Signer: h("riot")[:20], OEM: "Riot Games", Loads: 1},
		{Name: "exactly-thirty-two-bytes-long.sy", HashAlg: "sha1", ImageHash: h("x")[:20], Signer: h("x")[:20], Loads: 3, Unloaded: true},
	}
}

func TestDriverPackageVerifiesAndLists(t *testing.T) {
	nonce := [32]byte{1, 2, 3}
	pkg := driverlisttest.Package(driverlisttest.DriverReport(sampleDrivers(), 0), nonce, driverKey)
	key, err := attest.IDKSPublicKey(driverlisttest.IDKSEvent(&driverKey.PublicKey))
	if err != nil || key.N.Cmp(driverKey.N) != 0 || key.E != driverKey.E {
		t.Fatalf("signing key event: %v", err)
	}
	r, err := attest.CheckDriverPackage(pkg, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Verified || r.Overflowed || len(r.Drivers) != 3 {
		t.Fatalf("report %+v", r)
	}
	for i, want := range sampleDrivers() {
		got := r.Drivers[i]
		if got.Name != want.Name || got.HashAlg != want.HashAlg || !bytes.Equal(got.ImageHash, want.ImageHash) || !bytes.Equal(got.Signer, want.Signer) ||
			got.OEM != want.OEM || got.Loads != want.Loads || got.Unloaded != want.Unloaded || got.Boot != want.Boot {
			t.Errorf("driver %d: %+v, want %+v", i, got, want)
		}
	}

	// Without the boot record's key the list is read and not called verified.
	if r, err := attest.CheckDriverPackage(pkg, nonce, nil); err != nil || r.Verified || len(r.Drivers) != 3 {
		t.Fatalf("without a key: %+v %v", r, err)
	}
	// Another machine's key.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := attest.CheckDriverPackage(pkg, nonce, &other.PublicKey); !errors.Is(err, attest.ErrDriverSignature) {
		t.Fatalf("a package signed by another key: %v", err)
	}
	// A list made for another handshake.
	if _, err := attest.CheckDriverPackage(pkg, [32]byte{9}, key); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("replayed package: %v", err)
	}
}

func TestDriverPackageRejectsTampering(t *testing.T) {
	nonce := [32]byte{7}
	report := driverlisttest.DriverReport(sampleDrivers(), 0)
	pkg := driverlisttest.Package(report, nonce, driverKey)
	key := &driverKey.PublicKey
	reportAt := len(pkg) - len(report)

	change := func(name string, f func(p []byte) []byte, want string) {
		t.Helper()
		p := f(append([]byte{}, pkg...))
		_, err := attest.CheckDriverPackage(p, nonce, key)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error about %q", name, err, want)
		}
		// Whatever is wrong, a package that fails with the key never passes as an
		// unverified list of something else either, except for the signature itself.
		if _, err := attest.CheckDriverPackage(p, nonce, nil); err == nil && want != "signature" {
			t.Errorf("%s: accepted without a key", name)
		}
	}
	change("a driver renamed", func(p []byte) []byte { p[reportAt+12+56] = 'x'; return p }, "digest")
	change("a driver removed from the count", func(p []byte) []byte { p[reportAt+8] = 2; return p }, "digest")
	change("a digest rewritten to match", func(p []byte) []byte { p[72+4] ^= 1; return p }, "digest")
	change("the signature", func(p []byte) []byte { p[72+68+5] ^= 1; return p }, "signature")
	change("the nonce", func(p []byte) []byte { p[40] ^= 1; return p }, "nonce")
	change("the magic", func(p []byte) []byte { p[0] = 0; return p }, "magic")
	change("the version", func(p []byte) []byte { p[4] = 2; return p }, "version")
	change("the scheme", func(p []byte) []byte { p[26] = 2; return p }, "scheme")
	change("a cut package", func(p []byte) []byte { return p[:len(p)-1] }, "bytes")
	change("bytes appended", func(p []byte) []byte { return append(p, 0) }, "bytes")
	change("nothing", func(p []byte) []byte { return nil }, "short")

	// The first builds with the function signed an empty list. It is not a clean PC.
	empty := driverlisttest.Package(driverlisttest.DriverReport(nil, 0), nonce, driverKey)
	if _, err := attest.CheckDriverPackage(empty, nonce, key); err == nil || !strings.Contains(err.Error(), "no driver") {
		t.Errorf("an empty signed list: %v", err)
	}
	// Entries that point outside the report, in a correctly signed package.
	bad := append([]byte{}, report...)
	binary.LittleEndian.PutUint32(bad[12+36:], uint32(len(bad)-4))
	if _, err := attest.CheckDriverPackage(driverlisttest.Package(bad, nonce, driverKey), nonce, key); err == nil {
		t.Error("an image hash running past the report was accepted")
	}
	binary.LittleEndian.PutUint32(bad[12+36:], 4)
	if _, err := attest.CheckDriverPackage(driverlisttest.Package(bad, nonce, driverKey), nonce, key); err == nil {
		t.Error("an image hash inside the headers was accepted")
	}
	over, err := attest.CheckDriverPackage(driverlisttest.Package(driverlisttest.DriverReport(sampleDrivers(), driverlisttest.ReportOverflowed), nonce, driverKey), nonce, key)
	if err != nil || !over.Overflowed {
		t.Errorf("overflowed list: %+v %v", over, err)
	}
}

// The header and the vgk.sys entry of a package from a real Windows 11 PC, as published
// in the analysis the format was taken from: the field offsets here are Windows' own.
func TestDriverEntryLayoutMatchesAPublishedPackage(t *testing.T) {
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	header := unhex("50525452 0100 0100 0100000000000000 514d0000 0e80 4400 0000 0100 00010000 c54b0000 00000000")
	if size, sig, reports := binary.LittleEndian.Uint32(header[16:]), binary.LittleEndian.Uint32(header[28:]), binary.LittleEndian.Uint32(header[32:]); len(header) != 40 || 72+68+sig+reports != size {
		t.Fatalf("published header: %d bytes, sizes %d %d %d", len(header), size, sig, reports)
	}

	entry := append(append([]byte("vgk.sys"), make([]byte, 25)...), unhex("0c80 0480 cb2a0000 eb2a0000 0100 0a00 ff2a0000 0000 0000")...)
	hash := unhex("7f9c9d6bc6b08440727733fd34641c76cccaa43f8291f7bdc659129134236a70")
	signer := unhex("6022340c9f4cb00307df8db036d392adac766212")
	report := make([]byte, 0x2b0a)
	binary.LittleEndian.PutUint32(report[4:], uint32(len(report)))
	binary.LittleEndian.PutUint16(report[8:], 1)
	copy(report[12:], entry)
	copy(report[0x2acb:], hash)
	copy(report[0x2aeb:], signer)
	copy(report[0x2aff:], "Riot Games")

	nonce := [32]byte{4}
	r, err := attest.CheckDriverPackage(driverlisttest.Package(report, nonce, driverKey), nonce, &driverKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	d := r.Drivers[0]
	if d.Name != "vgk.sys" || d.HashAlg != "sha256" || !bytes.Equal(d.ImageHash, hash) || !bytes.Equal(d.Signer, signer) || d.OEM != "Riot Games" || d.Loads != 1 || d.Unloaded || d.Boot {
		t.Fatalf("entry %+v", d)
	}
}

func TestIDKSPublicKeyRejectsOtherPayloads(t *testing.T) {
	good := driverlisttest.IDKSEvent(&driverKey.PublicKey)
	if good[0] != 1 || binary.LittleEndian.Uint32(good[4:]) != 2048 || binary.LittleEndian.Uint32(good[8:]) != 3 || binary.LittleEndian.Uint32(good[12:]) != 256 {
		t.Fatalf("event header % x", good[:16])
	}
	for name, p := range map[string][]byte{
		"short":         good[:10],
		"cut":           good[:len(good)-1],
		"not RSA":       append([]byte{2}, good[1:]...),
		"even exponent": append(append(append([]byte{}, good[:16]...), 1, 0, 0), good[19:]...),
		"small modulus": append(append([]byte{}, good[:19]...), make([]byte, 256)...),
	} {
		if _, err := attest.IDKSPublicKey(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
