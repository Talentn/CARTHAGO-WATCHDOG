package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Synthetic boot evidence for the verifier tests: a software P-256 key stands in for the AK
// and signs hand-built TPMS_ATTEST quotes over a hand-built crypto-agile event log. The
// gateway never accepts such a key as an AK (enrollment needs TPM creation evidence and the
// EK challenge); the tests only exercise what VerifyBootEvidence does with a quote.

type testAK struct {
	key *ecdsa.PrivateKey
	pub []byte
}

func newTestAK(t *testing.T) *testAK {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagRestricted | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			Sign:    &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256},
			CurveID: tpm2.CurveNISTP256,
			Point:   tpm2.ECPoint{XRaw: key.X.FillBytes(make([]byte, 32)), YRaw: key.Y.FillBytes(make([]byte, 32))},
		},
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return &testAK{key: key, pub: pub}
}

// quote signs a TPMS_ATTEST quote whose selection is sel and whose PCR digest covers
// values (in the order given).
func (a *testAK) quote(t *testing.T, nonce []byte, sel tpm2.PCRSelection, values [][]byte) (quote, sig []byte) {
	t.Helper()
	h := sha256.New()
	for _, v := range values {
		h.Write(v)
	}
	quote, err := tpm2.AttestationData{
		Magic:             0xff544347,
		Type:              tpm2.TagAttestQuote,
		QualifiedSigner:   tpm2.Name{Digest: &tpm2.HashValue{Alg: tpm2.AlgSHA256, Value: make([]byte, 32)}},
		ExtraData:         nonce,
		AttestedQuoteInfo: &tpm2.QuoteInfo{PCRSelection: sel, PCRDigest: h.Sum(nil)},
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(quote)
	r, s, err := ecdsa.Sign(rand.Reader, a.key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err = tpmutil.Pack(tpm2.AlgECDSA, tpm2.AlgSHA256, tpmutil.U16Bytes(r.Bytes()), tpmutil.U16Bytes(s.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return quote, sig
}

type testEvent struct {
	pcr  int
	data string
}

// testLog encodes a crypto-agile TCG event log (SHA-256 only) and returns it with the PCR
// values it replays to for WindowsPCRs.
func testLog(events []testEvent) (log []byte, pcrs []PCRValue) {
	var b bytes.Buffer
	le := func(v any) { binary.Write(&b, binary.LittleEndian, v) }
	var spec bytes.Buffer
	spec.WriteString("Spec ID Event03\x00")
	binary.Write(&spec, binary.LittleEndian, struct {
		PlatformClass uint32
		Minor, Major  uint8
		Errata, Uintn uint8
		NumAlgs       uint32
		Alg, Size     uint16
		VendorSize    uint8
	}{0, 0, 2, 0, 2, 1, 0x000b, 32, 0})
	le(uint32(0))
	le(uint32(3)) // EV_NO_ACTION
	b.Write(make([]byte, 20))
	le(uint32(spec.Len()))
	b.Write(spec.Bytes())

	state := map[int][]byte{}
	for _, e := range events {
		d := sha256.Sum256([]byte(e.data))
		le(uint32(e.pcr))
		le(uint32(0xd)) // EV_IPL
		le(uint32(1))
		le(uint16(0x000b))
		b.Write(d[:])
		le(uint32(len(e.data)))
		b.WriteString(e.data)
		prev := state[e.pcr]
		if prev == nil {
			prev = make([]byte, 32)
		}
		next := sha256.Sum256(append(append([]byte{}, prev...), d[:]...))
		state[e.pcr] = next[:]
	}
	for _, i := range WindowsPCRs {
		v := state[i]
		if v == nil {
			v = make([]byte, 32)
		}
		pcrs = append(pcrs, PCRValue{Index: i, Digest: v})
	}
	return b.Bytes(), pcrs
}

func digests(pcrs []PCRValue) [][]byte {
	out := make([][]byte, len(pcrs))
	for i, p := range pcrs {
		out[i] = p.Digest
	}
	return out
}

func failedCheck(r *BootResult) string {
	for _, c := range r.Checks {
		if !c.OK {
			return c.Name + ": " + c.Detail
		}
	}
	return ""
}

var (
	testNonce  = bytes.Repeat([]byte{0x5a}, 32)
	sha256Sel  = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: WindowsPCRs}
	bootEvents = []testEvent{{0, "firmware"}, {2, "option roms"}, {4, "boot manager"}, {7, "secure boot policy"}, {11, "bitlocker"}, {12, "boot options"}, {13, "boot modules"}, {14, "boot authorities"}}
)

func TestBootEvidenceAcceptsConsistentQuoteAndLog(t *testing.T) {
	ak := newTestAK(t)
	log, pcrs := testLog(bootEvents)
	quote, sig := ak.quote(t, testNonce, sha256Sel, digests(pcrs))
	r := VerifyBootEvidence(ak.pub, testNonce, quote, sig, pcrs, log)
	if !r.QuoteOK {
		t.Fatalf("consistent evidence rejected: %s", failedCheck(r))
	}
	if r2 := VerifyBootEvidence(ak.pub, bytes.Repeat([]byte{1}, 32), quote, sig, pcrs, log); r2.QuoteOK {
		t.Fatal("quote accepted for another handshake's nonce")
	}
}

// A duplicated PCR index used to let the quote check take the last value (the TPM's real
// one) while the event-log replay accepted the first (replayed from a fabricated log).
func TestBootEvidenceRejectsDuplicatePCRIndex(t *testing.T) {
	ak := newTestAK(t)
	_, real := testLog(bootEvents)
	quote, sig := ak.quote(t, testNonce, sha256Sel, digests(real))

	forged := append([]testEvent{}, bootEvents...)
	forged[5] = testEvent{12, "fabricated boot options"}
	forgedLog, forgedPCRs := testLog(forged)

	// Forged PCR 12 first, then the full real set (so the quote digest still matches).
	supplied := append([]PCRValue{forgedPCRs[5]}, real...)
	r := VerifyBootEvidence(ak.pub, testNonce, quote, sig, supplied, forgedLog)
	if r.QuoteOK || r.Security != nil {
		t.Fatal("duplicate PCR index accepted: a fabricated event log would be trusted")
	}
	if got := failedCheck(r); !strings.HasPrefix(got, "pcr_set:") {
		t.Fatalf("want the pcr_set check to fail, got %q", got)
	}
}

func TestBootEvidenceRejectsWrongPCRSet(t *testing.T) {
	ak := newTestAK(t)
	log, pcrs := testLog(bootEvents)
	quote, sig := ak.quote(t, testNonce, sha256Sel, digests(pcrs))
	short := append([]PCRValue{}, pcrs[:7]...)
	swapped := append(append([]PCRValue{}, pcrs[:7]...), PCRValue{Index: 23, Digest: make([]byte, 32)})
	sha1Len := append(append([]PCRValue{}, pcrs[:7]...), PCRValue{Index: 14, Digest: make([]byte, 20)})
	for name, set := range map[string][]PCRValue{"missing": short, "other index": swapped, "sha1 digest": sha1Len, "none": nil} {
		if r := VerifyBootEvidence(ak.pub, testNonce, quote, sig, set, log); r.QuoteOK {
			t.Errorf("%s: PCR set accepted", name)
		}
	}
}

// The quote's own selection decides which values it authenticates. Anything but the
// requested SHA-256 set must be refused before the values are used.
func TestBootEvidenceRejectsQuoteOverOtherSelection(t *testing.T) {
	ak := newTestAK(t)
	log, pcrs := testLog(bootEvents)
	cases := map[string]struct {
		sel    tpm2.PCRSelection
		values [][]byte
	}{
		// An empty selection in another bank authenticates no value at all; before the
		// selection check the SHA-256 values supplied next to it were not compared with it.
		"empty sha1 selection": {tpm2.PCRSelection{Hash: tpm2.AlgSHA1}, nil},
		"sha1 bank":            {tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: WindowsPCRs}, digests(pcrs)},
		"subset":               {tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 2, 4, 7}}, digests(pcrs[:4])},
		"superset":             {tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: append([]int{1}, WindowsPCRs...)}, digests(pcrs)},
	}
	for name, c := range cases {
		quote, sig := ak.quote(t, testNonce, c.sel, c.values)
		r := VerifyBootEvidence(ak.pub, testNonce, quote, sig, pcrs, log)
		if r.QuoteOK {
			t.Errorf("%s: quote accepted", name)
		}
		if got := failedCheck(r); !strings.HasPrefix(got, "quote_pcr_selection:") {
			t.Errorf("%s: want the quote_pcr_selection check to fail, got %q", name, got)
		}
	}
	if err := checkQuoteSelection([]byte("not a quote")); err == nil {
		t.Error("garbage accepted as a quote")
	}
}

// Dropping every event of one PCR used to pass the replay, so the boot options measured
// into PCR 12 (test signing, debugging) could be hidden.
func TestBootEvidenceRejectsLogMissingAPCR(t *testing.T) {
	ak := newTestAK(t)
	_, pcrs := testLog(bootEvents)
	quote, sig := ak.quote(t, testNonce, sha256Sel, digests(pcrs))
	var without12 []testEvent
	for _, e := range bootEvents {
		if e.pcr != 12 {
			without12 = append(without12, e)
		}
	}
	truncated, _ := testLog(without12)
	r := VerifyBootEvidence(ak.pub, testNonce, quote, sig, pcrs, truncated)
	if r.QuoteOK {
		t.Fatal("log without PCR 12 events accepted although PCR 12 was extended")
	}
	if got := failedCheck(r); !strings.Contains(got, "no events for PCR 12") {
		t.Fatalf("unexpected failure: %q", got)
	}

	// A PCR that was never extended needs no events.
	log, pcrs := testLog(without12)
	quote, sig = ak.quote(t, testNonce, sha256Sel, digests(pcrs))
	if r := VerifyBootEvidence(ak.pub, testNonce, quote, sig, pcrs, log); !r.QuoteOK {
		t.Fatalf("unextended PCR rejected: %s", failedCheck(r))
	}
}
