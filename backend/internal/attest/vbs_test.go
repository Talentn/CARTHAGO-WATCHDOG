package attest

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"

	goattest "github.com/google/go-attestation/attest"
)

func sipa(typ uint32, val uint64) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:], typ)
	binary.LittleEndian.PutUint32(b[4:], 8)
	binary.LittleEndian.PutUint64(b[8:], val)
	return b
}

func pcr12(typ goattest.EventType, data []byte) goattest.Event {
	d := sha256.Sum256(data)
	return goattest.Event{Index: 12, Type: typ, Data: data, Digest: d[:]}
}

func tagged(entries ...[]byte) goattest.Event {
	var body []byte
	for _, e := range entries {
		body = append(body, e...)
	}
	data := make([]byte, 8, 8+len(body))
	binary.LittleEndian.PutUint32(data[4:], uint32(len(body)))
	return pcr12(evEventTag, append(data, body...))
}

func TestParseVBSReadsBootOptions(t *testing.T) {
	events := []goattest.Event{
		tagged(sipa(sipaCodeIntegrity, 1), sipa(sipaHypervisorLaunch, 1), sipa(sipaVSMLaunchType, 1), sipa(sipaVBSHVCIPolicy, 1)),
		tagged(sipa(sipaTestSigning, 1)),
		pcr12(evSeparator, []byte("WBCL")),
		tagged(sipa(sipaOSKernelDebug, 1)), // after the separator: not part of the boot state
	}
	v, err := ParseVBS(events)
	if err != nil {
		t.Fatal(err)
	}
	if !v.HVCIEnforced() || v.TestSigning == nil || *v.TestSigning != 1 || v.OSKernelDebug != nil {
		t.Errorf("state %+v", v)
	}
}

// The event type is not covered by the PCR digest. A client that relabels the event
// reporting test signing must not end up with "test signing off".
func TestParseVBSRejectsRelabelledEvents(t *testing.T) {
	ci := tagged(sipa(sipaCodeIntegrity, 1))
	testSigning := tagged(sipa(sipaTestSigning, 1))

	relabelled := testSigning
	relabelled.Type = 0x5 // EV_ACTION: same digest, so the log still replays
	if v, err := ParseVBS([]goattest.Event{ci, relabelled}); err == nil {
		t.Errorf("relabelled event skipped silently, state %+v", v)
	}

	fakeSep := ci
	fakeSep.Type = evSeparator
	if _, err := ParseVBS([]goattest.Event{fakeSep, testSigning}); err == nil || !strings.Contains(err.Error(), "separator") {
		t.Errorf("event relabelled as a separator accepted: %v", err)
	}

	sep := pcr12(evSeparator, []byte("WBCL"))
	if _, err := ParseVBS([]goattest.Event{ci, sep, sep}); err == nil {
		t.Error("duplicate separator accepted")
	}

	// Data that does not hash to the replayed digest, whatever the digest length.
	for _, n := range []int{32, 20, 0} {
		forged := tagged(sipa(sipaTestSigning, 0))
		forged.Digest = make([]byte, n)
		if _, err := ParseVBS([]goattest.Event{forged}); err == nil {
			t.Errorf("event data not matching a %d-byte digest accepted", n)
		}
	}
}
