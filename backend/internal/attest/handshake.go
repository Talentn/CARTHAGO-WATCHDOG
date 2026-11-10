package attest

import (
	"crypto"
	"crypto/elliptic"
	"crypto/subtle"
	"fmt"
	"math/big"
	"sort"
	"time"

	goattest "github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"

	"carthago/backend/internal/attest/ekroots"
)

// Handshake-oriented verification used by the gateway: no HTTP enrollment state, every
// check is bound to the caller-supplied nonce (the handshake's quote_nonce).

// Enrollment is a validated, not yet bound, AK enrollment with its EK challenge.
type Enrollment struct {
	EKPublicSHA256 string
	EK             EKReport
	AKPublic       []byte
	hmacKey        *goattest.HMAC
	Challenge      EKChallenge
}

// PrepareEnrollment validates the AK creation evidence (restricted, fixedTPM,
// TPM-generated) and creates a decryption-EK challenge only this TPM's EK can answer.
func PrepareEnrollment(ekPublicBlob []byte, ekCerts, ekChainCerts [][]byte, ak AKParams, manufacturer string, fetchEK bool, roots *ekroots.Bundle, now time.Time) (*Enrollment, error) {
	ekPub, err := DecodeBCryptRSAPublic(ekPublicBlob)
	if err != nil {
		return nil, clientErr("EK public: %v", err)
	}
	if _, err := goattest.ParseAKPublic(ak.Public); err != nil {
		return nil, clientErr("AK public: %v", err)
	}
	params := goattest.ActivationParameters{
		EK: ekPub,
		AK: goattest.AttestationParameters{Public: ak.Public, CreateData: ak.CreateData, CreateAttestation: ak.CreateAttestation, CreateSignature: ak.CreateSignature},
	}
	if _, _, err := params.Generate(); err != nil {
		return nil, clientErr("AK creation evidence rejected: %v", err)
	}
	ch, hmacKey, err := goattest.GenerateEkChallenge(ekPub)
	if err != nil {
		return nil, fmt.Errorf("EK challenge: %w", err)
	}
	rep := CheckEK(ekPub, ekCerts, ekChainCerts, manufacturer, fetchEK, roots, now)
	return &Enrollment{
		EKPublicSHA256: rep.PublicSHA256,
		EK:             rep,
		AKPublic:       ak.Public,
		hmacKey:        hmacKey,
		Challenge:      EKChallenge{ObjectPublic: ch.ObjectPublic, Duplicate: ch.Duplicate, InSymSeed: ch.InSymSeed},
	}, nil
}

// RecheckEK re-verifies the EK certificate chain of a device whose AK is already bound, so
// bundle updates apply to returning devices. It fails if the presented EK is not the one the
// AK was bound to (boundEKSHA256).
func RecheckEK(ekPublicBlob []byte, ekCerts, ekChainCerts [][]byte, manufacturer string, fetchEK bool, roots *ekroots.Bundle, now time.Time, boundEKSHA256 string) (EKReport, error) {
	ekPub, err := DecodeBCryptRSAPublic(ekPublicBlob)
	if err != nil {
		return EKReport{}, clientErr("EK public: %v", err)
	}
	rep := CheckEK(ekPub, ekCerts, ekChainCerts, manufacturer, fetchEK, roots, now)
	if subtle.ConstantTimeCompare([]byte(rep.PublicSHA256), []byte(boundEKSHA256)) != 1 {
		return EKReport{}, clientErr("presented EK is not the EK this AK is bound to")
	}
	return rep, nil
}

// VerifyEKCertify checks the solved EK challenge: the AK was certified by an HMAC key that
// only the TPM owning the EK could import.
func (e *Enrollment) VerifyEKCertify(attest, signature []byte) error {
	cp := &goattest.CertificationParameters{Public: e.AKPublic, CreateAttestation: attest, CreateSignature: signature}
	if err := goattest.VerifySolvedDecryptionEkChallenge(e.AKPublic, cp, *e.hmacKey); err != nil {
		return clientErr("EK challenge not solved for this AK: %v", err)
	}
	return nil
}

// VerifyDeviceKeyCertify checks TPM2_Certify(device key) signed by the AK, with the
// handshake nonce as qualifying data, and that the certified key is the P-256 device key
// (uncompressed SEC1) used in the handshake. It proves the device key is TPM-generated,
// non-exportable and non-duplicable.
func VerifyDeviceKeyCertify(akPublic, devicePublicArea, deviceSEC1, attest, signature, nonce []byte) error {
	ak, err := goattest.ParseAKPublic(akPublic)
	if err != nil {
		return clientErr("AK public: %v", err)
	}
	pub, err := tpm2.DecodePublic(devicePublicArea)
	if err != nil {
		return clientErr("device key TPMT_PUBLIC: %v", err)
	}
	if pub.Type != tpm2.AlgECC || pub.ECCParameters == nil || pub.ECCParameters.CurveID != tpm2.CurveNISTP256 {
		return clientErr("device key TPMT_PUBLIC is not ECC P-256")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), deviceSEC1)
	if x == nil || pub.ECCParameters.Point.XRaw == nil ||
		new(big.Int).SetBytes(pub.ECCParameters.Point.XRaw).Cmp(x) != 0 || new(big.Int).SetBytes(pub.ECCParameters.Point.YRaw).Cmp(y) != 0 {
		return clientErr("certified TPM key is not the handshake device key")
	}
	cp := &goattest.CertificationParameters{Public: devicePublicArea, CreateAttestation: attest, CreateSignature: signature}
	if err := cp.Verify(goattest.VerifyOpts{Public: ak.Public, Hash: ak.Hash}); err != nil {
		return clientErr("device key certification: %v", err)
	}
	ad, err := tpm2.DecodeAttestationData(attest)
	if err != nil {
		return clientErr("certify attestation: %v", err)
	}
	if subtle.ConstantTimeCompare(ad.ExtraData, nonce) != 1 {
		return clientErr("device key certification is not bound to this handshake")
	}
	return nil
}

// BootResult is the verified boot evidence for one quote.
type BootResult struct {
	Checks   []Check        `json:"checks"`
	Security *SecurityState `json:"security_state,omitempty"`
	Policy   PolicyResult   `json:"policy"`
	EventLog map[string]any `json:"event_log,omitempty"`
	// QuoteOK: quote signature, nonce and PCR digest verified and the event log replays.
	QuoteOK bool `json:"quote_ok"`
}

// VerifyBootEvidence verifies a TPM2_Quote by the AK bound to nonce, replays the WBCL
// against the quoted PCRs and parses the Windows boot security state.
func VerifyBootEvidence(akPublic, nonce, quote, quoteSig []byte, pcrValues []PCRValue, eventLog []byte) *BootResult {
	r := &BootResult{}
	add := func(name string, err error, okDetail string) bool {
		c := Check{Name: name, OK: err == nil, Detail: okDetail}
		if err != nil {
			c.Detail = err.Error()
		}
		r.Checks = append(r.Checks, c)
		return err == nil
	}
	ak, err := goattest.ParseAKPublic(akPublic)
	if !add("ak_public", err, "") {
		r.Policy = evaluatePolicy(false, nil)
		return r
	}
	pcrs := make([]goattest.PCR, 0, len(pcrValues))
	idx := make([]int, 0, len(pcrValues))
	for _, p := range pcrValues {
		pcrs = append(pcrs, goattest.PCR{Index: p.Index, Digest: p.Digest, DigestAlg: crypto.SHA256})
		idx = append(idx, p.Index)
	}
	sort.Ints(idx)
	quoteErr := ak.Verify(goattest.Quote{Quote: quote, Signature: quoteSig}, pcrs, nonce)
	add("quote_signature_nonce_pcrs", quoteErr, fmt.Sprintf("AK signature valid, nonce bound, PCR digest matches PCRs %v (sha256)", idx))

	el, err := goattest.ParseEventLog(eventLog)
	var events []goattest.Event
	if err == nil {
		r.EventLog = map[string]any{"bytes": len(eventLog), "algs": fmt.Sprint(el.Algs), "raw_events": len(el.Events(goattest.HashSHA256))}
		events, err = el.Verify(pcrs)
	}
	logOK := add("event_log_replay", err, fmt.Sprintf("%d events replay to the quoted PCRs", len(events)))
	r.QuoteOK = quoteErr == nil && logOK
	if logOK {
		sec, perr := securityState(events)
		if add("boot_state_parse", perr, "Secure Boot (PCR7), SIPA (PCR12/13)") {
			r.Security = sec
		}
	}
	r.Policy = evaluatePolicy(r.QuoteOK && r.Security != nil, r.Security)
	return r
}
