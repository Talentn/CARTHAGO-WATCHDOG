// Package attest verifies TPM attestation evidence from the Sentinel client (plan §5.4):
// AK enrollment via credential activation, TPM2_Quote over the Windows PCRs bound to a
// server nonce, event-log replay, and the boot security state parsed from the WBCL.
package attest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	goattest "github.com/google/go-attestation/attest"
)

const nonceTTL = 2 * time.Minute

type AKParams struct {
	Public            []byte `json:"public"`
	CreateData        []byte `json:"create_data"`
	CreateAttestation []byte `json:"create_attestation"`
	CreateSignature   []byte `json:"create_signature"`
}

type EnrollRequest struct {
	TPM             json.RawMessage `json:"tpm"`
	EKPublic        []byte          `json:"ek_public"`
	EKCerts         [][]byte        `json:"ek_certs"`
	AK              AKParams        `json:"ak"`
	DeviceKeyAlg    string          `json:"device_key_alg"`
	DeviceKeyPublic []byte          `json:"device_key_public"`
	Client          json.RawMessage `json:"client"`
}

// EKChallenge is go-attestation's DecryptionEkChallenge: an HMAC key duplicated to the EK.
type EKChallenge struct {
	ObjectPublic []byte `json:"object_public"`
	Duplicate    []byte `json:"duplicate"`
	InSymSeed    []byte `json:"in_sym_seed"`
}

type EnrollResponse struct {
	EnrollmentID string `json:"enrollment_id"`
	// ActivationBlob is TPM2B_ID_OBJECT || TPM2B_ENCRYPTED_SECRET for TPM2_ActivateCredential.
	ActivationBlob []byte `json:"activation_blob"`
	// EKChallenge is the alternative proof that TBS permits without elevation.
	EKChallenge EKChallenge `json:"ek_challenge"`
}

// ActivateRequest carries one of the two AK-to-EK binding proofs.
type ActivateRequest struct {
	EnrollmentID     string `json:"enrollment_id"`
	Method           string `json:"method"`
	Secret           []byte `json:"secret,omitempty"`
	CertifyAttest    []byte `json:"certify_attest,omitempty"`
	CertifySignature []byte `json:"certify_signature,omitempty"`
}

type ActivateResponse struct {
	Nonce []byte `json:"nonce"`
}

type PCRValue struct {
	Index  int    `json:"index"`
	Digest []byte `json:"digest"`
}

type AttestRequest struct {
	EnrollmentID    string          `json:"enrollment_id"`
	Nonce           []byte          `json:"nonce"`
	Quote           []byte          `json:"quote"`
	QuoteSignature  []byte          `json:"quote_signature"`
	PCRs            []PCRValue      `json:"pcrs"`
	EventLog        []byte          `json:"event_log"`
	DeviceSignature []byte          `json:"device_signature"`
	Steps           json.RawMessage `json:"steps"`
}

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type SecurityState struct {
	SecureBoot           bool     `json:"secure_boot"`
	HVCI                 bool     `json:"hvci_memory_integrity"`
	TestSigning          bool     `json:"test_signing"`
	KernelDebug          bool     `json:"kernel_debug"`
	BootDebug            bool     `json:"boot_debug"`
	CodeIntegrity        string   `json:"code_integrity"`
	DEP                  string   `json:"dep"`
	ColdBoot             bool     `json:"cold_boot"`
	BootCount            uint64   `json:"boot_count"`
	ELAMDrivers          []string `json:"elam_drivers"`
	BootModules          int      `json:"boot_modules_measured"`
	SecureBootDBEntries  int      `json:"secure_boot_db_entries"`
	SecureBootDBXEntries int      `json:"secure_boot_dbx_hashes"`
	VBS                  VBSState `json:"vbs_raw"`
	Source               string   `json:"windows_events_source"`
}

type PolicyResult struct {
	Casual         bool     `json:"casual"`
	Ranked         bool     `json:"ranked"`
	RankedFailures []string `json:"ranked_failures,omitempty"`
}

type Report struct {
	Verdict      string          `json:"verdict"`
	EnrollmentID string          `json:"enrollment_id"`
	VerifiedAt   time.Time       `json:"verified_at"`
	TPM          json.RawMessage `json:"tpm"`
	Client       json.RawMessage `json:"client"`
	Checks       []Check         `json:"checks"`
	EK           EKReport        `json:"ek"`
	AK           map[string]any  `json:"ak"`
	EventLog     map[string]any  `json:"event_log"`
	Security     *SecurityState  `json:"security_state,omitempty"`
	Policy       PolicyResult    `json:"policy"`
	ClientSteps  json.RawMessage `json:"client_steps"`
}

type enrollment struct {
	req       EnrollRequest
	ekPub     *rsa.PublicKey
	ek        EKReport
	akPub     *goattest.AKPublic
	devicePub crypto.PublicKey
	secret    []byte
	hmacKey   *goattest.HMAC
	activated string
	nonce     []byte
	nonceAt   time.Time
}

type Verifier struct {
	FetchEKCerts bool

	mu          sync.Mutex
	enrollments map[string]*enrollment
}

func NewVerifier(fetchEKCerts bool) *Verifier {
	return &Verifier{FetchEKCerts: fetchEKCerts, enrollments: map[string]*enrollment{}}
}

// ClientError marks failures caused by the evidence rather than the verifier.
type ClientError struct{ Err error }

func (e ClientError) Error() string { return e.Err.Error() }

func clientErr(format string, a ...any) error { return ClientError{fmt.Errorf(format, a...)} }

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func decodeDeviceKey(alg string, blob []byte) (crypto.PublicKey, error) {
	switch alg {
	case "EcdsaP256":
		// BCRYPT_ECCKEY_BLOB: magic "ECS1", cbKey, X, Y.
		if len(blob) < 8 || binary.LittleEndian.Uint32(blob[0:4]) != 0x31534345 {
			return nil, errors.New("not a BCRYPT_ECDSA_PUBLIC_P256 blob")
		}
		n := int(binary.LittleEndian.Uint32(blob[4:8]))
		if n != 32 || len(blob) < 8+2*n {
			return nil, errors.New("bad P-256 blob length")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(blob[8 : 8+n]), Y: new(big.Int).SetBytes(blob[8+n : 8+2*n])}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("device key point not on P-256")
		}
		return pub, nil
	case "Rsa2048":
		return DecodeBCryptRSAPublic(blob)
	}
	return nil, fmt.Errorf("unsupported device key algorithm %q", alg)
}

// Enroll validates the AK creation evidence and returns a credential-activation challenge
// encrypted to the EK, so only the TPM holding both EK and AK can answer it.
func (v *Verifier) Enroll(req EnrollRequest, manufacturer string) (*EnrollResponse, error) {
	ekPub, err := DecodeBCryptRSAPublic(req.EKPublic)
	if err != nil {
		return nil, clientErr("EK public: %v", err)
	}
	akPub, err := goattest.ParseAKPublic(req.AK.Public)
	if err != nil {
		return nil, clientErr("AK public: %v", err)
	}
	devicePub, err := decodeDeviceKey(req.DeviceKeyAlg, req.DeviceKeyPublic)
	if err != nil {
		return nil, clientErr("device key: %v", err)
	}
	params := goattest.ActivationParameters{
		EK: ekPub,
		AK: goattest.AttestationParameters{
			Public:            req.AK.Public,
			CreateData:        req.AK.CreateData,
			CreateAttestation: req.AK.CreateAttestation,
			CreateSignature:   req.AK.CreateSignature,
		},
	}
	secret, ec, err := params.Generate()
	if err != nil {
		return nil, clientErr("AK creation evidence rejected: %v", err)
	}
	challenge, hmacKey, err := goattest.GenerateEkChallenge(ekPub)
	if err != nil {
		return nil, fmt.Errorf("EK challenge: %w", err)
	}
	e := &enrollment{
		req:       req,
		ekPub:     ekPub,
		ek:        CheckEK(ekPub, req.EKCerts, manufacturer, v.FetchEKCerts),
		akPub:     akPub,
		devicePub: devicePub,
		secret:    secret,
		hmacKey:   hmacKey,
	}
	id := hex.EncodeToString(randomBytes(8))
	v.mu.Lock()
	v.enrollments[id] = e
	v.mu.Unlock()
	return &EnrollResponse{
		EnrollmentID:   id,
		ActivationBlob: append(append([]byte{}, ec.Credential...), ec.Secret...),
		EKChallenge:    EKChallenge{ObjectPublic: challenge.ObjectPublic, Duplicate: challenge.Duplicate, InSymSeed: challenge.InSymSeed},
	}, nil
}

func (v *Verifier) get(id string) (*enrollment, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.enrollments[id]
	if !ok {
		return nil, clientErr("unknown enrollment %q", id)
	}
	return e, nil
}

// Activate checks the AK-to-EK binding proof and, on success, issues a fresh quote nonce.
func (v *Verifier) Activate(req ActivateRequest) (*ActivateResponse, error) {
	e, err := v.get(req.EnrollmentID)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	switch req.Method {
	case "activate-credential":
		if subtle.ConstantTimeCompare(req.Secret, e.secret) != 1 {
			return nil, clientErr("activation secret mismatch: AK is not resident in the TPM that owns this EK")
		}
	case "ek-certify":
		cp := &goattest.CertificationParameters{Public: e.req.AK.Public, CreateAttestation: req.CertifyAttest, CreateSignature: req.CertifySignature}
		if err := goattest.VerifySolvedDecryptionEkChallenge(e.req.AK.Public, cp, *e.hmacKey); err != nil {
			return nil, clientErr("EK challenge not solved for this AK: %v", err)
		}
	default:
		return nil, clientErr("unknown binding method %q", req.Method)
	}
	e.activated = req.Method
	e.nonce = randomBytes(32)
	e.nonceAt = time.Now()
	return &ActivateResponse{Nonce: e.nonce}, nil
}

func ternary(t goattest.Ternary) string {
	switch t {
	case goattest.TernaryTrue:
		return "enabled"
	case goattest.TernaryFalse:
		return "disabled"
	}
	return "unknown"
}

// Attest verifies the quote, replays the event log and evaluates the boot state.
func (v *Verifier) Attest(req AttestRequest) (*Report, error) {
	e, err := v.get(req.EnrollmentID)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	nonce, nonceAt, activated := e.nonce, e.nonceAt, e.activated
	e.nonce = nil
	v.mu.Unlock()

	rep := &Report{
		EnrollmentID: req.EnrollmentID,
		VerifiedAt:   time.Now().UTC(),
		TPM:          e.req.TPM,
		Client:       e.req.Client,
		EK:           e.ek,
		ClientSteps:  req.Steps,
		AK: map[string]any{
			"hash": e.akPub.Hash.String(),
			"type": fmt.Sprintf("%T", e.akPub.Public),
		},
	}
	add := func(name string, err error, okDetail string) bool {
		c := Check{Name: name, OK: err == nil, Detail: okDetail}
		if err != nil {
			c.Detail = err.Error()
		}
		rep.Checks = append(rep.Checks, c)
		return err == nil
	}

	add("ak_creation_evidence", nil, "restricted, fixedTPM, TPM-generated (checked at enroll)")
	var actErr error
	bindDetail := map[string]string{
		"activate-credential": "TPM2_ActivateCredential returned the server secret",
		"ek-certify":          "AK certified by a server HMAC key that only this EK could import (TPM2_Import/Load/Certify)",
	}[activated]
	if activated == "" {
		actErr = errors.New("AK-to-EK binding not completed")
	}
	add("ak_ek_binding", actErr, bindDetail)
	rep.AK["ek_binding_method"] = activated

	var nonceErr error
	switch {
	case nonce == nil:
		nonceErr = errors.New("no outstanding nonce (already used or never issued)")
	case time.Since(nonceAt) > nonceTTL:
		nonceErr = fmt.Errorf("nonce expired after %s", time.Since(nonceAt).Round(time.Second))
	case subtle.ConstantTimeCompare(nonce, req.Nonce) != 1:
		nonceErr = errors.New("nonce does not match the one issued")
	}
	add("nonce_fresh_single_use", nonceErr, fmt.Sprintf("issued %s ago", time.Since(nonceAt).Round(time.Millisecond)))

	pcrs := make([]goattest.PCR, 0, len(req.PCRs))
	idx := make([]int, 0, len(req.PCRs))
	for _, p := range req.PCRs {
		pcrs = append(pcrs, goattest.PCR{Index: p.Index, Digest: p.Digest, DigestAlg: crypto.SHA256})
		idx = append(idx, p.Index)
	}
	sort.Ints(idx)
	quoteErr := e.akPub.Verify(goattest.Quote{Quote: req.Quote, Signature: req.QuoteSignature}, pcrs, nonce)
	add("quote_signature_nonce_pcrs", quoteErr, fmt.Sprintf("AK signature valid, nonce bound, PCR digest matches PCRs %v (sha256)", idx))

	var devErr error
	digest := sha256.Sum256(append(append([]byte{}, req.Nonce...), req.Quote...))
	switch pub := e.devicePub.(type) {
	case *ecdsa.PublicKey:
		if len(req.DeviceSignature) != 64 {
			devErr = fmt.Errorf("ECDSA signature is %d bytes, want 64", len(req.DeviceSignature))
		} else if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(req.DeviceSignature[:32]), new(big.Int).SetBytes(req.DeviceSignature[32:])) {
			devErr = errors.New("device key signature invalid")
		}
	case *rsa.PublicKey:
		devErr = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], req.DeviceSignature)
	}
	add("device_key_signature", devErr, e.req.DeviceKeyAlg+" signature over sha256(nonce||quote)")

	el, err := goattest.ParseEventLog(req.EventLog)
	var events []goattest.Event
	if err == nil {
		rep.EventLog = map[string]any{"bytes": len(req.EventLog), "algs": fmt.Sprint(el.Algs), "raw_events": len(el.Events(goattest.HashSHA256))}
		events, err = el.Verify(pcrs)
	}
	if add("event_log_replay", err, "") {
		rep.EventLog["verified_events"] = len(events)
		rep.Checks[len(rep.Checks)-1].Detail = fmt.Sprintf("%d events replay to the quoted PCRs", len(events))
	}

	cryptoOK := true
	for _, c := range rep.Checks {
		cryptoOK = cryptoOK && c.OK
	}

	if err == nil {
		sec, perr := securityState(events)
		add("boot_state_parse", perr, "Secure Boot (PCR7), SIPA (PCR12/13)")
		if perr == nil {
			rep.Security = sec
		}
		cryptoOK = cryptoOK && perr == nil
	}

	rep.Policy = evaluatePolicy(cryptoOK, rep.Security)
	rep.Verdict = "fail"
	if cryptoOK {
		rep.Verdict = "pass"
	}
	return rep, nil
}

func securityState(events []goattest.Event) (*SecurityState, error) {
	sb, err := goattest.ParseSecurebootState(events)
	if err != nil {
		return nil, fmt.Errorf("secure boot: %w", err)
	}
	vbs, err := ParseVBS(events)
	if err != nil {
		return nil, fmt.Errorf("vbs: %w", err)
	}
	s := &SecurityState{
		SecureBoot:           sb.Enabled,
		HVCI:                 vbs.HVCIEnforced(),
		SecureBootDBEntries:  len(sb.PermittedKeys) + len(sb.PermittedHashes),
		SecureBootDBXEntries: len(sb.ForbiddenHashes),
		VBS:                  vbs,
	}
	win, err := goattest.ParseWinEvents(events)
	if err != nil {
		// go-attestation rejects SIPA event types it does not know (newer Windows builds add
		// some), so fall back to the same signals read by our own PCR 12 walker.
		s.Source = "sentinel SIPA walker (go-attestation ParseWinEvents: " + err.Error() + ")"
		set := func(p *uint64) bool { return p != nil && *p != 0 }
		s.TestSigning = set(vbs.TestSigning)
		s.KernelDebug = set(vbs.OSKernelDebug)
		s.BootDebug = set(vbs.BootDebugging)
		s.CodeIntegrity = "unknown"
		if vbs.CodeIntegrity != nil {
			s.CodeIntegrity = map[bool]string{true: "enabled", false: "disabled"}[*vbs.CodeIntegrity != 0]
		}
		s.DEP = "unknown"
		return s, nil
	}
	s.Source = "go-attestation ParseWinEvents"
	s.TestSigning = win.TestSigningEnabled
	s.KernelDebug = win.KernelDebugEnabled
	s.BootDebug = win.BootDebuggingEnabled
	s.CodeIntegrity = ternary(win.CodeIntegrityEnabled)
	s.DEP = ternary(win.DEPEnabled)
	s.ColdBoot = win.ColdBoot
	s.BootCount = win.BootCount
	s.BootModules = len(win.LoadedModules)
	for name := range win.ELAM {
		s.ELAMDrivers = append(s.ELAMDrivers, name)
	}
	sort.Strings(s.ELAMDrivers)
	return s, nil
}

// evaluatePolicy applies the example queue policies from plan §5.4 step 5.
func evaluatePolicy(cryptoOK bool, s *SecurityState) PolicyResult {
	r := PolicyResult{Casual: true}
	fail := func(cond bool, why string) {
		if cond {
			r.RankedFailures = append(r.RankedFailures, why)
		}
	}
	fail(!cryptoOK, "attestation evidence did not verify")
	if s == nil {
		fail(true, "no verified boot state")
	} else {
		fail(!s.SecureBoot, "Secure Boot off")
		fail(!s.HVCI, "HVCI (Memory Integrity) not enforced")
		fail(s.TestSigning, "test-signing on")
		fail(s.KernelDebug, "kernel debugging on")
		fail(s.BootDebug, "boot debugging on")
		fail(s.CodeIntegrity != "enabled", "code integrity not consistently enabled")
	}
	r.Ranked = len(r.RankedFailures) == 0
	return r
}
