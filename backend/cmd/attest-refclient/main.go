// Command attest-refclient runs the enroll/activate/quote flow entirely through
// go-attestation's own Windows client. It is a reference for the Rust client in
// client/spikes/attest-spike: when both fail the same way the cause is the platform,
// not our PCP/TBS code.
package main

import (
	"crypto"
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	goattest "github.com/google/go-attestation/attest"
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

// run leaves a randomly named per-user PCP key (ak-<hex>) behind on every invocation.
func run() error {
	tpm, err := goattest.OpenTPM(nil)
	if err != nil {
		return fmt.Errorf("OpenTPM: %w", err)
	}
	defer tpm.Close()

	info, err := tpm.Info()
	if err != nil {
		return fmt.Errorf("Info: %w", err)
	}
	fmt.Printf("TPM: %s vendor=%q fw=%d.%d\n", info.Manufacturer, info.VendorInfo, info.FirmwareVersionMajor, info.FirmwareVersionMinor)

	eks, err := tpm.EKs()
	if err != nil {
		return fmt.Errorf("EKs: %w", err)
	}
	fmt.Printf("EKs: %d\n", len(eks))

	ak, err := tpm.NewAK(nil)
	if err != nil {
		return fmt.Errorf("NewAK: %w", err)
	}
	defer ak.Close(tpm)
	params := ak.AttestationParameters()

	for i, ek := range eks {
		ap := goattest.ActivationParameters{EK: ek.Public, AK: params}
		secret, ec, err := ap.Generate()
		if err != nil {
			return fmt.Errorf("Generate(ek %d): %w", i, err)
		}
		got, err := ak.ActivateCredential(tpm, *ec)
		fmt.Printf("EK %d (%T): ActivateCredential err=%v match=%v\n", i, ek.Public, err, err == nil && string(got) == string(secret))
	}

	for i := range eks {
		ek := eks[i]
		challenge, key, err := goattest.GenerateEkChallenge(ek.Public)
		if err != nil {
			fmt.Printf("EK %d: GenerateEkChallenge: %v\n", i, err)
			continue
		}
		cp, err := ak.CertifyWithDecryptionEk(tpm, &ek, *challenge)
		if err == nil {
			err = goattest.VerifySolvedDecryptionEkChallenge(params.Public, cp, *key)
		}
		fmt.Printf("EK %d (%T): decryption-EK certify err=%v\n", i, ek.Public, err)
	}

	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	pa, err := tpm.AttestPlatform(ak, nonce, nil)
	if err != nil {
		return fmt.Errorf("AttestPlatform: %w", err)
	}
	akPub, err := goattest.ParseAKPublic(params.Public)
	if err != nil {
		return err
	}
	var pcrs []goattest.PCR
	for _, p := range pa.PCRs {
		if p.DigestAlg == crypto.SHA256 {
			pcrs = append(pcrs, p)
		}
	}
	for _, q := range pa.Quotes {
		fmt.Printf("quote verify (%d PCRs sha256): %v\n", len(pcrs), akPub.Verify(q, pa.PCRs, nonce))
	}
	return nil
}
