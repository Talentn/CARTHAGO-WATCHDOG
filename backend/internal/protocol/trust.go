package protocol

// attest_flags bits carried in session tokens (mirrored in carthago-crypto and proto/README.md).
const (
	FlagTPMDeviceKey         uint64 = 1 << 0  // device key claims to be a PCP (TPM) key
	FlagDeviceKeyCertified   uint64 = 1 << 1  // TPM2_Certify by the AK proves the device key is TPM-resident
	FlagAKBoundToEK          uint64 = 1 << 2  // AK proven to live in the TPM owning the EK
	FlagQuoteVerified        uint64 = 1 << 3  // quote bound to this handshake + WBCL replayed
	FlagSecureBoot           uint64 = 1 << 4  // from the verified log
	FlagHVCI                 uint64 = 1 << 5  // from the verified log
	FlagTestSigningOff       uint64 = 1 << 6  // from the verified log
	FlagKernelDebugOff       uint64 = 1 << 7  // from the verified log
	FlagBootDebugOff         uint64 = 1 << 8  // from the verified log
	FlagCodeIntegrity        uint64 = 1 << 9  // from the verified log
	FlagEKCertMatches        uint64 = 1 << 10 // an EK certificate for this EK was found
	FlagEKChainVerified      uint64 = 1 << 11 // EK certificate chains to a bundled manufacturer root
	FlagEKChainUnknownVendor uint64 = 1 << 12 // EK certificate found, but no path to a bundled root
	FlagEKChainInvalid       uint64 = 1 << 13 // EK certificate or its chain failed verification
)

// Trust levels (studios gate queues on these).
const (
	TrustSoftware   uint32 = 0 // software device key, no TPM
	TrustTPMKey     uint32 = 1 // TPM key claimed; attestation missing or failed, or EK chain not verified
	TrustAttested   uint32 = 2 // device key certified + AK bound to a manufacturer-certified EK + quote verified
	TrustRankedBoot uint32 = 3 // attested and the boot state meets the ranked policy
)

const (
	// Level 2 and above require a verified EK chain: without it an emulated TPM (swtpm with
	// a self-issued EK certificate) passes every other check.
	attestedMask = FlagTPMDeviceKey | FlagDeviceKeyCertified | FlagAKBoundToEK | FlagQuoteVerified | FlagEKCertMatches | FlagEKChainVerified
	rankedMask   = attestedMask | FlagSecureBoot | FlagHVCI | FlagTestSigningOff | FlagKernelDebugOff | FlagBootDebugOff | FlagCodeIntegrity
)

// TrustLevel derives the token trust level from verified attestation flags.
func TrustLevel(flags uint64) uint32 {
	if flags&FlagTPMDeviceKey == 0 {
		return TrustSoftware
	}
	if flags&FlagEKChainInvalid != 0 {
		return TrustTPMKey
	}
	switch {
	case flags&rankedMask == rankedMask:
		return TrustRankedBoot
	case flags&attestedMask == attestedMask:
		return TrustAttested
	}
	return TrustTPMKey
}
