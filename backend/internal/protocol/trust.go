package protocol

// attest_flags bits carried in session tokens (mirrored in sn-crypto and proto/README.md).
const (
	FlagTPMDeviceKey       uint64 = 1 << 0  // device key claims to be a PCP (TPM) key
	FlagDeviceKeyCertified uint64 = 1 << 1  // TPM2_Certify by the AK proves the device key is TPM-resident
	FlagAKBoundToEK        uint64 = 1 << 2  // AK proven to live in the TPM owning the EK
	FlagQuoteVerified      uint64 = 1 << 3  // quote bound to this handshake + WBCL replayed
	FlagSecureBoot         uint64 = 1 << 4  // from the verified log
	FlagHVCI               uint64 = 1 << 5  // from the verified log
	FlagTestSigningOff     uint64 = 1 << 6  // from the verified log
	FlagKernelDebugOff     uint64 = 1 << 7  // from the verified log
	FlagBootDebugOff       uint64 = 1 << 8  // from the verified log
	FlagCodeIntegrity      uint64 = 1 << 9  // from the verified log
	FlagEKCertMatches      uint64 = 1 << 10 // an EK certificate for this EK was found
	FlagEKChainVerified    uint64 = 1 << 11 // EK certificate chains to a bundled manufacturer root
)

// Trust levels (studios gate queues on these).
const (
	TrustSoftware   uint32 = 0 // software device key, no TPM
	TrustTPMKey     uint32 = 1 // TPM key claimed, attestation missing or failed
	TrustAttested   uint32 = 2 // device key certified + AK bound to EK + quote verified
	TrustRankedBoot uint32 = 3 // attested and the boot state meets the ranked policy
)

const (
	attestedMask = FlagTPMDeviceKey | FlagDeviceKeyCertified | FlagAKBoundToEK | FlagQuoteVerified
	rankedMask   = attestedMask | FlagSecureBoot | FlagHVCI | FlagTestSigningOff | FlagKernelDebugOff | FlagBootDebugOff | FlagCodeIntegrity
)

// TrustLevel derives the token trust level from verified attestation flags.
func TrustLevel(flags uint64) uint32 {
	switch {
	case flags&rankedMask == rankedMask:
		return TrustRankedBoot
	case flags&attestedMask == attestedMask:
		return TrustAttested
	case flags&FlagTPMDeviceKey != 0:
		return TrustTPMKey
	}
	return TrustSoftware
}
