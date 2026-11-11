package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	goattest "github.com/google/go-attestation/attest"
)

// SIPA event identifiers from Windows wbcl.h that go-attestation's WinEvents does not surface.
const (
	sipaTypeMask            = 0x000f0000
	sipaContainer           = 0x00010000
	sipaBootDebugging       = 0x00040001
	sipaOSKernelDebug       = 0x00050001
	sipaCodeIntegrity       = 0x00050002
	sipaTestSigning         = 0x00050003
	sipaHypervisorLaunch    = 0x0005000A
	sipaHypervisorDebug     = 0x0005000D
	sipaVSMLaunchType       = 0x00050012
	sipaVBSVSMRequired      = 0x000A0001
	sipaVBSSecureBootReq    = 0x000A0002
	sipaVBSIOMMURequired    = 0x000A0003
	sipaVBSNXRequired       = 0x000A0004
	sipaVBSMandatoryEnforce = 0x000A0006
	sipaVBSHVCIPolicy       = 0x000A0007
	sipaVBSMSBootChainReq   = 0x000A0008

	evEventTag  = 0x6
	evSeparator = 0x4
)

// VBSState is the virtualization-based-security configuration Windows measured into
// PCR 12 at boot. Values are the raw little-endian integers; nil means "not measured".
type VBSState struct {
	HypervisorLaunchType  *uint64 `json:"hypervisor_launch_type"`
	HypervisorDebug       *uint64 `json:"hypervisor_debug"`
	VSMLaunchType         *uint64 `json:"vsm_launch_type"`
	VSMRequired           *uint64 `json:"vbs_vsm_required"`
	SecureBootRequired    *uint64 `json:"vbs_secureboot_required"`
	IOMMURequired         *uint64 `json:"vbs_iommu_required"`
	NXRequired            *uint64 `json:"vbs_nx_required"`
	MandatoryEnforcement  *uint64 `json:"vbs_mandatory_enforcement"`
	HVCIPolicy            *uint64 `json:"vbs_hvci_policy"`
	MicrosoftBootChainReq *uint64 `json:"vbs_microsoft_boot_chain_required"`
	// Raw copies of the signals WinEvents also parses, kept for cross-checking.
	OSKernelDebug *uint64 `json:"os_kernel_debug"`
	BootDebugging *uint64 `json:"boot_debugging"`
	CodeIntegrity *uint64 `json:"code_integrity"`
	TestSigning   *uint64 `json:"test_signing"`
}

// HVCIEnforced reports whether the measured boot configuration launched the hypervisor
// and VSM with an HVCI policy whose enable bit is set.
func (v VBSState) HVCIEnforced() bool {
	set := func(p *uint64) bool { return p != nil && *p != 0 }
	return set(v.HypervisorLaunchType) && set(v.VSMLaunchType) && v.HVCIPolicy != nil && *v.HVCIPolicy&1 == 1
}

// ParseVBS walks the verified PCR 12 EV_EVENT_TAG events before the WBCL separator,
// mirroring the scoping go-attestation applies in ParseWinEvents.
//
// The replay only authenticates each event's digest. Its type and data come from the
// client, so both are checked here: PCR 12 may hold nothing but tagged events and one
// "WBCL" separator, and every event's data must hash to its digest. Otherwise relabelling
// the event that reports test signing or debugging (or planting an early separator) would
// hide it while the log still replays.
func ParseVBS(events []goattest.Event) (VBSState, error) {
	var out VBSState
	seenSeparator := false
	for _, e := range events {
		if e.Index != 12 {
			continue
		}
		sum := sha256.Sum256(e.Data)
		digestOK := bytes.Equal(sum[:], e.Digest)
		switch e.Type {
		case evSeparator:
			if seenSeparator {
				return out, fmt.Errorf("duplicate PCR12 separator")
			}
			if !bytes.Equal(e.Data, []byte("WBCL")) || !digestOK {
				return out, fmt.Errorf("PCR12 separator is not the WBCL separator")
			}
			seenSeparator = true
		case evEventTag:
			if seenSeparator {
				continue
			}
			if !digestOK {
				return out, fmt.Errorf("PCR12 tagged event digest does not match its data")
			}
			if len(e.Data) < 8 {
				return out, fmt.Errorf("short tagged event (%d bytes)", len(e.Data))
			}
			n := binary.LittleEndian.Uint32(e.Data[4:8])
			if int(n) > len(e.Data)-8 {
				return out, fmt.Errorf("tagged event length %d exceeds data", n)
			}
			if err := out.walk(e.Data[8:8+n], 0); err != nil {
				return out, err
			}
		default:
			return out, fmt.Errorf("unexpected event type 0x%x in PCR12", uint32(e.Type))
		}
	}
	return out, nil
}

func (v *VBSState) walk(b []byte, depth int) error {
	if depth > 8 {
		return fmt.Errorf("SIPA nesting too deep")
	}
	for len(b) > 0 {
		if len(b) < 8 {
			return fmt.Errorf("truncated SIPA header")
		}
		typ := binary.LittleEndian.Uint32(b[0:4])
		size := binary.LittleEndian.Uint32(b[4:8])
		if int(size) > len(b)-8 {
			return fmt.Errorf("SIPA event 0x%08x size %d exceeds container", typ, size)
		}
		payload := b[8 : 8+size]
		b = b[8+size:]

		if typ&sipaTypeMask == sipaContainer {
			if err := v.walk(payload, depth+1); err != nil {
				return err
			}
			continue
		}
		var dst **uint64
		switch typ {
		case sipaHypervisorLaunch:
			dst = &v.HypervisorLaunchType
		case sipaHypervisorDebug:
			dst = &v.HypervisorDebug
		case sipaVSMLaunchType:
			dst = &v.VSMLaunchType
		case sipaVBSVSMRequired:
			dst = &v.VSMRequired
		case sipaVBSSecureBootReq:
			dst = &v.SecureBootRequired
		case sipaVBSIOMMURequired:
			dst = &v.IOMMURequired
		case sipaVBSNXRequired:
			dst = &v.NXRequired
		case sipaVBSMandatoryEnforce:
			dst = &v.MandatoryEnforcement
		case sipaVBSHVCIPolicy:
			dst = &v.HVCIPolicy
		case sipaVBSMSBootChainReq:
			dst = &v.MicrosoftBootChainReq
		case sipaOSKernelDebug:
			dst = &v.OSKernelDebug
		case sipaBootDebugging:
			dst = &v.BootDebugging
		case sipaCodeIntegrity:
			dst = &v.CodeIntegrity
		case sipaTestSigning:
			dst = &v.TestSigning
		default:
			continue
		}
		if len(payload) == 0 || len(payload) > 8 {
			return fmt.Errorf("SIPA event 0x%08x has unexpected size %d", typ, len(payload))
		}
		var buf [8]byte
		copy(buf[:], payload)
		val := binary.LittleEndian.Uint64(buf[:])
		// Debug and test-signing signals latch on if any boot application reported them.
		weakening := typ == sipaOSKernelDebug || typ == sipaBootDebugging || typ == sipaHypervisorDebug || typ == sipaTestSigning
		if weakening && *dst != nil {
			val |= **dst
		}
		// Code integrity latches off if any boot application reported it disabled.
		if typ == sipaCodeIntegrity && *dst != nil && **dst == 0 {
			val = 0
		}
		*dst = &val
	}
	return nil
}
