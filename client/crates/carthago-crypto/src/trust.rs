//! `attest_flags` bits and trust levels carried in session tokens (mirrors
//! `backend/internal/protocol/trust.go`).

pub const TPM_DEVICE_KEY: u64 = 1 << 0;
pub const DEVICE_KEY_CERTIFIED: u64 = 1 << 1;
pub const AK_BOUND_TO_EK: u64 = 1 << 2;
pub const QUOTE_VERIFIED: u64 = 1 << 3;
pub const SECURE_BOOT: u64 = 1 << 4;
pub const HVCI: u64 = 1 << 5;
pub const TEST_SIGNING_OFF: u64 = 1 << 6;
pub const KERNEL_DEBUG_OFF: u64 = 1 << 7;
pub const BOOT_DEBUG_OFF: u64 = 1 << 8;
pub const CODE_INTEGRITY: u64 = 1 << 9;
pub const EK_CERT_MATCHES: u64 = 1 << 10;
pub const EK_CHAIN_VERIFIED: u64 = 1 << 11;
pub const EK_CHAIN_UNKNOWN_VENDOR: u64 = 1 << 12;
pub const EK_CHAIN_INVALID: u64 = 1 << 13;

pub const TRUST_SOFTWARE: u32 = 0;
pub const TRUST_TPM_KEY: u32 = 1;
pub const TRUST_ATTESTED: u32 = 2;
pub const TRUST_RANKED_BOOT: u32 = 3;

pub const FLAG_NAMES: [(u64, &str); 14] = [
    (TPM_DEVICE_KEY, "tpm_device_key"),
    (DEVICE_KEY_CERTIFIED, "device_key_certified"),
    (AK_BOUND_TO_EK, "ak_bound_to_ek"),
    (QUOTE_VERIFIED, "quote_verified"),
    (SECURE_BOOT, "secure_boot"),
    (HVCI, "hvci"),
    (TEST_SIGNING_OFF, "test_signing_off"),
    (KERNEL_DEBUG_OFF, "kernel_debug_off"),
    (BOOT_DEBUG_OFF, "boot_debug_off"),
    (CODE_INTEGRITY, "code_integrity"),
    (EK_CERT_MATCHES, "ek_cert_matches"),
    (EK_CHAIN_VERIFIED, "ek_chain_verified"),
    (EK_CHAIN_UNKNOWN_VENDOR, "ek_chain_unknown_vendor"),
    (EK_CHAIN_INVALID, "ek_chain_invalid"),
];

pub fn flag_names(flags: u64) -> Vec<&'static str> {
    FLAG_NAMES.iter().filter(|(b, _)| flags & b != 0).map(|(_, n)| *n).collect()
}
