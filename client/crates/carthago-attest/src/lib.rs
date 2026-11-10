//! TPM-backed device identity and boot attestation from user mode (architecture plan §5.4).
//!
//! Everything goes through the Microsoft Platform Crypto Provider (PCP) and TPM Base
//! Services, so no driver is needed. Keys are per-user PCP keys (no `NCRYPT_MACHINE_KEY_FLAG`).

pub mod ek_chain;
mod error;
mod pcp;
mod process;
mod tbs;
mod tpm2;

use std::collections::BTreeMap;

pub use error::{Error, Result};
pub use pcp::{Key, Provider, SigningAlg};
pub use process::{current_token, ProcessToken};
pub use tbs::{device_info, tcg_log, DeviceInfo};
pub use tpm2::{Certification, RawQuote, ALG_SHA256};

/// PCRs Windows uses for measured boot; see plan §5.4 step 3.
pub const WINDOWS_ATTEST_PCRS: [u32; 8] = [0, 2, 4, 7, 11, 12, 13, 14];

pub struct Tpm {
    prov: Provider,
}

#[derive(Debug, Clone)]
pub struct TpmInfo {
    /// Four-character TCG vendor ID, e.g. `INTC`, `AMD`, `IFX`, `MSFT`.
    pub manufacturer: String,
    pub manufacturer_raw: u32,
    pub vendor_string: String,
    /// `FIRMWARE_VERSION_1.hi.lo` + `FIRMWARE_VERSION_2.hi.lo`, as `Get-Tpm` prints it.
    pub firmware_version: String,
    pub spec_family: String,
    pub spec_level: u32,
    pub spec_revision: String,
    pub spec_year: u32,
    pub vendor_tpm_type: u32,
    pub pcp_platform_type: Option<String>,
    pub pcp_provider_version: Option<String>,
    pub device: DeviceInfo,
    pub kind: &'static str,
}

/// `nonceCaller` for unsalted, unbound policy sessions; it only needs to be unique.
fn session_nonce() -> [u8; 16] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut n = [0u8; 16];
    n[..8].copy_from_slice(&t.to_le_bytes());
    n[8..12].copy_from_slice(&std::process::id().to_le_bytes());
    n[12..].copy_from_slice(&(COUNTER.fetch_add(1, Ordering::Relaxed) as u32).to_le_bytes());
    n
}

fn be_ascii(v: u32) -> String {
    v.to_be_bytes().iter().filter(|b| b.is_ascii_graphic()).map(|&b| b as char).collect()
}

fn tpm_kind(manufacturer: &str) -> &'static str {
    match manufacturer {
        "INTC" => "Intel PTT (firmware TPM)",
        "AMD" => "AMD fTPM (firmware TPM)",
        "MSFT" => "Microsoft (Pluton or Hyper-V virtual TPM)",
        "IFX" => "Infineon (discrete TPM)",
        "NTC" => "Nuvoton (discrete TPM)",
        "STM" => "STMicroelectronics (discrete TPM)",
        "ATML" => "Microchip/Atmel (discrete TPM)",
        "NTZ" => "Nationz (discrete TPM)",
        "QCOM" => "Qualcomm (TrustZone firmware TPM)",
        _ => "unknown vendor",
    }
}

/// AK creation evidence in go-attestation's `AttestationParameters` layout.
#[derive(Debug, Clone)]
pub struct AkParams {
    /// `TPMT_PUBLIC`.
    pub public: Vec<u8>,
    /// `TPMS_CREATION_DATA`.
    pub create_data: Vec<u8>,
    /// `TPMS_ATTEST` (creation certification).
    pub create_attestation: Vec<u8>,
    /// `TPMT_SIGNATURE` over `create_attestation`.
    pub create_signature: Vec<u8>,
}

impl AkParams {
    /// Splits the TPM 2.0 `PCP_TPM12_IDBINDING` blob:
    /// `TPM2B_PUBLIC || TPM2B_CREATION_DATA || TPM2B_ATTEST || TPMT_SIGNATURE`.
    pub fn from_id_binding(blob: &[u8]) -> Result<Self> {
        if blob.starts_with(&[1, 1, 0, 0]) {
            return Err(Error::Parse("TPM 1.2 identity binding is not supported".into()));
        }
        let mut pos = 0usize;
        let mut next = || -> Result<Vec<u8>> {
            let hdr = blob
                .get(pos..pos + 2)
                .ok_or_else(|| Error::Parse("IDBINDING truncated".into()))?;
            let n = u16::from_be_bytes([hdr[0], hdr[1]]) as usize;
            let body = blob
                .get(pos + 2..pos + 2 + n)
                .ok_or_else(|| Error::Parse("IDBINDING truncated".into()))?;
            pos += 2 + n;
            Ok(body.to_vec())
        };
        let public = next()?;
        let create_data = next()?;
        let create_attestation = next()?;
        Ok(Self { public, create_data, create_attestation, create_signature: blob[pos..].to_vec() })
    }
}

pub struct AttestationKey {
    key: Key,
    pub params: AkParams,
}

impl AttestationKey {
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// TPM2_ActivateCredential through the PCP. `blob` is go-attestation's
    /// `EncryptedCredential.Credential || EncryptedCredential.Secret`.
    pub fn activate_credential(&self, blob: &[u8]) -> Result<Vec<u8>> {
        self.key.set_property("PCP_TPM12_IDACTIVATION", blob)?;
        self.key.property("PCP_TPM12_IDACTIVATION")
    }
}

impl Tpm {
    pub fn open() -> Result<Self> {
        Ok(Self { prov: Provider::open()? })
    }

    pub fn provider(&self) -> &Provider {
        &self.prov
    }

    fn channel(&self) -> Result<tbs::Channel> {
        Ok(tbs::Channel(self.prov.tbs_context()?))
    }

    pub fn info(&self) -> Result<TpmInfo> {
        let props = tpm2::fixed_properties(self.channel()?)?;
        let p = |tag: u32| props.get(&tag).copied().unwrap_or(0);
        let manufacturer = be_ascii(p(0x105));
        let vendor_string: String = (0x106..=0x109).map(|t| be_ascii(p(t))).collect();
        let (fw1, fw2) = (p(0x10B), p(0x10C));
        let revision = p(0x102);
        Ok(TpmInfo {
            kind: tpm_kind(&manufacturer),
            manufacturer,
            manufacturer_raw: p(0x105),
            vendor_string,
            firmware_version: format!("{}.{}.{}.{}", fw1 >> 16, fw1 & 0xffff, fw2 >> 16, fw2 & 0xffff),
            spec_family: be_ascii(p(0x100)),
            spec_level: p(0x101),
            spec_revision: format!("{}.{:02}", revision / 100, revision % 100),
            spec_year: p(0x104),
            vendor_tpm_type: p(0x10A),
            pcp_platform_type: self.prov.string_property("PCP_PLATFORM_TYPE").ok(),
            pcp_provider_version: self.prov.string_property("PCP_PROVIDER_VERSION").ok(),
            device: tbs::device_info()?,
        })
    }

    /// RSA EK public key as a `BCRYPT_RSAKEY_BLOB` (`RSA1` magic).
    pub fn ek_public(&self) -> Result<Vec<u8>> {
        self.prov.property("PCP_EKPUB")
    }

    /// EK certificates from TPM NV (per PCP property), with a per-property outcome.
    pub fn ek_certificates(&self) -> Vec<(&'static str, Result<Vec<Vec<u8>>>)> {
        ["PCP_RSA_EKNVCERT", "PCP_ECC_EKNVCERT", "PCP_EKNVCERT"]
            .into_iter()
            .map(|name| (name, self.prov.cert_store_property(name)))
            .collect()
    }

    /// Certificates in the TPM's EK certificate chain NV indices (`0x01C00100..=0x01C001FF`),
    /// per index. Intel PTT keeps the issuers of its EK certificate there. These are
    /// untrusted until the gateway chains them to a bundled manufacturer root.
    pub fn ek_chain_certificates(&self) -> Result<ek_chain::IndexCerts> {
        let ch = self.channel()?;
        let buffer_max = tpm2::fixed_properties(ch).ok().and_then(|p| p.get(&tpm2::PT_NV_BUFFER_MAX).copied());
        ek_chain::read(ch, buffer_max)
    }

    /// Opens the named per-user AK or creates it. Returns `true` if it was created.
    ///
    /// `cached` supplies the creation evidence when the PCP no longer exposes
    /// `PCP_TPM12_IDBINDING` on a reopened key.
    pub fn load_or_create_ak(&self, name: &str, cached: Option<&[u8]>) -> Result<(AttestationKey, bool, Vec<u8>)> {
        let (key, created) = match self.prov.open_key(name)? {
            Some(k) => (k, false),
            None => (self.prov.create_ak(name)?, true),
        };
        let binding = match key.property("PCP_TPM12_IDBINDING") {
            Ok(b) => b,
            Err(e) => cached.map(<[u8]>::to_vec).ok_or(e)?,
        };
        let params = AkParams::from_id_binding(&binding)?;
        Ok((AttestationKey { key, params }, created, binding))
    }

    /// Opens the named per-user device key or creates it, preferring ECDSA P-256.
    pub fn load_or_create_device_key(&self, name: &str) -> Result<(Key, bool)> {
        if let Some(k) = self.prov.open_key(name)? {
            return Ok((k, false));
        }
        match self.prov.create_signing_key(SigningAlg::EcdsaP256, name) {
            Ok(k) => Ok((k, true)),
            Err(ecc_err) => self
                .prov
                .create_signing_key(SigningAlg::Rsa2048, name)
                .map(|k| (k, true))
                .map_err(|_| ecc_err),
        }
    }

    pub fn read_pcrs(&self, hash: u16, pcrs: &[u32]) -> Result<BTreeMap<u32, Vec<u8>>> {
        tpm2::pcr_read(self.channel()?, hash, pcrs)
    }

    /// Finds the persistent RSA EK whose modulus matches `PCP_EKPUB` (Windows normally
    /// persists it at `0x81010001`).
    pub fn persistent_rsa_ek(&self) -> Result<u32> {
        let ekpub = self.ek_public()?;
        let modulus = ekpub
            .get(8..16)
            .map(|h| {
                let exp = u32::from_le_bytes(h[..4].try_into().unwrap()) as usize;
                let m = u32::from_le_bytes(h[4..8].try_into().unwrap()) as usize;
                (24 + exp, m)
            })
            .and_then(|(off, m)| ekpub.get(off..off + m))
            .ok_or_else(|| Error::Parse("bad PCP_EKPUB blob".into()))?;
        let ch = self.channel()?;
        let mut last = None;
        for handle in [0x8101_0001u32, 0x8101_0002, 0x8101_0003] {
            match tpm2::read_public(ch, handle).and_then(|p| tpm2::rsa_modulus(&p)) {
                Ok(m) if m == modulus => return Ok(handle),
                Ok(_) => {}
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| Error::Parse("no persistent EK matches PCP_EKPUB".into())))
    }

    /// TPM2_ActivateCredential over the PCP's TBS context instead of the
    /// `PCP_TPM12_IDACTIVATION` property (which the PCP gates on administrator rights).
    pub fn activate_credential_tbs(&self, ak: &AttestationKey, ek_handle: u32, blob: &[u8]) -> Result<Vec<u8>> {
        tpm2::activate_credential(self.channel()?, ak.key.tpm_handle()?, ek_handle, blob, session_nonce())
    }

    /// Answers a decryption-EK challenge by certifying the AK with a server key that only
    /// this TPM's EK can unwrap. Unlike credential activation, TBS permits this unelevated.
    pub fn certify_ak_with_ek(
        &self,
        ak: &AttestationKey,
        ek_handle: u32,
        object_public: &[u8],
        duplicate: &[u8],
        in_sym_seed: &[u8],
    ) -> Result<Certification> {
        tpm2::certify_with_ek(
            self.channel()?,
            ak.key.tpm_handle()?,
            ek_handle,
            object_public,
            duplicate,
            in_sym_seed,
            session_nonce,
        )
    }

    /// `TPMT_PUBLIC` of a PCP key, read from the TPM (the verifier recomputes its Name).
    pub fn key_public_area(&self, key: &Key) -> Result<Vec<u8>> {
        tpm2::read_public(self.channel()?, key.tpm_handle()?)
    }

    /// TPM2_Certify of `key` by the AK: proves `key` is TPM-generated and non-exportable.
    pub fn certify_key(&self, key: &Key, ak: &AttestationKey, qualifying: &[u8]) -> Result<Certification> {
        tpm2::certify(self.channel()?, key.tpm_handle()?, ak.key.tpm_handle()?, qualifying)
    }

    pub fn quote(&self, ak: &AttestationKey, nonce: &[u8], hash: u16, pcrs: &[u32]) -> Result<RawQuote> {
        tpm2::quote(self.channel()?, ak.key.tpm_handle()?, nonce, hash, pcrs)
    }
}
