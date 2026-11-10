//! Device identity: a non-exportable PCP (TPM) P-256 key with an attestation key, or a
//! software Ed25519 fallback that earns a lower trust level (plan §5.4 step 1).

use std::path::PathBuf;

use sha2::{Digest, Sha256};
use carthago_attest::{ek_chain, AttestationKey, Key, SigningAlg, Tpm, ALG_SHA256};
use carthago_crypto::SigningKey;
use carthago_proto::v1 as pb;

const AK_NAME: &str = "carthago-ak";

fn data_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join("CarthagoWatchdog")
}

/// Device keys are per tenant so studios can't correlate players across titles (plan §10).
fn tenant_tag(tenant: &str) -> String {
    hex::encode(&Sha256::digest(format!("carthago tenant key name: {tenant}"))[..6])
}

pub struct TpmDevice {
    tpm: Tpm,
    ak: AttestationKey,
    key: Key,
    sec1: Vec<u8>,
    enrollment: pb::TpmEnrollment,
}

pub enum DeviceIdentity {
    Tpm(Box<TpmDevice>),
    Software(Box<SigningKey>),
}

/// `BCRYPT_ECCPUBLIC_BLOB` ("ECS1", cbKey = 32, X, Y) to an uncompressed SEC1 point.
fn ecs1_to_sec1(blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() != 8 + 64 || &blob[..4] != b"ECS1" || u32::from_le_bytes(blob[4..8].try_into().unwrap()) != 32 {
        return Err("device key public blob is not ECDSA P-256".into());
    }
    let mut out = Vec::with_capacity(65);
    out.push(0x04);
    out.extend_from_slice(&blob[8..]);
    Ok(out)
}

impl TpmDevice {
    fn open(tenant: &str) -> Result<Self, String> {
        let tpm = Tpm::open().map_err(|e| format!("open PCP: {e}"))?;
        let info = tpm.info().map_err(|e| format!("TPM info: {e}"))?;
        let cache = data_dir().join(format!("{AK_NAME}.idbinding"));
        let cached = std::fs::read(&cache).ok();
        let (ak, _created, binding) = tpm.load_or_create_ak(AK_NAME, cached.as_deref()).map_err(|e| format!("AK: {e}"))?;
        let _ = std::fs::create_dir_all(data_dir());
        let _ = std::fs::write(&cache, &binding);
        let (key, _) = tpm
            .load_or_create_device_key(&format!("carthago-device-{}", tenant_tag(tenant)))
            .map_err(|e| format!("device key: {e}"))?;
        if key.algorithm().map_err(|e| e.to_string())? != SigningAlg::EcdsaP256 {
            return Err("TPM device key is not ECDSA P-256".into());
        }
        let sec1 = ecs1_to_sec1(&key.export_public().map_err(|e| format!("export device key: {e}"))?)?;
        let mut ek_certs = Vec::new();
        for (_, certs) in tpm.ek_certificates() {
            for c in certs.unwrap_or_default() {
                if !ek_certs.contains(&c) {
                    ek_certs.push(c);
                }
            }
        }
        // Failures here only cost the chain: the gateway then reports the EK as unverified.
        let mut ek_chain_certs = Vec::new();
        for (_, certs) in tpm.ek_chain_certificates().unwrap_or_default() {
            for c in certs.unwrap_or_default() {
                if ek_chain_certs.len() < ek_chain::MAX_CERTS && !ek_certs.contains(&c) && !ek_chain_certs.contains(&c) {
                    ek_chain_certs.push(c);
                }
            }
        }
        let enrollment = pb::TpmEnrollment {
            ek_public: tpm.ek_public().map_err(|e| format!("EK public: {e}"))?,
            ek_certs,
            ek_chain_certs,
            ak_public: ak.params.public.clone(),
            ak_create_data: ak.params.create_data.clone(),
            ak_create_attestation: ak.params.create_attestation.clone(),
            ak_create_signature: ak.params.create_signature.clone(),
            tpm_manufacturer: info.manufacturer.clone(),
            tpm_firmware: info.firmware_version.clone(),
        };
        Ok(Self { tpm, ak, key, sec1, enrollment })
    }

    /// Answers the server's attestation request. Partial failures are reported in `error`
    /// and lower the trust level server-side; they don't abort the handshake.
    fn evidence(&self, req: &pb::AttestRequest, nonce: &[u8; 32]) -> pb::TpmEvidence {
        let mut ev = pb::TpmEvidence::default();
        let mut errs = Vec::new();
        if let Some(c) = &req.ek_challenge {
            match self
                .tpm
                .persistent_rsa_ek()
                .and_then(|h| self.tpm.certify_ak_with_ek(&self.ak, h, &c.object_public, &c.duplicate, &c.in_sym_seed))
            {
                Ok(cert) => (ev.ek_certify_attest, ev.ek_certify_signature) = (cert.attest, cert.signature),
                Err(e) => errs.push(format!("EK challenge: {e}")),
            }
        }
        if req.certify_device_key {
            match self.tpm.key_public_area(&self.key).and_then(|p| Ok((p, self.tpm.certify_key(&self.key, &self.ak, nonce)?))) {
                Ok((public, cert)) => {
                    ev.device_key_public_area = public;
                    (ev.device_key_certify_attest, ev.device_key_certify_signature) = (cert.attest, cert.signature);
                }
                Err(e) => errs.push(format!("device key certify: {e}")),
            }
        }
        if !req.pcrs.is_empty() {
            match self.tpm.quote(&self.ak, nonce, ALG_SHA256, &req.pcrs) {
                Ok(q) => (ev.quote, ev.quote_signature) = (q.attest, q.signature),
                Err(e) => errs.push(format!("quote: {e}")),
            }
            match self.tpm.read_pcrs(ALG_SHA256, &req.pcrs) {
                Ok(p) => ev.pcrs = p.into_iter().map(|(index, digest)| pb::Pcr { index, digest }).collect(),
                Err(e) => errs.push(format!("PCR read: {e}")),
            }
            match carthago_attest::tcg_log() {
                Ok(l) => ev.event_log = l,
                Err(e) => errs.push(format!("WBCL: {e}")),
            }
        }
        ev.error = errs.join("; ");
        ev
    }
}

fn software_key(tenant: &str) -> Result<SigningKey, String> {
    let path = data_dir().join(format!("software-device-{}.key", tenant_tag(tenant)));
    if let Ok(s) = std::fs::read_to_string(&path) {
        if let Ok(Ok(seed)) = hex::decode(s.trim()).map(<[u8; 32]>::try_from) {
            return Ok(SigningKey::from_bytes(&seed));
        }
    }
    let mut seed = [0u8; 32];
    getrandom(&mut seed)?;
    std::fs::create_dir_all(data_dir()).map_err(|e| e.to_string())?;
    std::fs::write(&path, hex::encode(seed)).map_err(|e| e.to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

pub(crate) fn getrandom(buf: &mut [u8]) -> Result<(), String> {
    use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
    let st = unsafe { BCryptGenRandom(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if st != 0 {
        return Err(format!("BCryptGenRandom: 0x{st:08X}"));
    }
    Ok(())
}

impl DeviceIdentity {
    /// Opens the TPM identity, or falls back to the software key. The second value says why
    /// the TPM was not used.
    pub fn open(tenant: &str, allow_tpm: bool) -> Result<(Self, Option<String>), String> {
        let why = if allow_tpm {
            match TpmDevice::open(tenant) {
                Ok(d) => return Ok((Self::Tpm(Box::new(d)), None)),
                Err(e) => e,
            }
        } else {
            "TPM disabled by configuration".to_owned()
        };
        Ok((Self::Software(Box::new(software_key(tenant)?)), Some(why)))
    }

    pub fn device_key(&self) -> pb::DeviceKey {
        match self {
            Self::Tpm(d) => pb::DeviceKey { alg: pb::DeviceKeyAlg::EcdsaP256Tpm as i32, public_key: d.sec1.clone() },
            Self::Software(k) => pb::DeviceKey { alg: pb::DeviceKeyAlg::Ed25519Software as i32, public_key: k.verifying_key().to_bytes().to_vec() },
        }
    }

    pub fn is_tpm(&self) -> bool {
        matches!(self, Self::Tpm(_))
    }

    pub fn enrollment(&self) -> Option<pb::TpmEnrollment> {
        match self {
            Self::Tpm(d) => Some(d.enrollment.clone()),
            Self::Software(_) => None,
        }
    }

    pub fn tpm_manufacturer(&self) -> String {
        match self {
            Self::Tpm(d) => d.enrollment.tpm_manufacturer.clone(),
            Self::Software(_) => String::new(),
        }
    }

    /// Signs the handshake `prove_digest`.
    pub fn sign_prove(&self, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
        match self {
            Self::Tpm(d) => d.key.sign_sha256(digest).map_err(|e| format!("TPM sign: {e}")),
            Self::Software(k) => {
                use ed25519_dalek::Signer;
                Ok(k.sign(digest).to_bytes().to_vec())
            }
        }
    }

    pub fn evidence(&self, req: &pb::AttestRequest, nonce: &[u8; 32]) -> Option<pb::TpmEvidence> {
        match self {
            Self::Tpm(d) => Some(d.evidence(req, nonce)),
            Self::Software(_) => None,
        }
    }
}
