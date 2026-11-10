//! Thin wrappers over NCrypt with the Microsoft Platform Crypto Provider (PCP).
//!
//! Property names and blob layouts follow Microsoft's PCP whitepaper ("Using the Windows 8
//! Platform Crypto Provider and Associated TPM Functionality") and match what
//! google/go-attestation does in `attest/pcp_windows.go`.

use std::ptr;

use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, NCryptCreatePersistedKey, NCryptExportKey,
    NCryptFinalizeKey, NCryptFreeObject, NCryptGetProperty, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash, BCRYPT_PKCS1_PADDING_INFO,
    HCERTSTORE,
};

use crate::error::{Error, Result};

const PCP_PROVIDER: &str = "Microsoft Platform Crypto Provider";
const NTE_BAD_KEYSET: u32 = 0x8009_0016;
const BCRYPT_PAD_PKCS1: u32 = 0x2;
/// `NCRYPT_PCP_IDENTITY_KEY`: restricted signing key usable only for attestation.
const PCP_KEY_USAGE_POLICY_IDENTITY: u32 = 0x8;

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check(op: &str, hr: i32) -> Result<()> {
    if hr == 0 {
        Ok(())
    } else {
        Err(Error::win32(op, hr as u32))
    }
}

fn get_property(handle: usize, name: &str) -> Result<Vec<u8>> {
    let wname = wide(name);
    let mut size = 0u32;
    let op = format!("NCryptGetProperty({name})");
    check(&op, unsafe {
        NCryptGetProperty(handle, wname.as_ptr(), ptr::null_mut(), 0, &mut size, 0)
    })?;
    let mut buf = vec![0u8; size as usize];
    check(&op, unsafe {
        NCryptGetProperty(handle, wname.as_ptr(), buf.as_mut_ptr(), size, &mut size, 0)
    })?;
    buf.truncate(size as usize);
    Ok(buf)
}

fn set_property(handle: usize, name: &str, value: &[u8]) -> Result<()> {
    let wname = wide(name);
    check(&format!("NCryptSetProperty({name})"), unsafe {
        NCryptSetProperty(handle, wname.as_ptr(), value.as_ptr(), value.len() as u32, 0)
    })
}

fn utf16_bytes_to_string(buf: &[u8]) -> String {
    let units: Vec<u16> = buf
        .as_chunks::<2>().0.iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

pub struct Provider {
    handle: usize,
}

impl Provider {
    pub fn open() -> Result<Self> {
        let name = wide(PCP_PROVIDER);
        let mut handle = 0usize;
        check("NCryptOpenStorageProvider(PCP)", unsafe {
            NCryptOpenStorageProvider(&mut handle, name.as_ptr(), 0)
        })?;
        Ok(Self { handle })
    }

    pub fn property(&self, name: &str) -> Result<Vec<u8>> {
        get_property(self.handle, name)
    }

    pub fn string_property(&self, name: &str) -> Result<String> {
        Ok(utf16_bytes_to_string(&self.property(name)?))
    }

    /// The TBS context the PCP uses internally. Key handles returned by
    /// [`Key::tpm_handle`] are only valid on this context.
    pub(crate) fn tbs_context(&self) -> Result<usize> {
        let raw = self.property("PCP_PLATFORMHANDLE")?;
        let mut bytes = [0u8; 8];
        bytes[..raw.len().min(8)].copy_from_slice(&raw[..raw.len().min(8)]);
        Ok(usize::from_le_bytes(bytes))
    }

    /// DER certificates from a PCP property that yields an `HCERTSTORE`
    /// (`PCP_RSA_EKNVCERT`, `PCP_ECC_EKNVCERT`, `PCP_EKNVCERT`).
    pub fn cert_store_property(&self, name: &str) -> Result<Vec<Vec<u8>>> {
        let raw = self.property(name)?;
        if raw.len() < std::mem::size_of::<usize>() {
            return Err(Error::Parse(format!("{name}: short HCERTSTORE ({} bytes)", raw.len())));
        }
        let store = usize::from_le_bytes(raw[..8].try_into().unwrap()) as HCERTSTORE;
        let mut out = Vec::new();
        let mut ctx = ptr::null_mut();
        unsafe {
            loop {
                ctx = CertEnumCertificatesInStore(store, ctx);
                if ctx.is_null() {
                    break;
                }
                let c = &*ctx;
                out.push(std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize).to_vec());
            }
            CertCloseStore(store, 0);
        }
        Ok(out)
    }

    pub fn open_key(&self, name: &str) -> Result<Option<Key>> {
        let wname = wide(name);
        let mut handle = 0usize;
        let hr = unsafe { NCryptOpenKey(self.handle, &mut handle, wname.as_ptr(), 0, 0) };
        match hr as u32 {
            0 => Ok(Some(Key { handle })),
            NTE_BAD_KEYSET => Ok(None),
            code => Err(Error::win32(format!("NCryptOpenKey({name})"), code)),
        }
    }

    fn create_key(&self, alg: &str, name: &str, props: &[(&str, Vec<u8>)]) -> Result<Key> {
        let walg = wide(alg);
        let wname = wide(name);
        let mut handle = 0usize;
        check(&format!("NCryptCreatePersistedKey({alg}, {name})"), unsafe {
            NCryptCreatePersistedKey(self.handle, &mut handle, walg.as_ptr(), wname.as_ptr(), 0, 0)
        })?;
        let key = Key { handle };
        for (prop, value) in props {
            set_property(key.handle, prop, value)?;
        }
        check("NCryptFinalizeKey", unsafe { NCryptFinalizeKey(key.handle, 0) })?;
        Ok(key)
    }

    /// Creates a per-user, TPM-resident RSA-2048 identity key (AK).
    pub fn create_ak(&self, name: &str) -> Result<Key> {
        self.create_key(
            "RSA",
            name,
            &[
                ("Length", 2048u32.to_le_bytes().to_vec()),
                ("PCP_KEY_USAGE_POLICY", PCP_KEY_USAGE_POLICY_IDENTITY.to_le_bytes().to_vec()),
            ],
        )
    }

    /// Creates a per-user, TPM-resident, non-exportable signing key.
    pub fn create_signing_key(&self, alg: SigningAlg, name: &str) -> Result<Key> {
        match alg {
            SigningAlg::EcdsaP256 => self.create_key("ECDSA_P256", name, &[]),
            SigningAlg::Rsa2048 => {
                self.create_key("RSA", name, &[("Length", 2048u32.to_le_bytes().to_vec())])
            }
        }
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        unsafe { NCryptFreeObject(self.handle) };
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningAlg {
    EcdsaP256,
    Rsa2048,
}

pub struct Key {
    handle: usize,
}

impl Key {
    pub fn property(&self, name: &str) -> Result<Vec<u8>> {
        get_property(self.handle, name)
    }

    pub fn string_property(&self, name: &str) -> Result<String> {
        Ok(utf16_bytes_to_string(&self.property(name)?))
    }

    pub fn u32_property(&self, name: &str) -> Result<u32> {
        let raw = self.property(name)?;
        raw.get(..4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .ok_or_else(|| Error::Parse(format!("{name}: expected 4 bytes, got {}", raw.len())))
    }

    pub fn set_property(&self, name: &str, value: &[u8]) -> Result<()> {
        set_property(self.handle, name, value)
    }

    /// TBS-virtualised TPM handle; valid only on [`Provider::tbs_context`].
    pub fn tpm_handle(&self) -> Result<u32> {
        self.u32_property("PCP_PLATFORMHANDLE")
    }

    pub fn algorithm(&self) -> Result<SigningAlg> {
        match self.string_property("Algorithm Name")?.as_str() {
            "RSA" => Ok(SigningAlg::Rsa2048),
            "ECDSA_P256" | "ECDSA" => Ok(SigningAlg::EcdsaP256),
            other => Err(Error::Parse(format!("unexpected key algorithm {other}"))),
        }
    }

    /// `BCRYPT_ECCPUBLIC_BLOB` or `BCRYPT_RSAPUBLIC_BLOB`, depending on the key.
    pub fn export_public(&self) -> Result<Vec<u8>> {
        let blob = match self.algorithm()? {
            SigningAlg::EcdsaP256 => "ECCPUBLICBLOB",
            SigningAlg::Rsa2048 => "RSAPUBLICBLOB",
        };
        let wblob = wide(blob);
        let mut size = 0u32;
        check("NCryptExportKey", unsafe {
            NCryptExportKey(self.handle, 0, wblob.as_ptr(), ptr::null(), ptr::null_mut(), 0, &mut size, 0)
        })?;
        let mut buf = vec![0u8; size as usize];
        check("NCryptExportKey", unsafe {
            NCryptExportKey(self.handle, 0, wblob.as_ptr(), ptr::null(), buf.as_mut_ptr(), size, &mut size, 0)
        })?;
        buf.truncate(size as usize);
        Ok(buf)
    }

    /// Signs a SHA-256 digest. ECDSA yields raw `r || s`; RSA yields PKCS#1 v1.5.
    pub fn sign_sha256(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let sha256 = wide("SHA256");
        let pad = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: sha256.as_ptr() };
        let (padding, flags) = match self.algorithm()? {
            SigningAlg::EcdsaP256 => (ptr::null(), 0),
            SigningAlg::Rsa2048 => (&pad as *const _ as *const core::ffi::c_void, BCRYPT_PAD_PKCS1),
        };
        let mut size = 0u32;
        check("NCryptSignHash", unsafe {
            NCryptSignHash(self.handle, padding, digest.as_ptr(), 32, ptr::null_mut(), 0, &mut size, flags)
        })?;
        let mut sig = vec![0u8; size as usize];
        check("NCryptSignHash", unsafe {
            NCryptSignHash(self.handle, padding, digest.as_ptr(), 32, sig.as_mut_ptr(), size, &mut size, flags)
        })?;
        sig.truncate(size as usize);
        Ok(sig)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { NCryptFreeObject(self.handle) };
    }
}
