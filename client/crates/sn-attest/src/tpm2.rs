//! Minimal TPM 2.0 command marshaling (TPM 2.0 Library Part 3) for the commands the
//! attestation flow needs: GetCapability, PCR_Read and Quote.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::tbs::Channel;

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;
const CC_GET_CAPABILITY: u32 = 0x0000_017A;
const CC_PCR_READ: u32 = 0x0000_017E;
const CC_QUOTE: u32 = 0x0000_0158;
const RS_PW: u32 = 0x4000_0009;
const ALG_NULL: u16 = 0x0010;
pub const ALG_SHA256: u16 = 0x000B;
const CAP_TPM_PROPERTIES: u32 = 6;
const PT_FIXED: u32 = 0x100;

fn command(tag: u16, cc: u32, body: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(10 + body.len());
    c.extend_from_slice(&tag.to_be_bytes());
    c.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    c.extend_from_slice(&cc.to_be_bytes());
    c.extend_from_slice(body);
    c
}

fn pcr_selection(hash: u16, pcrs: &[u32]) -> Vec<u8> {
    let mut bitmap = [0u8; 3];
    for &p in pcrs {
        bitmap[(p / 8) as usize] |= 1 << (p % 8);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&hash.to_be_bytes());
    out.push(3);
    out.extend_from_slice(&bitmap);
    out
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, pos: 0, what }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len()).ok_or_else(|| {
            Error::Parse(format!("{}: truncated at offset {} (+{n})", self.what, self.pos))
        })?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn tpm2b(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// Fixed TPM properties (`TPM_PT_FIXED` group), keyed by property tag.
pub(crate) fn fixed_properties(ch: Channel) -> Result<BTreeMap<u32, u32>> {
    let mut props = BTreeMap::new();
    let mut next = PT_FIXED;
    loop {
        let mut body = Vec::new();
        body.extend_from_slice(&CAP_TPM_PROPERTIES.to_be_bytes());
        body.extend_from_slice(&next.to_be_bytes());
        body.extend_from_slice(&64u32.to_be_bytes());
        let resp = ch.submit("TPM2_GetCapability", &command(ST_NO_SESSIONS, CC_GET_CAPABILITY, &body))?;
        let mut r = Reader::new(&resp[10..], "TPM2_GetCapability");
        let more = r.u8()? != 0;
        let _cap = r.u32()?;
        let count = r.u32()?;
        let mut last = next;
        for _ in 0..count {
            let tag = r.u32()?;
            let val = r.u32()?;
            if tag >= PT_FIXED + 0x100 {
                return Ok(props);
            }
            props.insert(tag, val);
            last = tag;
        }
        if !more || count == 0 {
            return Ok(props);
        }
        next = last + 1;
    }
}

/// Reads the given PCRs from one bank, looping because the TPM may return a subset.
pub(crate) fn pcr_read(ch: Channel, hash: u16, pcrs: &[u32]) -> Result<BTreeMap<u32, Vec<u8>>> {
    let mut out = BTreeMap::new();
    for _ in 0..pcrs.len() {
        let pending: Vec<u32> = pcrs.iter().copied().filter(|p| !out.contains_key(p)).collect();
        if pending.is_empty() {
            break;
        }
        let resp = ch.submit("TPM2_PCR_Read", &command(ST_NO_SESSIONS, CC_PCR_READ, &pcr_selection(hash, &pending)))?;
        let mut r = Reader::new(&resp[10..], "TPM2_PCR_Read");
        let _update_counter = r.u32()?;
        let mut returned = Vec::new();
        for _ in 0..r.u32()? {
            let _hash = r.u16()?;
            let size = r.u8()? as usize;
            let bitmap = r.take(size)?;
            for (byte, bits) in bitmap.iter().enumerate() {
                for bit in 0..8 {
                    if bits & (1 << bit) != 0 {
                        returned.push((byte * 8 + bit) as u32);
                    }
                }
            }
        }
        let digests = r.u32()? as usize;
        if digests != returned.len() {
            return Err(Error::Parse(format!(
                "TPM2_PCR_Read: {digests} digests for {} selected PCRs",
                returned.len()
            )));
        }
        for pcr in returned {
            out.insert(pcr, r.tpm2b()?.to_vec());
        }
    }
    if out.len() != pcrs.len() {
        return Err(Error::Parse(format!("TPM2_PCR_Read: got {} of {} PCRs", out.len(), pcrs.len())));
    }
    Ok(out)
}

const CC_READ_PUBLIC: u32 = 0x0000_0173;
const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
const CC_POLICY_SECRET: u32 = 0x0000_0151;
const CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const RH_NULL: u32 = 0x4000_0007;
const RH_ENDORSEMENT: u32 = 0x4000_000B;
const SE_POLICY: u8 = 0x01;

fn pw_session() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&RS_PW.to_be_bytes());
    s.extend_from_slice(&0u16.to_be_bytes());
    s.push(0);
    s.extend_from_slice(&0u16.to_be_bytes());
    s
}

fn policy_session_auth(handle: u32) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&handle.to_be_bytes());
    s.extend_from_slice(&0u16.to_be_bytes());
    s.push(0); // continueSession clear: the TPM flushes the session after use
    s.extend_from_slice(&0u16.to_be_bytes());
    s
}

/// `TPMT_PUBLIC` of a loaded or persistent object.
pub(crate) fn read_public(ch: Channel, handle: u32) -> Result<Vec<u8>> {
    let resp = ch.submit("TPM2_ReadPublic", &command(ST_NO_SESSIONS, CC_READ_PUBLIC, &handle.to_be_bytes()))?;
    let mut r = Reader::new(&resp[10..], "TPM2_ReadPublic");
    Ok(r.tpm2b()?.to_vec())
}

/// RSA modulus from a `TPMT_PUBLIC` of type RSA.
pub(crate) fn rsa_modulus(public: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(public, "TPMT_PUBLIC");
    if r.u16()? != 0x0001 {
        return Err(Error::Parse("not an RSA key".into()));
    }
    let _name_alg = r.u16()?;
    let _attrs = r.u32()?;
    let _policy = r.tpm2b()?;
    let sym = r.u16()?;
    if sym != ALG_NULL {
        r.take(4)?; // keyBits + mode
    }
    let scheme = r.u16()?;
    if scheme != ALG_NULL {
        r.take(2)?;
    }
    let _bits = r.u16()?;
    let _exp = r.u32()?;
    Ok(r.tpm2b()?.to_vec())
}

fn flush(ch: Channel, handle: u32) {
    let _ = ch.submit("TPM2_FlushContext", &command(ST_NO_SESSIONS, CC_FLUSH_CONTEXT, &handle.to_be_bytes()));
}

/// TPM2_ActivateCredential issued directly over TBS, satisfying the standard EK policy
/// (`PolicySecret(TPM_RH_ENDORSEMENT)`) with an empty endorsement authValue.
/// `blob` is `TPM2B_ID_OBJECT || TPM2B_ENCRYPTED_SECRET`, i.e. the command's parameter area.
pub(crate) fn activate_credential(ch: Channel, ak: u32, ek: u32, blob: &[u8], nonce_caller: [u8; 16]) -> Result<Vec<u8>> {
    let session = ek_policy_session(ch, nonce_caller)?;
    let mut body = Vec::new();
    body.extend_from_slice(&ak.to_be_bytes());
    body.extend_from_slice(&ek.to_be_bytes());
    let mut auth = pw_session();
    auth.extend_from_slice(&policy_session_auth(session));
    body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    body.extend_from_slice(&auth);
    body.extend_from_slice(blob);
    let resp = ch
        .submit("TPM2_ActivateCredential", &command(ST_SESSIONS, CC_ACTIVATE_CREDENTIAL, &body))
        .inspect_err(|_| flush(ch, session))?;
    let mut r = Reader::new(&resp[10..], "TPM2_ActivateCredential");
    let _param_size = r.u32()?;
    Ok(r.tpm2b()?.to_vec())
}

const CC_IMPORT: u32 = 0x0000_0156;
const CC_LOAD: u32 = 0x0000_0157;
const CC_CERTIFY: u32 = 0x0000_0148;
const ALG_HMAC: u16 = 0x0005;

/// Starts a policy session satisfying the standard EK policy, `PolicySecret(TPM_RH_ENDORSEMENT)`.
fn ek_policy_session(ch: Channel, nonce_caller: [u8; 16]) -> Result<u32> {
    let mut body = Vec::new();
    body.extend_from_slice(&RH_NULL.to_be_bytes());
    body.extend_from_slice(&RH_NULL.to_be_bytes());
    body.extend_from_slice(&(nonce_caller.len() as u16).to_be_bytes());
    body.extend_from_slice(&nonce_caller);
    body.extend_from_slice(&0u16.to_be_bytes());
    body.push(SE_POLICY);
    body.extend_from_slice(&ALG_NULL.to_be_bytes());
    body.extend_from_slice(&ALG_SHA256.to_be_bytes());
    let resp = ch.submit("TPM2_StartAuthSession", &command(ST_NO_SESSIONS, CC_START_AUTH_SESSION, &body))?;
    let session = u32::from_be_bytes(resp[10..14].try_into().unwrap());

    let mut body = Vec::new();
    body.extend_from_slice(&RH_ENDORSEMENT.to_be_bytes());
    body.extend_from_slice(&session.to_be_bytes());
    let auth = pw_session();
    body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    body.extend_from_slice(&auth);
    body.extend_from_slice(&[0u8; 2 + 2 + 2 + 4]); // nonceTPM, cpHashA, policyRef, expiration
    if let Err(e) = ch.submit("TPM2_PolicySecret(endorsement)", &command(ST_SESSIONS, CC_POLICY_SECRET, &body)) {
        flush(ch, session);
        return Err(e);
    }
    Ok(session)
}

fn u16_prefixed(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

pub struct Certification {
    /// `TPMS_ATTEST` with tag `TPM_ST_ATTEST_CERTIFY`.
    pub attest: Vec<u8>,
    /// `TPMT_SIGNATURE` (HMAC).
    pub signature: Vec<u8>,
}

/// Solves a decryption-EK challenge (go-attestation `GenerateEkChallenge`): imports the
/// server's HMAC key under the EK, loads it and certifies the AK with it. Only a TPM
/// holding the EK private key can load the key, so the HMAC proves AK and EK share a TPM.
pub(crate) fn certify_with_ek(
    ch: Channel,
    ak: u32,
    ek: u32,
    object_public: &[u8],
    duplicate: &[u8],
    in_sym_seed: &[u8],
    nonce: impl Fn() -> [u8; 16],
) -> Result<Certification> {
    let session = ek_policy_session(ch, nonce())?;
    let mut body = Vec::new();
    body.extend_from_slice(&ek.to_be_bytes());
    let auth = policy_session_auth(session);
    body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    body.extend_from_slice(&auth);
    u16_prefixed(&mut body, &[]); // encryptionKey
    u16_prefixed(&mut body, object_public);
    u16_prefixed(&mut body, duplicate);
    u16_prefixed(&mut body, in_sym_seed);
    body.extend_from_slice(&ALG_NULL.to_be_bytes()); // symmetricAlg
    let resp = ch.submit("TPM2_Import(EK parent)", &command(ST_SESSIONS, CC_IMPORT, &body)).inspect_err(|_| flush(ch, session))?;
    let mut r = Reader::new(&resp[10..], "TPM2_Import");
    let _param_size = r.u32()?;
    let private = r.tpm2b()?.to_vec();

    let session = ek_policy_session(ch, nonce())?;
    let mut body = Vec::new();
    body.extend_from_slice(&ek.to_be_bytes());
    let auth = policy_session_auth(session);
    body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    body.extend_from_slice(&auth);
    u16_prefixed(&mut body, &private);
    u16_prefixed(&mut body, object_public);
    let resp = ch.submit("TPM2_Load(EK parent)", &command(ST_SESSIONS, CC_LOAD, &body)).inspect_err(|_| flush(ch, session))?;
    let hmac_key = u32::from_be_bytes(resp[10..14].try_into().unwrap());

    let result = (|| {
        let mut body = Vec::new();
        body.extend_from_slice(&ak.to_be_bytes());
        body.extend_from_slice(&hmac_key.to_be_bytes());
        let mut auth = pw_session();
        auth.extend_from_slice(&pw_session());
        body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth);
        u16_prefixed(&mut body, &[]); // qualifyingData
        body.extend_from_slice(&ALG_HMAC.to_be_bytes());
        body.extend_from_slice(&ALG_SHA256.to_be_bytes());
        let resp = ch.submit("TPM2_Certify(AK by EK-wrapped HMAC)", &command(ST_SESSIONS, CC_CERTIFY, &body))?;
        let mut r = Reader::new(&resp[10..], "TPM2_Certify");
        let param_size = r.u32()? as usize;
        let params = r.take(param_size)?;
        let mut p = Reader::new(params, "TPM2_Certify params");
        let attest = p.tpm2b()?.to_vec();
        Ok(Certification { attest, signature: params[p.pos..].to_vec() })
    })();
    flush(ch, hmac_key);
    result
}

/// TPM2_Certify of `object` signed by `sign_key` (the AK) with its own scheme. Both keys
/// use empty-password sessions, as PCP keys without a PIN do.
pub(crate) fn certify(ch: Channel, object: u32, sign_key: u32, qualifying: &[u8]) -> Result<Certification> {
    if qualifying.len() > 64 {
        return Err(Error::Parse("certify qualifying data longer than 64 bytes".into()));
    }
    let mut body = Vec::new();
    body.extend_from_slice(&object.to_be_bytes());
    body.extend_from_slice(&sign_key.to_be_bytes());
    let mut auth = pw_session();
    auth.extend_from_slice(&pw_session());
    body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    body.extend_from_slice(&auth);
    u16_prefixed(&mut body, qualifying);
    body.extend_from_slice(&ALG_NULL.to_be_bytes());
    let resp = ch.submit("TPM2_Certify(device key by AK)", &command(ST_SESSIONS, CC_CERTIFY, &body))?;
    let mut r = Reader::new(&resp[10..], "TPM2_Certify");
    let param_size = r.u32()? as usize;
    let params = r.take(param_size)?;
    let mut p = Reader::new(params, "TPM2_Certify params");
    let attest = p.tpm2b()?.to_vec();
    Ok(Certification { attest, signature: params[p.pos..].to_vec() })
}

pub struct RawQuote {
    /// `TPMS_ATTEST` bytes (contents of the returned `TPM2B_ATTEST`).
    pub attest: Vec<u8>,
    /// `TPMT_SIGNATURE` bytes.
    pub signature: Vec<u8>,
}

/// TPM2_Quote with an empty password session and the key's own signing scheme.
pub(crate) fn quote(ch: Channel, key: u32, nonce: &[u8], hash: u16, pcrs: &[u32]) -> Result<RawQuote> {
    if nonce.len() > 64 {
        return Err(Error::Parse("quote nonce longer than 64 bytes".into()));
    }
    let mut body = Vec::new();
    body.extend_from_slice(&key.to_be_bytes());
    // Authorization area: one TPMS_AUTH_COMMAND for the password session, empty auth.
    let mut auth = Vec::new();
    auth.extend_from_slice(&RS_PW.to_be_bytes());
    auth.extend_from_slice(&0u16.to_be_bytes());
    auth.push(0);
    auth.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    body.extend_from_slice(&auth);
    body.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    body.extend_from_slice(nonce);
    body.extend_from_slice(&ALG_NULL.to_be_bytes());
    body.extend_from_slice(&pcr_selection(hash, pcrs));

    let resp = ch.submit("TPM2_Quote", &command(ST_SESSIONS, CC_QUOTE, &body))?;
    let mut r = Reader::new(&resp[10..], "TPM2_Quote");
    let param_size = r.u32()? as usize;
    let params = r.take(param_size)?;
    let mut p = Reader::new(params, "TPM2_Quote params");
    let attest = p.tpm2b()?.to_vec();
    let signature = params[p.pos..].to_vec();
    Ok(RawQuote { attest, signature })
}
