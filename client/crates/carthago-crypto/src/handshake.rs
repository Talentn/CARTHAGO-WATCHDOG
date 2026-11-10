use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::Error;

pub const PROTOCOL_VERSION: u32 = 1;

pub const FRAME_HELLO: u8 = 0x01;
pub const FRAME_CHALLENGE: u8 = 0x02;
pub const FRAME_SEALED: u8 = 0x03;

pub const NONCE_LEN: usize = 32;
pub const SESSION_ID_LEN: usize = 16;

const DST_TRANSCRIPT: &[u8] = b"carthago/v1/transcript";
const DST_CHALLENGE_SIG: &[u8] = b"carthago/v1/challenge-sig";
const DST_PROVE: &[u8] = b"carthago/v1/prove";
const DST_QUOTE: &[u8] = b"carthago/v1/quote";
const DST_DEVICE_ID: &[u8] = b"carthago/v1/device-id";
const INFO_C2S: &[u8] = b"carthago/v1/key/c2s";
const INFO_S2C: &[u8] = b"carthago/v1/key/s2c";

/// SHA-256(dst || u32be(len(hello)) || hello || u32be(len(body)) || body) over the exact
/// bytes on the wire.
pub fn transcript_hash(hello: &[u8], challenge_body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DST_TRANSCRIPT);
    h.update((hello.len() as u32).to_be_bytes());
    h.update(hello);
    h.update((challenge_body.len() as u32).to_be_bytes());
    h.update(challenge_body);
    h.finalize().into()
}

/// Message the server identity key signs (Ed25519).
pub fn challenge_sig_input(th: &[u8; 32]) -> Vec<u8> {
    [DST_CHALLENGE_SIG, th].concat()
}

fn tagged(dst: &[u8], th: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(dst);
    h.update(th);
    h.finalize().into()
}

/// What the device key signs: Ed25519 signs these bytes as the message, ECDSA P-256 signs
/// them as a prehashed digest.
pub fn prove_digest(th: &[u8; 32]) -> [u8; 32] {
    tagged(DST_PROVE, th)
}

/// Qualifying data for TPM2_Quote and TPM2_Certify in this handshake.
pub fn quote_nonce(th: &[u8; 32]) -> [u8; 32] {
    tagged(DST_QUOTE, th)
}

pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// X25519, rejecting non-contributory (low-order) peer keys.
pub fn x25519(secret: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32], Error> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*peer));
    if !shared.was_contributory() {
        return Err(Error::LowOrderPoint);
    }
    Ok(shared.to_bytes())
}

pub struct SessionKeys {
    pub c2s: [u8; 32],
    pub s2c: [u8; 32],
}

/// HKDF-SHA256(ikm = shared secret, salt = transcript hash), one key per direction.
pub fn derive_keys(shared: &[u8; 32], th: &[u8; 32]) -> SessionKeys {
    let hk = Hkdf::<Sha256>::new(Some(th), shared);
    let mut keys = SessionKeys { c2s: [0; 32], s2c: [0; 32] };
    hk.expand(INFO_C2S, &mut keys.c2s).expect("32 bytes is a valid HKDF length");
    hk.expand(INFO_S2C, &mut keys.s2c).expect("32 bytes is a valid HKDF length");
    keys
}

/// hex(SHA-256(dst || alg || public key)[..16]): the device identifier carried in tokens.
pub fn device_id(alg: u8, public_key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(DST_DEVICE_ID);
    h.update([alg]);
    h.update(public_key);
    hex::encode(&h.finalize()[..16])
}
