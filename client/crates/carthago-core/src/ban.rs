//! The gateway's refusal of a banned account or device key: signed by the pinned server
//! identity key, carrying a reference and nothing about what was detected.

use carthago_crypto::VerifyingKey;
use carthago_proto::v1 as pb;
use ed25519_dalek::Verifier;
use prost::Message;

/// Longest ban reference accepted.
pub const MAX_REF_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRefusal {
    /// The handshake this refusal answered.
    pub session_id: [u8; 16],
    pub tenant_id: String,
    pub player_id_hash: String,
    pub issued_at_ms: u64,
    /// What the player can quote to the studio.
    pub reference: String,
    /// The encoded `BanRefusal` as it arrived (body, signature, key id). A game can pass
    /// these bytes to its server, which checks them with [`BanRefusal::from_signed`].
    pub signed: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BanError {
    #[error("ban refusal is not a valid message")]
    Encoding,
    #[error("ban refusal is signed by a key other than the pinned server identity key")]
    KeyId,
    #[error("ban refusal signature does not verify under the pinned server identity key")]
    Signature,
    #[error("ban refusal answers another handshake")]
    Session,
}

impl BanRefusal {
    /// Checks the signature over the body bytes as received, then decodes them.
    pub fn verify(key: &VerifyingKey, r: &pb::BanRefusal) -> Result<BanRefusal, BanError> {
        if r.server_key_id != carthago_crypto::key_id(key) {
            return Err(BanError::KeyId);
        }
        let sig = ed25519_dalek::Signature::from_slice(&r.server_sig).map_err(|_| BanError::Signature)?;
        key.verify(&carthago_crypto::ban_sig_input(&r.body), &sig).map_err(|_| BanError::Signature)?;
        let body = pb::BanRefusalBody::decode(r.body.as_slice()).map_err(|_| BanError::Encoding)?;
        if body.ban_ref.is_empty() || body.ban_ref.len() > MAX_REF_LEN || !body.ban_ref.chars().all(|c| c.is_ascii_graphic()) {
            return Err(BanError::Encoding);
        }
        Ok(BanRefusal {
            session_id: body.session_id.as_slice().try_into().map_err(|_| BanError::Encoding)?,
            tenant_id: body.tenant_id,
            player_id_hash: body.player_id_hash,
            issued_at_ms: body.issued_at_ms,
            reference: body.ban_ref,
            signed: r.encode_to_vec(),
        })
    }

    /// Verifies a refusal that was passed on as bytes ([`BanRefusal::signed`]).
    pub fn from_signed(key: &VerifyingKey, signed: &[u8]) -> Result<BanRefusal, BanError> {
        Self::verify(key, &pb::BanRefusal::decode(signed).map_err(|_| BanError::Encoding)?)
    }

    /// As [`BanRefusal::verify`], and the refusal must answer the handshake `session_id`.
    pub fn verify_for_session(key: &VerifyingKey, r: &pb::BanRefusal, session_id: &[u8]) -> Result<BanRefusal, BanError> {
        let refusal = Self::verify(key, r)?;
        if refusal.session_id != session_id {
            return Err(BanError::Session);
        }
        Ok(refusal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The same bytes are in the gateway's test (backend/internal/protocol/ban_test.go).
    const PUB: &str = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
    const RAW: &str = "0a370a10000102030405060708090a0b0c0d0e0f120464656d6f1a08706c617965722d312080d095ffbc312a0c43572d414243442d32333435124085ca56c74123e3ace0cb7d2de75ba1e8f4096772f1312bfab56130ee4ff0d3812140947c5fbe06b73aee2a09b2da862d17b802be9f70d8444964fc61a5d4cb021a1033303937653264656532636234613334";

    fn key() -> VerifyingKey {
        VerifyingKey::from_bytes(&hex::decode(PUB).unwrap().try_into().unwrap()).unwrap()
    }

    #[test]
    fn a_refusal_signed_by_the_gateway_verifies_and_decodes() {
        let raw = hex::decode(RAW).unwrap();
        let r = BanRefusal::from_signed(&key(), &raw).unwrap();
        assert_eq!(r.reference, "CW-ABCD-2345");
        assert_eq!(r.tenant_id, "demo");
        assert_eq!(r.player_id_hash, "player-1");
        assert_eq!(r.issued_at_ms, 1_700_000_000_000);
        assert_eq!(hex::encode(r.session_id), "000102030405060708090a0b0c0d0e0f");
        assert_eq!(r.signed, raw, "a refusal is passed on as the bytes that arrived");

        let msg = pb::BanRefusal::decode(raw.as_slice()).unwrap();
        assert!(BanRefusal::verify_for_session(&key(), &msg, &r.session_id).is_ok());
        assert_eq!(BanRefusal::verify_for_session(&key(), &msg, &[9u8; 16]), Err(BanError::Session));
    }

    #[test]
    fn a_refusal_that_was_changed_or_signed_by_somebody_else_is_rejected() {
        let msg = pb::BanRefusal::decode(hex::decode(RAW).unwrap().as_slice()).unwrap();

        let mut body = msg.clone();
        *body.body.last_mut().unwrap() ^= 1;
        assert_eq!(BanRefusal::verify(&key(), &body), Err(BanError::Signature));

        let mut sig = msg.clone();
        sig.server_sig[0] ^= 1;
        assert_eq!(BanRefusal::verify(&key(), &sig), Err(BanError::Signature));

        let mut kid = msg.clone();
        kid.server_key_id.push('0');
        assert_eq!(BanRefusal::verify(&key(), &kid), Err(BanError::KeyId));

        // A signature the same key made over the same bytes as a notice is not a refusal.
        let other = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        assert_eq!(other.verifying_key(), key());
        use ed25519_dalek::Signer;
        let mut as_notice = msg.clone();
        as_notice.server_sig = other.sign(&carthago_crypto::notice_sig_input(&msg.body)).to_bytes().to_vec();
        assert_eq!(BanRefusal::verify(&key(), &as_notice), Err(BanError::Signature));

        assert_eq!(BanRefusal::from_signed(&key(), b"not a message"), Err(BanError::Encoding));
    }
}
