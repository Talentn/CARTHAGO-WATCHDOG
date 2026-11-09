//! PASETO v4.public session tokens with a JSON claims payload and a `{"kid":...}` footer.

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::time;

const HEADER: &str = "v4.public.";
pub const TOKEN_ISSUER: &str = "sentinel-gateway";
pub const DEFAULT_LEEWAY_SECS: i64 = 30;

/// Field order is part of the golden vectors; keep it in sync with the Go `Claims`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub tenant: String,
    pub player_hash: String,
    pub device_id: String,
    pub session_id: String,
    pub iat: String,
    pub exp: String,
    pub trust_level: u32,
    pub attest_flags: u64,
}

impl Claims {
    pub fn exp_unix(&self) -> Option<i64> {
        time::parse_rfc3339(&self.exp)
    }
}

#[derive(Serialize, Deserialize)]
struct Footer {
    kid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("malformed token: {0}")]
    Malformed(&'static str),
    #[error("unknown token key id {0:?}")]
    UnknownKey(String),
    #[error("token signature invalid")]
    BadSignature,
    #[error("token expired at {0}")]
    Expired(String),
    #[error("token not valid until {0}")]
    NotYetValid(String),
}

impl TokenError {
    /// Error class names used in proto/testvectors/token.json.
    pub fn class(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::UnknownKey(_) => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::Expired(_) => "expired",
            Self::NotYetValid(_) => "not_yet_valid",
        }
    }
}

/// hex of the first 8 bytes of SHA-256 over the Ed25519 public key.
pub fn key_id(public: &VerifyingKey) -> String {
    hex::encode(&Sha256::digest(public.as_bytes())[..8])
}

fn pae(pieces: &[&[u8]]) -> Vec<u8> {
    let le64 = |out: &mut Vec<u8>, n: u64| out.extend_from_slice(&(n & !(1 << 63)).to_le_bytes());
    let mut out = Vec::new();
    le64(&mut out, pieces.len() as u64);
    for p in pieces {
        le64(&mut out, p.len() as u64);
        out.extend_from_slice(p);
    }
    out
}

pub fn sign_token(key: &SigningKey, claims: &Claims) -> String {
    let msg = serde_json::to_vec(claims).expect("claims serialize");
    let footer = serde_json::to_vec(&Footer { kid: key_id(&key.verifying_key()) }).expect("footer serialize");
    let sig = key.sign(&pae(&[HEADER.as_bytes(), &msg, &footer, b""]));
    let mut body = msg;
    body.extend_from_slice(&sig.to_bytes());
    format!("{HEADER}{}.{}", URL_SAFE_NO_PAD.encode(body), URL_SAFE_NO_PAD.encode(footer))
}

/// Trusted token keys, by key id. Game servers load these from the gateway's published
/// key set ahead of time; verification never makes a network call.
#[derive(Default, Clone)]
pub struct TokenKeys(HashMap<String, VerifyingKey>);

impl TokenKeys {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: VerifyingKey) -> String {
        let kid = key_id(&key);
        self.0.insert(kid.clone(), key);
        kid
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Checks format, key id, signature, `iat` and `exp` (with `leeway_secs` of clock skew).
    pub fn verify(&self, token: &str, now_unix: i64, leeway_secs: i64) -> Result<Claims, TokenError> {
        let rest = token.strip_prefix(HEADER).ok_or(TokenError::Malformed("not v4.public"))?;
        let (payload, footer_b64) = rest.split_once('.').ok_or(TokenError::Malformed("want payload.footer"))?;
        if footer_b64.contains('.') {
            return Err(TokenError::Malformed("too many segments"));
        }
        let body = URL_SAFE_NO_PAD.decode(payload).map_err(|_| TokenError::Malformed("payload base64url"))?;
        let footer = URL_SAFE_NO_PAD.decode(footer_b64).map_err(|_| TokenError::Malformed("footer base64url"))?;
        if body.len() < 64 {
            return Err(TokenError::Malformed("payload shorter than a signature"));
        }
        let f: Footer = serde_json::from_slice(&footer).map_err(|_| TokenError::Malformed("footer json"))?;
        let key = self.0.get(&f.kid).ok_or_else(|| TokenError::UnknownKey(f.kid.clone()))?;
        let (msg, sig) = body.split_at(body.len() - 64);
        let sig = Signature::from_bytes(sig.try_into().unwrap());
        key.verify(&pae(&[HEADER.as_bytes(), msg, &footer, b""]), &sig).map_err(|_| TokenError::BadSignature)?;
        let claims: Claims = serde_json::from_slice(msg).map_err(|_| TokenError::Malformed("claims json"))?;
        let exp = time::parse_rfc3339(&claims.exp).ok_or(TokenError::Malformed("exp"))?;
        let iat = time::parse_rfc3339(&claims.iat).ok_or(TokenError::Malformed("iat"))?;
        if now_unix >= exp + leeway_secs {
            return Err(TokenError::Expired(claims.exp));
        }
        if now_unix + leeway_secs < iat {
            return Err(TokenError::NotYetValid(claims.iat));
        }
        Ok(claims)
    }
}
