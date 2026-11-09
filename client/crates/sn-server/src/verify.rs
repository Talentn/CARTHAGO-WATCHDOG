use std::path::Path;

use serde::Deserialize;
use sn_crypto::time::now_unix;
use sn_crypto::token::{key_id, Claims, TokenError, TokenKeys, DEFAULT_LEEWAY_SECS, TOKEN_ISSUER};
use sn_crypto::VerifyingKey;

#[derive(Debug, Deserialize)]
struct PublishedKey {
    kid: String,
    public_key: String,
}

/// The gateway's `public-keys.json` (served at `/v1/keys`).
#[derive(Debug, Deserialize)]
pub struct PublicKeysJson {
    server_identity: PublishedKey,
    token_keys: Vec<PublishedKey>,
}

pub struct PublicKeys {
    pub server_identity: VerifyingKey,
    pub token_keys: TokenKeys,
}

impl PublicKeys {
    pub fn parse(json: &str) -> Result<Self, String> {
        let j: PublicKeysJson = serde_json::from_str(json).map_err(|e| format!("public keys json: {e}"))?;
        let server_identity = parse_key(&j.server_identity)?;
        let mut token_keys = TokenKeys::new();
        for k in &j.token_keys {
            token_keys.insert(parse_key(k)?);
        }
        if token_keys.is_empty() {
            return Err("public keys json: no token keys".into());
        }
        Ok(Self { server_identity, token_keys })
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let p = path.as_ref();
        Self::parse(&std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?)
    }
}

fn parse_key(k: &PublishedKey) -> Result<VerifyingKey, String> {
    let b: [u8; 32] = hex::decode(&k.public_key)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("key {}: not 32 hex bytes", k.kid))?;
    let key = VerifyingKey::from_bytes(&b).map_err(|_| format!("key {}: invalid Ed25519 point", k.kid))?;
    if key_id(&key) != k.kid {
        return Err(format!("key {}: kid does not match the key", k.kid));
    }
    Ok(key)
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error(transparent)]
    Token(#[from] TokenError),
    #[error("issuer {0:?} is not the Sentinel gateway")]
    WrongIssuer(String),
    #[error("token is for tenant {got:?}, this server is {want:?}")]
    WrongTenant { got: String, want: String },
    #[error("trust level {got} below the required {need}")]
    TrustTooLow { got: u32, need: u32 },
}

impl VerifyError {
    /// Stable reason string for logs and the player-facing reject.
    pub fn class(&self) -> &'static str {
        match self {
            Self::Token(t) => t.class(),
            Self::WrongIssuer(_) => "wrong_issuer",
            Self::WrongTenant { .. } => "wrong_tenant",
            Self::TrustTooLow { .. } => "trust_too_low",
        }
    }
}

/// Offline verifier for one tenant's game servers.
pub struct Verifier {
    keys: TokenKeys,
    tenant: String,
    min_trust: u32,
    leeway_secs: i64,
}

impl Verifier {
    pub fn new(keys: TokenKeys, tenant: impl Into<String>) -> Self {
        Self { keys, tenant: tenant.into(), min_trust: 0, leeway_secs: DEFAULT_LEEWAY_SECS }
    }

    /// Ranked queues can require e.g. trust level 2 (attested TPM device key).
    pub fn with_min_trust(mut self, level: u32) -> Self {
        self.min_trust = level;
        self
    }

    pub fn with_leeway(mut self, secs: i64) -> Self {
        self.leeway_secs = secs;
        self
    }

    pub fn verify(&self, token: &str) -> Result<Claims, VerifyError> {
        self.verify_at(token, now_unix())
    }

    pub fn verify_at(&self, token: &str, now_unix: i64) -> Result<Claims, VerifyError> {
        let c = self.keys.verify(token.trim(), now_unix, self.leeway_secs)?;
        if c.iss != TOKEN_ISSUER {
            return Err(VerifyError::WrongIssuer(c.iss));
        }
        if c.tenant != self.tenant {
            return Err(VerifyError::WrongTenant { got: c.tenant, want: self.tenant.clone() });
        }
        if c.trust_level < self.min_trust {
            return Err(VerifyError::TrustTooLow { got: c.trust_level, need: self.min_trust });
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sn_crypto::time::format_rfc3339;
    use sn_crypto::token::sign_token;
    use sn_crypto::SigningKey;

    const NOW: i64 = 1_800_000_000;

    fn claims(tenant: &str, trust: u32) -> Claims {
        Claims {
            iss: TOKEN_ISSUER.into(),
            tenant: tenant.into(),
            player_hash: "p".into(),
            device_id: "d".into(),
            session_id: "00112233445566778899aabbccddeeff".into(),
            iat: format_rfc3339(NOW),
            exp: format_rfc3339(NOW + 900),
            trust_level: trust,
            attest_flags: 0,
        }
    }

    fn setup() -> (SigningKey, Verifier) {
        let sk = SigningKey::from_bytes(&[7; 32]);
        let mut keys = TokenKeys::new();
        keys.insert(sk.verifying_key());
        (sk, Verifier::new(keys, "demo"))
    }

    #[test]
    fn accepts_valid_and_rejects_tamper_expiry_tenant_trust() {
        let (sk, v) = setup();
        let tok = sign_token(&sk, &claims("demo", 2));
        assert_eq!(v.verify_at(&tok, NOW + 10).unwrap().trust_level, 2);

        assert_eq!(v.verify_at(&tok, NOW + 900 + 31).unwrap_err().class(), "expired");
        assert!(v.verify_at(&tok, NOW + 900 + 29).is_ok(), "within leeway");
        assert_eq!(v.verify_at(&tok, NOW - 31).unwrap_err().class(), "not_yet_valid");

        // Flip one bit in each part of the payload (claims, then signature).
        let prefix = "v4.public.".len();
        for pos in [prefix + 5, prefix + 120] {
            let mut b = tok.clone().into_bytes();
            b[pos] = if b[pos] == b'A' { b'B' } else { b'A' };
            let t = String::from_utf8(b).unwrap();
            assert!(v.verify_at(&t, NOW).is_err(), "tamper at {pos} accepted");
        }

        assert_eq!(v.verify_at(&sign_token(&sk, &claims("other", 2)), NOW).unwrap_err().class(), "wrong_tenant");
        let strict = setup().1.with_min_trust(3);
        assert_eq!(strict.verify_at(&tok, NOW).unwrap_err().class(), "trust_too_low");

        let other = SigningKey::from_bytes(&[8; 32]);
        assert_eq!(v.verify_at(&sign_token(&other, &claims("demo", 2)), NOW).unwrap_err().class(), "unknown_key");
    }

    #[test]
    fn parses_gateway_public_keys() {
        let sk = SigningKey::from_bytes(&[7; 32]);
        let pk = sk.verifying_key();
        let j = format!(
            r#"{{"server_identity":{{"kid":"{k}","public_key":"{h}"}},"token_keys":[{{"kid":"{k}","public_key":"{h}"}}]}}"#,
            k = key_id(&pk),
            h = hex::encode(pk.as_bytes())
        );
        let keys = PublicKeys::parse(&j).unwrap();
        assert_eq!(keys.token_keys.len(), 1);
        assert!(PublicKeys::parse(&j.replace(&key_id(&pk), "0000000000000000")).is_err());
    }
}
