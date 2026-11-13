//! Enforcement notices: the gateway telling this client that its session was flagged, so the
//! game can show its own screen. A notice carries a category and a severity and nothing
//! about the rule behind it. It informs only; ending a session stays with the game server.

use carthago_crypto::VerifyingKey;
use carthago_proto::v1 as pb;
use ed25519_dalek::Verifier;
use prost::Message;

pub const CATEGORY_TEST: u32 = pb::EnforcementCategory::Test as u32;
pub const CATEGORY_GAME_INTEGRITY: u32 = pb::EnforcementCategory::GameIntegrity as u32;
pub const CATEGORY_DEBUGGER: u32 = pb::EnforcementCategory::Debugger as u32;
pub const CATEGORY_TIME_MANIPULATION: u32 = pb::EnforcementCategory::TimeManipulation as u32;
pub const CATEGORY_AIM_ASSISTANCE: u32 = pb::EnforcementCategory::AimAssistance as u32;
pub const CATEGORY_VISIBILITY: u32 = pb::EnforcementCategory::Visibility as u32;

pub const SEVERITY_NOTICE: u32 = pb::EnforcementSeverity::Notice as u32;
pub const SEVERITY_HIGH: u32 = pb::EnforcementSeverity::High as u32;
pub const SEVERITY_CRITICAL: u32 = pb::EnforcementSeverity::Critical as u32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub notice_id: [u8; 16],
    pub session_id: [u8; 16],
    pub tenant_id: String,
    pub player_id_hash: String,
    pub issued_at_ms: u64,
    /// `CATEGORY_*`; values this build does not know are passed through.
    pub category: u32,
    /// `SEVERITY_*`.
    pub severity: u32,
    /// The encoded `EnforcementNotice` as it arrived (body, signature, key id). A game can
    /// pass these bytes to its server, which checks them with [`Notice::from_signed`].
    pub signed: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NoticeError {
    #[error("notice is not a valid message")]
    Encoding,
    #[error("notice is signed by a key other than the pinned server identity key")]
    KeyId,
    #[error("notice signature does not verify under the pinned server identity key")]
    Signature,
    #[error("notice is about another session")]
    Session,
}

impl Notice {
    /// Checks the signature over the body bytes as received, then decodes them.
    pub fn verify(key: &VerifyingKey, n: &pb::EnforcementNotice) -> Result<Notice, NoticeError> {
        if n.server_key_id != carthago_crypto::key_id(key) {
            return Err(NoticeError::KeyId);
        }
        let sig = ed25519_dalek::Signature::from_slice(&n.server_sig).map_err(|_| NoticeError::Signature)?;
        key.verify(&carthago_crypto::notice_sig_input(&n.body), &sig).map_err(|_| NoticeError::Signature)?;
        let body = pb::EnforcementNoticeBody::decode(n.body.as_slice()).map_err(|_| NoticeError::Encoding)?;
        Ok(Notice {
            notice_id: body.notice_id.as_slice().try_into().map_err(|_| NoticeError::Encoding)?,
            session_id: body.session_id.as_slice().try_into().map_err(|_| NoticeError::Encoding)?,
            tenant_id: body.tenant_id,
            player_id_hash: body.player_id_hash,
            issued_at_ms: body.issued_at_ms,
            category: body.category,
            severity: body.severity,
            signed: n.encode_to_vec(),
        })
    }

    /// Verifies a notice that was passed on as bytes ([`Notice::signed`]).
    pub fn from_signed(key: &VerifyingKey, signed: &[u8]) -> Result<Notice, NoticeError> {
        Self::verify(key, &pb::EnforcementNotice::decode(signed).map_err(|_| NoticeError::Encoding)?)
    }

    /// As [`Notice::verify`], and the notice must be about `session_id`.
    pub fn verify_for_session(key: &VerifyingKey, n: &pb::EnforcementNotice, session_id: &[u8]) -> Result<Notice, NoticeError> {
        let notice = Self::verify(key, n)?;
        if notice.session_id != session_id {
            return Err(NoticeError::Session);
        }
        Ok(notice)
    }

    /// A test sent on an operator's request: nothing was detected.
    pub fn is_test(&self) -> bool {
        self.category == CATEGORY_TEST
    }

    pub fn category_name(&self) -> &'static str {
        match self.category {
            CATEGORY_TEST => "test",
            CATEGORY_GAME_INTEGRITY => "game_integrity",
            CATEGORY_DEBUGGER => "debugger",
            CATEGORY_TIME_MANIPULATION => "time_manipulation",
            CATEGORY_AIM_ASSISTANCE => "aim_assistance",
            CATEGORY_VISIBILITY => "visibility",
            _ => "other",
        }
    }

    pub fn severity_name(&self) -> &'static str {
        match self.severity {
            SEVERITY_NOTICE => "notice",
            SEVERITY_HIGH => "high",
            SEVERITY_CRITICAL => "critical",
            _ => "other",
        }
    }

    /// One line a game can show the player. It names the category, never a rule.
    pub fn reason(&self) -> &'static str {
        match self.category {
            CATEGORY_TEST => "Test of the alert screen. Nothing was detected.",
            CATEGORY_GAME_INTEGRITY => "The game's code, memory or libraries were tampered with.",
            CATEGORY_DEBUGGER => "A debugger is attached to the game.",
            CATEGORY_TIME_MANIPULATION => "The game's clocks were manipulated.",
            CATEGORY_AIM_ASSISTANCE => "Aim assistance was detected in this match.",
            CATEGORY_VISIBILITY => "A visibility cheat (wallhack) was detected on this game.",
            _ => "This session was flagged by the anti-cheat service.",
        }
    }

    pub fn notice_id_hex(&self) -> String {
        hex::encode(self.notice_id)
    }

    pub fn session_id_hex(&self) -> String {
        hex::encode(self.session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../proto/testvectors/notice.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("notice.json")).unwrap()
    }

    fn hx(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    fn key(v: &Value) -> VerifyingKey {
        VerifyingKey::from_bytes(&hx(&v["server_identity_pub"]).try_into().unwrap()).unwrap()
    }

    #[test]
    fn notices_signed_by_the_gateway_verify_and_decode() {
        let v = vectors();
        let key = key(&v);
        for c in v["valid"].as_array().unwrap() {
            let signed = hx(&c["notice_bytes"]);
            let n = Notice::from_signed(&key, &signed).unwrap_or_else(|e| panic!("{}: {e}", c["name"]));
            assert_eq!(n.notice_id.to_vec(), hx(&c["notice_id"]));
            assert_eq!(n.session_id.to_vec(), hx(&c["session_id"]));
            assert_eq!(n.tenant_id, c["tenant_id"].as_str().unwrap());
            assert_eq!(n.player_id_hash, c["player_id_hash"].as_str().unwrap());
            assert_eq!(n.issued_at_ms, c["issued_at_ms"].as_u64().unwrap());
            assert_eq!(n.category as u64, c["category"].as_u64().unwrap());
            assert_eq!(n.severity as u64, c["severity"].as_u64().unwrap());
            assert_eq!(n.signed, signed, "a notice is passed on as the bytes that arrived");

            // The body this client would encode from the same fields is the body Go signed.
            let body = pb::EnforcementNoticeBody {
                notice_id: n.notice_id.to_vec(),
                session_id: n.session_id.to_vec(),
                tenant_id: n.tenant_id.clone(),
                player_id_hash: n.player_id_hash.clone(),
                issued_at_ms: n.issued_at_ms,
                category: n.category,
                severity: n.severity,
            };
            assert_eq!(body.encode_to_vec(), hx(&c["body_bytes"]));
        }
        let names: Vec<&str> = v["valid"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["test_notice", "aim_assistance_high", "game_integrity_critical"]);
        let first = Notice::from_signed(&key, &hx(&v["valid"][0]["notice_bytes"])).unwrap();
        assert!(first.is_test());
        assert_eq!((first.category_name(), first.severity_name()), ("test", "notice"));
        let aim = Notice::from_signed(&key, &hx(&v["valid"][1]["notice_bytes"])).unwrap();
        assert!(!aim.is_test());
        assert_eq!((aim.category_name(), aim.severity_name()), ("aim_assistance", "high"));
    }

    #[test]
    fn changed_or_foreign_notices_are_refused() {
        let v = vectors();
        let key = key(&v);
        let invalid = v["invalid"].as_array().unwrap();
        assert!(invalid.len() >= 5);
        for c in invalid {
            let r = Notice::from_signed(&key, &hx(&c["notice_bytes"]));
            assert!(r.is_err(), "{} was accepted: {r:?}", c["name"]);
        }
        assert_eq!(Notice::from_signed(&key, b"\xff\xff"), Err(NoticeError::Encoding));

        // A valid notice about another session is not for this client.
        let n = pb::EnforcementNotice::decode(hx(&v["valid"][1]["notice_bytes"]).as_slice()).unwrap();
        let own = hx(&v["valid"][1]["session_id"]);
        assert!(Notice::verify_for_session(&key, &n, &own).is_ok());
        let mut other = own.clone();
        other[0] ^= 1;
        assert_eq!(Notice::verify_for_session(&key, &n, &other), Err(NoticeError::Session));
    }
}
