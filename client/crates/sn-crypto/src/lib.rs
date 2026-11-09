//! Sentinel protocol crypto shared by the client SDK and the game-server SDK. Mirrors
//! `backend/internal/protocol`; `proto/README.md` is the specification and
//! `proto/testvectors/` the golden vectors both implementations must pass.

pub mod aead;
pub mod handshake;
pub mod time;
pub mod token;
pub mod trust;

pub use aead::{Channel, Direction, FrameError};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use handshake::*;
pub use token::{key_id, sign_token, Claims, TokenError, TokenKeys, DEFAULT_LEEWAY_SECS, TOKEN_ISSUER};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("X25519 peer key is low-order")]
    LowOrderPoint,
}
