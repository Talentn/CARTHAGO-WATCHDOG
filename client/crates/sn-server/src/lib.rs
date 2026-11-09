//! Game-server SDK (plan §3.5): offline session-token verification against the gateway's
//! published token keys, plus a kick listener on the gateway's game-server channel.
//! Verification needs no network; the kick channel is advisory and a game server keeps
//! admitting verified tokens while it is down.

pub mod kick;
mod verify;

pub use kick::{GsEvent, KickListener};
pub use sn_crypto::token::{Claims, TokenError};
pub use verify::{PublicKeys, Verifier, VerifyError};
