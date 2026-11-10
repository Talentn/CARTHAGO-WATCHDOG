//! Game-server SDK (plan §3.5): offline session-token verification against the gateway's
//! published token keys, a kick listener on the gateway's game-server channel, and the
//! gameplay telemetry stream for server-side detection (Phase 1).
//! Verification needs no network; the kick channel is advisory and a game server keeps
//! admitting verified tokens while it is down.

pub mod gameplay;
pub mod kick;
mod verify;

pub use gameplay::{GameplayStream, IngestEvent, MatchRecorder};
pub use kick::{GsEvent, KickListener};
pub use carthago_proto::v1 as pb;
pub use carthago_crypto::token::{Claims, TokenError};
pub use verify::{PublicKeys, Verifier, VerifyError};
