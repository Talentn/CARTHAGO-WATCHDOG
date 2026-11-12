//! Game-server SDK (plan §3.5): offline session-token verification against the gateway's
//! published token keys, a kick listener on the gateway's game-server channel, and the
//! gameplay telemetry stream for server-side detection (Phase 1), with decoy placement
//! (Phase 2).
//! Verification needs no network; the kick channel is advisory and a game server keeps
//! admitting verified tokens while it is down.

pub mod decoy;
pub mod gameplay;
pub mod kick;
mod verify;

pub use decoy::{DecoyPlanner, DecoyRules, DecoyView};
pub use gameplay::{
    GameplayStream, IngestEvent, MatchRecorder, DECOY_ROLL_MIN_S, DEFAULT_MOTION_STRIDE, MAX_DECOYS_ALIVE, MAX_DECOY_RECIPIENTS, MAX_DECOY_SAMPLES_PER_FLUSH,
    MAX_ITEMS_PER_FLUSH, MAX_MOTION_SAMPLES_PER_FLUSH, MAX_SOUNDS_PER_FLUSH, MAX_TEAM_INFO_PER_FLUSH, SCHEMA_V2,
};
pub use kick::{GsEvent, KickListener};
pub use carthago_proto::v1 as pb;
pub use carthago_crypto::token::{Claims, TokenError};
pub use verify::{PublicKeys, Verifier, VerifyError};
