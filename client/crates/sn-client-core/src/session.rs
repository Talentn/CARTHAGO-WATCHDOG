//! Client side of the Hello/Challenge/Prove handshake and the sealed session channel.

use std::time::Duration;

use carthago_net::{Pin, Stream};
use ed25519_dalek::Verifier;
use prost::Message;
use sn_crypto::{Channel, VerifyingKey};
use sn_proto::v1 as pb;
use tungstenite::{Message as WsMessage, WebSocket};

use crate::device::DeviceIdentity;

pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("connect: {0}")]
    Connect(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("server identity check failed: {0}")]
    ServerIdentity(&'static str),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("rejected by gateway: {code}: {message}")]
    Rejected { code: String, message: String },
    #[error("device key: {0}")]
    Device(String),
}

pub struct Params {
    pub gateway_url: String,
    pub tenant_id: String,
    pub build_id: String,
    pub player_id_hash: String,
    /// Pinned server identity key (plan §5.1: embedded and obfuscated in production builds).
    pub server_identity: VerifyingKey,
    /// Pinned gateway TLS keys (SHA-256 of the SPKI), current plus backup; required for wss://.
    pub tls_pins: Vec<Pin>,
}

pub struct Established {
    pub ws: WebSocket<Stream>,
    pub chan: Channel,
    pub session: pb::Session,
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
    /// Timings for the log: handshake total and the TPM evidence part.
    pub handshake_ms: u128,
    pub tpm_ms: u128,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn connect(url: &str, pins: &[Pin]) -> Result<WebSocket<Stream>, SessionError> {
    carthago_net::connect(url, pins, Duration::from_secs(5)).map_err(|e| SessionError::Connect(e.to_string()))
}

fn read_binary(ws: &mut WebSocket<Stream>) -> Result<Vec<u8>, SessionError> {
    loop {
        match ws.read() {
            Ok(WsMessage::Binary(b)) => return Ok(b.to_vec()),
            Ok(WsMessage::Close(f)) => {
                return Err(SessionError::Transport(format!("closed by gateway: {}", f.map(|f| f.reason.to_string()).unwrap_or_default())))
            }
            Ok(_) => continue,
            Err(e) => return Err(SessionError::Transport(e.to_string())),
        }
    }
}

fn send_sealed(ws: &mut WebSocket<Stream>, chan: &mut Channel, mut m: pb::ClientMsg) -> Result<(), SessionError> {
    m.seq = chan.next_send_seq();
    m.session_id = chan.session_id().to_vec();
    m.client_ts_ms = now_ms();
    let frame = chan.seal_next(&m.encode_to_vec());
    ws.send(WsMessage::Binary(frame.into())).map_err(|e| SessionError::Transport(e.to_string()))
}

/// Opens and decodes one sealed server frame, checking the inner seq and session id.
pub fn open_server_msg(chan: &mut Channel, frame: &[u8]) -> Result<pb::ServerMsg, SessionError> {
    let (seq, pt) = chan.open_next(frame).map_err(|e| SessionError::Protocol(e.to_string()))?;
    let m = pb::ServerMsg::decode(pt.as_slice()).map_err(|e| SessionError::Protocol(format!("decode ServerMsg: {e}")))?;
    if m.seq != seq || m.session_id != chan.session_id() {
        return Err(SessionError::Protocol("ServerMsg seq/session_id do not match the frame".into()));
    }
    Ok(m)
}

pub fn send_heartbeat(ws: &mut WebSocket<Stream>, chan: &mut Channel, hb: pb::Heartbeat) -> Result<(), SessionError> {
    send_sealed(ws, chan, pb::ClientMsg { body: Some(pb::client_msg::Body::Heartbeat(hb)), ..Default::default() })
}

pub fn handshake(p: &Params, device: &DeviceIdentity, log: &dyn Fn(u8, &str)) -> Result<Established, SessionError> {
    let t0 = std::time::Instant::now();
    let mut ws = connect(&p.gateway_url, &p.tls_pins)?;

    let mut eph = [0u8; 32];
    crate::device::getrandom(&mut eph).map_err(SessionError::Device)?;
    let token = sn_attest::current_token();
    let hello = pb::Hello {
        protocol_version: sn_crypto::PROTOCOL_VERSION,
        sdk_version: SDK_VERSION.into(),
        tenant_id: p.tenant_id.clone(),
        build_id: p.build_id.clone(),
        client_eph_pub: sn_crypto::x25519_public(&eph).to_vec(),
        device_key: Some(device.device_key()),
        player_id_hash: p.player_id_hash.clone(),
        env: Some(pb::EnvReport {
            os_build: crate::os_build(),
            elevated: token.map(|t| t.elevated).unwrap_or(false),
            tpm_present: device.is_tpm(),
            tpm_manufacturer: device.tpm_manufacturer(),
        }),
        tpm_enrollment: device.enrollment(),
        tpm_attestation_available: device.is_tpm(),
        client_ts_ms: now_ms(),
    }
    .encode_to_vec();
    let mut frame = vec![sn_crypto::FRAME_HELLO];
    frame.extend_from_slice(&hello);
    ws.send(WsMessage::Binary(frame.into())).map_err(|e| SessionError::Transport(e.to_string()))?;

    let ch = read_binary(&mut ws)?;
    if ch.first() != Some(&sn_crypto::FRAME_CHALLENGE) {
        return Err(SessionError::Protocol("expected Challenge".into()));
    }
    let ch = pb::Challenge::decode(&ch[1..]).map_err(|e| SessionError::Protocol(format!("decode Challenge: {e}")))?;
    if ch.server_key_id != sn_crypto::key_id(&p.server_identity) {
        return Err(SessionError::ServerIdentity("Challenge signed by an unpinned key id"));
    }
    let th = sn_crypto::transcript_hash(&hello, &ch.body);
    let sig = ed25519_dalek::Signature::from_slice(&ch.server_sig).map_err(|_| SessionError::ServerIdentity("bad signature encoding"))?;
    p.server_identity
        .verify(&sn_crypto::challenge_sig_input(&th), &sig)
        .map_err(|_| SessionError::ServerIdentity("Challenge signature does not verify under the pinned key"))?;
    let body = pb::ChallengeBody::decode(ch.body.as_slice()).map_err(|e| SessionError::Protocol(format!("decode ChallengeBody: {e}")))?;
    let server_eph: [u8; 32] = body.server_eph_pub.as_slice().try_into().map_err(|_| SessionError::Protocol("server_eph_pub length".into()))?;
    if body.session_id.len() != sn_crypto::SESSION_ID_LEN {
        return Err(SessionError::Protocol("session_id length".into()));
    }
    let shared = sn_crypto::x25519(&eph, &server_eph).map_err(|e| SessionError::Protocol(e.to_string()))?;
    let keys = sn_crypto::derive_keys(&shared, &th);
    let mut chan = Channel::client(&keys, &body.session_id);

    let t_tpm = std::time::Instant::now();
    let attestation = body.attest.as_ref().and_then(|req| device.evidence(req, &sn_crypto::quote_nonce(&th)));
    if let Some(e) = attestation.as_ref().filter(|e| !e.error.is_empty()) {
        log(2, &format!("TPM evidence incomplete: {}", e.error));
    }
    let device_sig = device.sign_prove(&sn_crypto::prove_digest(&th)).map_err(SessionError::Device)?;
    let tpm_ms = t_tpm.elapsed().as_millis();
    send_sealed(&mut ws, &mut chan, pb::ClientMsg { body: Some(pb::client_msg::Body::Prove(pb::Prove { device_sig, attestation })), ..Default::default() })?;

    let reply = read_binary(&mut ws)?;
    match open_server_msg(&mut chan, &reply)?.body {
        Some(pb::server_msg::Body::Session(session)) => Ok(Established {
            ws,
            chan,
            session,
            heartbeat_interval: Duration::from_millis(body.heartbeat_interval_ms.max(500) as u64),
            heartbeat_timeout: Duration::from_millis(body.heartbeat_timeout_ms as u64),
            handshake_ms: t0.elapsed().as_millis(),
            tpm_ms,
        }),
        Some(pb::server_msg::Body::Error(e)) => Err(SessionError::Rejected { code: e.code, message: e.message }),
        _ => Err(SessionError::Protocol("expected Session".into())),
    }
}

/// True for the read-timeout errors that just mean "no frame yet".
pub fn is_timeout(e: &tungstenite::Error) -> bool {
    carthago_net::is_timeout(e)
}
