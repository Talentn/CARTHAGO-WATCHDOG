use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;

use crate::handshake::FRAME_SEALED;

const DST_AEAD: &[u8] = b"sentinel/v1/aead";
pub const SEALED_HEADER_LEN: usize = 1 + 8;
const TAG_LEN: usize = 16;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer = 0,
    ServerToClient = 1,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("sealed frame malformed")]
    Malformed,
    #[error("sealed frame out of sequence: got {got}, want {want}")]
    Seq { got: u64, want: u64 },
    #[error("sealed frame failed authentication")]
    Auth,
}

impl FrameError {
    /// Error class names used in proto/testvectors/aead.json.
    pub fn class(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Seq { .. } => "seq",
            Self::Auth => "auth",
        }
    }
}

fn nonce(dir: Direction, seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&(dir as u32).to_be_bytes());
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

fn aad(session_id: &[u8], seq: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(DST_AEAD.len() + session_id.len() + SEALED_HEADER_LEN);
    a.extend_from_slice(DST_AEAD);
    a.extend_from_slice(session_id);
    a.push(FRAME_SEALED);
    a.extend_from_slice(&seq.to_be_bytes());
    a
}

/// 0x03 || u64be(seq) || ChaCha20-Poly1305(plaintext); nonce = u32be(dir) || u64be(seq),
/// AAD = dst || session_id || 0x03 || u64be(seq).
pub fn seal(key: &[u8; 32], session_id: &[u8], dir: Direction, seq: u64, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(&nonce(dir, seq).into(), Payload { msg: plaintext, aad: &aad(session_id, seq) })
        .expect("ChaCha20-Poly1305 encryption cannot fail for in-range lengths");
    let mut out = Vec::with_capacity(SEALED_HEADER_LEN + ct.len());
    out.push(FRAME_SEALED);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ct);
    out
}

/// Opens a frame that must carry exactly `want_seq` (replays and gaps both fail).
pub fn open(key: &[u8; 32], session_id: &[u8], dir: Direction, want_seq: u64, frame: &[u8]) -> Result<Vec<u8>, FrameError> {
    if frame.len() < SEALED_HEADER_LEN + TAG_LEN || frame[0] != FRAME_SEALED {
        return Err(FrameError::Malformed);
    }
    let seq = u64::from_be_bytes(frame[1..SEALED_HEADER_LEN].try_into().unwrap());
    if seq != want_seq {
        return Err(FrameError::Seq { got: seq, want: want_seq });
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(&nonce(dir, seq).into(), Payload { msg: &frame[SEALED_HEADER_LEN..], aad: &aad(session_id, seq) })
        .map_err(|_| FrameError::Auth)
}

/// Per-connection sealed channel with independent, strictly increasing sequence numbers.
pub struct Channel {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_dir: Direction,
    recv_dir: Direction,
    session_id: Vec<u8>,
    send_seq: u64,
    recv_seq: u64,
}

impl Channel {
    pub fn client(keys: &crate::SessionKeys, session_id: &[u8]) -> Self {
        Self {
            send_key: keys.c2s,
            recv_key: keys.s2c,
            send_dir: Direction::ClientToServer,
            recv_dir: Direction::ServerToClient,
            session_id: session_id.to_vec(),
            send_seq: 0,
            recv_seq: 0,
        }
    }

    pub fn server(keys: &crate::SessionKeys, session_id: &[u8]) -> Self {
        Self {
            send_key: keys.s2c,
            recv_key: keys.c2s,
            send_dir: Direction::ServerToClient,
            recv_dir: Direction::ClientToServer,
            session_id: session_id.to_vec(),
            send_seq: 0,
            recv_seq: 0,
        }
    }

    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Sequence number the next sealed frame will carry.
    pub fn next_send_seq(&self) -> u64 {
        self.send_seq
    }

    pub fn seal_next(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let f = seal(&self.send_key, &self.session_id, self.send_dir, self.send_seq, plaintext);
        self.send_seq += 1;
        f
    }

    /// Returns the plaintext and the sequence number it was sealed with.
    pub fn open_next(&mut self, frame: &[u8]) -> Result<(u64, Vec<u8>), FrameError> {
        let pt = open(&self.recv_key, &self.session_id, self.recv_dir, self.recv_seq, frame)?;
        let seq = self.recv_seq;
        self.recv_seq += 1;
        Ok((seq, pt))
    }
}
