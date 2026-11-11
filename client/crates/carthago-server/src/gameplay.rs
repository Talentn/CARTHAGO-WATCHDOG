//! Gameplay telemetry for the server-side behavioural rules (plan §8, Phase 1): the game
//! server records what it already knows authoritatively (view angles, shots, visibility,
//! user-command counts, trigger timing) with [`MatchRecorder`], and [`GameplayStream`]
//! delivers the batches to the gateway's `/v1/ingest` endpoint.
//!
//! Delivery is in order, one batch in flight, and at-least-once: a batch stays queued until
//! the gateway acknowledges it, survives reconnects, and is resent with the same `batch_seq`
//! (the gateway acks a duplicate with `accepted = false` and does not analyse it twice). A
//! "busy" ack is retried after a short pause. Nothing here blocks the game's tick: `send`
//! only enqueues, and a full queue hands the batch back to the caller.

use std::collections::{BTreeMap, VecDeque};
use std::sync::mpsc::{channel, sync_channel, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use carthago_net::{Pin, Stream};
use prost::Message as _;
use carthago_proto::v1 as pb;
use tungstenite::{Message as WsMessage, WebSocket};

use crate::kick::connect;

/// Per-flush caps on telemetry v2 events. Anything over a cap is dropped and counted in the
/// batch's `dropped_events`, so a misbehaving game loop costs bounded memory and bandwidth.
pub const MAX_MOTION_SAMPLES_PER_FLUSH: usize = 16_384;
pub const MAX_SOUNDS_PER_FLUSH: usize = 4_096;
pub const MAX_TEAM_INFO_PER_FLUSH: usize = 1_024;
pub const MAX_ITEMS_PER_FLUSH: usize = 1_024;
/// Default motion sampling: every 4th tick (16 Hz at 64 ticks/s).
pub const DEFAULT_MOTION_STRIDE: u32 = 4;

/// Telemetry v2 schema version written into batches once any v2 call was made.
pub const SCHEMA_V2: u32 = 2;

struct MotionBuf {
    track: pb::MotionTrack,
    last_tick: u32,
    last: [i32; 6],
}

/// Builds `GameplayBatch`es from per-tick calls. Aim samples for consecutive ticks are packed
/// into one track per player; command counts are summed into one window per flush.
///
/// Telemetry v2 (positions, sounds, team info, items, map geometry) is opt-in: a recorder
/// that never calls a v2 method produces exactly the v1 batches it always did.
pub struct MatchRecorder {
    match_id: String,
    tick_rate: u32,
    seq: u64,
    tick: u32,
    window_from: u32,
    players: BTreeMap<u32, pb::MatchPlayer>,
    players_dirty: bool,
    aim: BTreeMap<u32, pb::AimTrack>,
    aim_done: Vec<pb::AimTrack>,
    shots: Vec<pb::ShotEvent>,
    visibility: Vec<pb::VisibilityEvent>,
    commands: BTreeMap<u32, u32>,
    triggers: BTreeMap<u32, Vec<u64>>,
    v2: bool,
    mode: pb::GameMode,
    map: Option<pb::MapRef>,
    geometry: Option<pb::MapGeometry>,
    motion_stride: u32,
    motion: BTreeMap<u32, MotionBuf>,
    motion_done: Vec<pb::MotionTrack>,
    motion_samples: usize,
    sounds: Vec<pb::SoundEvent>,
    team_info: Vec<pb::TeamInfo>,
    items: Vec<pb::ItemEvent>,
    dropped: u32,
}

fn cm(m: f32) -> i32 {
    (m * 100.0).round().clamp(i32::MIN as f32, i32::MAX as f32) as i32
}

impl MatchRecorder {
    pub fn new(match_id: impl Into<String>, tick_rate: u32) -> Self {
        Self {
            match_id: match_id.into(),
            tick_rate,
            seq: 0,
            tick: 0,
            window_from: 0,
            players: BTreeMap::new(),
            players_dirty: false,
            aim: BTreeMap::new(),
            aim_done: Vec::new(),
            shots: Vec::new(),
            visibility: Vec::new(),
            commands: BTreeMap::new(),
            triggers: BTreeMap::new(),
            v2: false,
            mode: pb::GameMode::Unspecified,
            map: None,
            geometry: None,
            motion_stride: DEFAULT_MOTION_STRIDE,
            motion: BTreeMap::new(),
            motion_done: Vec::new(),
            motion_samples: 0,
            sounds: Vec::new(),
            team_info: Vec::new(),
            items: Vec::new(),
            dropped: 0,
        }
    }

    /// v2: the player's team (0 = solo), input device and whether the game assists their aim.
    /// These select the calibration segment the leak scorer judges them in.
    pub fn player_profile(&mut self, slot: u32, team: u32, device: pb::InputDevice, aim_assist: bool) {
        self.v2 = true;
        let p = self.players.entry(slot).or_insert_with(|| pb::MatchPlayer { slot, ..Default::default() });
        let (t, d) = (team, device as i32);
        if p.team != t || p.input_device != d || p.aim_assist != aim_assist {
            p.team = t;
            p.input_device = d;
            p.aim_assist = aim_assist;
            self.players_dirty = true;
        }
    }

    /// v2: the match's mode, which picks the scorer's thresholds.
    pub fn set_mode(&mut self, mode: pb::GameMode) {
        self.v2 = true;
        self.mode = mode;
    }

    /// v2: the map the match runs on. The geometry is sent once, with the next batch; later
    /// matches on the same version may call [`MatchRecorder::set_map_ref`] instead.
    pub fn set_map(&mut self, geometry: pb::MapGeometry) {
        self.v2 = true;
        self.map = Some(pb::MapRef { map_id: geometry.map_id.clone(), version: geometry.version });
        self.geometry = Some(geometry);
    }

    /// v2: names a map version the gateway already holds, without resending its geometry.
    pub fn set_map_ref(&mut self, map_id: &str, version: u32) {
        self.v2 = true;
        self.map = Some(pb::MapRef { map_id: map_id.into(), version });
    }

    /// v2: motion is kept every `stride` ticks (default 4). Call before recording motion.
    pub fn set_motion_stride(&mut self, stride: u32) {
        self.motion_stride = stride.max(1);
    }

    /// v2: a slot's eye position (metres) and velocity (m/s) at `tick`. Call every tick if
    /// convenient: only ticks that are a multiple of the stride are kept, so samples stay
    /// evenly spaced across batches.
    pub fn motion(&mut self, slot: u32, tick: u32, pos_m: [f32; 3], vel_m_s: [f32; 3]) {
        self.v2 = true;
        let stride = self.motion_stride;
        if !tick.is_multiple_of(stride) {
            return;
        }
        if self.motion_samples >= MAX_MOTION_SAMPLES_PER_FLUSH {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.motion_samples += 1;
        let v = [cm(pos_m[0]), cm(pos_m[1]), cm(pos_m[2]), cm(vel_m_s[0]), cm(vel_m_s[1]), cm(vel_m_s[2])];
        let fresh = |tick| MotionBuf { track: pb::MotionTrack { slot, first_tick: tick, stride, ..Default::default() }, last_tick: tick, last: [0; 6] };
        let b = self.motion.entry(slot).or_insert_with(|| fresh(tick));
        if !b.track.x_cm.is_empty() && tick != b.last_tick + stride {
            let done = std::mem::replace(b, fresh(tick));
            self.motion_done.push(done.track);
        }
        let t = &mut b.track;
        let d: [i32; 6] = std::array::from_fn(|i| v[i].wrapping_sub(b.last[i]));
        t.x_cm.push(d[0]);
        t.y_cm.push(d[1]);
        t.z_cm.push(d[2]);
        t.vx_cm_s.push(d[3]);
        t.vy_cm_s.push(d[4]);
        t.vz_cm_s.push(d[5]);
        b.last = v;
        b.last_tick = tick;
    }

    /// v2: a sound the game played. `radius_m` is the game's own audibility rule for it.
    pub fn sound(&mut self, tick: u32, source_slot: Option<u32>, kind: pb::SoundKind, pos_m: [f32; 3], radius_m: f32) {
        self.v2 = true;
        if self.sounds.len() >= MAX_SOUNDS_PER_FLUSH {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.sounds.push(pb::SoundEvent {
            tick,
            source_slot: source_slot.map_or(-1, |s| s as i32),
            kind: kind as i32,
            x_cm: cm(pos_m[0]),
            y_cm: cm(pos_m[1]),
            z_cm: cm(pos_m[2]),
            radius_cm: cm(radius_m).max(0) as u32,
        });
    }

    /// v2: information the game gave a whole team (pings, spotted enemies, radar reveals).
    pub fn team_info(&mut self, info: pb::TeamInfo) {
        self.v2 = true;
        if self.team_info.len() >= MAX_TEAM_INFO_PER_FLUSH {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.team_info.push(info);
    }

    /// v2: loot or an objective spawned, moved or was picked up (`removed`).
    pub fn item(&mut self, item: pb::ItemEvent) {
        self.v2 = true;
        if item.item_id == 0 || self.items.len() >= MAX_ITEMS_PER_FLUSH {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.items.push(item);
    }

    /// Declares or updates a slot. `session_id` is the verified token's session ("" for bots),
    /// so the gateway can attach evidence to the session the client is running.
    pub fn player(&mut self, slot: u32, session_id: &str, player_hash: &str, mmr: i32) {
        let p = self.players.entry(slot).or_insert_with(|| pb::MatchPlayer { slot, ..Default::default() });
        if p.session_id != session_id || p.player_hash != player_hash || p.mmr != mmr {
            p.session_id = session_id.into();
            p.player_hash = player_hash.into();
            p.mmr = mmr;
            self.players_dirty = true;
        }
    }

    /// Sets the current server tick. Command windows end at the tick current at flush.
    pub fn set_tick(&mut self, tick: u32) {
        if self.window_from == 0 && self.tick == 0 {
            self.window_from = tick;
        }
        self.tick = tick;
    }

    /// The view angles a slot's command carried for `tick`, in degrees.
    pub fn aim(&mut self, slot: u32, tick: u32, yaw: f32, pitch: f32) {
        let t = self.aim.entry(slot).or_insert_with(|| pb::AimTrack { slot, first_tick: tick, ..Default::default() });
        if !t.yaw.is_empty() && t.first_tick + t.yaw.len() as u32 != tick {
            let done = std::mem::replace(t, pb::AimTrack { slot, first_tick: tick, ..Default::default() });
            self.aim_done.push(done);
        }
        t.yaw.push(yaw);
        t.pitch.push(pitch);
    }

    /// One user command received from `slot` (call per command, not per tick).
    pub fn command(&mut self, slot: u32) {
        *self.commands.entry(slot).or_default() += 1;
    }

    pub fn shot(&mut self, shot: pb::ShotEvent) {
        self.shots.push(shot);
    }

    /// Server-side line-of-sight changes: `visible` when `target` enters `observer`'s view.
    pub fn visibility(&mut self, observer: u32, target: u32, tick: u32, visible: bool) {
        self.visibility.push(pb::VisibilityEvent { observer_slot: observer, target_slot: target, tick, visible });
    }

    /// The client timestamp (µs) of a trigger press, as carried in the user command.
    pub fn trigger(&mut self, slot: u32, client_time_us: u64) {
        self.triggers.entry(slot).or_default().push(client_time_us);
    }

    pub fn match_id(&self) -> &str {
        &self.match_id
    }

    /// Takes everything recorded since the last flush as the next batch.
    pub fn flush(&mut self, match_over: bool) -> pb::GameplayBatch {
        self.seq += 1;
        let mut aim = std::mem::take(&mut self.aim_done);
        aim.extend(std::mem::take(&mut self.aim).into_values());
        let mut commands = Vec::new();
        if self.tick > self.window_from {
            commands = std::mem::take(&mut self.commands)
                .into_iter()
                .map(|(slot, n)| pb::CommandWindow { slot, tick_from: self.window_from, tick_to: self.tick, commands: n })
                .collect();
            self.window_from = self.tick;
        }
        let players = if std::mem::take(&mut self.players_dirty) { self.players.values().cloned().collect() } else { Vec::new() };
        // Every batch's tracks start from absolute values, so a lost or rejected batch never
        // corrupts the next one.
        let mut motion = std::mem::take(&mut self.motion_done);
        motion.extend(std::mem::take(&mut self.motion).into_values().map(|b| b.track));
        self.motion_samples = 0;
        pb::GameplayBatch {
            match_id: self.match_id.clone(),
            batch_seq: self.seq,
            tick_rate: self.tick_rate,
            players,
            aim,
            shots: std::mem::take(&mut self.shots),
            visibility: std::mem::take(&mut self.visibility),
            commands,
            triggers: std::mem::take(&mut self.triggers).into_iter().map(|(slot, t)| pb::TriggerPresses { slot, client_time_us: t }).collect(),
            match_over,
            schema_version: if self.v2 { SCHEMA_V2 } else { 0 },
            mode: self.mode as i32,
            map: if self.v2 { self.map.clone() } else { None },
            map_geometry: self.geometry.take(),
            motion,
            sounds: std::mem::take(&mut self.sounds),
            team_info: std::mem::take(&mut self.team_info),
            items: std::mem::take(&mut self.items),
            dropped_events: std::mem::take(&mut self.dropped),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestEvent {
    Connected,
    Disconnected(String),
    /// `accepted = false` means the gateway already had this batch (a resend after reconnect).
    /// `warning` is set when the gateway could only partly use it (for example it refused the
    /// map geometry); the batch is not resent.
    Acked { match_id: String, batch_seq: u64, accepted: bool, warning: String },
    /// The gateway refused the batch for good (malformed); it is not retried.
    Rejected { match_id: String, batch_seq: u64, error: String },
}

pub struct GameplayStream {
    tx: Option<SyncSender<pb::GameplayBatch>>,
    thread: Option<JoinHandle<()>>,
}

const QUEUE: usize = 256;
const ACK_TIMEOUT: Duration = Duration::from_secs(10);
const BUSY_RETRY: Duration = Duration::from_millis(250);

impl GameplayStream {
    /// `url` is e.g. `wss://gateway.example:8750/v1/ingest`; `server_key` is the tenant's server
    /// API key; `tls_pins` are the gateway's pinned TLS keys (required for `wss://`, empty for
    /// `ws://` on loopback).
    pub fn start(url: &str, server_key: &str, tls_pins: &[Pin]) -> (Self, Receiver<IngestEvent>) {
        let (tx, rx) = sync_channel(QUEUE);
        let (ev_tx, ev_rx) = channel();
        let (url, key, pins) = (url.to_owned(), server_key.to_owned(), tls_pins.to_vec());
        let thread = std::thread::Builder::new()
            .name("carthago-gs-ingest".into())
            .spawn(move || run(&url, &key, &pins, rx, ev_tx))
            .expect("spawn gameplay stream");
        (Self { tx: Some(tx), thread: Some(thread) }, ev_rx)
    }

    /// Queues a batch. Never blocks; a full queue returns the batch to the caller.
    pub fn send(&self, batch: pb::GameplayBatch) -> Result<(), Box<pb::GameplayBatch>> {
        let tx = self.tx.as_ref().expect("sender lives until drop");
        tx.try_send(batch).map_err(|e| match e {
            TrySendError::Full(b) | TrySendError::Disconnected(b) => Box::new(b),
        })
    }
}

impl Drop for GameplayStream {
    /// Stops accepting batches and waits until queued ones are acknowledged or the gateway
    /// becomes unreachable.
    fn drop(&mut self) {
        self.tx.take();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

enum Outcome {
    Done,
    Retry,
    Lost(String),
}

fn deliver(ws: &mut WebSocket<Stream>, b: &pb::GameplayBatch, ev: &Sender<IngestEvent>) -> Outcome {
    if let Err(e) = ws.send(WsMessage::Binary(b.encode_to_vec().into())) {
        return Outcome::Lost(e.to_string());
    }
    let deadline = Instant::now() + ACK_TIMEOUT;
    while Instant::now() < deadline {
        match ws.read() {
            Ok(WsMessage::Binary(data)) => {
                let Ok(ack) = pb::IngestAck::decode(&data[..]) else { return Outcome::Lost("undecodable ack".into()) };
                if ack.match_id != b.match_id || ack.batch_seq != b.batch_seq {
                    continue;
                }
                return match ack.error.as_str() {
                    "" => {
                        let _ = ev.send(IngestEvent::Acked { match_id: ack.match_id, batch_seq: ack.batch_seq, accepted: ack.accepted, warning: ack.warning });
                        Outcome::Done
                    }
                    "busy" | "context deadline exceeded" => Outcome::Retry,
                    _ => {
                        let _ = ev.send(IngestEvent::Rejected { match_id: ack.match_id, batch_seq: ack.batch_seq, error: ack.error });
                        Outcome::Done
                    }
                };
            }
            Ok(WsMessage::Close(_)) => return Outcome::Lost("closed by gateway".into()),
            Ok(_) => {}
            Err(tungstenite::Error::Io(e)) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(e) => return Outcome::Lost(e.to_string()),
        }
    }
    Outcome::Lost("no ack".into())
}

fn run(url: &str, key: &str, pins: &[Pin], rx: Receiver<pb::GameplayBatch>, ev: Sender<IngestEvent>) {
    let mut pending: VecDeque<pb::GameplayBatch> = VecDeque::new();
    let mut closed = false;
    let mut backoff = Duration::from_millis(250);
    // Pull whatever is queued without blocking; note when the owner has gone away.
    let drain = |pending: &mut VecDeque<pb::GameplayBatch>, closed: &mut bool| loop {
        match rx.try_recv() {
            Ok(b) => pending.push_back(b),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => {
                *closed = true;
                break;
            }
        }
    };
    loop {
        drain(&mut pending, &mut closed);
        if closed && pending.is_empty() {
            return;
        }
        let mut ws = match connect(url, key, pins) {
            Ok(ws) => ws,
            Err(e) => {
                let _ = ev.send(IngestEvent::Disconnected(e));
                // After the owner dropped the stream, an unreachable gateway ends delivery
                // rather than holding the game server's shutdown hostage.
                if closed {
                    return;
                }
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(10));
                continue;
            }
        };
        backoff = Duration::from_millis(250);
        let _ = ev.send(IngestEvent::Connected);
        loop {
            drain(&mut pending, &mut closed);
            let Some(front) = pending.front() else {
                if closed {
                    let _ = ws.close(None);
                    let _ = ws.flush();
                    return;
                }
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(b) => pending.push_back(b),
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => closed = true,
                }
                continue;
            };
            match deliver(&mut ws, front, &ev) {
                Outcome::Done => {
                    pending.pop_front();
                }
                Outcome::Retry => std::thread::sleep(BUSY_RETRY),
                Outcome::Lost(why) => {
                    let _ = ev.send(IngestEvent::Disconnected(why));
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn recorder_packs_tracks_windows_and_players() {
        let mut r = MatchRecorder::new("m", 64);
        r.player(1, "sess", "p1", 1500);
        r.set_tick(100);
        for t in 100..104 {
            r.set_tick(t);
            r.aim(1, t, t as f32, 0.0);
            r.command(1);
        }
        r.aim(1, 110, 5.0, 1.0); // gap: new track
        r.set_tick(110);
        r.trigger(1, 1000);
        r.shot(pb::ShotEvent { slot: 1, tick: 102, target_slot: -1, ..Default::default() });
        let b = r.flush(false);
        assert_eq!((b.match_id.as_str(), b.batch_seq, b.tick_rate), ("m", 1, 64));
        assert_eq!(b.players.len(), 1);
        assert_eq!(b.aim.len(), 2);
        assert_eq!((b.aim[0].first_tick, b.aim[0].yaw.len()), (100, 4));
        assert_eq!((b.aim[1].first_tick, b.aim[1].yaw.len()), (110, 1));
        assert_eq!(b.commands, vec![pb::CommandWindow { slot: 1, tick_from: 100, tick_to: 110, commands: 4 }]);
        assert_eq!(b.triggers[0].client_time_us, vec![1000]);
        assert_eq!(b.shots.len(), 1);

        // Unchanged players are not resent; an empty window carries its commands forward.
        r.player(1, "sess", "p1", 1500);
        r.command(1);
        let b = r.flush(false);
        assert_eq!(b.batch_seq, 2);
        assert!(b.players.is_empty() && b.commands.is_empty() && b.aim.is_empty());
        r.set_tick(120);
        let b = r.flush(true);
        assert_eq!(b.commands, vec![pb::CommandWindow { slot: 1, tick_from: 110, tick_to: 120, commands: 1 }]);
        assert!(b.match_over);
    }

    fn decode_track(t: &pb::MotionTrack) -> Vec<[i32; 6]> {
        let mut cur = [0i32; 6];
        (0..t.x_cm.len())
            .map(|i| {
                for (k, v) in [&t.x_cm, &t.y_cm, &t.z_cm, &t.vx_cm_s, &t.vy_cm_s, &t.vz_cm_s].iter().enumerate() {
                    cur[k] = cur[k].wrapping_add(v[i]);
                }
                cur
            })
            .collect()
    }

    #[test]
    fn v1_callers_get_v1_batches() {
        let mut r = MatchRecorder::new("m", 64);
        r.player(1, "s", "p", 0);
        r.aim(1, 1, 0.0, 0.0);
        let b = r.flush(true);
        assert_eq!(b.schema_version, 0);
        assert!(b.map.is_none() && b.map_geometry.is_none() && b.motion.is_empty() && b.mode == 0);
    }

    #[test]
    fn motion_is_strided_delta_coded_and_absolute_per_batch() {
        let mut r = MatchRecorder::new("m", 64);
        r.set_mode(pb::GameMode::Extraction);
        r.set_map(pb::MapGeometry { map_id: "yard".into(), version: 3, ..Default::default() });
        r.player(2, "s", "p", 0);
        r.player_profile(2, 1, pb::InputDevice::Controller, true);
        for t in 0..16u32 {
            r.motion(2, 100 + t, [t as f32 * 0.25, 1.0, 1.7], [4.0, 0.0, 0.0]);
        }
        r.motion(2, 140, [9.0, 9.0, 1.7], [0.0; 3]); // gap: new track
        let b = r.flush(false);
        assert_eq!(b.schema_version, SCHEMA_V2);
        assert_eq!(b.mode, pb::GameMode::Extraction as i32);
        assert_eq!(b.map, Some(pb::MapRef { map_id: "yard".into(), version: 3 }));
        assert!(b.map_geometry.is_some());
        assert_eq!((b.players[0].team, b.players[0].input_device, b.players[0].aim_assist), (1, pb::InputDevice::Controller as i32, true));
        assert_eq!(b.motion.len(), 2);
        let t = &b.motion[0];
        assert_eq!((t.slot, t.first_tick, t.stride, t.x_cm.len()), (2, 100, 4, 4));
        let s = decode_track(t);
        assert_eq!(s[0], [0, 100, 170, 400, 0, 0]);
        assert_eq!(s[3], [300, 100, 170, 400, 0, 0]);
        assert_eq!((b.motion[1].first_tick, decode_track(&b.motion[1])[0][0]), (140, 900));

        r.motion(2, 144, [9.5, 9.0, 1.7], [0.0; 3]);
        let b = r.flush(true);
        assert!(b.map_geometry.is_none(), "geometry goes with one batch only");
        assert_eq!(b.map.as_ref().unwrap().map_id, "yard");
        assert_eq!(decode_track(&b.motion[0])[0][0], 950, "each batch starts absolute");
    }

    #[test]
    fn v2_events_are_capped_and_counted() {
        let mut r = MatchRecorder::new("m", 64);
        for i in 0..(MAX_SOUNDS_PER_FLUSH + 5) {
            r.sound(i as u32, Some(1), pb::SoundKind::Footstep, [1.0, 2.0, 0.0], 18.0);
        }
        r.item(pb::ItemEvent { item_id: 0, ..Default::default() });
        for slot in 0..200u32 {
            for t in 0..400u32 {
                r.motion(slot, t * 4, [0.0; 3], [0.0; 3]);
            }
        }
        let b = r.flush(false);
        assert_eq!(b.sounds.len(), MAX_SOUNDS_PER_FLUSH);
        assert_eq!(b.sounds[0].radius_cm, 1800);
        let samples: usize = b.motion.iter().map(|t| t.x_cm.len()).sum();
        assert_eq!(samples, MAX_MOTION_SAMPLES_PER_FLUSH);
        assert_eq!(b.dropped_events as usize, 5 + 1 + (200 * 400 - MAX_MOTION_SAMPLES_PER_FLUSH));
        assert_eq!(r.flush(false).dropped_events, 0);
    }

    /// The client budget for the game server: a 10-player match at 64 ticks/s with motion at
    /// the default stride adds only a few bytes per player-tick on top of v1 aim tracks.
    #[test]
    fn motion_bytes_per_player_tick() {
        let mut r = MatchRecorder::new("m", 64);
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % 1000) as f32 / 1000.0
        };
        let mut pos = [[0.0f32; 3]; 10];
        for t in 0..64u32 {
            for (slot, p) in pos.iter_mut().enumerate() {
                let v = [5.0 * (rnd() - 0.5) * 2.0, 5.0 * (rnd() - 0.5) * 2.0, 0.0];
                p[0] += v[0] / 64.0;
                p[1] += v[1] / 64.0;
                r.motion(slot as u32, t, [30.0 + p[0], 20.0 + p[1], 1.7], v);
            }
        }
        let b = r.flush(false);
        let bytes: usize = b.motion.iter().map(|t| t.encoded_len()).sum();
        let per = bytes as f64 / (10.0 * 64.0);
        eprintln!("motion: {per:.2} bytes per player-tick");
        assert!(per < 4.0, "motion costs {per:.2} bytes per player-tick");
    }

    /// A minimal /v1/ingest: answers the first copy of each batch "busy", then accepts it;
    /// drops the connection once to force a resend.
    fn fake_gateway(listener: TcpListener, batches: usize) -> JoinHandle<Vec<u64>> {
        std::thread::spawn(move || {
            let mut seen = Vec::new();
            let mut busy_sent = std::collections::HashSet::new();
            let mut dropped_once = false;
            while seen.len() < batches {
                let (tcp, _) = listener.accept().unwrap();
                let mut ws = tungstenite::accept(tcp).unwrap();
                while let Ok(msg) = ws.read() {
                    let WsMessage::Binary(data) = msg else { continue };
                    let b = pb::GameplayBatch::decode(&data[..]).unwrap();
                    if b.batch_seq == 2 && !dropped_once {
                        dropped_once = true;
                        break; // connection lost before the ack
                    }
                    let mut ack = pb::IngestAck { match_id: b.match_id.clone(), batch_seq: b.batch_seq, accepted: true, ..Default::default() };
                    if busy_sent.insert(b.batch_seq) {
                        ack.accepted = false;
                        ack.error = "busy".into();
                    } else {
                        seen.push(b.batch_seq);
                    }
                    ws.send(WsMessage::Binary(ack.encode_to_vec().into())).unwrap();
                    if seen.len() == batches {
                        break;
                    }
                }
            }
            seen
        })
    }

    #[test]
    fn stream_delivers_in_order_through_busy_and_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = fake_gateway(listener, 3);
        let (stream, events) = GameplayStream::start(&format!("ws://{addr}/v1/ingest"), "k", &[]);
        let mut rec = MatchRecorder::new("m1", 64);
        for _ in 0..3 {
            stream.send(rec.flush(false)).unwrap();
        }
        drop(stream); // waits for all three acks
        assert_eq!(server.join().unwrap(), vec![1, 2, 3]);
        let acked: Vec<u64> = events
            .try_iter()
            .filter_map(|e| match e {
                IngestEvent::Acked { batch_seq, accepted: true, .. } => Some(batch_seq),
                _ => None,
            })
            .collect();
        assert_eq!(acked, vec![1, 2, 3]);
    }

    #[test]
    fn drop_does_not_hang_without_a_gateway() {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (stream, _events) = GameplayStream::start(&format!("ws://127.0.0.1:{port}/v1/ingest"), "k", &[]);
        stream.send(MatchRecorder::new("m", 64).flush(true)).unwrap();
        let t = Instant::now();
        drop(stream);
        assert!(t.elapsed() < Duration::from_secs(15));
    }
}
