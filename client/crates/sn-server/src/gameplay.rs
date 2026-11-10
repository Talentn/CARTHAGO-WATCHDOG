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
use std::net::TcpStream;
use std::sync::mpsc::{channel, sync_channel, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use prost::Message as _;
use sn_proto::v1 as pb;
use tungstenite::{Message as WsMessage, WebSocket};

use crate::kick::connect;

/// Builds `GameplayBatch`es from per-tick calls. Aim samples for consecutive ticks are packed
/// into one track per player; command counts are summed into one window per flush.
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
        }
    }

    /// Declares or updates a slot. `session_id` is the verified token's session ("" for bots),
    /// so the gateway can attach evidence to the session the client is running.
    pub fn player(&mut self, slot: u32, session_id: &str, player_hash: &str, mmr: i32) {
        let p = pb::MatchPlayer { slot, session_id: session_id.into(), player_hash: player_hash.into(), mmr };
        if self.players.get(&slot) != Some(&p) {
            self.players.insert(slot, p);
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestEvent {
    Connected,
    Disconnected(String),
    /// `accepted = false` means the gateway already had this batch (a resend after reconnect).
    Acked { match_id: String, batch_seq: u64, accepted: bool },
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
    /// `url` is e.g. `ws://127.0.0.1:8750/v1/ingest`; `server_key` is the tenant's server API key.
    pub fn start(url: &str, server_key: &str) -> (Self, Receiver<IngestEvent>) {
        let (tx, rx) = sync_channel(QUEUE);
        let (ev_tx, ev_rx) = channel();
        let (url, key) = (url.to_owned(), server_key.to_owned());
        let thread = std::thread::Builder::new()
            .name("carthago-gs-ingest".into())
            .spawn(move || run(&url, &key, rx, ev_tx))
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

fn deliver(ws: &mut WebSocket<TcpStream>, b: &pb::GameplayBatch, ev: &Sender<IngestEvent>) -> Outcome {
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
                        let _ = ev.send(IngestEvent::Acked { match_id: ack.match_id, batch_seq: ack.batch_seq, accepted: ack.accepted });
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

fn run(url: &str, key: &str, rx: Receiver<pb::GameplayBatch>, ev: Sender<IngestEvent>) {
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
        let mut ws = match connect(url, key) {
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
                    let mut ack = pb::IngestAck { match_id: b.match_id.clone(), batch_seq: b.batch_seq, accepted: true, error: String::new() };
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
        let (stream, events) = GameplayStream::start(&format!("ws://{addr}/v1/ingest"), "k");
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
        let (stream, _events) = GameplayStream::start(&format!("ws://127.0.0.1:{port}/v1/ingest"), "k");
        stream.send(MatchRecorder::new("m", 64).flush(true)).unwrap();
        let t = Instant::now();
        drop(stream);
        assert!(t.elapsed() < Duration::from_secs(15));
    }
}
