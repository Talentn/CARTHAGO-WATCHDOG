//! Game-server control channel to the gateway (`/v1/gs`): watch verified sessions, receive
//! kicks (heartbeat timeout, protocol violation). Reconnects with backoff and re-watches.

use std::collections::HashSet;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::thread::JoinHandle;
use std::time::Duration;

use carthago_net::{Pin, Stream};
use prost::Message as _;
use carthago_proto::v1 as pb;
use tungstenite::client::IntoClientRequest;
use tungstenite::{Message as WsMessage, WebSocket};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GsEvent {
    Connected,
    Disconnected(String),
    WatchAck { session_id: String, known: bool },
    Kick { session_id: String, reason: String, player_hash: String },
}

enum Cmd {
    Watch(String),
    Unwatch(String),
}

pub struct KickListener {
    cmd: Option<Sender<Cmd>>,
    thread: Option<JoinHandle<()>>,
}

impl KickListener {
    /// `url` is e.g. `wss://gateway.example:8750/v1/gs` (or `ws://` on loopback);
    /// `server_key` is the tenant's server API key; `tls_pins` are the gateway's pinned TLS
    /// keys (SHA-256 of the SPKI), required for `wss://`.
    pub fn start(url: &str, server_key: &str, tls_pins: &[Pin]) -> (Self, Receiver<GsEvent>) {
        let (cmd_tx, cmd_rx) = channel();
        let (ev_tx, ev_rx) = channel();
        let (url, key, pins) = (url.to_owned(), server_key.to_owned(), tls_pins.to_vec());
        let thread = std::thread::Builder::new()
            .name("carthago-gs-kick".into())
            .spawn(move || run(&url, &key, &pins, cmd_rx, ev_tx))
            .expect("spawn kick listener");
        (Self { cmd: Some(cmd_tx), thread: Some(thread) }, ev_rx)
    }

    pub fn watch(&self, session_id: &str) {
        if let Some(c) = &self.cmd {
            let _ = c.send(Cmd::Watch(session_id.to_owned()));
        }
    }

    pub fn unwatch(&self, session_id: &str) {
        if let Some(c) = &self.cmd {
            let _ = c.send(Cmd::Unwatch(session_id.to_owned()));
        }
    }
}

impl Drop for KickListener {
    fn drop(&mut self) {
        self.cmd.take();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub(crate) fn connect(url: &str, key: &str, pins: &[Pin]) -> Result<WebSocket<Stream>, String> {
    let mut req = url.into_client_request().map_err(|e| e.to_string())?;
    req.headers_mut().insert("Authorization", format!("Bearer {key}").parse().map_err(|_| "bad server key")?);
    let ws = carthago_net::connect(req, pins, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    ws.get_ref().set_read_timeout(Some(Duration::from_millis(50))).ok();
    Ok(ws)
}

fn send(ws: &mut WebSocket<Stream>, body: pb::gs_client_msg::Body) -> tungstenite::Result<()> {
    ws.send(WsMessage::Binary(pb::GsClientMsg { body: Some(body) }.encode_to_vec().into()))
}

fn run(url: &str, key: &str, pins: &[Pin], cmd: Receiver<Cmd>, ev: Sender<GsEvent>) {
    let mut watched: HashSet<String> = HashSet::new();
    let mut backoff = Duration::from_millis(250);
    loop {
        let mut ws = match connect(url, key, pins) {
            Ok(ws) => ws,
            Err(e) => {
                let _ = ev.send(GsEvent::Disconnected(e));
                // Keep draining commands so watches made while offline are applied on reconnect.
                let deadline = std::time::Instant::now() + backoff;
                while std::time::Instant::now() < deadline {
                    match cmd.recv_timeout(Duration::from_millis(50)) {
                        Ok(Cmd::Watch(s)) => {
                            watched.insert(s);
                        }
                        Ok(Cmd::Unwatch(s)) => {
                            watched.remove(&s);
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(_) => return,
                    }
                }
                backoff = (backoff * 2).min(Duration::from_secs(10));
                continue;
            }
        };
        backoff = Duration::from_millis(250);
        let _ = ev.send(GsEvent::Connected);
        let mut ok = watched.iter().all(|s| send(&mut ws, pb::gs_client_msg::Body::Watch(pb::WatchSession { session_id: s.clone() })).is_ok());
        while ok {
            loop {
                match cmd.try_recv() {
                    Ok(Cmd::Watch(s)) => {
                        ok &= send(&mut ws, pb::gs_client_msg::Body::Watch(pb::WatchSession { session_id: s.clone() })).is_ok();
                        watched.insert(s);
                    }
                    Ok(Cmd::Unwatch(s)) => {
                        ok &= send(&mut ws, pb::gs_client_msg::Body::Unwatch(pb::UnwatchSession { session_id: s.clone() })).is_ok();
                        watched.remove(&s);
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        let _ = ws.close(None);
                        let _ = ws.flush();
                        return;
                    }
                }
            }
            match ws.read() {
                Ok(WsMessage::Binary(b)) => match pb::GsServerMsg::decode(&b[..]).ok().and_then(|m| m.body) {
                    Some(pb::gs_server_msg::Body::Kick(k)) => {
                        watched.remove(&k.session_id);
                        let _ = ev.send(GsEvent::Kick { session_id: k.session_id, reason: k.reason, player_hash: k.player_hash });
                    }
                    Some(pb::gs_server_msg::Body::WatchAck(a)) => {
                        let _ = ev.send(GsEvent::WatchAck { session_id: a.session_id, known: a.known });
                    }
                    None => {}
                },
                Ok(WsMessage::Close(_)) => ok = false,
                Ok(_) => {}
                Err(tungstenite::Error::Io(e)) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(_) => ok = false,
            }
        }
        let _ = ev.send(GsEvent::Disconnected("connection lost".into()));
    }
}
