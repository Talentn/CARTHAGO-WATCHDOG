//! `carthago-cs16-bridge`: receives the Counter-Strike 1.6 server plugin's stream on
//! loopback UDP and delivers it to the gateway as gameplay telemetry.
//!
//!   carthago-cs16-bridge run --keys public-keys.json [--listen 127.0.0.1:27991]
//!         [--ingest wss://127.0.0.1:8750/v1/ingest] [--server-key demo-server-key]
//!         [--tenant demo] [--session-file FILE] [--record FILE] [--stop-file FILE]
//!         [--log FILE] [--idle-secs 20] [--maps DIR]...
//!       Runs until the stop file appears. --session-file is the companion's session; its
//!       token is verified against the gateway's keys before the local player's slot is
//!       bound to it. --record keeps the raw stream for a later replay. Each --maps is a
//!       folder the game loads maps from (cstrike\maps); the map being played is read from
//!       the first that has it and its walls are sent to the gateway, which is what turns
//!       information-leak scoring on. Without --maps that scoring stays off.
//!
//!   carthago-cs16-bridge replay FILE --keys public-keys.json [--ingest ...] [--session-file FILE]
//!         [--maps DIR]...
//!       Feeds a recorded or synthetic stream straight to the gateway.
//!
//!   carthago-cs16-bridge convert FILE --out BATCHES [--maps DIR]...
//!       Turns a stream file into the batches the gateway would receive, without a gateway:
//!       each as a little-endian u32 length and the encoded GameplayBatch. For calibration.
//!
//!   carthago-cs16-bridge map-hash FILE.bsp [--id NAME] [--out GEOMETRY.pb]
//!       Reads a map file and prints the hash the gateway identifies its geometry by, in the
//!       form of a line for the gateway's -map-pins file. --out also writes the geometry.
//!
//!   carthago-cs16-bridge map-pins --maps DIR [--maps DIR]...
//!       The same line for every map file in the folders, the way `run` would pick them
//!       (the first folder that has a map wins). Files that are not usable maps are listed
//!       as comments.
//!
//!   carthago-cs16-bridge send FILE [--to 127.0.0.1:27991] [--speed 8]
//!       Plays a stream file over UDP the way the plugin would (for testing `run`).
//!
//!   carthago-cs16-bridge synth --out FILE [--seconds 120] [--rate 32] [--match ID] [--local-is-machine]
//!       Writes a synthetic match: one local human against bots, one of them machine-like.
//!       With --local-is-machine the local player is the machine-like one.
//!
//! Exit code 0 = every batch was acknowledged by the gateway.

use std::io::Write;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use carthago_cs16_bridge::{bsp, synth, Binding, Bridge};
use carthago_cs16_companion::{parse_keys, SessionFile};
use carthago_server::{pb, GameplayStream, IngestEvent, PublicKeys, Verifier};

struct Args(Vec<String>);

impl Args {
    fn get(&self, name: &str) -> Option<String> {
        self.0.iter().position(|a| a == name).and_then(|i| self.0.get(i + 1)).cloned()
    }
    fn get_or(&self, name: &str, default: &str) -> String {
        self.get(name).unwrap_or_else(|| default.to_owned())
    }
    fn all(&self, name: &str) -> Vec<String> {
        self.0.windows(2).filter(|w| w[0] == name).map(|w| w[1].clone()).collect()
    }
    fn has(&self, name: &str) -> bool {
        self.0.iter().any(|a| a == name)
    }
}

struct Log {
    file: Option<std::fs::File>,
    t0: Instant,
}

impl Log {
    fn line(&mut self, msg: &str) {
        let line = format!("[{:9.3}] {msg}", self.t0.elapsed().as_secs_f64());
        println!("{line}");
        if let Some(f) = self.file.as_mut() {
            let _ = writeln!(f, "{line}");
            let _ = f.flush();
        }
    }
}

/// Delivery to the gateway plus the tally of what it answered.
struct Sink {
    stream: Option<GameplayStream>,
    events: Receiver<IngestEvent>,
    sent: u64,
    acked: u64,
    duplicates: u64,
    rejected: u64,
    warnings: u64,
}

impl Sink {
    fn open(a: &Args) -> Result<Self, String> {
        let keys = a.get("--keys").ok_or("--keys is required")?;
        let url = a.get_or("--ingest", "wss://127.0.0.1:8750/v1/ingest");
        let pins = parse_keys(&std::fs::read_to_string(&keys).map_err(|e| format!("{keys}: {e}"))?)?.tls_pins;
        if url.starts_with("wss://") && pins.is_empty() {
            return Err("the gateway published no TLS key pins; refusing an unpinned wss:// connection".into());
        }
        let (stream, events) = GameplayStream::start(&url, &a.get_or("--server-key", "demo-server-key"), &pins);
        Ok(Self { stream: Some(stream), events, sent: 0, acked: 0, duplicates: 0, rejected: 0, warnings: 0 })
    }

    fn drain(&mut self, log: &mut Log) {
        while let Ok(ev) = self.events.try_recv() {
            match ev {
                IngestEvent::Connected => log.line("gateway: connected"),
                IngestEvent::Disconnected(why) => log.line(&format!("gateway: disconnected ({why}); batches wait and are resent")),
                IngestEvent::Acked { match_id, batch_seq, accepted, warning } => {
                    self.acked += 1;
                    self.duplicates += !accepted as u64;
                    if !warning.is_empty() {
                        self.warnings += 1;
                        log.line(&format!("gateway: warning on {match_id} batch {batch_seq}: {warning}"));
                    }
                }
                IngestEvent::Rejected { match_id, batch_seq, error } => {
                    self.rejected += 1;
                    log.line(&format!("gateway: REJECTED {match_id} batch {batch_seq}: {error}"));
                }
            }
        }
    }

    fn send(&mut self, batches: Vec<pb::GameplayBatch>, log: &mut Log) {
        for mut b in batches {
            if b.match_over {
                log.line(&format!("match {} ended after {} batches", b.match_id, b.batch_seq));
            }
            self.sent += 1;
            // The queue holds 256 batches (over eight minutes); wait rather than lose one.
            loop {
                match self.stream.as_ref().expect("open until close").send(b) {
                    Ok(()) => break,
                    Err(back) => {
                        b = *back;
                        self.drain(log);
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        }
        self.drain(log);
    }

    /// Waits for the queued batches to be acknowledged; true when all were.
    fn close(mut self, log: &mut Log) -> bool {
        drop(self.stream.take());
        self.drain(log);
        log.line(&format!(
            "RESULT batches sent={} acknowledged={} rejected={} resent={} warnings={}",
            self.sent,
            self.acked,
            self.rejected,
            self.duplicates,
            self.warnings
        ));
        self.acked == self.sent && self.rejected == 0
    }
}

/// Reads the companion's session file and binds its session once the token verifies.
struct SessionWatch {
    path: Option<PathBuf>,
    verifier: Option<Verifier>,
    last: String,
    bound: Option<Binding>,
}

impl SessionWatch {
    fn new(a: &Args) -> Self {
        let path = a.get("--session-file").map(PathBuf::from);
        let verifier = a.get("--keys").and_then(|k| PublicKeys::load(k).ok()).map(|k| Verifier::new(k.token_keys, a.get_or("--tenant", "demo")));
        Self { path, verifier, last: String::new(), bound: None }
    }

    fn poll(&mut self, bridge: &mut Bridge, log: &mut Log) {
        let (Some(path), Some(verifier)) = (&self.path, &self.verifier) else { return };
        let Ok(text) = std::fs::read_to_string(path) else { return };
        if text == self.last {
            return;
        }
        self.last = text;
        let Ok(s) = SessionFile::parse(&self.last) else { return };
        if s.token.is_empty() {
            return;
        }
        match verifier.verify(&s.token) {
            Ok(c) => {
                let b = Binding { session_id: c.session_id, player_hash: c.player_hash };
                if self.bound.as_ref() != Some(&b) {
                    log.line(&format!("SESSION ready: the companion's token verified (session {}, player {}, trust level {}); waiting for its player in a match", b.session_id, b.player_hash, c.trust_level));
                    self.bound = Some(b.clone());
                    bridge.bind(Some(b));
                }
            }
            // An expired token for the session already bound changes nothing: the binding
            // was verified when it was made.
            Err(e) if self.bound.as_ref().is_some_and(|b| b.session_id == s.session_id) => {
                let _ = e;
            }
            Err(e) => log.line(&format!("SESSION not bound: the companion's token did not verify ({})", e.class())),
        }
    }
}

/// Says so, once per slot, when a player slot is actually tied to the companion's session.
fn report_bound(bridge: &Bridge, seen: &mut Vec<(u32, String)>, log: &mut Log) {
    let now = bridge.bound_slots();
    for (slot, name) in now.iter().filter(|b| !seen.contains(b)) {
        log.line(&format!("SLOT bound: slot {slot} ({name}) is tied to the companion's session"));
    }
    *seen = now;
}

fn status(bridge: &Bridge, sink: &Sink, log: &mut Log) {
    let st = bridge.stats;
    let roster = bridge.roster();
    let (bots, humans) = (roster.iter().filter(|r| r.2).count(), roster.iter().filter(|r| !r.2).count());
    log.line(&format!(
        "STATUS match={} map={} {}/s humans={humans} bots={bots} datagrams={} lost={} samples={} shots={} hits={} bad_lines={} batches sent={} acked={}",
        if bridge.match_id().is_empty() { "-" } else { bridge.match_id() },
        if bridge.map().is_empty() { "-" } else { bridge.map() },
        bridge.tick_rate(),
        st.datagrams,
        st.lost,
        st.samples,
        st.shots,
        st.hits,
        st.bad_lines,
        sink.sent,
        sink.acked
    ));
}

fn new_bridge(a: &Args, log: &mut Log) -> Bridge {
    let mut bridge = Bridge::new();
    let dirs: Vec<PathBuf> = a.all("--maps").into_iter().map(PathBuf::from).collect();
    if dirs.is_empty() {
        log.line("MAP folders not given (--maps): no map geometry is sent and information-leak scoring stays off");
    } else {
        log.line(&format!("MAP folders: {}", dirs.iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(", ")));
    }
    bridge.set_map_dirs(dirs);
    bridge
}

fn notes(bridge: &mut Bridge, log: &mut Log) {
    for n in bridge.take_notes() {
        log.line(&n);
    }
}

fn map_hash(a: &Args, file: &str) -> Result<bool, String> {
    let bytes = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    let world = bsp::World::parse(&bytes).map_err(|e| format!("{file}: {e}"))?;
    let stem = Path::new(file).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let id = bsp::safe_name(&a.get_or("--id", &stem)).ok_or("the map name must be letters, digits, '_' or '-'; give one with --id")?;
    let g = world.geometry(&id);
    println!("# {file}: {} splits, {} planes, file sha256 {}, version {}", world.nodes.len(), world.planes.len(), hex::encode(world.sha256), g.version);
    println!("{id} {}", bsp::geometry_hash(&g));
    if let Some(out) = a.get("--out") {
        use prost::Message;
        std::fs::write(&out, g.encode_to_vec()).map_err(|e| format!("{out}: {e}"))?;
    }
    Ok(true)
}

fn map_pins(a: &Args) -> Result<bool, String> {
    let dirs: Vec<PathBuf> = a.all("--maps").into_iter().map(PathBuf::from).collect();
    if dirs.is_empty() {
        return Err("--maps is required".into());
    }
    let mut names = std::collections::BTreeSet::new();
    for dir in &dirs {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for e in entries.flatten() {
            let file = e.file_name().to_string_lossy().to_ascii_lowercase();
            if let Some(name) = file.strip_suffix(".bsp").and_then(bsp::safe_name) {
                names.insert(name);
            }
        }
    }
    for name in &names {
        match bsp::find(&dirs, name).and_then(|(_, bytes)| bsp::World::parse(&bytes)) {
            Ok(world) => println!("{name} {}", bsp::geometry_hash(&world.geometry(name))),
            Err(e) => println!("# {name}: not usable: {e}"),
        }
    }
    Ok(true)
}

fn convert(a: &Args, file: &str) -> Result<bool, String> {
    use prost::Message;
    let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    let out = a.get("--out").ok_or("--out is required")?;
    let mut bridge = Bridge::new();
    bridge.set_map_dirs(a.all("--maps").into_iter().map(PathBuf::from).collect());
    let mut batches = bridge.feed(&text);
    batches.extend(bridge.finish());
    let mut bytes = Vec::new();
    for b in &batches {
        let enc = b.encode_to_vec();
        bytes.extend_from_slice(&(enc.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&enc);
    }
    std::fs::write(&out, bytes).map_err(|e| format!("{out}: {e}"))?;
    for n in bridge.take_notes() {
        println!("{n}");
    }
    let st = bridge.stats;
    println!("{} batches, {} samples, {} shots, {} callouts, {} bad lines", batches.len(), st.samples, st.shots, st.callouts, st.bad_lines);
    Ok(st.bad_lines == 0)
}

fn open_log(a: &Args) -> Log {
    Log { file: a.get("--log").and_then(|p| std::fs::File::create(p).ok()), t0: Instant::now() }
}

fn run(a: &Args) -> Result<bool, String> {
    let mut log = open_log(a);
    let listen = a.get_or("--listen", "127.0.0.1:27991");
    let sock = UdpSocket::bind(&listen).map_err(|e| format!("listen on {listen}: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_millis(250))).map_err(|e| e.to_string())?;
    let mut sink = Sink::open(a)?;
    let mut watch = SessionWatch::new(a);
    let mut record = match a.get("--record") {
        Some(p) => Some(std::fs::File::create(&p).map_err(|e| format!("{p}: {e}"))?),
        None => None,
    };
    let stop = a.get("--stop-file").map(PathBuf::from);
    let idle = Duration::from_secs(a.get_or("--idle-secs", "20").parse().map_err(|_| "--idle-secs: not a number")?);
    let mut bridge = new_bridge(a, &mut log);
    log.line(&format!("listening for the game server plugin on {listen} (loopback only)"));

    let mut buf = vec![0u8; 4096];
    let (mut last_data, mut last_status, mut last_poll) = (Instant::now(), Instant::now(), Instant::now() - Duration::from_secs(5));
    let mut live = false;
    let mut bound = Vec::new();
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if from.ip().is_loopback() => {
                let text = String::from_utf8_lossy(&buf[..n]);
                if let Some(f) = record.as_mut() {
                    let _ = write!(f, "@ {}\n{text}", log.t0.elapsed().as_millis());
                }
                if !live {
                    live = true;
                    log.line("PLUGIN stream started");
                }
                last_data = Instant::now();
                let batches = bridge.feed(&text);
                notes(&mut bridge, &mut log);
                sink.send(batches, &mut log);
                report_bound(&bridge, &mut bound, &mut log);
            }
            Ok(_) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            // Windows reports a previous send's ICMP error on a UDP socket this way.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(e) => return Err(format!("receive: {e}")),
        }
        if last_poll.elapsed() >= Duration::from_secs(1) {
            last_poll = Instant::now();
            watch.poll(&mut bridge, &mut log);
            report_bound(&bridge, &mut bound, &mut log);
            sink.drain(&mut log);
            if live && last_data.elapsed() >= idle {
                live = false;
                log.line(&format!("PLUGIN stream silent for {} s; closing the match", idle.as_secs()));
                let batches = bridge.finish();
                notes(&mut bridge, &mut log);
                sink.send(batches, &mut log);
            }
            if stop.as_ref().is_some_and(|p| p.exists()) {
                break;
            }
        }
        if last_status.elapsed() >= Duration::from_secs(10) {
            last_status = Instant::now();
            status(&bridge, &sink, &mut log);
        }
    }
    let batches = bridge.finish();
    notes(&mut bridge, &mut log);
    sink.send(batches, &mut log);
    status(&bridge, &sink, &mut log);
    if bridge.stats.datagrams == 0 {
        log.line("NO DATA: the plugin never sent anything. Was a map started (New Game), and is the plugin loaded (type 'amxx plugins' in the game console)?");
    }
    Ok(sink.close(&mut log))
}

fn replay(a: &Args, file: &str) -> Result<bool, String> {
    let mut log = open_log(a);
    let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    let mut sink = Sink::open(a)?;
    let mut watch = SessionWatch::new(a);
    let mut bridge = new_bridge(a, &mut log);
    watch.poll(&mut bridge, &mut log);
    let mut bound = Vec::new();
    for chunk in datagrams(&text) {
        let batches = bridge.feed(chunk);
        notes(&mut bridge, &mut log);
        sink.send(batches, &mut log);
        report_bound(&bridge, &mut bound, &mut log);
    }
    let batches = bridge.finish();
    notes(&mut bridge, &mut log);
    sink.send(batches, &mut log);
    status(&bridge, &sink, &mut log);
    Ok(sink.close(&mut log) && bridge.stats.bad_lines == 0)
}

/// Splits a stream file into the datagrams it was recorded from (each starts with "D ").
fn datagrams(text: &str) -> Vec<&str> {
    let mut starts: Vec<usize> = text.match_indices("\nD ").map(|(i, _)| i + 1).collect();
    if text.starts_with("D ") {
        starts.insert(0, 0);
    }
    starts.iter().enumerate().map(|(i, &s)| &text[s..starts.get(i + 1).copied().unwrap_or(text.len())]).collect()
}

fn send(a: &Args, file: &str) -> Result<bool, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    let to = a.get_or("--to", "127.0.0.1:27991");
    let speed: f64 = a.get_or("--speed", "8").parse().map_err(|_| "--speed: not a number")?;
    let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    sock.connect(&to).map_err(|e| format!("{to}: {e}"))?;
    let rate = text.lines().find(|l| l.starts_with("H ")).and_then(|l| l.split(' ').nth(3)).and_then(|r| r.parse::<f64>().ok()).unwrap_or(32.0);
    let (t0, mut first_tick, mut n) = (Instant::now(), None, 0u64);
    for d in datagrams(&text) {
        let body: String = d.lines().filter(|l| !l.starts_with('@')).map(|l| format!("{l}\n")).collect();
        let tick = d.lines().next().and_then(|l| l.split(' ').nth(2)).and_then(|t| t.parse::<f64>().ok()).unwrap_or(0.0);
        let base = *first_tick.get_or_insert(tick);
        let due = Duration::from_secs_f64(((tick - base) / rate / speed).max(0.0));
        if let Some(wait) = due.checked_sub(t0.elapsed()) {
            std::thread::sleep(wait);
        }
        let _ = sock.send(body.as_bytes());
        n += 1;
    }
    println!("sent {n} datagrams to {to} in {:.1} s", t0.elapsed().as_secs_f64());
    Ok(true)
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let a = Args(argv.clone());
    let file = argv.get(1).filter(|f| !f.starts_with("--")).cloned();
    let result = match (argv.first().map(String::as_str), file) {
        (Some("run"), _) => run(&a),
        (Some("replay"), Some(f)) => replay(&a, &f),
        (Some("send"), Some(f)) => send(&a, &f),
        (Some("map-hash"), Some(f)) => map_hash(&a, &f),
        (Some("convert"), Some(f)) => convert(&a, &f),
        (Some("map-pins"), _) => map_pins(&a),
        (Some("synth"), _) => (|| {
            let out = a.get("--out").ok_or("--out is required")?;
            let seconds = a.get_or("--seconds", "120").parse().map_err(|_| "--seconds: not a number")?;
            let rate = a.get_or("--rate", "32").parse().map_err(|_| "--rate: not a number")?;
            let text = synth(seconds, rate, &a.get_or("--match", "cs16-synth"), a.has("--local-is-machine"));
            std::fs::write(Path::new(&out), &text).map_err(|e| format!("{out}: {e}"))?;
            println!("wrote {out}: {} lines", text.lines().count());
            Ok(true)
        })(),
        _ => Err("usage: carthago-cs16-bridge run|replay FILE|send FILE|synth --out FILE|convert FILE --out FILE|map-hash FILE.bsp|map-pins --maps DIR [...] (see the source header)".into()),
    };
    match result {
        Ok(true) => {}
        Ok(false) => std::process::exit(2),
        Err(e) => {
            eprintln!("carthago-cs16-bridge: {e}");
            std::process::exit(1);
        }
    }
}
