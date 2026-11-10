//! Game-server stub for the Phase 0 end-to-end demo.
//!
//!   gs-stub serve  --keys public-keys.json [--tenant demo] [--listen 127.0.0.1:8760]
//!                  [--gateway ws://127.0.0.1:8750/v1/gs] [--gateway-pin HEX[,HEX]]
//!                  [--server-key demo-server-key] [--min-trust 0]
//!       Players connect over TCP and send `TOKEN <token>\n`. The stub verifies it offline and
//!       answers `OK <session_id> trust=<n> flags=<hex>` or `REJECT <reason>`. Admitted sessions
//!       are watched on the gateway; a gateway kick is forwarded as `KICK <reason>` and the
//!       player is disconnected.
//!
//!   gs-stub verify --keys public-keys.json (--token T | --token-file F) [--tenant demo]
//!                  [--skew SECS] [--tamper] [--min-trust N]
//!       One-shot offline check. Exit 0 = accepted, 2 = rejected, 1 = usage/IO error.
//!
//!   gs-stub simulate [--ingest ws://127.0.0.1:8750/v1/ingest] [--gateway-pin HEX[,HEX]]
//!                    [--server-key demo-server-key]
//!                    [--match ID] [--players 8] [--seconds 120] [--tick-rate 64] [--realtime]
//!                    [--sessions FILE] [--anomaly SLOT=profile[+profile]]...
//!       Streams a synthetic match's gameplay telemetry for server-side analysis (see
//!       simulate.rs). Exit 0 = every batch acknowledged.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use carthago_crypto::time::now_unix;
use carthago_server::{GsEvent, KickListener, PublicKeys, Verifier};

mod simulate;

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

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(mode) = argv.first().cloned() else { usage() };
    let a = Args(argv);
    let code = match mode.as_str() {
        "serve" => serve(&a),
        "verify" => verify(&a),
        "simulate" => simulate::simulate(&a),
        _ => usage(),
    };
    std::process::exit(code);
}

fn usage() -> ! {
    eprintln!("usage: gs-stub serve --keys FILE [...] | gs-stub verify --keys FILE --token T [...] | gs-stub simulate [...] (see source header)");
    std::process::exit(1)
}

fn verifier(a: &Args) -> Result<Verifier, String> {
    let keys = PublicKeys::load(a.get("--keys").ok_or("--keys is required")?)?;
    let min_trust = a.get_or("--min-trust", "0").parse().map_err(|_| "--min-trust: not a number")?;
    Ok(Verifier::new(keys.token_keys, a.get_or("--tenant", "demo")).with_min_trust(min_trust))
}

/// Flips one base64url character in the signed payload, keeping it decodable.
fn tamper(token: &str) -> String {
    let pos = "v4.public.".len() + 20;
    let mut b = token.as_bytes().to_vec();
    b[pos] = if b[pos] == b'A' { b'B' } else { b'A' };
    String::from_utf8(b).unwrap()
}

fn verify(a: &Args) -> i32 {
    let v = match verifier(a) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("gs-stub: {e}");
            return 1;
        }
    };
    let token = match (a.get("--token"), a.get("--token-file")) {
        (Some(t), _) => t,
        (None, Some(f)) => match std::fs::read_to_string(&f) {
            Ok(t) => t.trim().to_owned(),
            Err(e) => {
                eprintln!("gs-stub: {f}: {e}");
                return 1;
            }
        },
        _ => usage(),
    };
    let token = if a.has("--tamper") { tamper(&token) } else { token };
    let skew: i64 = a.get_or("--skew", "0").parse().unwrap_or(0);
    let label = match (a.has("--tamper"), skew) {
        (true, _) => "tampered token".to_owned(),
        (false, 0) => "token".to_owned(),
        (false, s) => format!("token at now{s:+}s"),
    };
    match v.verify_at(&token, now_unix() + skew) {
        Ok(c) => {
            println!("ACCEPT {label}: session {} player {} trust_level {} attest_flags {:#x} exp {}", c.session_id, c.player_hash, c.trust_level, c.attest_flags, c.exp);
            0
        }
        Err(e) => {
            println!("REJECT {label}: {} ({e})", e.class());
            2
        }
    }
}

type Players = Arc<Mutex<HashMap<String, TcpStream>>>;

fn serve(a: &Args) -> i32 {
    let v = match verifier(a) {
        Ok(v) => Arc::new(v),
        Err(e) => {
            eprintln!("gs-stub: {e}");
            return 1;
        }
    };
    let listen = a.get_or("--listen", "127.0.0.1:8760");
    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("gs-stub: bind {listen}: {e}");
            return 1;
        }
    };
    let pins = match carthago_net::parse_pins(&a.get_or("--gateway-pin", "")) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("gs-stub: --gateway-pin: {e}");
            return 1;
        }
    };
    let (kick, events) = KickListener::start(&a.get_or("--gateway", "ws://127.0.0.1:8750/v1/gs"), &a.get_or("--server-key", "demo-server-key"), &pins);
    let kick = Arc::new(kick);
    let players: Players = Arc::default();
    println!("[gs] listening on {listen}");

    let p = players.clone();
    std::thread::spawn(move || {
        for e in events {
            match e {
                GsEvent::Kick { session_id, reason, player_hash } => {
                    println!("[gs] gateway KICK session {session_id} (player {player_hash}): {reason}");
                    if let Some(mut s) = p.lock().unwrap().remove(&session_id) {
                        let _ = writeln!(s, "KICK {reason}");
                        let _ = s.shutdown(Shutdown::Both);
                        println!("[gs] player for session {session_id} disconnected");
                    }
                }
                GsEvent::WatchAck { session_id, known } => println!("[gs] watching session {session_id} (gateway knows it: {known})"),
                GsEvent::Connected => println!("[gs] kick channel connected"),
                GsEvent::Disconnected(why) => println!("[gs] kick channel down: {why}"),
            }
        }
    });

    for conn in listener.incoming().flatten() {
        let (v, kick, players) = (v.clone(), kick.clone(), players.clone());
        std::thread::spawn(move || handle_player(conn, &v, &kick, &players));
    }
    0
}

fn handle_player(conn: TcpStream, v: &Verifier, kick: &KickListener, players: &Players) {
    let peer = conn.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let Ok(mut out) = conn.try_clone() else { return };
    let mut lines = BufReader::new(conn).lines();
    let Some(Ok(line)) = lines.next() else { return };
    let Some(token) = line.strip_prefix("TOKEN ") else {
        let _ = writeln!(out, "REJECT malformed");
        return;
    };
    let claims = match v.verify(token) {
        Ok(c) => c,
        Err(e) => {
            println!("[gs] {peer}: REJECT {} ({e})", e.class());
            let _ = writeln!(out, "REJECT {}", e.class());
            return;
        }
    };
    println!(
        "[gs] {peer}: ADMIT player {} session {} trust_level {} attest_flags {:#x} (verified offline)",
        claims.player_hash, claims.session_id, claims.trust_level, claims.attest_flags
    );
    let _ = writeln!(out, "OK {} trust={} flags={:#x}", claims.session_id, claims.trust_level, claims.attest_flags);
    if let Ok(s) = out.try_clone() {
        players.lock().unwrap().insert(claims.session_id.clone(), s);
    }
    kick.watch(&claims.session_id);
    // Drain until the player leaves; a real server would run gameplay here.
    for _ in lines.map_while(Result::ok) {}
    if players.lock().unwrap().remove(&claims.session_id).is_some() {
        kick.unwatch(&claims.session_id);
        println!("[gs] {peer}: player left (session {})", claims.session_id);
    }
}
