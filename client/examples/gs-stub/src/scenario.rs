//! `gs-stub simulate --scenario FILE`: replays a match written by `carthago-sim -scenario-out`
//! through the game-server SDK's telemetry v2 API, the way a real game server would record it:
//! map geometry once, player profiles, per-tick positions and view angles, sounds with their
//! audible radius, team pings and spots, loot, visibility changes and shots, and decoys
//! (created, replicated to their recipient, unreplicated, ended, with every position).
//!
//! The file is synthetic simulator output (format in backend/internal/knowledge/synth/emit.go).
//! Its `role` column is printed for the operator and never sent.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::time::{Duration, Instant};

use carthago_server::{pb, GameplayStream, IngestEvent, MatchRecorder};

use crate::simulate::{load_sessions, Session};
use crate::Args;

fn mode(word: &str) -> Result<pb::GameMode, String> {
    match word {
        "shooter" => Ok(pb::GameMode::CompetitiveShooter),
        "extraction" => Ok(pb::GameMode::Extraction),
        "unspecified" => Ok(pb::GameMode::Unspecified),
        _ => Err(format!("unknown mode {word:?}")),
    }
}

fn device(word: &str) -> Result<pb::InputDevice, String> {
    match word {
        "mouse" => Ok(pb::InputDevice::MouseKeyboard),
        "controller" => Ok(pb::InputDevice::Controller),
        "touch" => Ok(pb::InputDevice::Touch),
        "unspecified" => Ok(pb::InputDevice::Unspecified),
        _ => Err(format!("unknown input device {word:?}")),
    }
}

fn sound(word: &str) -> Result<pb::SoundKind, String> {
    match word {
        "footstep" => Ok(pb::SoundKind::Footstep),
        "gunshot" => Ok(pb::SoundKind::Gunshot),
        "reload" => Ok(pb::SoundKind::Reload),
        "ability" => Ok(pb::SoundKind::Ability),
        "interact" => Ok(pb::SoundKind::Interact),
        _ => Err(format!("unknown sound {word:?}")),
    }
}

fn team_kind(word: &str) -> Result<pb::TeamInfoKind, String> {
    match word {
        "ping" => Ok(pb::TeamInfoKind::Ping),
        "spotted" => Ok(pb::TeamInfoKind::Spotted),
        "radar" => Ok(pb::TeamInfoKind::Radar),
        _ => Err(format!("unknown team info {word:?}")),
    }
}

/// The integer fields of a record, after its keyword.
fn nums<T: std::str::FromStr>(f: &[&str]) -> Result<Vec<T>, String> {
    f.iter().map(|s| s.parse().map_err(|_| format!("bad number {s:?}"))).collect()
}

fn m(cm: i32) -> f32 {
    cm as f32 / 100.0
}

struct Header {
    match_id: String,
    mode: pb::GameMode,
    tick_rate: u32,
    ticks: u32,
    geometry: pb::MapGeometry,
    players: Vec<(u32, u32, pb::InputDevice, bool, String)>,
}

pub fn run(a: &Args, path: &str) -> Result<i32, String> {
    let url = a.get_or("--ingest", "ws://127.0.0.1:8750/v1/ingest");
    let key = a.get_or("--server-key", "demo-server-key");
    let realtime = a.has("--realtime");
    let map_ref_only = a.has("--map-ref-only");
    let sessions: HashMap<u32, Session> = match a.get("--sessions") {
        Some(p) => load_sessions(&p)?,
        None => HashMap::new(),
    };
    let file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut lines = BufReader::new(file).lines().enumerate().peekable();
    let mut next = || -> Option<Result<(usize, String), String>> { lines.next().map(|(n, l)| l.map(|l| (n + 1, l)).map_err(|e| e.to_string())) };

    let mut h = Header { match_id: String::new(), mode: pb::GameMode::Unspecified, tick_rate: 64, ticks: 0, geometry: pb::MapGeometry::default(), players: Vec::new() };
    let mut pending: Option<(usize, String)> = None;
    match next() {
        Some(Ok((_, l))) if l.trim() == "carthago-scenario 1" => {}
        _ => return Err(format!("{path}: not a carthago-scenario 1 file")),
    }
    while let Some(r) = next() {
        let (n, line) = r?;
        let f: Vec<&str> = line.split_whitespace().collect();
        let bad = |e: String| format!("{path}:{n}: {e}");
        match f.first().copied() {
            Some("match") if f.len() == 5 => {
                h.match_id = a.get_or("--match", f[1]);
                h.mode = mode(f[2]).map_err(bad)?;
                h.tick_rate = f[3].parse().map_err(|_| bad("tick rate".into()))?;
                h.ticks = f[4].parse().map_err(|_| bad("ticks".into()))?;
            }
            Some("map") if f.len() == 4 => {
                h.geometry.map_id = f[1].into();
                h.geometry.version = f[2].parse().map_err(|_| bad("map version".into()))?;
                h.geometry.mode = mode(f[3]).map_err(bad)? as i32;
            }
            Some("occluder") if f.len() >= 9 => {
                let v: Vec<i32> = nums(&f[1..]).map_err(bad)?;
                h.geometry.occluders.push(pb::Occluder { z_min_cm: v[0], z_max_cm: v[1], xy_cm: v[2..].to_vec() });
            }
            Some("zone") if f.len() >= 8 => {
                h.geometry.zones.push(pb::Zone { name: f[1].replace('_', " "), xy_cm: nums(&f[2..]).map_err(bad)? });
            }
            Some("loot") if f.len() == 5 => {
                let v: Vec<i32> = nums(&f[1..]).map_err(bad)?;
                h.geometry.loot_spawns.push(pb::LootSpawn { spawn_id: v[0] as u32, x_cm: v[1], y_cm: v[2], z_cm: v[3] });
            }
            Some("player") if f.len() == 6 => {
                let slot = f[1].parse().map_err(|_| bad("slot".into()))?;
                let team = f[2].parse().map_err(|_| bad("team".into()))?;
                h.players.push((slot, team, device(f[3]).map_err(bad)?, f[4] == "1", f[5].into()));
            }
            Some("t") => {
                pending = Some((n, line));
                break;
            }
            _ => return Err(bad(format!("unexpected header line {line:?}"))),
        }
    }
    if h.match_id.is_empty() || h.geometry.map_id.is_empty() || h.players.is_empty() {
        return Err(format!("{path}: header lacks match, map or players"));
    }

    let mut rec = MatchRecorder::new(h.match_id.clone(), h.tick_rate);
    rec.set_mode(h.mode);
    if map_ref_only {
        rec.set_map_ref(&h.geometry.map_id, h.geometry.version);
    } else {
        rec.set_map(h.geometry.clone());
    }
    for (slot, team, dev, assist, role) in &h.players {
        let sess = sessions.get(slot);
        let hash = sess.map_or_else(|| format!("bot-{slot}"), |s| s.player.clone());
        rec.player(*slot, sess.map_or("", |s| &s.id), &hash, sess.map_or(1500, |s| s.mmr));
        rec.player_profile(*slot, *team, *dev, *assist);
        println!("[gs] slot {slot}: team {team}, {dev:?}{}, simulated role {role}", if *assist { " with aim assist" } else { "" });
    }

    let pins = carthago_net::parse_pins(&a.get_or("--gateway-pin", "")).map_err(|e| format!("--gateway-pin: {e}"))?;
    let (stream, events) = GameplayStream::start(&url, &key, &pins);
    println!(
        "[gs] replaying {} ({:?}, map {} v{}): {} players, {}s at {} Hz -> {url}",
        h.match_id,
        h.mode,
        h.geometry.map_id,
        h.geometry.version,
        h.players.len(),
        h.ticks / h.tick_rate.max(1),
        h.tick_rate
    );

    let start = Instant::now();
    let (mut sent, mut tick) = (0u64, 0u32);
    let mut send = |rec: &mut MatchRecorder, over: bool, tick: u32| {
        let mut b = rec.flush(over);
        // A replay must not lose batches: wait for queue space instead of dropping.
        loop {
            match stream.send(b) {
                Ok(()) => break,
                Err(back) => {
                    b = *back;
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
        sent += 1;
        if realtime {
            let due = Duration::from_secs_f64(f64::from(tick) / f64::from(h.tick_rate));
            if let Some(wait) = due.checked_sub(start.elapsed()) {
                std::thread::sleep(wait);
            }
        }
    };
    let handle = |rec: &mut MatchRecorder, n: usize, line: &str, tick: u32| -> Result<(), String> {
        let f: Vec<&str> = line.split_whitespace().collect();
        let bad = |e: String| format!("{path}:{n}: {e}");
        match f.first().copied() {
            Some("p") if f.len() == 10 => {
                let v: Vec<i32> = nums(&f[1..]).map_err(bad)?;
                let slot = v[0] as u32;
                rec.motion(slot, tick, [m(v[1]), m(v[2]), m(v[3])], [m(v[4]), m(v[5]), m(v[6])]);
                rec.aim(slot, tick, v[7] as f32 / 100.0, v[8] as f32 / 100.0);
                rec.command(slot);
            }
            Some("s") if f.len() == 7 => {
                let src: i32 = f[1].parse().map_err(|_| bad("source".into()))?;
                let v: Vec<i32> = nums(&f[3..]).map_err(bad)?;
                rec.sound(tick, u32::try_from(src).ok(), sound(f[2]).map_err(bad)?, [m(v[0]), m(v[1]), m(v[2])], m(v[3]));
            }
            Some("i") if f.len() == 10 => {
                let team: u32 = f[1].parse().map_err(|_| bad("team".into()))?;
                let v: Vec<i32> = nums(&f[3..]).map_err(bad)?;
                rec.team_info(pb::TeamInfo {
                    tick,
                    team,
                    kind: team_kind(f[2]).map_err(bad)? as i32,
                    source_slot: v[0],
                    target_slot: v[1],
                    item_id: v[2] as u32,
                    x_cm: v[3],
                    y_cm: v[4],
                    z_cm: v[5],
                    duration_ms: v[6] as u32,
                });
            }
            Some("o") if f.len() == 7 => {
                let v: Vec<i32> = nums(&f[1..]).map_err(bad)?;
                rec.item(pb::ItemEvent { item_id: v[0] as u32, tick, x_cm: v[1], y_cm: v[2], z_cm: v[3], tier: v[4] as u32, removed: v[5] == 1 });
            }
            Some("v") if f.len() == 4 => {
                let v: Vec<u32> = nums(&f[1..]).map_err(bad)?;
                rec.visibility(v[0], v[1], tick, v[2] == 1);
            }
            Some("f") if f.len() == 6 => {
                let v: Vec<i32> = nums(&f[1..]).map_err(bad)?;
                rec.shot(pb::ShotEvent {
                    slot: v[0] as u32,
                    tick,
                    target_slot: v[1],
                    hit: v[2] == 1,
                    headshot: v[3] == 1,
                    kill: false,
                    weapon: "rifle".into(),
                    distance_m: m(v[4]),
                });
            }
            Some("dc") if f.len() == 5 => {
                let v: Vec<i32> = nums(&f[1..4]).map_err(bad)?;
                let recipients: Vec<u32> = f[4].split(',').map(|r| r.parse().map_err(|_| bad(format!("bad recipient {r:?}")))).collect::<Result<_, _>>()?;
                rec.decoy_create(v[0] as u32, v[1] as u32, &recipients, u32::try_from(v[2]).ok());
            }
            Some("dr") if f.len() == 2 => rec.decoy_replicated(f[1].parse().map_err(|_| bad("decoy id".into()))?, tick),
            Some("du") if f.len() == 2 => rec.decoy_unreplicated(f[1].parse().map_err(|_| bad("decoy id".into()))?, tick),
            Some("de") if f.len() == 2 => rec.decoy_end(f[1].parse().map_err(|_| bad("decoy id".into()))?),
            Some("dp") if f.len() == 8 => {
                let v: Vec<i32> = nums(&f[1..]).map_err(bad)?;
                rec.decoy_motion(v[0] as u32, tick, [m(v[1]), m(v[2]), m(v[3])], [m(v[4]), m(v[5]), m(v[6])]);
            }
            _ => return Err(bad(format!("unexpected record {line:?}"))),
        }
        Ok(())
    };

    let mut cur = pending;
    while let Some((n, line)) = cur.take().map(Ok).or_else(&mut next).transpose()? {
        if let Some(t) = line.strip_prefix("t ") {
            if tick > 0 && tick.is_multiple_of(h.tick_rate) {
                send(&mut rec, false, tick);
            }
            tick = t.trim().parse().map_err(|_| format!("{path}:{n}: bad tick"))?;
            rec.set_tick(tick);
            continue;
        }
        handle(&mut rec, n, &line, tick)?;
    }
    send(&mut rec, true, tick);
    drop(stream);

    let (mut accepted, mut dup, mut rejected, mut warned) = (0u64, 0, 0, 0);
    for e in events.try_iter() {
        match e {
            IngestEvent::Acked { accepted: ok, warning, batch_seq, .. } => {
                if ok {
                    accepted += 1;
                } else {
                    dup += 1;
                }
                if !warning.is_empty() {
                    warned += 1;
                    eprintln!("[gs] batch {batch_seq} warning: {warning}");
                }
            }
            IngestEvent::Rejected { error, .. } => {
                rejected += 1;
                eprintln!("[gs] batch rejected: {error}");
            }
            IngestEvent::Disconnected(why) => eprintln!("[gs] ingest down: {why}"),
            IngestEvent::Connected => {}
        }
    }
    println!("[gs] match {} done: {sent} batches sent, {accepted} accepted, {dup} duplicates, {rejected} rejected, {warned} warnings", h.match_id);
    Ok(if accepted == sent && rejected == 0 && warned == 0 { 0 } else { 2 })
}
