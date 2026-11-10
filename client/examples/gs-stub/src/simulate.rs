//! `gs-stub simulate`: generates a synthetic match and streams its gameplay telemetry to the
//! gateway through the game-server SDK, for the Phase 1 demo and end-to-end test. Everything
//! is made-up numbers: baseline slots get human-like noise, and an anomaly profile on a slot
//! shifts one statistic outside the range a server-side rule accepts.
//!
//! Anomaly profiles (combine with `+`), one per rule in backend/internal/analyzer:
//!   snap        view angle jumps in one tick and then holds still   -> angle_snap
//!   fast        reaction time far below the lobby                    -> time_to_damage
//!   headshot    headshot share far above the MMR baseline            -> headshot_rate
//!   cmdrate     more user commands than ticks                        -> command_rate
//!   regular     trigger presses at near-constant intervals           -> macro_interval

use std::collections::HashMap;
use std::time::{Duration, Instant};

use sn_server::{pb, GameplayStream, IngestEvent, MatchRecorder};

use crate::Args;

#[derive(Default, Clone, Copy)]
struct Profile {
    snap: bool,
    fast: bool,
    headshot: bool,
    cmdrate: bool,
    regular: bool,
}

impl Profile {
    fn parse(s: &str) -> Result<Self, String> {
        let mut p = Profile::default();
        for part in s.split('+') {
            match part {
                "snap" => p.snap = true,
                "fast" => p.fast = true,
                "headshot" => p.headshot = true,
                "cmdrate" => p.cmdrate = true,
                "regular" => p.regular = true,
                _ => return Err(format!("unknown anomaly profile {part:?} (snap, fast, headshot, cmdrate, regular)")),
            }
        }
        Ok(p)
    }
}

/// xorshift64*: deterministic, dependency-free noise.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn range(&mut self, lo: u32, hi: u32) -> u32 {
        lo + (self.next() % u64::from(hi - lo + 1)) as u32
    }
    fn normal(&mut self) -> f64 {
        let (u, v) = (self.unit().max(1e-12), self.unit());
        (-2.0 * u.ln()).sqrt() * (std::f64::consts::TAU * v).cos()
    }
}

struct Slot {
    profile: Profile,
    mmr: i32,
    yaw: f64,
    pitch: f64,
    vel: f64,
    next_engage: u32,
    engage: Option<(u32, u32)>, // (target slot, tick of the reaction shot)
    cmd_carry: f64,
    click_us: u64,
}

struct Session {
    id: String,
    player: String,
    mmr: i32,
}

/// Session file lines: `slot session_id player_hash [mmr]` (written by carthago-sim).
fn load_sessions(path: &str) -> Result<HashMap<u32, Session>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut out = HashMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (Some(slot), Some(id), Some(player)) = (f.first().and_then(|s| s.parse().ok()), f.get(1), f.get(2)) else {
            return Err(format!("{path}: bad line {line:?}"));
        };
        let mmr = f.get(3).and_then(|m| m.parse().ok()).unwrap_or(1500);
        out.insert(slot, Session { id: (*id).into(), player: (*player).into(), mmr });
    }
    Ok(out)
}

fn baseline_headshot(mmr: i32) -> f64 {
    (0.18 + 0.12 * f64::from(mmr - 1500) / 1000.0).clamp(0.08, 0.45)
}

pub fn simulate(a: &Args) -> i32 {
    match run(a) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("gs-stub simulate: {e}");
            1
        }
    }
}

fn run(a: &Args) -> Result<i32, String> {
    let url = a.get_or("--ingest", "ws://127.0.0.1:8750/v1/ingest");
    let key = a.get_or("--server-key", "demo-server-key");
    let tick_rate: u32 = a.get_or("--tick-rate", "64").parse().map_err(|_| "--tick-rate")?;
    let seconds: u32 = a.get_or("--seconds", "120").parse().map_err(|_| "--seconds")?;
    let n: u32 = a.get_or("--players", "8").parse().map_err(|_| "--players")?;
    let realtime = a.has("--realtime");
    let match_id = a.get_or("--match", &format!("match-{}", sn_crypto::time::now_unix()));
    let sessions = match a.get("--sessions") {
        Some(p) => load_sessions(&p)?,
        None => HashMap::new(),
    };
    let mut profiles: HashMap<u32, Profile> = HashMap::new();
    for spec in a.all("--anomaly") {
        let (slot, p) = spec.split_once('=').ok_or("--anomaly wants SLOT=profile[+profile]")?;
        profiles.insert(slot.parse().map_err(|_| "--anomaly: bad slot")?, Profile::parse(p)?);
    }

    let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ u64::from(n) ^ u64::from(seconds));
    let mut rec = MatchRecorder::new(match_id.clone(), tick_rate);
    let mut slots: Vec<Slot> = (1..=n)
        .map(|s| {
            let sess = sessions.get(&s);
            let mmr = sess.map_or(1200 + 100 * s as i32, |x| x.mmr);
            rec.player(s, sess.map_or("", |x| &x.id), &sess.map_or_else(|| format!("bot-{s}"), |x| x.player.clone()), mmr);
            Slot {
                profile: profiles.get(&s).copied().unwrap_or_default(),
                mmr,
                yaw: rng.unit() * 360.0,
                pitch: 0.0,
                vel: 0.0,
                next_engage: rng.range(20, 120),
                engage: None,
                cmd_carry: 0.0,
                click_us: 1_000_000 * u64::from(s),
            }
        })
        .collect();

    let (stream, events) = GameplayStream::start(&url, &key);
    println!("[gs] simulating {match_id}: {n} players, {seconds}s at {tick_rate} Hz -> {url}");
    for (s, p) in &profiles {
        let mut names = Vec::new();
        for (on, name) in [(p.snap, "snap"), (p.fast, "fast"), (p.headshot, "headshot"), (p.cmdrate, "cmdrate"), (p.regular, "regular")] {
            if on {
                names.push(name);
            }
        }
        println!("[gs] slot {s}: anomaly profile {}", names.join("+"));
    }

    let start = Instant::now();
    let ticks = seconds * tick_rate;
    let (mut sent, mut queue_full) = (0u64, 0u64);
    for tick in 1..=ticks {
        rec.set_tick(tick);
        for i in 0..slots.len() {
            let slot = i as u32 + 1;
            step(&mut rng, &mut rec, &mut slots, i, slot, tick, n, tick_rate);
        }
        if tick.is_multiple_of(tick_rate) || tick == ticks {
            match stream.send(rec.flush(tick == ticks)) {
                Ok(()) => sent += 1,
                Err(_) => queue_full += 1,
            }
            if realtime {
                let due = Duration::from_secs_f64(f64::from(tick) / f64::from(tick_rate));
                if let Some(wait) = due.checked_sub(start.elapsed()) {
                    std::thread::sleep(wait);
                }
            }
        }
    }
    drop(stream);
    let (mut accepted, mut dup, mut rejected) = (0, 0, 0);
    for e in events.try_iter() {
        match e {
            IngestEvent::Acked { accepted: true, .. } => accepted += 1,
            IngestEvent::Acked { accepted: false, .. } => dup += 1,
            IngestEvent::Rejected { error, .. } => {
                rejected += 1;
                eprintln!("[gs] batch rejected: {error}");
            }
            IngestEvent::Disconnected(why) => eprintln!("[gs] ingest down: {why}"),
            IngestEvent::Connected => {}
        }
    }
    println!("[gs] match {match_id} done: {sent} batches sent, {accepted} accepted, {dup} duplicates, {rejected} rejected, {queue_full} dropped (queue full)");
    Ok(if accepted as u64 == sent && rejected == 0 { 0 } else { 2 })
}

#[allow(clippy::too_many_arguments)]
fn step(rng: &mut Rng, rec: &mut MatchRecorder, slots: &mut [Slot], i: usize, slot: u32, tick: u32, n: u32, tick_rate: u32) {
    let p = slots[i].profile;
    let s = &mut slots[i];

    // View angles.
    if p.snap {
        if tick.is_multiple_of(90) {
            s.yaw = (s.yaw + 40.0 + rng.unit() * 60.0) % 360.0;
        }
    } else {
        if rng.range(0, 60) == 0 {
            s.vel = (rng.unit() * 2.0 - 1.0) * 45.0;
        }
        s.vel *= 0.6;
        s.yaw = (s.yaw + s.vel + rng.normal() * 0.8).rem_euclid(360.0);
        s.pitch = (s.pitch + rng.normal() * 0.3).clamp(-60.0, 60.0);
    }
    rec.aim(slot, tick, s.yaw as f32, s.pitch as f32);

    // User commands: one per tick, with jitter that averages out.
    s.cmd_carry += if p.cmdrate { 1.25 } else { 1.0 + rng.normal() * 0.05 };
    while s.cmd_carry >= 1.0 {
        rec.command(slot);
        s.cmd_carry -= 1.0;
    }

    // Engagements: a target becomes visible, the reaction shot lands after a delay.
    if s.engage.is_none() && tick >= s.next_engage && n > 1 {
        let target = (slot + rng.range(1, n - 1) - 1) % n + 1;
        let react_ms = if p.fast { rng.range(0, 20) } else { rng.range(200, 380) };
        rec.visibility(slot, target, tick, true);
        s.engage = Some((target, tick + react_ms * tick_rate / 1000));
    }
    if let Some((target, at)) = s.engage {
        if tick >= at {
            let hs_rate = if p.headshot { 0.75 } else { baseline_headshot(s.mmr) };
            for k in 0..3 {
                let hit = k == 0 || rng.unit() < 0.5;
                rec.shot(pb::ShotEvent {
                    slot,
                    tick: tick + k * 6,
                    target_slot: target as i32,
                    hit,
                    headshot: hit && rng.unit() < hs_rate,
                    kill: false,
                    weapon: "rifle".into(),
                    distance_m: 10.0 + rng.unit() as f32 * 30.0,
                });
                let gap = if p.regular { 100_000 + rng.range(0, 400) as u64 } else { (110_000.0 + rng.normal() * 18_000.0).max(40_000.0) as u64 };
                s.click_us += gap;
                rec.trigger(slot, s.click_us);
            }
            s.click_us += 1_500_000;
            rec.visibility(slot, target, tick + 30, false);
            s.engage = None;
            s.next_engage = tick + rng.range(60, 160);
        }
    }
}
