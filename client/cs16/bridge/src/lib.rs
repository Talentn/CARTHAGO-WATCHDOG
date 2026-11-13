//! Turns the text stream of the Counter-Strike 1.6 server plugin (`carthago_cs16.sma`) into
//! `GameplayBatch`es with the game-server SDK's [`MatchRecorder`].
//!
//! What the bridge adds to the plugin's raw state:
//! - GoldSrc units (inches) become metres, engine pitch (positive down) becomes pitch up;
//! - line of sight between two opponents becomes a visibility event per direction, true
//!   while the target is also inside the observer's field of view;
//! - user commands are counted in server ticks of simulated time (`msec`), because a GoldSrc
//!   client sends one command per rendered frame and the frame rate is not the tick rate;
//! - gunshot and footstep sounds are derived from shots and from running on the ground;
//! - bots are declared as bots, and the local human's slot is bound to the companion's
//!   verified session.
//!
//! No map geometry is sent, so the gateway stores the telemetry v2 part and does not run
//! information-leak scoring on it.

use std::collections::{BTreeMap, BTreeSet};

use carthago_server::pb;
use carthago_server::MatchRecorder;

/// GoldSrc world units (inches) to metres.
pub const UNIT_M: f32 = 0.0254;
const FLAG_BOT: u32 = 1;
const FLAG_HLTV: u32 = 2;
const FLAG_LOCAL: u32 = 4;
/// Half of the horizontal field of view a target must be inside to count as seen. CS 1.6
/// renders 90 degrees; the margin covers the target's width at the edge of the screen.
const HALF_FOV_DEG: f32 = 50.0;
/// Seconds of telemetry per batch.
const BATCH_SECS: u32 = 2;
const FOOTSTEP_SPEED: f32 = 150.0;
const FOOTSTEP_RADIUS: f32 = 1000.0;
const HIT_HEAD: u32 = 1;

/// The session the companion holds for the human playing on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub session_id: String,
    pub player_hash: String,
}

#[derive(Debug, Clone, Default)]
struct Sample {
    tick: u32,
    yaw: f32,
    pitch_up: f32,
    eye: [f32; 3],
    vel: [f32; 3],
    flags: u32,
}

#[derive(Debug, Clone, Default)]
struct Slot {
    flags: u32,
    team: u32,
    name: String,
    last: Option<Sample>,
    cmd_acc: u64,
    next_step: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub datagrams: u64,
    pub lost: u64,
    pub lines: u64,
    pub bad_lines: u64,
    pub samples: u64,
    pub shots: u64,
    pub hits: u64,
    pub batches: u64,
    pub matches: u64,
}

pub struct Bridge {
    rec: Option<MatchRecorder>,
    match_id: String,
    ended: BTreeSet<String>,
    map: String,
    rate: u32,
    tick: u32,
    last_flush: u32,
    next_seq: Option<u64>,
    slots: BTreeMap<u32, Slot>,
    los: BTreeSet<(u32, u32)>,
    seen: BTreeSet<(u32, u32)>,
    binding: Option<Binding>,
    pub stats: Stats,
}

impl Default for Bridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Gunshot audibility in game units, from the attenuation the game plays each weapon with.
fn gunshot_radius(weapon: &str) -> f32 {
    match weapon {
        "awp" | "scout" | "g3sg1" | "sg550" | "m249" => 3500.0,
        "tmp" => 1200.0,
        _ => 2500.0,
    }
}

fn hash_part(name: &str) -> String {
    let s: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || "-_.".contains(c) { c } else { '_' }).take(40).collect();
    if s.is_empty() {
        "unnamed".into()
    } else {
        s
    }
}

fn in_view(obs: &Sample, target: &Sample) -> bool {
    let d = [target.eye[0] - obs.eye[0], target.eye[1] - obs.eye[1], target.eye[2] - obs.eye[2]];
    let len = (d[0] * d[0] + d[1] * d[1] + d[2] * d[2]).sqrt();
    if len < 1.0 {
        return true;
    }
    let (y, p) = (obs.yaw.to_radians(), obs.pitch_up.to_radians());
    let f = [p.cos() * y.cos(), p.cos() * y.sin(), p.sin()];
    let cos = (d[0] * f[0] + d[1] * f[1] + d[2] * f[2]) / len;
    cos >= HALF_FOV_DEG.to_radians().cos()
}

impl Bridge {
    pub fn new() -> Self {
        Self {
            rec: None,
            match_id: String::new(),
            ended: BTreeSet::new(),
            map: String::new(),
            rate: 32,
            tick: 0,
            last_flush: 0,
            next_seq: None,
            slots: BTreeMap::new(),
            los: BTreeSet::new(),
            seen: BTreeSet::new(),
            binding: None,
            stats: Stats::default(),
        }
    }

    pub fn match_id(&self) -> &str {
        &self.match_id
    }

    pub fn map(&self) -> &str {
        &self.map
    }

    pub fn tick_rate(&self) -> u32 {
        self.rate
    }

    /// Slots as (slot, name, bot, local), for the status line.
    pub fn roster(&self) -> Vec<(u32, String, bool, bool)> {
        self.slots.iter().map(|(s, p)| (*s, p.name.clone(), p.flags & FLAG_BOT != 0, p.flags & FLAG_LOCAL != 0)).collect()
    }

    /// The slots that are tied to the companion's session right now: a session is known, a
    /// match is running, and the plugin reported a human on this machine in that slot.
    pub fn bound_slots(&self) -> Vec<(u32, String)> {
        if self.binding.is_none() || self.rec.is_none() {
            return Vec::new();
        }
        self.slots.iter().filter(|(_, p)| p.flags & (FLAG_BOT | FLAG_HLTV) == 0 && p.flags & FLAG_LOCAL != 0).map(|(s, p)| (*s, p.name.clone())).collect()
    }

    /// Sets or clears the companion's session. The local human's slot is declared with it
    /// from the next batch on.
    pub fn bind(&mut self, binding: Option<Binding>) {
        if self.binding != binding {
            self.binding = binding;
            let slots: Vec<u32> = self.slots.keys().copied().collect();
            for s in slots {
                self.declare(s);
            }
        }
    }

    fn declare(&mut self, slot: u32) {
        let (Some(rec), Some(p)) = (self.rec.as_mut(), self.slots.get(&slot)) else { return };
        if p.flags & FLAG_HLTV != 0 {
            return;
        }
        let bot = p.flags & FLAG_BOT != 0;
        match (&self.binding, bot, p.flags & FLAG_LOCAL != 0) {
            (_, true, _) => rec.player(slot, "", &format!("bot:{}", hash_part(&p.name)), 0),
            (Some(b), false, true) => rec.player(slot, &b.session_id, &b.player_hash, 0),
            _ => rec.player(slot, "", &format!("cs16:{}", hash_part(&p.name)), 0),
        }
        rec.bot(slot, bot);
        let team = if matches!(p.team, 1 | 2) { p.team } else { 0 };
        rec.player_profile(slot, team, pb::InputDevice::Unspecified, false);
    }

    fn fresh(&self, slot: u32) -> Option<&Sample> {
        self.slots.get(&slot)?.last.as_ref().filter(|s| s.tick + 2 >= self.tick)
    }

    /// Closes a tick: who sees whom, and who makes footstep noise.
    fn end_tick(&mut self) {
        let tick = self.tick;
        let mut want = BTreeSet::new();
        for &(a, b) in &self.los {
            if let (Some(sa), Some(sb)) = (self.fresh(a), self.fresh(b)) {
                if in_view(sa, sb) {
                    want.insert((a, b));
                }
                if in_view(sb, sa) {
                    want.insert((b, a));
                }
            }
        }
        let Some(rec) = self.rec.as_mut() else { return };
        for &(o, t) in self.seen.difference(&want) {
            rec.visibility(o, t, tick, false);
        }
        for &(o, t) in want.difference(&self.seen) {
            rec.visibility(o, t, tick, true);
        }
        self.seen = want;
        let step_gap = (self.rate * 2 / 5).max(1);
        for (&slot, p) in self.slots.iter_mut() {
            let Some(s) = p.last.as_ref().filter(|s| s.tick == tick) else { continue };
            let speed = (s.vel[0] * s.vel[0] + s.vel[1] * s.vel[1]).sqrt();
            if s.flags & 1 != 0 && s.flags & 2 == 0 && speed > FOOTSTEP_SPEED && tick >= p.next_step {
                p.next_step = tick + step_gap;
                rec.sound(tick, Some(slot), pb::SoundKind::Footstep, s.eye.map(|v| v * UNIT_M), FOOTSTEP_RADIUS * UNIT_M);
            }
        }
    }

    fn flush(&mut self, over: bool, out: &mut Vec<pb::GameplayBatch>) {
        if let Some(rec) = self.rec.as_mut() {
            rec.set_tick(self.tick);
            out.push(rec.flush(over));
            self.stats.batches += 1;
            self.last_flush = self.tick;
        }
        if over {
            if self.rec.take().is_some() {
                self.ended.insert(self.match_id.clone());
            }
            self.los.clear();
            self.seen.clear();
            for p in self.slots.values_mut() {
                p.last = None;
            }
        }
    }

    /// Ends the match in progress (the map changed, the server stopped or went quiet).
    pub fn finish(&mut self) -> Vec<pb::GameplayBatch> {
        let mut out = Vec::new();
        if self.rec.is_some() {
            self.end_tick();
            self.flush(true, &mut out);
        }
        out
    }

    fn hello(&mut self, f: &[&str], out: &mut Vec<pb::GameplayBatch>) -> Option<()> {
        let (id, map, rate) = (*f.get(1)?, *f.get(2)?, f.get(3)?.parse::<u32>().ok()?);
        if id.is_empty() || id.len() > 64 || !(1..=1000).contains(&rate) {
            return None;
        }
        if self.rec.is_some() && self.match_id == id {
            return Some(());
        }
        // A match that was closed for silence and then resumes must not reuse its id: the
        // gateway has already seen that match end.
        if self.ended.contains(id) && self.match_id == id {
            return Some(());
        }
        if self.rec.is_some() {
            self.end_tick();
            self.flush(true, out);
            self.slots.clear();
        }
        self.match_id = id.to_owned();
        self.map = map.to_owned();
        self.rate = rate;
        self.last_flush = self.tick;
        let mut rec = MatchRecorder::new(id, rate);
        rec.set_mode(pb::GameMode::CompetitiveShooter);
        rec.set_motion_stride(1);
        rec.set_tick(self.tick);
        self.rec = Some(rec);
        self.stats.matches += 1;
        let slots: Vec<u32> = self.slots.keys().copied().collect();
        for s in slots {
            self.declare(s);
        }
        Some(())
    }

    fn line(&mut self, l: &str, out: &mut Vec<pb::GameplayBatch>) -> Option<()> {
        let f: Vec<&str> = l.split(' ').collect();
        let num = |i: usize| f.get(i).and_then(|v| v.parse::<i64>().ok());
        let slot = |i: usize| num(i).filter(|s| (1..=64).contains(s)).map(|s| s as u32);
        match *f.first()? {
            "D" => {
                let (seq, tick) = (num(1)? as u64, u32::try_from(num(2)?).ok()?);
                self.stats.datagrams += 1;
                if let Some(want) = self.next_seq {
                    if seq > want {
                        self.stats.lost += seq - want;
                    }
                }
                self.next_seq = Some(seq + 1);
                if tick != self.tick {
                    self.end_tick();
                    self.tick = tick;
                    if let Some(rec) = self.rec.as_mut() {
                        rec.set_tick(tick);
                    }
                    // A new map restarts the engine clock, so ticks can go backwards; its
                    // hello line follows and closes the old match.
                    if tick < self.last_flush {
                        self.last_flush = tick;
                    } else if tick - self.last_flush >= self.rate * BATCH_SECS {
                        self.flush(false, out);
                    }
                }
            }
            "H" => self.hello(&f, out)?,
            "E" => {
                self.end_tick();
                self.flush(true, out);
            }
            "P" => {
                let s = slot(1)?;
                let (flags, team) = (num(2)? as u32, num(3)? as u32);
                let name = l.splitn(5, ' ').nth(4).unwrap_or("").trim();
                let p = self.slots.entry(s).or_default();
                if p.flags != flags || p.team != team || p.name != name {
                    p.flags = flags;
                    p.team = team;
                    p.name = name.to_owned();
                }
                self.declare(s);
            }
            "X" => {
                let s = slot(1)?;
                self.slots.remove(&s);
                self.los.retain(|&(a, b)| a != s && b != s);
            }
            "T" => {
                let s = slot(1)?;
                let v: Vec<f32> = (2..=10).map(|i| num(i).map(|n| n as f32)).collect::<Option<_>>()?;
                let sample = Sample {
                    tick: self.tick,
                    yaw: (v[0] / 100.0).rem_euclid(360.0),
                    pitch_up: (-v[1] / 100.0).clamp(-90.0, 90.0),
                    eye: [v[2], v[3], v[4]],
                    vel: [v[5], v[6], v[7]],
                    flags: v[8] as u32,
                };
                let rec = self.rec.as_mut()?;
                rec.aim(s, self.tick, sample.yaw, sample.pitch_up);
                rec.motion(s, self.tick, sample.eye.map(|c| c * UNIT_M), sample.vel.map(|c| c * UNIT_M));
                self.slots.entry(s).or_default().last = Some(sample);
                self.stats.samples += 1;
            }
            "C" => {
                let s = slot(1)?;
                let msec = u64::try_from(num(3)?).ok()?.min(60_000);
                let p = self.slots.entry(s).or_default();
                p.cmd_acc += msec * self.rate as u64;
                let n = p.cmd_acc / 1000;
                p.cmd_acc %= 1000;
                self.rec.as_mut()?.commands(s, n as u32);
            }
            "G" => {
                let (s, ms) = (slot(1)?, u64::try_from(num(2)?).ok()?);
                self.rec.as_mut()?.trigger(s, ms * 1000);
            }
            "S" => {
                let s = slot(1)?;
                let weapon = *f.get(2)?;
                let target = num(3)?;
                let (group, kill, dist) = (num(4)? as u32, num(5)? != 0, num(6)? as f32);
                let hit = (1..=64).contains(&target);
                let tick = self.tick;
                let at = self.fresh(s).map(|p| p.eye);
                let rec = self.rec.as_mut()?;
                rec.shot(pb::ShotEvent {
                    slot: s,
                    tick,
                    target_slot: if hit { target as i32 } else { -1 },
                    hit,
                    headshot: hit && group == HIT_HEAD,
                    kill: hit && kill,
                    weapon: weapon.chars().take(24).collect(),
                    distance_m: if hit { dist * UNIT_M } else { 0.0 },
                });
                if let Some(eye) = at {
                    rec.sound(tick, Some(s), pb::SoundKind::Gunshot, eye.map(|c| c * UNIT_M), gunshot_radius(weapon) * UNIT_M);
                }
                self.stats.shots += 1;
                self.stats.hits += hit as u64;
            }
            "V" => {
                let (a, b) = (slot(1)?, slot(2)?);
                let key = (a.min(b), a.max(b));
                if num(3)? != 0 {
                    self.los.insert(key);
                } else {
                    self.los.remove(&key);
                }
            }
            _ => return None,
        }
        Some(())
    }

    /// Feeds one datagram (or any run of plugin lines) and returns the batches that became
    /// ready.
    pub fn feed(&mut self, text: &str) -> Vec<pb::GameplayBatch> {
        let mut out = Vec::new();
        for l in text.lines() {
            let l = l.trim_end_matches('\r');
            if l.is_empty() || l.starts_with('@') {
                continue;
            }
            self.stats.lines += 1;
            if self.line(l, &mut out).is_none() {
                self.stats.bad_lines += 1;
            }
        }
        out
    }
}

/// A synthetic plugin stream for tests and for trying the bridge without the game: one
/// human on the server's own machine (slot 1) against bots, one of which aims like a
/// machine (instant snaps, headshots the moment a target appears). Deterministic.
pub fn synth(seconds: u32, rate: u32, match_id: &str) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    let mut rnd = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        (rng >> 11) as f64 / (1u64 << 53) as f64
    };
    // slot, flags, team, name
    let roster = [(1u32, FLAG_LOCAL, 1u32, "Founder"), (2, FLAG_BOT, 2, "[BOT] Snap"), (3, FLAG_BOT, 2, "[BOT] Calm"), (4, FLAG_BOT, 1, "[BOT] Mate")];
    let mut yaw = [10.0f64, 200.0, 90.0, 300.0];
    let mut pos = [[0.0f64, 0.0], [900.0, 0.0], [0.0, 900.0], [-200.0, 100.0]];
    let mut seq = 0u64;
    let mut client_ms = 0u64;
    let mut visible = [false; 2];
    for t in 1..=seconds * rate {
        let _ = writeln!(out, "D {seq} {t}");
        seq += 1;
        if t == 1 || t % 64 == 0 {
            let _ = writeln!(out, "H {match_id} de_synth {rate} 32 0");
            for (slot, flags, team, name) in roster {
                let _ = writeln!(out, "P {slot} {flags} {team} {name}");
            }
        }
        // Slot 2 comes into slot 1's sight for a second, every four seconds.
        let phase = t % (rate * 4);
        let exposed = phase < rate;
        for (i, target) in [2u32, 3].into_iter().enumerate() {
            let now = if target == 2 { exposed } else { phase >= rate * 2 && phase < rate * 3 };
            if now != visible[i] {
                visible[i] = now;
                let _ = writeln!(out, "V 1 {target} {}", now as u8);
            }
        }
        for (i, (slot, ..)) in roster.iter().enumerate() {
            let to_enemy = |from: [f64; 2], to: [f64; 2]| (to[1] - from[1]).atan2(to[0] - from[0]).to_degrees();
            match slot {
                // The human turns toward a visible enemy over a third of a second, with jitter.
                1 => {
                    let want = if visible[0] { to_enemy(pos[0], pos[1]) } else if visible[1] { to_enemy(pos[0], pos[2]) } else { yaw[0] };
                    let d = (want - yaw[0] + 540.0).rem_euclid(360.0) - 180.0;
                    yaw[0] += d * 0.25 + (rnd() - 0.5) * 0.8;
                }
                // The machine-like bot looks away, then lands on the target in one sample.
                2 => yaw[1] = if exposed { to_enemy(pos[1], pos[0]) } else { 95.0 + (t / rate) as f64 * 37.0 },
                _ => yaw[i] += (rnd() - 0.5) * 2.0,
            }
            pos[i][0] += (rnd() - 0.5) * 6.0;
            pos[i][1] += (rnd() - 0.5) * 6.0;
            let _ = writeln!(
                out,
                "T {slot} {} {} {} {} 64 {} {} 0 1",
                (yaw[i].rem_euclid(360.0) * 100.0) as i64,
                ((rnd() - 0.5) * 200.0) as i64,
                pos[i][0] as i64,
                pos[i][1] as i64,
                (rnd() * 250.0) as i64,
                (rnd() * 250.0) as i64
            );
        }
        // The machine-like bot fires the sample its target appears, mostly at the head.
        if exposed && phase < 3 {
            let _ = writeln!(out, "S 2 ak47 1 {} 0 900", if rnd() < 0.9 { 1 } else { 2 });
        }
        // The human fires a pistol about a third of a second after seeing someone.
        if visible[0] && phase >= rate / 3 && (phase - rate / 3).is_multiple_of((rate / 4).max(1)) {
            client_ms += 240 + (rnd() * 90.0) as u64;
            let _ = writeln!(out, "G 1 {client_ms}");
            let hit = rnd() < 0.6;
            let _ = writeln!(out, "S 1 usp {} {} 0 900", if hit { 2 } else { -1 }, if hit && rnd() < 0.2 { 1 } else { 3 });
        }
        if t % 16 == 0 {
            let ms = 16_000 / rate as u64;
            for (slot, ..) in roster {
                let _ = writeln!(out, "C {slot} {} {ms}", ms / 10);
            }
        }
    }
    let _ = writeln!(out, "D {seq} {}\nE", seconds * rate);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str, binding: Option<Binding>) -> (Bridge, Vec<pb::GameplayBatch>) {
        let mut b = Bridge::new();
        b.bind(binding);
        let mut out = b.feed(text);
        out.extend(b.finish());
        (b, out)
    }

    fn players(batches: &[pb::GameplayBatch]) -> BTreeMap<u32, pb::MatchPlayer> {
        batches.iter().flat_map(|b| b.players.iter().cloned()).map(|p| (p.slot, p)).collect()
    }

    #[test]
    fn converts_units_angles_and_marks_bots() {
        let text = "D 0 100\nH m1 de_dust2 32 32 0\nP 1 4 1 Ala Ghabi\nP 2 1 2 [BOT] Eric\nT 1 -9000 1500 100 200 64 250 0 0 1\nT 2 4500 0 1000 200 64 0 0 0 1\n";
        let bind = Binding { session_id: "ab".repeat(16), player_hash: "cs16-local-player".into() };
        let (b, out) = run(text, Some(bind.clone()));
        assert_eq!(b.stats.bad_lines, 0);
        assert_eq!(out.len(), 1);
        let batch = &out[0];
        assert!(batch.match_over && batch.schema_version == 2 && batch.tick_rate == 32 && batch.map.is_none());
        let p = players(&out);
        assert_eq!((p[&1].session_id.as_str(), p[&1].player_hash.as_str(), p[&1].bot, p[&1].team), (bind.session_id.as_str(), "cs16-local-player", false, 1));
        assert_eq!((p[&2].session_id.as_str(), p[&2].player_hash.as_str(), p[&2].bot, p[&2].team), ("", "bot:_BOT__Eric", true, 2));
        let aim = batch.aim.iter().find(|a| a.slot == 1).unwrap();
        assert_eq!((aim.first_tick, aim.yaw[0], aim.pitch[0]), (100, 270.0, -15.0), "yaw wraps to 0..360, pitch is positive up");
        let m = batch.motion.iter().find(|m| m.slot == 1).unwrap();
        assert_eq!((m.x_cm[0], m.y_cm[0], m.z_cm[0], m.vx_cm_s[0]), (254, 508, 163, 635), "inches to centimetres");
    }

    #[test]
    fn a_slot_is_bound_only_when_a_local_human_is_in_a_match() {
        let bind = Binding { session_id: "ab".repeat(16), player_hash: "cs16-local-player".into() };
        let mut b = Bridge::new();
        b.bind(Some(bind));
        assert!(b.bound_slots().is_empty(), "a session alone binds nothing");
        b.feed("D 0 1\nH m1 de_dust2 32 12 0\nP 2 1 2 Bot\nP 3 0 1 Remote\n");
        assert!(b.bound_slots().is_empty(), "bots and remote humans are not the companion's player");
        b.feed("D 1 2\nP 1 4 1 Ala\n");
        assert_eq!(b.bound_slots(), vec![(1, "Ala".to_owned())]);
        b.bind(None);
        assert!(b.bound_slots().is_empty());
    }

    #[test]
    fn an_unbound_local_human_is_a_named_player_not_a_bot() {
        let (_, out) = run("D 0 1\nH m1 de_dust2 32 32 0\nP 1 4 1 Ala\n", None);
        let p = players(&out);
        assert_eq!((p[&1].session_id.as_str(), p[&1].player_hash.as_str(), p[&1].bot), ("", "cs16:Ala", false));
    }

    #[test]
    fn line_of_sight_becomes_visibility_only_inside_the_field_of_view() {
        // Slot 1 at the origin looks along +X at slot 2; slot 2 looks away from slot 1.
        let mut text = String::from("D 0 10\nH m1 de_dust2 32 32 0\nP 1 4 1 A\nP 2 1 2 B\nT 1 0 0 0 0 64 0 0 0 1\nT 2 0 0 500 0 64 0 0 0 1\nV 1 2 1\n");
        text += "D 1 11\nT 1 0 0 0 0 64 0 0 0 1\nT 2 0 0 500 0 64 0 0 0 1\n";
        // Slot 2 turns around to face slot 1.
        text += "D 2 12\nT 1 0 0 0 0 64 0 0 0 1\nT 2 18000 0 500 0 64 0 0 0 1\n";
        text += "D 3 13\nT 1 0 0 0 0 64 0 0 0 1\nT 2 18000 0 500 0 64 0 0 0 1\nV 1 2 0\nD 4 14\n";
        let (_, out) = run(&text, None);
        let vis: Vec<(u32, u32, u32, bool)> = out.iter().flat_map(|b| &b.visibility).map(|v| (v.observer_slot, v.target_slot, v.tick, v.visible)).collect();
        assert_eq!(vis, vec![(1, 2, 10, true), (2, 1, 12, true), (1, 2, 13, false), (2, 1, 13, false)]);
    }

    #[test]
    fn shots_commands_and_triggers() {
        let text = "D 0 32\nH m1 de_dust2 32 32 0\nP 1 4 1 A\nP 2 1 2 B\nT 1 0 0 0 0 64 0 0 0 1\nS 1 ak47 2 1 1 1000\nS 1 ak47 -1 0 0 0\nG 1 1500\nC 1 50 500\nD 1 48\nC 1 50 500\n";
        let (b, out) = run(text, None);
        assert_eq!((b.stats.shots, b.stats.hits, b.stats.bad_lines), (2, 1, 0));
        let batch = &out[0];
        let s = &batch.shots[0];
        assert!(s.hit && s.headshot && s.kill && s.target_slot == 2 && s.weapon == "ak47" && (s.distance_m - 25.4).abs() < 0.01);
        assert!(!batch.shots[1].hit && batch.shots[1].target_slot == -1);
        assert_eq!(batch.triggers[0].client_time_us, vec![1_500_000]);
        // One second of simulated time at 32 ticks/s is 32 commands, whatever the frame rate.
        assert_eq!(batch.commands.iter().find(|c| c.slot == 1).unwrap().commands, 32);
        assert_eq!(batch.sounds.iter().filter(|s| s.kind == pb::SoundKind::Gunshot as i32).count(), 2);
    }

    #[test]
    fn batches_every_two_seconds_and_a_new_map_ends_the_match() {
        let mut text = String::from("D 0 1\nH m1 de_dust2 32 32 0\nP 1 4 1 A\n");
        for t in 2..=200 {
            text += &format!("D {} {t}\nT 1 0 0 0 0 64 0 0 0 1\n", t - 1);
        }
        text += "D 200 5\nH m2 de_inferno 32 32 0\nP 1 4 1 A\nT 1 0 0 0 0 64 0 0 0 1\n";
        let (b, out) = run(&text, None);
        let ids: Vec<(&str, u64, bool)> = out.iter().map(|b| (b.match_id.as_str(), b.batch_seq, b.match_over)).collect();
        assert_eq!(ids, vec![("m1", 1, false), ("m1", 2, false), ("m1", 3, false), ("m1", 4, true), ("m2", 1, true)]);
        assert_eq!((b.stats.matches, b.stats.lost), (2, 0));
        assert!(out[4].players.iter().any(|p| p.slot == 1), "the roster is declared again in the new match");
    }

    #[test]
    fn counts_lost_datagrams_and_bad_lines() {
        let (b, _) = run("D 0 1\nH m1 de_dust2 32 32 0\nD 3 2\nT 1 x\nQ 1\n", None);
        assert_eq!((b.stats.lost, b.stats.bad_lines), (2, 2));
    }

    #[test]
    fn synthetic_stream_is_well_formed() {
        let (b, out) = run(&synth(30, 32, "synth-test"), None);
        assert_eq!(b.stats.bad_lines, 0);
        assert!(out.len() >= 14 && out.last().unwrap().match_over);
        assert!(b.stats.shots > 20 && b.stats.hits > 10);
    }
}
