//! Decoy placement for the game server (detection strategy B1). A decoy is a fake enemy
//! replicated only to chosen players, and only while none of them could see or hear it.
//! [`DecoyPlanner`] tests that against the same simplified map geometry, and with the same
//! rules, the gateway applies to every decoy sample and to its controls:
//!
//! - every recipient is between `min_dist_m` (beyond footstep range; the game must never
//!   play a sound for a decoy anyway) and `max_dist_m` from it;
//! - no recipient has line of sight to its eye or chest point, in any direction, nor from
//!   `peek_m` to either side of their eye, so it never waits just behind a corner they hold;
//! - it is away from real enemies and from every place the recipients' team was just told
//!   about (pings, spots, radar), so a teammate's call can never explain a reaction to it.
//!
//! Only recipients matter: a teammate who is not a recipient is never sent the decoy and
//! sees nothing there.
//!
//! The decoy's route must not depend on its recipients: move it with the game's own bot
//! navigation toward goals of its own, and let replication alone keep it out of sight.
//! A decoy that steered by what its recipient does would make its own positions at other
//! times an unfair control (see the README's decoy integration rules). Create it, unreplicated,
//! at least [`crate::DECOY_ROLL_MIN_S`] seconds before replicating it; call
//! [`DecoyPlanner::can_replicate`] to start and [`DecoyPlanner::keep`] every tick while
//! replicated, stopping replication the tick it returns false; keep moving it unreplicated for
//! the same post-roll before ending it. Each call is a few hundred segment-versus-prism tests
//! and allocates nothing after construction.

use carthago_proto::v1 as pb;

/// Placement and keep-alive distances, metres. The defaults are the gateway's.
#[derive(Debug, Clone, Copy)]
pub struct DecoyRules {
    /// Distance band from every recipient a replicated decoy must stay in.
    pub min_dist_m: f32,
    pub max_dist_m: f32,
    /// A recipient must not see it from this far to either side of their eye either.
    pub peek_m: f32,
    /// Minimum distance from any real enemy to start replicating, and to stay replicated.
    pub enemy_clear_m: f32,
    pub keep_clear_m: f32,
    /// Minimum distance from any position recently shared with the recipients' team.
    pub info_clear_m: f32,
    /// Eye to chest offset used for the second sight test.
    pub chest_drop_m: f32,
}

impl Default for DecoyRules {
    fn default() -> Self {
        Self { min_dist_m: 20.0, max_dist_m: 40.0, peek_m: 1.5, enemy_clear_m: 10.0, keep_clear_m: 7.0, info_clear_m: 10.0, chest_drop_m: 0.3 }
    }
}

/// What the decoy's recipients could perceive right now.
#[derive(Debug, Clone, Copy)]
pub struct DecoyView<'a> {
    /// Eye positions of every recipient of the decoy.
    pub recipients: &'a [[f32; 3]],
    /// Positions of every real enemy of the recipients.
    pub enemies: &'a [[f32; 3]],
    /// Positions shared with the recipients' team recently: pings, spotted enemies, radar.
    pub shared: &'a [[f32; 3]],
}

struct Prism {
    poly: Vec<[f32; 2]>, // counter-clockwise
    z_min: f32,
    z_max: f32,
    min: [f32; 2],
    max: [f32; 2],
}

/// Line-of-sight and placement checks over one map version's geometry.
pub struct DecoyPlanner {
    prisms: Vec<Prism>,
    rules: DecoyRules,
}

fn dist(a: [f32; 3], b: [f32; 3]) -> f32 {
    ((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2) + (a[2] - b[2]).powi(2)).sqrt()
}

impl DecoyPlanner {
    /// Builds the planner from the geometry uploaded with `MatchRecorder::set_map`. Occluders
    /// with fewer than three vertices are skipped.
    pub fn new(geometry: &pb::MapGeometry, rules: DecoyRules) -> Self {
        let mut prisms = Vec::with_capacity(geometry.occluders.len());
        for o in &geometry.occluders {
            let mut poly: Vec<[f32; 2]> = o.xy_cm.as_chunks::<2>().0.iter().map(|c| [c[0] as f32 / 100.0, c[1] as f32 / 100.0]).collect();
            if poly.len() < 3 {
                continue;
            }
            let area: f32 = (0..poly.len()).map(|i| {
                let (p, q) = (poly[i], poly[(i + 1) % poly.len()]);
                p[0] * q[1] - q[0] * p[1]
            }).sum();
            if area < 0.0 {
                poly.reverse();
            }
            let mut min = [f32::INFINITY; 2];
            let mut max = [f32::NEG_INFINITY; 2];
            for p in &poly {
                min = [min[0].min(p[0]), min[1].min(p[1])];
                max = [max[0].max(p[0]), max[1].max(p[1])];
            }
            prisms.push(Prism { poly, z_min: o.z_min_cm as f32 / 100.0, z_max: o.z_max_cm as f32 / 100.0, min, max });
        }
        Self { prisms, rules }
    }

    pub fn rules(&self) -> &DecoyRules {
        &self.rules
    }

    /// True when no occluder blocks the segment from `a` to `b`.
    pub fn line_of_sight(&self, a: [f32; 3], b: [f32; 3]) -> bool {
        let (lo, hi) = ([a[0].min(b[0]), a[1].min(b[1])], [a[0].max(b[0]), a[1].max(b[1])]);
        !self.prisms.iter().any(|p| p.max[0] >= lo[0] && p.min[0] <= hi[0] && p.max[1] >= lo[1] && p.min[1] <= hi[1] && blocks(p, a, b))
    }

    /// True when nobody at `eyes` can see `pos` (eye or chest), in any direction, even from
    /// `peek_m` to either side of their eye.
    pub fn hidden_from(&self, pos: [f32; 3], eyes: &[[f32; 3]]) -> bool {
        let chest = [pos[0], pos[1], pos[2] - self.rules.chest_drop_m];
        eyes.iter().all(|&e| {
            let (dx, dy) = (pos[0] - e[0], pos[1] - e[1]);
            let l = (dx * dx + dy * dy).sqrt();
            let mut from = [e, e, e];
            if self.rules.peek_m > 0.0 && l > 1e-6 {
                let (sx, sy) = (-dy / l * self.rules.peek_m, dx / l * self.rules.peek_m);
                from[1] = [e[0] + sx, e[1] + sy, e[2]];
                from[2] = [e[0] - sx, e[1] - sy, e[2]];
            }
            from.iter().all(|&f| !self.line_of_sight(f, pos) && !self.line_of_sight(f, chest))
        })
    }

    fn valid(&self, pos: [f32; 3], view: &DecoyView<'_>, enemy_clear: f32) -> bool {
        !view.recipients.is_empty()
            && view.recipients.iter().all(|&r| (self.rules.min_dist_m..=self.rules.max_dist_m).contains(&dist(r, pos)))
            && view.enemies.iter().all(|&e| dist(e, pos) >= enemy_clear)
            && self.hidden_from(pos, view.recipients)
    }

    /// Whether a decoy at `pos` may start being replicated: in the distance band of every
    /// recipient, hidden from all of them, clear of real enemies and of recently shared
    /// positions.
    pub fn can_replicate(&self, pos: [f32; 3], view: &DecoyView<'_>) -> bool {
        view.shared.iter().all(|&s| dist(s, pos) >= self.rules.info_clear_m) && self.valid(pos, view, self.rules.enemy_clear_m)
    }

    /// Picks a starting point among `candidates` (for example navigation points at eye height)
    /// where the decoy could be replicated now. `pick` chooses among the valid ones, so
    /// placement varies per session; pass a random number.
    pub fn place(&self, candidates: &[[f32; 3]], view: &DecoyView<'_>, pick: u64) -> Option<[f32; 3]> {
        let valid = candidates.iter().filter(|&&c| self.can_replicate(c, view)).count();
        if valid == 0 {
            return None;
        }
        let k = (pick % valid as u64) as usize;
        candidates.iter().copied().filter(|&c| self.can_replicate(c, view)).nth(k)
    }

    /// Whether a replicated decoy at `pos` may stay replicated. False means stop replicating
    /// it this tick, before the move is sent.
    pub fn keep(&self, pos: [f32; 3], view: &DecoyView<'_>) -> bool {
        self.valid(pos, view, self.rules.keep_clear_m)
    }
}

/// Cyrus-Beck clip of the segment against the prism in XY, then the Z interval (the same test
/// as the gateway's `Map.LineOfSight`).
fn blocks(p: &Prism, a: [f32; 3], b: [f32; 3]) -> bool {
    let (mut t0, mut t1) = (0.0f32, 1.0f32);
    let (dx, dy) = (b[0] - a[0], b[1] - a[1]);
    let n = p.poly.len();
    for i in 0..n {
        let (s, q) = (p.poly[i], p.poly[(i + 1) % n]);
        let (nx, ny) = (q[1] - s[1], -(q[0] - s[0]));
        let num = nx * (s[0] - a[0]) + ny * (s[1] - a[1]);
        let den = nx * dx + ny * dy;
        if den.abs() < 1e-9 {
            if num < 0.0 {
                return false;
            }
            continue;
        }
        let t = num / den;
        if den < 0.0 {
            t0 = t0.max(t);
        } else {
            t1 = t1.min(t);
        }
        if t0 > t1 {
            return false;
        }
    }
    let (za, zb) = (a[2] + t0 * (b[2] - a[2]), a[2] + t1 * (b[2] - a[2]));
    za.max(zb) >= p.z_min && za.min(zb) <= p.z_max
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wall(x0: i32, y0: i32, x1: i32, y1: i32, h: i32) -> pb::Occluder {
        pb::Occluder { xy_cm: vec![x0, y0, x1, y0, x1, y1, x0, y1], z_min_cm: 0, z_max_cm: h }
    }

    /// A 40 x 40 m square with a 3 m wall along x = 20 from y = 0 to y = 30.
    fn planner() -> DecoyPlanner {
        let g = pb::MapGeometry { map_id: "t".into(), version: 1, occluders: vec![wall(2000, 0, 2100, 3000, 300)], ..Default::default() };
        DecoyPlanner::new(&g, DecoyRules::default())
    }

    #[test]
    fn line_of_sight_matches_prisms_and_height() {
        let p = planner();
        assert!(!p.line_of_sight([10.0, 10.0, 1.6], [30.0, 10.0, 1.6]));
        assert!(p.line_of_sight([10.0, 35.0, 1.6], [30.0, 35.0, 1.6]), "past the wall's end");
        assert!(p.line_of_sight([10.0, 10.0, 4.0], [30.0, 10.0, 4.0]), "over the wall");
        // Clockwise input is normalised.
        let g = pb::MapGeometry { occluders: vec![pb::Occluder { xy_cm: vec![2000, 0, 2000, 3000, 2100, 3000, 2100, 0], z_min_cm: 0, z_max_cm: 300 }], ..Default::default() };
        assert!(!DecoyPlanner::new(&g, DecoyRules::default()).line_of_sight([10.0, 10.0, 1.6], [30.0, 10.0, 1.6]));
    }

    #[test]
    fn placement_hides_from_recipients_and_respects_clearances() {
        let p = planner();
        let me = [[10.0, 10.0, 1.6]];
        let behind = [32.0, 12.0, 1.6];
        let view = DecoyView { recipients: &me, enemies: &[], shared: &[] };
        assert!(p.can_replicate(behind, &view));
        assert!(!p.can_replicate([16.0, 38.0, 1.6], &view), "visible past the wall's end");
        assert!(!p.can_replicate([21.5, 5.0, 1.6], &view), "behind the wall but within footstep range");
        assert!(!p.can_replicate([55.0, 10.0, 1.6], &view), "beyond the band");
        let enemies = [[30.0, 14.0, 1.6]];
        assert!(!p.can_replicate(behind, &DecoyView { enemies: &enemies, ..view }), "a real enemy is next to it");
        let shared = [[33.0, 10.0, 1.6]];
        assert!(!p.can_replicate(behind, &DecoyView { shared: &shared, ..view }), "the team was just pinged there");
        assert!(p.keep(behind, &DecoyView { shared: &shared, ..view }), "shared positions only gate the start");
        let cands = [[16.0, 38.0, 1.6], behind, [21.5, 5.0, 1.6]];
        for pick in 0..5 {
            assert_eq!(p.place(&cands, &view, pick), Some(behind));
        }
        let moved = [[18.0, 33.0, 1.6]];
        assert!(!p.keep(behind, &DecoyView { recipients: &moved, ..view }), "the recipient walked round the wall");
        assert!(!p.keep(behind, &DecoyView { recipients: &[], ..view }), "no recipient, nothing to replicate");
    }

    #[test]
    fn peek_margin_keeps_decoys_off_corners() {
        let p = planner();
        let strict = DecoyPlanner::new(&pb::MapGeometry { occluders: vec![wall(2000, 0, 2100, 3000, 300)], ..Default::default() }, DecoyRules { peek_m: 0.0, ..DecoyRules::default() });
        // Just past the wall's end: hidden from the recipient's eye, but a half-step strafe
        // toward the end would reveal it.
        let me = [[10.0, 28.5, 1.6]];
        let near_edge = [34.0, 31.0, 1.6];
        assert!(strict.hidden_from(near_edge, &me), "hidden from the eye alone");
        assert!(!p.hidden_from(near_edge, &me), "a 1.5 m peek reveals it");
        assert!(p.hidden_from([34.0, 10.0, 1.6], &me), "deep behind the wall stays hidden");
    }
}
