//! Reads the solid world out of a GoldSrc map file (BSP version 30), which is what a line of
//! sight in Counter-Strike 1.6 is traced against.
//!
//! Only the world model's point hull is taken: its planes, its nodes and whether each leaf is
//! solid. That is the tree the engine itself walks for `TraceLine`. Doors, breakable glass
//! and every other brush entity are separate models that move or vanish during a round; they
//! are left out, so sight is credited through them. Water, sky and every content other than
//! solid count as open for the same reason: when in doubt a player is credited with seeing.
//!
//! Nothing here trusts the file. Every offset, count and index is checked, a node that is
//! reached twice is an error, and sizes are capped.

use carthago_server::pb;
use sha2::{Digest, Sha256};

const VERSION: i32 = 30;
const LUMPS: usize = 15;
const LUMP_PLANES: usize = 1;
const LUMP_NODES: usize = 5;
const LUMP_LEAVES: usize = 10;
const LUMP_MODELS: usize = 14;
const PLANE_SIZE: usize = 20;
const NODE_SIZE: usize = 24;
const LEAF_SIZE: usize = 28;
const MODEL_SIZE: usize = 64;
const CONTENTS_SOLID: i32 = -2;
/// The format's own limit: node children are 16-bit.
const MAX_NODES: usize = 32767;
/// The gateway refuses a deeper tree, and walking one must not exhaust the stack.
const MAX_DEPTH: usize = 2048;
/// Larger than any map the game ships or loads.
pub const MAX_FILE: u64 = 64 << 20;
/// GoldSrc units (inches) to centimetres.
const UNIT_CM: f32 = 2.54;

pub const OPEN: i32 = -1;
pub const SOLID: i32 = -2;

/// The solid world of one map: `planes` are (normal, distance in game units), `nodes` are
/// (plane, child in front, child behind) with children that are later nodes, [`OPEN`] or
/// [`SOLID`]. Node 0 is the root.
#[derive(Debug, Clone, PartialEq)]
pub struct World {
    pub planes: Vec<[f32; 4]>,
    pub nodes: Vec<[i32; 3]>,
    pub sha256: [u8; 32],
}

fn i32_at(b: &[u8], at: usize) -> i32 {
    i32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn f32_at(b: &[u8], at: usize) -> f32 {
    f32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn i16_at(b: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([b[at], b[at + 1]])
}

fn lump<'a>(file: &'a [u8], index: usize, item: usize, name: &str) -> Result<&'a [u8], String> {
    let (off, len) = (i32_at(file, 4 + index * 8), i32_at(file, 8 + index * 8));
    let (off, len) = (usize::try_from(off).map_err(|_| format!("{name}: negative offset"))?, usize::try_from(len).map_err(|_| format!("{name}: negative length"))?);
    let end = off.checked_add(len).filter(|e| *e <= file.len()).ok_or(format!("{name}: runs past the end of the file"))?;
    if len % item != 0 {
        return Err(format!("{name}: {len} bytes is not a whole number of {item}-byte records"));
    }
    Ok(&file[off..end])
}

impl World {
    /// Parses a map file.
    pub fn parse(file: &[u8]) -> Result<Self, String> {
        if file.len() < 4 + LUMPS * 8 {
            return Err("too short to be a map file".into());
        }
        let version = i32_at(file, 0);
        if version != VERSION {
            return Err(format!("map file version {version}; Counter-Strike 1.6 maps are version {VERSION}"));
        }
        let planes = lump(file, LUMP_PLANES, PLANE_SIZE, "planes")?;
        let nodes = lump(file, LUMP_NODES, NODE_SIZE, "nodes")?;
        let leaves = lump(file, LUMP_LEAVES, LEAF_SIZE, "leaves")?;
        let models = lump(file, LUMP_MODELS, MODEL_SIZE, "models")?;
        let (n_planes, n_nodes, n_leaves) = (planes.len() / PLANE_SIZE, nodes.len() / NODE_SIZE, leaves.len() / LEAF_SIZE);
        if models.is_empty() {
            return Err("the map has no world model".into());
        }
        if n_nodes > MAX_NODES {
            return Err(format!("{n_nodes} nodes; the format allows {MAX_NODES}"));
        }
        let root = i32_at(models, 36);
        if root < 0 || root as usize >= n_nodes {
            return Err(format!("the world's root node is {root} of {n_nodes}"));
        }

        let mut out = World { planes: Vec::new(), nodes: Vec::new(), sha256: Sha256::digest(file).into() };
        let mut plane_map = vec![u32::MAX; n_planes];
        let mut seen = vec![false; n_nodes];
        // (node in the file, node in the output whose child it is, which child). Nodes are
        // numbered as they are taken off the stack, so a child's number is always above its
        // parent's.
        let mut stack = vec![(root as usize, usize::MAX, 0usize, 0usize)];
        while let Some((old, parent, side, depth)) = stack.pop() {
            if depth > MAX_DEPTH {
                return Err(format!("the tree is deeper than {MAX_DEPTH}"));
            }
            if std::mem::replace(&mut seen[old], true) {
                return Err(format!("node {old} is reached twice: not a tree"));
            }
            let rec = &nodes[old * NODE_SIZE..(old + 1) * NODE_SIZE];
            let plane = usize::try_from(i32_at(rec, 0)).ok().filter(|p| *p < n_planes).ok_or(format!("node {old} names a plane that does not exist"))?;
            if plane_map[plane] == u32::MAX {
                let p = &planes[plane * PLANE_SIZE..(plane + 1) * PLANE_SIZE];
                let v = [f32_at(p, 0), f32_at(p, 4), f32_at(p, 8), f32_at(p, 12)];
                let len = (v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).sqrt();
                if !(v.iter().all(|x| x.is_finite()) && (0.99..=1.01).contains(&len)) {
                    return Err(format!("plane {plane} is not a unit normal with a finite distance"));
                }
                plane_map[plane] = out.planes.len() as u32;
                out.planes.push(v);
            }
            let me = out.nodes.len();
            out.nodes.push([plane_map[plane] as i32, 0, 0]);
            if parent != usize::MAX {
                out.nodes[parent][1 + side] = me as i32;
            }
            // The child behind is pushed first so the one in front is numbered first.
            for side in [1usize, 0] {
                let child = i16_at(rec, 4 + side * 2);
                if child >= 0 {
                    if child as usize >= n_nodes {
                        return Err(format!("node {old} has child node {child} of {n_nodes}"));
                    }
                    stack.push((child as usize, me, side, depth + 1));
                } else {
                    let leaf = -(child as i32 + 1) as usize;
                    if leaf >= n_leaves {
                        return Err(format!("node {old} names leaf {leaf} of {n_leaves}"));
                    }
                    let contents = i32_at(leaves, leaf * LEAF_SIZE);
                    out.nodes[me][1 + side] = if contents == CONTENTS_SOLID { SOLID } else { OPEN };
                }
            }
        }
        if !out.nodes.iter().any(|n| n[1] == SOLID || n[2] == SOLID) || !out.nodes.iter().any(|n| n[1] == OPEN || n[2] == OPEN) {
            return Err("the world has no solid or no open space".into());
        }
        Ok(out)
    }

    /// Whether a point (game units) is inside the solid world.
    pub fn solid(&self, p: [f32; 3]) -> bool {
        let mut n = 0i32;
        while n >= 0 {
            let [plane, front, back] = self.nodes[n as usize];
            let pl = self.planes[plane as usize];
            n = if pl[0] * p[0] + pl[1] * p[1] + pl[2] * p[2] - pl[3] >= 0.0 { front } else { back };
        }
        n == SOLID
    }

    /// Whether the straight line between two points (game units) touches the solid world.
    pub fn blocked(&self, a: [f32; 3], b: [f32; 3]) -> bool {
        self.cross(0, a.map(f64::from), b.map(f64::from))
    }

    fn cross(&self, mut n: i32, mut a: [f64; 3], b: [f64; 3]) -> bool {
        while n >= 0 {
            let [plane, front, back] = self.nodes[n as usize];
            let pl = self.planes[plane as usize].map(f64::from);
            let side = |p: [f64; 3]| pl[0] * p[0] + pl[1] * p[1] + pl[2] * p[2] - pl[3];
            let (da, db) = (side(a), side(b));
            if da >= 0.0 && db >= 0.0 {
                n = front;
            } else if da < 0.0 && db < 0.0 {
                n = back;
            } else {
                let f = da / (da - db);
                let mid = [a[0] + f * (b[0] - a[0]), a[1] + f * (b[1] - a[1]), a[2] + f * (b[2] - a[2])];
                let (near, far) = if da >= 0.0 { (front, back) } else { (back, front) };
                if self.cross(near, a, mid) {
                    return true;
                }
                n = far;
                a = mid;
            }
        }
        n == SOLID
    }

    /// The world as map geometry for the gateway, in centimetres. The version is taken from
    /// the file's hash, so a changed file is a new version and never replaces an old one.
    pub fn geometry(&self, map_id: &str) -> pb::MapGeometry {
        let version = u32::from_le_bytes([self.sha256[0], self.sha256[1], self.sha256[2], self.sha256[3]]).max(1);
        pb::MapGeometry {
            map_id: map_id.chars().take(64).collect(),
            version,
            mode: pb::GameMode::RoundShooter as i32,
            solid: Some(pb::SolidTree {
                planes: self.planes.iter().flat_map(|p| [p[0], p[1], p[2], p[3] * UNIT_CM]).collect(),
                nodes: self.nodes.iter().flatten().copied().collect(),
            }),
            source_sha256: self.sha256.to_vec(),
            ..Default::default()
        }
    }
}

/// A map name as the engine reports it, when it is safe to use as a file name.
pub fn safe_name(map: &str) -> Option<String> {
    let ok = !map.is_empty() && map.len() <= 64 && map.chars().all(|c| c.is_ascii_alphanumeric() || "_-".contains(c));
    ok.then(|| map.to_ascii_lowercase())
}

/// Finds `<map>.bsp` in the given folders, whatever the case of the file name, and reads it.
pub fn find(dirs: &[std::path::PathBuf], map: &str) -> Result<(std::path::PathBuf, Vec<u8>), String> {
    let name = safe_name(map).ok_or(format!("'{map}' is not a usable map name"))?;
    let want = format!("{name}.bsp");
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().to_ascii_lowercase() != want {
                continue;
            }
            let path = e.path();
            let len = e.metadata().map(|m| m.len()).unwrap_or(0);
            if len > MAX_FILE {
                return Err(format!("{} is {len} bytes; refusing more than {MAX_FILE}", path.display()));
            }
            return std::fs::read(&path).map(|b| (path.clone(), b)).map_err(|e| format!("{}: {e}", path.display()));
        }
    }
    Err(format!("{want} is in none of the map folders ({})", dirs.iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(", ")))
}

/// The hash the gateway pins a map by: SHA-256 of the geometry's deterministic encoding.
pub fn geometry_hash(g: &pb::MapGeometry) -> String {
    use prost::Message;
    hex::encode(Sha256::digest(g.encode_to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `tests/data/cs_fixture.bsp` is `cs_fixture.map` (the brushes of `cs_fixture.brushes`)
    /// compiled by ericw-tools 2.0.0-alpha11, `qbsp -hlbsp -notex`: a file from a real map
    /// compiler, independent of this reader.
    const FIXTURE: &[u8] = include_bytes!("../tests/data/cs_fixture.bsp");
    const BRUSHES: &str = include_str!("../tests/data/cs_fixture.brushes");

    /// A convex brush as planes (normal, distance); inside is behind all of them.
    fn brushes() -> Vec<Vec<[f64; 4]>> {
        let mut out = Vec::new();
        for line in BRUSHES.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let mut w = line.split_whitespace();
            let kind = w.next().unwrap();
            let v: Vec<f64> = w.map(|x| x.parse().unwrap()).collect();
            let (x0, y0, z0, x1, y1, z1) = (v[0], v[1], v[2], v[3], v[4], v[5]);
            let mut b = vec![[1.0, 0.0, 0.0, x1], [0.0, 1.0, 0.0, y1], [0.0, -1.0, 0.0, -y0], [0.0, 0.0, -1.0, -z0]];
            if kind == "box" {
                b.push([-1.0, 0.0, 0.0, -x0]);
                b.push([0.0, 0.0, 1.0, z1]);
            } else {
                let (dx, dz) = (x1 - x0, z1 - z0);
                let l = (dx * dx + dz * dz).sqrt();
                b.push([-dz / l, 0.0, dx / l, (-dz * x0 + dx * z0) / l]);
            }
            out.push(b);
        }
        out
    }

    fn side(p: &[f64; 4], v: [f64; 3]) -> f64 {
        p[0] * v[0] + p[1] * v[1] + p[2] * v[2] - p[3]
    }

    fn contains(b: &[[f64; 4]], v: [f64; 3], margin: f64) -> bool {
        b.iter().all(|p| side(p, v) <= margin)
    }

    fn hits(b: &[[f64; 4]], a: [f64; 3], c: [f64; 3], margin: f64) -> bool {
        let (mut t0, mut t1) = (0.0f64, 1.0f64);
        for p in b {
            let (da, dc) = (side(p, a) + margin, side(p, c) + margin);
            if da > 0.0 && dc > 0.0 {
                return false;
            }
            if da > 0.0 || dc > 0.0 {
                let t = da / (da - dc);
                if da > 0.0 {
                    t0 = t0.max(t);
                } else {
                    t1 = t1.min(t);
                }
            }
            if t0 > t1 {
                return false;
            }
        }
        true
    }

    struct Rng(u64);
    impl Rng {
        fn unit(&mut self) -> f64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 11) as f64 / (1u64 << 53) as f64
        }
        /// A point inside the room of the fixture.
        fn point(&mut self) -> [f64; 3] {
            [self.unit() * 2040.0 - 1020.0, self.unit() * 2040.0 - 1020.0, self.unit() * 504.0 + 4.0]
        }
    }

    fn f(p: [f64; 3]) -> [f32; 3] {
        p.map(|x| x as f32)
    }

    #[test]
    fn a_compiled_map_agrees_with_its_brushes() {
        let w = World::parse(FIXTURE).unwrap();
        assert!(w.nodes.len() >= 20 && w.planes.len() <= w.nodes.len());
        for (i, n) in w.nodes.iter().enumerate() {
            assert!((n[0] as usize) < w.planes.len());
            assert!(n[1..].iter().all(|&c| c == OPEN || c == SOLID || c > i as i32 && (c as usize) < w.nodes.len()), "node {i}: {n:?}");
        }
        let brushes = brushes();
        let mut rng = Rng(11);
        let (mut points, mut solid, mut lines, mut blocked) = (0, 0, 0, 0);
        for _ in 0..100_000 {
            let p = rng.point();
            let (inside, near) = (brushes.iter().any(|b| contains(b, p, -0.1)), brushes.iter().any(|b| contains(b, p, 0.1)));
            if inside != near {
                continue;
            }
            points += 1;
            solid += inside as u32;
            assert_eq!(w.solid(f(p)), inside, "point {p:?}");
        }
        for _ in 0..100_000 {
            let (a, b) = (rng.point(), rng.point());
            let (hit, graze) = (brushes.iter().any(|br| hits(br, a, b, 0.1)), brushes.iter().any(|br| hits(br, a, b, -0.1)));
            if hit != graze {
                continue;
            }
            lines += 1;
            blocked += hit as u32;
            assert_eq!(w.blocked(f(a), f(b)), hit, "line {a:?} - {b:?}");
        }
        assert!(points > 90_000 && solid > 3_000 && lines > 90_000 && blocked > 20_000 && lines - blocked > 20_000, "{points} {solid} {lines} {blocked}");
        // Outside the sealed room is solid in a compiled map.
        assert!(w.solid([3000.0, 0.0, 100.0]) && w.blocked([0.0, 900.0, 100.0], [0.0, 3000.0, 100.0]));
    }

    #[test]
    fn the_geometry_is_in_centimetres_and_names_its_file() {
        let w = World::parse(FIXTURE).unwrap();
        let g = w.geometry("cs_fixture");
        let st = g.solid.as_ref().unwrap();
        assert_eq!((st.planes.len(), st.nodes.len()), (w.planes.len() * 4, w.nodes.len() * 3));
        for (i, p) in w.planes.iter().enumerate() {
            assert_eq!(&st.planes[i * 4..i * 4 + 3], &p[..3]);
            assert!((st.planes[i * 4 + 3] - p[3] * 2.54).abs() < 1e-3);
        }
        assert_eq!(g.source_sha256, w.sha256.to_vec());
        assert_eq!(hex::encode(&g.source_sha256), "904481bc3653f3db853ea9595da63ac71d1a7ab44806c241b231c710433bf2a6");
        assert!(g.version != 0 && g.map_id == "cs_fixture" && g.occluders.is_empty());
        // The gateway computes this hash from the same message; the two must agree for a
        // pin written from `map-hash` to match.
        assert_eq!(geometry_hash(&g), "09b4e45e4aeb5616f51d52b07a5dd52a5aeb585bfdba8d946af40b1403832cc9");
    }

    fn patched(at: usize, bytes: &[u8]) -> Vec<u8> {
        let mut v = FIXTURE.to_vec();
        v[at..at + bytes.len()].copy_from_slice(bytes);
        v
    }

    fn lump_off(index: usize) -> usize {
        i32_at(FIXTURE, 4 + index * 8) as usize
    }

    #[test]
    fn a_broken_file_is_refused() {
        let err = |v: Vec<u8>| World::parse(&v).unwrap_err();
        assert!(err(FIXTURE[..100].to_vec()).contains("too short"));
        assert!(err(patched(0, &29i32.to_le_bytes())).contains("version 29"));
        assert!(err(patched(4 + LUMP_NODES * 8, &i32::MAX.to_le_bytes())).contains("past the end"));
        assert!(err(patched(4 + LUMP_NODES * 8, &(-4i32).to_le_bytes())).contains("negative"));
        assert!(err(patched(8 + LUMP_NODES * 8, &25i32.to_le_bytes())).contains("whole number"));
        assert!(err(patched(8 + LUMP_MODELS * 8, &0i32.to_le_bytes())).contains("no world model"));
        assert!(err(patched(lump_off(LUMP_MODELS) + 36, &9999i32.to_le_bytes())).contains("root node"));
        let root = i32_at(FIXTURE, lump_off(LUMP_MODELS) + 36) as usize;
        let node = lump_off(LUMP_NODES) + root * NODE_SIZE;
        assert!(err(patched(node, &9999i32.to_le_bytes())).contains("plane that does not exist"));
        assert!(err(patched(node + 4, &(root as i16).to_le_bytes())).contains("reached twice"));
        assert!(err(patched(node + 4, &30000i16.to_le_bytes())).contains("child node"));
        assert!(err(patched(node + 6, &(-30000i16).to_le_bytes())).contains("names leaf"));
        let plane = lump_off(LUMP_PLANES) + i32_at(FIXTURE, node) as usize * PLANE_SIZE;
        assert!(err(patched(plane, &f32::NAN.to_le_bytes())).contains("unit normal"));
        assert!(err(patched(plane + 12, &f32::INFINITY.to_le_bytes())).contains("unit normal"));
        // Every leaf open: nothing solid is left.
        let mut open = FIXTURE.to_vec();
        let leaves = lump_off(LUMP_LEAVES);
        for i in 0..i32_at(FIXTURE, 8 + LUMP_LEAVES * 8) as usize / LEAF_SIZE {
            open[leaves + i * LEAF_SIZE..leaves + i * LEAF_SIZE + 4].copy_from_slice(&(-1i32).to_le_bytes());
        }
        assert!(err(open).contains("no solid"));
        // Random damage never panics.
        let mut rng = Rng(5);
        for _ in 0..3000 {
            let mut v = FIXTURE.to_vec();
            for _ in 0..4 {
                let at = (rng.unit() * v.len() as f64) as usize;
                v[at] = (rng.unit() * 256.0) as u8;
            }
            let _ = World::parse(&v).map(|w| w.blocked([-900.0, -900.0, 50.0], [900.0, 900.0, 400.0]));
        }
    }

    #[test]
    fn a_map_file_is_found_whatever_its_case() {
        let dir = std::env::temp_dir().join(format!("carthago-bsp-test-{}", std::process::id()));
        let maps = dir.join("maps");
        std::fs::create_dir_all(&maps).unwrap();
        std::fs::write(maps.join("De_Test.BSP"), FIXTURE).unwrap();
        let dirs = vec![dir.join("missing"), maps.clone()];
        let (path, bytes) = find(&dirs, "de_test").unwrap();
        assert!(path.ends_with("De_Test.BSP") && bytes == FIXTURE);
        assert!(find(&dirs, "de_other").unwrap_err().contains("in none of the map folders"));
        for bad in ["", "../de_test", "maps/de_test", "de test", "a\\b", "c:de_test"] {
            assert!(find(&dirs, bad).unwrap_err().contains("not a usable map name"), "{bad}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
