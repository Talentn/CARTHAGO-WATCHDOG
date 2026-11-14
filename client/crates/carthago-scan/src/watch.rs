//! When a companion takes its picture of a started game, and what it remembers of the
//! first start it ever saw. Both are plain bookkeeping with no Windows calls, so they are
//! tested on every platform.
//!
//! A game that the SDK is not built into has no manifest to compare against. A modified
//! build loads its own unsigned files, maps code itself and may replace system libraries,
//! and does so at every start. What tells that apart from tampering is time:
//! - whatever is there once the game has finished starting is the picture ([`Baseline`]);
//!   what arrives later is a change;
//! - whatever was there at the first recorded start of a game folder ([`StartProfile`]) is
//!   taken to be the build; something that is there at a later start and was not there at
//!   the first one is new.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// Bits of `ObservedFlags` in the protocol.
pub mod observed {
    pub const AFTER_START: u64 = 1;
    pub const AT_START: u64 = 2;
    pub const KNOWN_START: u64 = 4;
    pub const SHADOWS_SYSTEM: u64 = 8;
    pub const FILE_CHANGED: u64 = 16;
    pub const NEW_FILE: u64 = 32;
    pub const FIRST_START: u64 = 64;
}

/// A game file compared with the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    /// The file that had this path when it was first seen, or no record is kept.
    Same,
    /// Another file had this path when it was first seen.
    Changed,
    /// Nothing was seen loaded from this path before this run.
    New,
}

/// How long a game is given to finish starting.
#[derive(Debug, Clone, Copy)]
pub struct Settle {
    /// The picture is not taken before the engine has been loaded for this long.
    pub min: Duration,
    /// Nor while modules are still arriving: none may have been new for this long.
    pub quiet: Duration,
    /// It is taken after this long whatever happens, counted from the start of the game.
    pub max: Duration,
}

impl Settle {
    /// `secs` after the engine is loaded, a quarter of that without a new module, and four
    /// times that at the latest.
    pub fn after(secs: u32) -> Self {
        let secs = secs.clamp(2, 600) as u64;
        Self { min: Duration::from_secs(secs), quiet: Duration::from_secs((secs / 4).clamp(1, 5)), max: Duration::from_secs(secs * 4) }
    }
}

impl Default for Settle {
    fn default() -> Self {
        Self::after(20)
    }
}

/// Decides the moment of the picture from what the module scan sees pass by pass.
#[derive(Debug, Clone)]
pub struct Baseline {
    settle: Settle,
    started: Instant,
    engine_seen: Option<Instant>,
    last_new: Instant,
    settled: Option<Instant>,
}

impl Baseline {
    pub fn new(settle: Settle, now: Instant) -> Self {
        Self { settle, started: now, engine_seen: None, last_new: now, settled: None }
    }

    /// One pass over the game's modules ended at `now`. Returns true on the pass that
    /// takes the picture.
    pub fn pass(&mut self, now: Instant, new_modules: bool, engine_loaded: bool) -> bool {
        if self.settled.is_some() {
            return false;
        }
        if new_modules {
            self.last_new = now;
        }
        if engine_loaded && self.engine_seen.is_none() {
            self.engine_seen = Some(now);
        }
        let ready = self.engine_seen.is_some_and(|t| now.duration_since(t) >= self.settle.min) && now.duration_since(self.last_new) >= self.settle.quiet;
        if ready || now.duration_since(self.started) >= self.settle.max {
            self.settled = Some(now);
            return true;
        }
        false
    }

    /// The picture by the clock: `max` after the game started it is taken whether or not
    /// the module scan has finished a pass by then. Without this, a module scan that the
    /// scheduler has stopped, or that never gets through the list, means no picture at all.
    pub fn expire(&mut self, now: Instant) -> bool {
        if self.settled.is_none() && now.duration_since(self.started) >= self.settle.max {
            self.settled = Some(now);
            return true;
        }
        false
    }

    pub fn settled(&self) -> bool {
        self.settled.is_some()
    }

    /// Seconds from the start of the game to the picture.
    pub fn settled_after(&self) -> Option<u32> {
        self.settled.map(|t| t.duration_since(self.started).as_secs() as u32)
    }

    pub fn secs_since_start(&self, now: Instant) -> u32 {
        now.duration_since(self.started).as_secs().min(u32::MAX as u64) as u32
    }
}

const HEADER: &str = "carthago start profile v1";

/// What the first recorded start of a game folder showed, kept in a small text file by the
/// companion. Two kinds of entries:
/// - `start <key>`: something of the kind that is reported with `AT_START` (a library that
///   shadows a system one, an unsigned module from outside the game folder, an image mapped
///   by hand). Recorded during the first start only, and never added to afterwards:
///   otherwise something that is there at one start would be excused at the next.
/// - `file <digest> <path>`: the content of a game file the first time it was seen loaded.
///   A path that was never loaded before is added when it first is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartProfile {
    /// No file was given: nothing can be compared, so everything at start counts as known.
    absent: bool,
    /// This is the first recorded start.
    learning: bool,
    start: BTreeSet<String>,
    files: BTreeMap<String, String>,
    /// Kinds of things of which a whole look at a started game has been recorded.
    whole: BTreeSet<String>,
    /// Kinds this run still records: the game was closed before they had been looked at.
    open: BTreeSet<String>,
    dirty: bool,
}

/// Kinds that are found by a job of their own, some seconds after the picture is taken. A
/// run that ends before that has not shown them, and the next run goes on recording them.
const LATE_KINDS: [&str; 2] = ["mapped", "holder"];

impl StartProfile {
    /// For a companion that keeps no record.
    pub fn none() -> Self {
        Self { absent: true, ..Self::default() }
    }

    /// `text` is the file's content, `None` when there is no file yet.
    pub fn load(text: Option<&str>) -> Self {
        let Some(text) = text.filter(|t| t.lines().next().map(str::trim) == Some(HEADER)) else {
            return Self { learning: true, dirty: true, ..Self::default() };
        };
        let mut p = Self::default();
        for line in text.lines().skip(1) {
            match line.trim().split_once(' ') {
                Some(("start", key)) => {
                    p.start.insert(key.trim().to_owned());
                }
                Some(("file", rest)) => {
                    if let Some((digest, path)) = rest.trim().split_once(' ') {
                        p.files.insert(path.trim().to_owned(), digest.to_owned());
                    }
                }
                Some(("whole", kind)) => {
                    p.whole.insert(kind.trim().to_owned());
                }
                _ => {}
            }
        }
        p.open = LATE_KINDS.iter().filter(|k| !p.whole.contains(**k)).map(|k| (*k).to_owned()).collect();
        p
    }

    pub fn learning(&self) -> bool {
        self.learning
    }

    /// Something is there at this start. True when it was there at the first recorded start
    /// too (or this is the first, or no record is kept).
    pub fn known_at_start(&mut self, key: &str) -> bool {
        let key = clean(key);
        if self.absent {
            return true;
        }
        if self.learning || key.split(':').next().is_some_and(|kind| self.open.contains(kind)) {
            self.dirty |= self.start.insert(key);
            return true;
        }
        self.start.contains(&key)
    }

    /// A whole look at the started game was made for things whose keys begin with `kind`.
    pub fn whole(&mut self, kind: &str) {
        if !self.absent {
            self.dirty |= self.whole.insert(kind.to_owned());
        }
    }

    /// Kinds no run has looked at in full yet: the next run goes on recording them.
    pub fn unrecorded(&self) -> Vec<&'static str> {
        if self.absent {
            return Vec::new();
        }
        LATE_KINDS.iter().filter(|k| !self.whole.contains(**k)).copied().collect()
    }

    /// A game file was seen loaded. A path that is new is recorded; during the first
    /// recorded start every path is, and none of them counts as new.
    pub fn file(&mut self, path: &str, digest: &str) -> FileState {
        if self.absent {
            return FileState::Same;
        }
        let path = clean(path);
        match self.files.get(&path) {
            Some(first) if first == digest => FileState::Same,
            Some(_) => FileState::Changed,
            None => {
                self.files.insert(path, digest.to_owned());
                self.dirty = true;
                if self.learning {
                    FileState::Same
                } else {
                    FileState::New
                }
            }
        }
    }

    /// The file's new content, when there is something to write. A first start stays a
    /// first start until the companion ends: what is found late in it still counts.
    pub fn save(&mut self) -> Option<String> {
        if self.absent || !self.dirty {
            return None;
        }
        self.dirty = false;
        let mut out = format!("{HEADER}\n");
        for k in &self.start {
            out.push_str(&format!("start {k}\n"));
        }
        for (path, digest) in &self.files {
            out.push_str(&format!("file {digest} {path}\n"));
        }
        for k in &self.whole {
            out.push_str(&format!("whole {k}\n"));
        }
        Some(out)
    }

    pub fn start_entries(&self) -> usize {
        self.start.len()
    }

    pub fn file_entries(&self) -> usize {
        self.files.len()
    }
}

fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect::<String>().trim().to_lowercase()
}

/// Libraries of the Windows system directory are found there and nowhere else. For a 32-bit
/// game on 64-bit Windows that directory is SysWOW64.
pub fn system_copy(windows_dir: &str, wow64: bool, base_name: &str) -> String {
    let dir = windows_dir.trim_end_matches(['\\', '/']);
    format!("{dir}\\{}\\{base_name}", if wow64 { "SysWOW64" } else { "System32" })
}

/// The file behind a module that a game's loader lists under the Windows directory. The
/// loader of a 32-bit game on 64-bit Windows names many of its libraries under `System32`
/// although they were read from `SysWOW64`, and a 64-bit companion that opens the
/// `System32` path gets the 64-bit file. Only the few 64-bit libraries of such a game,
/// which sit above 4 GB, are what their path says.
pub fn loaded_system_file(path: &str, wow64: bool, base: usize) -> String {
    const SYSTEM32: &str = "\\system32\\";
    let lower = path.to_ascii_lowercase().replace('/', "\\");
    match lower.find(SYSTEM32) {
        Some(i) if wow64 && (base as u64) <= u32::MAX as u64 => format!("{}\\SysWOW64\\{}", &path[..i], &path[i + SYSTEM32.len()..]),
        _ => path.to_owned(),
    }
}

/// Where a jump that an inline hook wrote into 32-bit code leads. `code` is the memory at
/// `addr`; `read_u32` reads a pointer for `jmp dword ptr [abs32]`.
pub fn jump32(code: &[u8], addr: u32, read_u32: impl Fn(u32) -> Option<u32>) -> crate::hook::Patch {
    use crate::hook::Patch;
    let u32_at = |i: usize| code.get(i..i + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()));
    match (code.first().copied(), code.get(1).copied()) {
        // jmp rel32, call rel32
        (Some(0xE9 | 0xE8), _) => u32_at(1).map_or(Patch::Unknown, |r| Patch::Jump(addr.wrapping_add(5).wrapping_add(r) as u64)),
        (Some(0xEB), Some(r)) => Patch::Jump(addr.wrapping_add(2).wrapping_add(r as i8 as i32 as u32) as u64),
        // jmp dword ptr [abs32]
        (Some(0xFF), Some(0x25)) => u32_at(2).and_then(&read_u32).map_or(Patch::Unknown, |t| Patch::Jump(t as u64)),
        // push imm32; ret
        (Some(0x68), _) if code.get(5) == Some(&0xC3) => u32_at(1).map_or(Patch::Unknown, |t| Patch::Jump(t as u64)),
        // mov eax, imm32; jmp eax
        (Some(0xB8), _) if code.get(5..7) == Some(&[0xFF, 0xE0]) => u32_at(1).map_or(Patch::Unknown, |t| Patch::Jump(t as u64)),
        (Some(0xCC), _) => Patch::Breakpoint,
        _ => Patch::Unknown,
    }
}

/// Bytes of a code change that are kept to recognise its undoing.
pub const PATCH: usize = 16;
const MAX_RUNS: usize = 8;

/// Stretches in which `now` differs from `was`, as index ranges. Differences less than
/// [`PATCH`] bytes apart are one stretch (bytes of a written instruction that happen to
/// equal the old ones do not split it); at most eight are returned.
pub fn diff_runs(now: &[u8], was: &[u8]) -> Vec<(usize, usize)> {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for (i, (a, b)) in now.iter().zip(was).enumerate() {
        if a == b {
            continue;
        }
        let joins = runs.last().is_some_and(|&(_, end)| i < end + PATCH);
        if joins {
            runs.last_mut().unwrap().1 = i + 1;
        } else if runs.len() == MAX_RUNS {
            break;
        } else {
            runs.push((i, i + 1));
        }
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::Patch;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn the_picture_is_taken_by_the_clock_when_no_pass_comes() {
        let t0 = Instant::now();
        let mut b = Baseline::new(Settle::after(20), t0);
        assert!(!b.expire(t0 + Duration::from_secs(79)));
        assert!(!b.settled());
        assert!(b.expire(t0 + Duration::from_secs(80)));
        assert_eq!(b.settled_after(), Some(80));
        // Taken once: neither the clock nor a late pass takes it again.
        assert!(!b.expire(t0 + Duration::from_secs(200)));
        assert!(!b.pass(t0 + Duration::from_secs(201), true, true));
        assert_eq!(b.settled_after(), Some(80));

        // A module scan that works takes it first, and the clock leaves it alone.
        let mut b = Baseline::new(Settle::after(20), t0);
        assert!(!b.pass(t0 + Duration::from_secs(2), true, true));
        assert!(b.pass(t0 + Duration::from_secs(23), false, true));
        assert!(!b.expire(t0 + Duration::from_secs(300)));
        assert_eq!(b.settled_after(), Some(23));
    }

    #[test]
    fn the_picture_waits_for_the_engine_and_for_quiet() {
        let t0 = Instant::now();
        let mut b = Baseline::new(Settle::after(20), t0);
        assert!(!b.pass(t0 + secs(5), true, false), "no engine yet");
        assert!(!b.pass(t0 + secs(10), true, true), "engine first seen now");
        assert!(!b.pass(t0 + secs(25), false, true), "15 s after the engine");
        assert!(!b.pass(t0 + secs(30), true, true), "20 s after the engine, but a module just arrived");
        assert!(!b.pass(t0 + secs(33), false, true), "3 s of quiet is not 5");
        assert!(b.pass(t0 + secs(35), false, true));
        assert!(b.settled() && b.settled_after() == Some(35));
        assert!(!b.pass(t0 + secs(40), true, true), "taken once");
    }

    #[test]
    fn the_picture_is_taken_at_the_latest_time_even_without_an_engine() {
        let t0 = Instant::now();
        let mut b = Baseline::new(Settle::after(20), t0);
        assert!(!b.pass(t0 + secs(79), true, false));
        assert!(b.pass(t0 + secs(80), true, false));
    }

    #[test]
    fn first_start_is_learned_and_later_starts_are_compared() {
        let mut first = StartProfile::load(None);
        assert!(first.learning());
        assert!(first.known_at_start("shadow:opengl32.dll:ab12"), "whatever the first start shows is the build");
        assert_eq!(first.file(r"cstrike\cl_dlls\client.dll", "11"), FileState::Same);
        let text = first.save().expect("something to write");
        assert!(first.save().is_none(), "written once");

        let mut later = StartProfile::load(Some(&text));
        assert!(!later.learning());
        assert!(later.known_at_start("SHADOW:opengl32.dll:ab12"));
        assert!(!later.known_at_start("shadow:opengl32.dll:ffff"), "another file under the same name is new");
        assert!(!later.known_at_start("module:other:hook.dll:77"));
        assert!(later.save().is_none(), "start entries are never added after the first start");

        assert_eq!(later.file(r"cstrike\cl_dlls\client.dll", "11"), FileState::Same);
        assert_eq!(later.file(r"CSTRIKE\cl_dlls\client.dll", "22"), FileState::Changed, "the file was replaced");
        assert_eq!(later.file(r"cstrike\dlls\mp.dll", "33"), FileState::New, "a path no earlier run loaded");
        assert_eq!(later.file(r"cstrike\dlls\mp.dll", "33"), FileState::Same, "new once");
        let text = later.save().expect("the new path is written");
        let mut third = StartProfile::load(Some(&text));
        assert_eq!(third.file(r"cstrike\dlls\mp.dll", "34"), FileState::Changed);
        assert_eq!(third.file(r"cstrike\dlls\mp.dll", "33"), FileState::Same);
        assert_eq!(third.file(r"cstrike\cl_dlls\client.dll", "22"), FileState::Changed, "the first content stays the reference");
        assert_eq!((third.start_entries(), third.file_entries()), (1, 2));
    }

    #[test]
    fn a_first_start_that_was_cut_short_is_continued() {
        let mut first = StartProfile::load(None);
        assert!(first.known_at_start("module:other:tool.dll:1"));
        let text = first.save().unwrap();

        // The game was closed before its memory and the other programs had been looked at.
        let mut second = StartProfile::load(Some(&text));
        assert!(!second.learning());
        assert!(!second.known_at_start("module:other:hook.dll:2"), "modules were recorded");
        assert!(second.known_at_start("mapped:aa"), "mapped images were not, so this run records them");
        assert!(second.known_at_start("holder:launcher.exe:3"));
        second.whole("mapped");
        assert!(second.known_at_start("mapped:bb"), "the whole run counts");
        let text = second.save().unwrap();

        assert_eq!(second.unrecorded(), ["holder"]);

        let mut third = StartProfile::load(Some(&text));
        assert!(third.known_at_start("mapped:aa") && third.known_at_start("mapped:bb"));
        assert!(!third.known_at_start("mapped:cc"), "recorded now, so another one is new");
        assert!(third.known_at_start("holder:other.exe:4"), "other programs still were not looked at");
    }

    #[test]
    fn without_a_record_nothing_at_start_is_new() {
        let mut p = StartProfile::none();
        assert!(p.known_at_start("anything"));
        assert!(p.file("a", "1") == FileState::Same && p.file("a", "2") == FileState::Same);
        assert!(p.save().is_none());
    }

    #[test]
    fn a_damaged_file_starts_over() {
        assert!(StartProfile::load(Some("garbage")).learning());
        assert!(StartProfile::load(Some("")).learning());
    }

    #[test]
    fn system_copies() {
        assert_eq!(system_copy(r"C:\Windows\", true, "opengl32.dll"), r"C:\Windows\SysWOW64\opengl32.dll");
        assert_eq!(system_copy(r"C:\Windows", false, "opengl32.dll"), r"C:\Windows\System32\opengl32.dll");
        // The file a 32-bit game really loaded, for hashing.
        assert_eq!(loaded_system_file(r"C:\Windows\SYSTEM32\version.dll", true, 0x7400_0000), r"C:\Windows\SysWOW64\version.dll");
        assert_eq!(loaded_system_file(r"C:\Windows\SysWOW64\version.dll", true, 0x7400_0000), r"C:\Windows\SysWOW64\version.dll");
        assert_eq!(loaded_system_file(r"C:\Windows\SYSTEM32\ntdll.dll", true, 0x7ffb_1234_0000), r"C:\Windows\SYSTEM32\ntdll.dll");
        assert_eq!(loaded_system_file(r"C:\Windows\System32\version.dll", false, 0x7400_0000), r"C:\Windows\System32\version.dll");
    }

    #[test]
    fn changed_stretches() {
        let was = vec![0x90u8; 200];
        let mut now = was.clone();
        assert!(diff_runs(&now, &was).is_empty());
        now[10..15].copy_from_slice(&[0xE9, 1, 2, 0x90, 4]);
        now[100] = 0xCC;
        assert_eq!(diff_runs(&now, &was), vec![(10, 15), (100, 101)], "an equal byte inside a patch does not split it");
        assert_eq!(diff_runs(&was, &now), vec![(10, 15), (100, 101)], "undoing a change shows the same stretches");
        let all: Vec<u8> = (0..200).map(|i| if i % 20 == 0 { 0 } else { 0x90 }).collect();
        assert_eq!(diff_runs(&all, &was).len(), 8, "bounded");
    }

    #[test]
    fn decodes_32_bit_jumps() {
        let none = |_| None;
        assert_eq!(jump32(&[0xE9, 0xFB, 0xFF, 0xFF, 0xFF], 0x1000, none), Patch::Jump(0x1000));
        assert_eq!(jump32(&[0xE9, 0x00, 0x00, 0x00, 0x80], 0x9000_0000, none), Patch::Jump(0x1000_0005), "wraps at 4 GB");
        assert_eq!(jump32(&[0xEB, 0xFE], 0x1000, none), Patch::Jump(0x1000));
        assert_eq!(jump32(&[0x68, 0x78, 0x56, 0x34, 0x12, 0xC3], 0x1000, none), Patch::Jump(0x1234_5678));
        assert_eq!(jump32(&[0xB8, 0x78, 0x56, 0x34, 0x12, 0xFF, 0xE0], 0x1000, none), Patch::Jump(0x1234_5678));
        assert_eq!(jump32(&[0xFF, 0x25, 0x00, 0x20, 0x00, 0x00], 0x1000, |a| (a == 0x2000).then_some(0x7000_0000)), Patch::Jump(0x7000_0000));
        assert_eq!(jump32(&[0xFF, 0x25, 0x00, 0x20, 0x00, 0x00], 0x1000, none), Patch::Unknown);
        assert_eq!(jump32(&[0xCC], 0x1000, none), Patch::Breakpoint);
        assert_eq!(jump32(&[0x90, 0x90], 0x1000, none), Patch::Unknown);
    }
}
