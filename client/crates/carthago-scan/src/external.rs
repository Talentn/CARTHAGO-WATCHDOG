//! Watching a game from a companion process beside it, for games the SDK cannot be built
//! into. Everything here opens the game with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
//! SYNCHRONIZE` only: it can ask the kernel about the process and read its memory, and it
//! cannot write to it, create threads in it, change its protections or suspend it. Nothing
//! is injected and nothing in the game is patched or hooked.
//!
//! What that buys, compared with the in-process scanners:
//! - liveness, the loader's module list with each file's Authenticode state, a summary of
//!   executable memory with no backing image, debugger attachment, other processes' handles
//!   to the game, overlay windows over it, and known-vulnerable drivers;
//! - changes against a picture taken once the game has finished starting ([`Watch`]): a
//!   module that arrives later, an image mapped by hand that appears later, and code of the
//!   renderer, engine and client libraries that is rewritten later, with the module a
//!   written jump leads to. Also a library that stands in for a Windows system library;
//! - no view of what runs inside: thread start addresses, function pointers in the game's
//!   data, and the game's own clocks are not checked. Executable private memory without a PE
//!   header cannot be judged per region, because the engine's own loader, script JITs and
//!   graphics drivers look the same from outside. Code that was already rewritten when the
//!   picture was taken is part of the picture.
//!
//! The jobs are bound to a [`TargetCell`], which stays empty until the companion has started
//! the game, so the scheduler (and the gateway session) can be up before the game is.

use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use carthago_proto::v1::{CodeChangeKind, DebugSignal, FindingCode, ModulePathClass, ModuleSignature, UnbackedFlags};
use carthago_sched::{Ctx, Job, JobBudget, Step};
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessDebugFlags, ProcessDebugObjectHandle, ProcessDebugPort};
use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, HANDLE, HMODULE, WAIT_TIMEOUT};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE};
use windows_sys::Win32::System::ProcessStatus::{
    K32EnumProcessModulesEx, K32EnumProcesses, K32GetModuleFileNameExW, K32GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, GetProcessId, IsWow64Process, OpenProcess, WaitForSingleObject,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use crate::hook::{self, Patch};
use crate::paths::{base_name, Dirs};
use crate::seen::{fnv1a, Seen};
use crate::signature;
use crate::watch::{self, observed, Baseline, FileState, Settle, StartProfile, PATCH};
use crate::win::{self, Owned};

const SYNCHRONIZE: u32 = 0x0010_0000;

/// The only access a companion ever holds on the game.
pub const READ_ONLY_ACCESS: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE;

/// A read-only handle to the watched game process.
pub struct Target {
    handle: Owned,
    pid: u32,
    wow64: bool,
}

// SAFETY: a process handle may be used from any thread, and every use here is a read.
unsafe impl Sync for Target {}

impl Target {
    pub fn open(pid: u32) -> std::io::Result<Self> {
        let h = unsafe { OpenProcess(READ_ONLY_ACCESS, 0, pid) };
        if h.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self::wrap(h))
    }

    /// Takes the handle `CreateProcess` returned, swaps it for a read-only duplicate and
    /// closes the original, so the companion does not keep full access to its child.
    ///
    /// # Safety
    /// `full` must be a valid process handle owned by the caller; it is closed here.
    pub unsafe fn from_created(full: HANDLE) -> std::io::Result<Self> {
        let mut ro: HANDLE = std::ptr::null_mut();
        let me = unsafe { GetCurrentProcess() };
        let ok = unsafe { DuplicateHandle(me, full, me, &mut ro, READ_ONLY_ACCESS, 0, 0) };
        let err = std::io::Error::last_os_error();
        unsafe { CloseHandle(full) };
        if ok == 0 {
            return Err(err);
        }
        Ok(Self::wrap(ro))
    }

    fn wrap(h: HANDLE) -> Self {
        let mut wow = 0;
        unsafe { IsWow64Process(h, &mut wow) };
        Self { pid: unsafe { GetProcessId(h) }, handle: Owned(h), wow64: wow != 0 }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// A 32-bit game on 64-bit Windows.
    pub fn is_wow64(&self) -> bool {
        self.wow64
    }

    pub fn alive(&self) -> bool {
        unsafe { WaitForSingleObject(self.handle.0, 0) == WAIT_TIMEOUT }
    }

    /// Blocks up to `timeout`; true when the process has exited.
    pub fn wait_exit(&self, timeout: Duration) -> bool {
        unsafe { WaitForSingleObject(self.handle.0, timeout.as_millis().min(u32::MAX as u128 - 1) as u32) != WAIT_TIMEOUT }
    }

    pub fn exit_code(&self) -> Option<u32> {
        let mut code = 0u32;
        (unsafe { GetExitCodeProcess(self.handle.0, &mut code) } != 0 && !self.alive()).then_some(code)
    }

    fn query(&self, addr: usize) -> Option<MEMORY_BASIC_INFORMATION> {
        let mut m: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let n = unsafe { VirtualQueryEx(self.handle.0, addr as *const c_void, &mut m, size_of::<MEMORY_BASIC_INFORMATION>()) };
        (n != 0).then_some(m)
    }

    fn read(&self, addr: usize, buf: &mut [u8]) -> bool {
        let mut n = 0usize;
        let ok = unsafe { ReadProcessMemory(self.handle.0, addr as *const c_void, buf.as_mut_ptr().cast(), buf.len(), &mut n) };
        ok != 0 && n == buf.len()
    }

    /// Loader-list module bases. Empty while the process is still initialising.
    fn modules(&self, out: &mut Vec<usize>) {
        let mut buf: Vec<HMODULE> = vec![std::ptr::null_mut(); 512];
        out.clear();
        for _ in 0..3 {
            let mut needed = 0u32;
            let ok = unsafe {
                K32EnumProcessModulesEx(self.handle.0, buf.as_mut_ptr(), (buf.len() * size_of::<HMODULE>()) as u32, &mut needed, LIST_MODULES_ALL)
            };
            if ok == 0 {
                return;
            }
            let n = needed as usize / size_of::<HMODULE>();
            if n <= buf.len() {
                out.extend(buf[..n].iter().map(|&h| h as usize));
                return;
            }
            buf.resize(n + 16, std::ptr::null_mut());
        }
    }

    fn module_size(&self, base: usize) -> usize {
        let mut info: MODULEINFO = unsafe { std::mem::zeroed() };
        let ok = unsafe { K32GetModuleInformation(self.handle.0, base as HMODULE, &mut info, size_of::<MODULEINFO>() as u32) };
        if ok != 0 {
            info.SizeOfImage as usize
        } else {
            0
        }
    }

    fn read_u32(&self, addr: u32) -> Option<u32> {
        let mut b = [0u8; 4];
        self.read(addr as usize, &mut b).then(|| u32::from_le_bytes(b))
    }

    fn read_u64(&self, addr: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        self.read(addr as usize, &mut b).then(|| u64::from_le_bytes(b))
    }

    fn module_path(&self, base: usize) -> Option<String> {
        let mut buf = vec![0u16; 1024];
        let n = unsafe { K32GetModuleFileNameExW(self.handle.0, base as HMODULE, buf.as_mut_ptr(), buf.len() as u32) } as usize;
        (n != 0).then(|| String::from_utf16_lossy(&buf[..n.min(buf.len())]))
    }

    /// Full path of the process image, or empty when the process is gone.
    pub fn image_path(&self) -> String {
        win::process_image_path_of(self.handle.0)
    }

    /// The first of `names` (lower-case base names) that is in the process's loader list.
    pub fn loaded_module(&self, names: &[&str]) -> Option<String> {
        let mut bases = Vec::new();
        self.modules(&mut bases);
        bases.iter().filter_map(|&b| self.module_path(b)).map(|p| crate::paths::base_name(&p).to_lowercase()).find(|n| names.contains(&n.as_str()))
    }

    /// End of the address range worth walking: 4 GB for a 32-bit game, so the 64-bit side of
    /// WOW64 is not mistaken for the game's own memory.
    fn top(&self) -> usize {
        if self.wow64 {
            0x1_0000_0000
        } else {
            0x7FFF_FFFF_0000
        }
    }
}

fn folder_of(path: &str) -> String {
    let p = path.strip_prefix(r"\\?\").unwrap_or(path).replace('/', "\\").to_lowercase();
    p.rsplit_once('\\').map_or(String::new(), |(dir, _)| dir.trim_end_matches('\\').to_owned())
}

/// Looks for the game a launcher started: a process, other than `skip` and this one, whose
/// image is in the same folder as `exe`, whose name `accept` allows, and which has loaded
/// one of `markers` (lower-case module base names; for GoldSrc the engine DLL). Each
/// candidate is opened with the same read-only access as any other target. Costs one pass
/// over the process list, so callers poll it sparingly and only while the game is unknown.
pub fn find_started_game(exe: &str, markers: &[&str], skip: &[u32], accept: &dyn Fn(&str) -> bool) -> Option<(Target, String)> {
    let dir = folder_of(exe);
    if dir.is_empty() {
        return None;
    }
    let mut pids = vec![0u32; 2048];
    let mut bytes = 0u32;
    if unsafe { K32EnumProcesses(pids.as_mut_ptr(), (pids.len() * 4) as u32, &mut bytes) } == 0 {
        return None;
    }
    let me = unsafe { GetCurrentProcessId() };
    for &pid in &pids[..(bytes as usize / 4).min(pids.len())] {
        if pid == 0 || pid == me || skip.contains(&pid) {
            continue;
        }
        let Ok(t) = Target::open(pid) else { continue };
        let image = t.image_path();
        if folder_of(&image) != dir || !accept(crate::paths::base_name(&image)) || !t.alive() {
            continue;
        }
        if let Some(marker) = t.loaded_module(markers) {
            return Some((t, marker));
        }
    }
    None
}

/// Late-bound target shared by the external jobs.
#[derive(Default)]
pub struct TargetCell(Mutex<Option<Arc<Target>>>);

impl TargetCell {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set(&self, t: Arc<Target>) {
        *self.0.lock().unwrap() = Some(t);
    }

    pub fn clear(&self) {
        *self.0.lock().unwrap() = None;
    }

    pub fn get(&self) -> Option<Arc<Target>> {
        self.0.lock().unwrap().clone()
    }

    fn live(&self) -> Option<Arc<Target>> {
        self.get().filter(|t| t.alive())
    }
}

/// A module of the game as the external jobs know it.
#[derive(Debug, Clone)]
pub struct Module {
    pub base: usize,
    pub size: usize,
    /// Lower-case base name.
    pub name: String,
    /// `None` under the Windows directory.
    pub class: Option<ModulePathClass>,
    /// `None` until the signature thread has looked at the file (never for Windows files).
    pub sig: Option<ModuleSignature>,
    /// First seen after the picture was taken.
    pub after_start: bool,
    /// Seconds from the start of the game to the first sight of the module.
    pub seen_secs: u32,
    /// Loaded from an `addons` folder: a server add-on (Metamod, AMX Mod X and their
    /// modules), present in the process of a listen server.
    pub addon: bool,
}

/// What a companion watches for in a particular game.
pub struct WatchConfig {
    /// Lower-case base names of the engine libraries; the picture waits for one of them.
    pub engine_modules: Vec<String>,
    /// Lower-case base names of the libraries whose code is compared with the picture.
    pub code_modules: Vec<String>,
    pub settle: Settle,
    pub profile: StartProfile,
}

struct WatchInner {
    pid: u32,
    baseline: Option<Baseline>,
    modules: Vec<Module>,
    profile: StartProfile,
}

/// For the companion's log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchStatus {
    /// Seconds from the start of the game to the picture, once it is taken.
    pub settled_after: Option<u32>,
    pub modules: usize,
    pub first_start: bool,
}

/// The picture of the started game, shared by the external jobs: when it was taken, which
/// modules are loaded, and the record of the first start.
pub struct Watch {
    cell: Arc<TargetCell>,
    engine: Vec<String>,
    code: Vec<String>,
    settle: Settle,
    inner: Mutex<WatchInner>,
}

impl Watch {
    pub fn new(cell: Arc<TargetCell>, cfg: WatchConfig) -> Arc<Self> {
        Arc::new(Self {
            cell,
            engine: cfg.engine_modules,
            code: cfg.code_modules,
            settle: cfg.settle,
            inner: Mutex::new(WatchInner { pid: 0, baseline: None, modules: Vec::new(), profile: cfg.profile }),
        })
    }

    /// The live target. A new process (a launcher handed over to the game) starts a new
    /// picture.
    pub(crate) fn target(&self) -> Option<Arc<Target>> {
        let t = self.cell.live()?;
        let mut w = self.inner.lock().unwrap();
        if w.pid != t.pid() {
            w.pid = t.pid();
            w.baseline = Some(Baseline::new(self.settle, Instant::now()));
            w.modules.clear();
        }
        Some(t)
    }

    /// True once the picture of process `pid` is taken.
    pub(crate) fn settled(&self, pid: u32) -> bool {
        let w = self.inner.lock().unwrap();
        w.pid == pid && w.baseline.as_ref().is_some_and(Baseline::settled)
    }

    fn secs(&self) -> u32 {
        self.inner.lock().unwrap().baseline.as_ref().map_or(0, |b| b.secs_since_start(Instant::now()))
    }

    fn pass(&self, new_modules: bool) {
        let mut w = self.inner.lock().unwrap();
        let engine = w.modules.iter().any(|m| self.engine.contains(&m.name));
        if let Some(b) = w.baseline.as_mut() {
            b.pass(Instant::now(), new_modules, engine);
        }
    }

    fn has_module(&self, base: usize) -> bool {
        self.inner.lock().unwrap().modules.iter().any(|m| m.base == base)
    }

    fn add_module(&self, m: Module) {
        self.inner.lock().unwrap().modules.push(m);
    }

    fn module(&self, base: usize) -> Option<Module> {
        self.inner.lock().unwrap().modules.iter().find(|m| m.base == base).cloned()
    }

    fn set_signature(&self, base: usize, sig: ModuleSignature) {
        if let Some(m) = self.inner.lock().unwrap().modules.iter_mut().find(|m| m.base == base) {
            m.sig = Some(sig);
        }
    }

    /// The module whose image holds `addr`.
    fn module_at(&self, addr: usize) -> Option<Module> {
        self.inner.lock().unwrap().modules.iter().find(|m| addr >= m.base && addr - m.base < m.size.max(1)).cloned()
    }

    fn code_modules(&self) -> Vec<Module> {
        self.inner.lock().unwrap().modules.iter().filter(|m| self.code.contains(&m.name)).cloned().collect()
    }

    fn addons_loaded(&self) -> bool {
        self.inner.lock().unwrap().modules.iter().any(|m| m.addon)
    }

    fn known_at_start(&self, key: &str) -> bool {
        self.inner.lock().unwrap().profile.known_at_start(key)
    }

    fn file(&self, path: &str, digest: &str) -> FileState {
        self.inner.lock().unwrap().profile.file(path, digest)
    }

    /// A job made its first whole pass after the picture was taken: what that pass and the
    /// ones before it showed is the start, for things whose keys begin with `kind`.
    pub(crate) fn whole(&self, kind: &str) {
        self.inner.lock().unwrap().profile.whole(kind);
    }

    /// What the record of the first start still lacks: "mapped" (code mapped by hand) and
    /// "holder" (other programs holding the game open) are looked at some seconds after the
    /// picture is taken.
    pub fn unrecorded(&self) -> Vec<&'static str> {
        self.inner.lock().unwrap().profile.unrecorded()
    }

    pub fn status(&self) -> WatchStatus {
        let w = self.inner.lock().unwrap();
        WatchStatus { settled_after: w.baseline.as_ref().and_then(Baseline::settled_after), modules: w.modules.len(), first_start: w.profile.learning() }
    }

    /// The record of the first start, when there is something new to write. Nothing is
    /// written before the picture is taken: a game that was closed while starting has not
    /// shown what a start looks like.
    pub fn save_profile(&self) -> Option<String> {
        let mut w = self.inner.lock().unwrap();
        if !w.baseline.as_ref().is_some_and(Baseline::settled) {
            return None;
        }
        w.profile.save()
    }
}

/// AT_START with KNOWN_START when `key` was there at the first recorded start, or AFTER_START.
pub(crate) fn observed_flags(watch: &Watch, after_start: bool, key: &str) -> u64 {
    if after_start {
        observed::AFTER_START
    } else if watch.known_at_start(key) {
        observed::AT_START | observed::KNOWN_START
    } else {
        observed::AT_START
    }
}

/// Module inventory of the game with each file's signature state. Modules under the Windows
/// directory are skipped, as in the in-process inventory; each other module is reported once
/// by base name, path class and [`ModuleSignature`], with [`observed`] flags: whether it was
/// there when the picture was taken, whether it stands in for a system library, and whether
/// a game file is still the file it was at the first recorded start.
pub struct ExtModules {
    watch: Arc<Watch>,
    dirs: Arc<Dirs>,
    cur: Option<Arc<Target>>,
    mods: Vec<usize>,
    idx: usize,
    new_any: bool,
    settled_at_begin: bool,
    waiting: Vec<(usize, ModulePathClass, String)>,
    unchecked: Vec<signature::Checked>,
    seen: Seen,
    sig: Option<signature::Worker>,
}

impl ExtModules {
    pub fn new(watch: Arc<Watch>, dirs: Arc<Dirs>) -> Self {
        Self {
            watch,
            dirs,
            cur: None,
            mods: Vec::new(),
            idx: 0,
            new_any: false,
            settled_at_begin: false,
            waiting: Vec::new(),
            unchecked: Vec::new(),
            seen: Seen::new(1024),
            sig: signature::Worker::start().ok(),
        }
    }

    fn report(&self, ctx: &Ctx<'_>, c: &signature::Checked) {
        let base = c.base as usize;
        let name = c.name.to_lowercase();
        let m = self.watch.module(base);
        let after_start = m.as_ref().is_some_and(|m| m.after_start);
        let secs = m.as_ref().map_or(0, |m| m.seen_secs).min(0xffff) as u64;
        self.watch.set_signature(base, c.state);
        // Only what could be reported as foreign is compared with the first start: a file
        // from outside the game folder and Program Files, or one that shadows a system
        // library. Game files are compared by content instead.
        let when = if after_start { observed::AFTER_START } else { observed::AT_START };
        let mut flags = if c.shadows_system {
            // A build that ships such a library loads it in every run, early or late.
            let known = self.watch.known_at_start(&format!("module:shadow:{name}:{}", c.digest));
            when | observed::SHADOWS_SYSTEM | if known { observed::KNOWN_START } else { 0 }
        } else if c.class == ModulePathClass::Other {
            observed_flags(&self.watch, after_start, &format!("module:other:{name}:{}", c.digest))
        } else if after_start {
            when
        } else {
            when | observed::KNOWN_START
        };
        if c.class == ModulePathClass::GameDir && !c.digest.is_empty() {
            let path = c.path.strip_prefix(r"\\?\").unwrap_or(&c.path).replace('/', "\\").to_lowercase();
            let rel = path.strip_prefix(self.dirs.game.as_str()).unwrap_or(&path);
            flags |= match self.watch.file(rel, &c.digest) {
                FileState::Same => 0,
                FileState::Changed => observed::FILE_CHANGED,
                FileState::New => observed::NEW_FILE,
            };
        }
        ctx.report_detail(FindingCode::ModuleSignature as u32, c.base, signature::pack(c.state, c.class) | flags << 16 | secs << 32, &c.name);
    }

    fn submit(&mut self, t: &Target, base: usize, class: ModulePathClass, path: String) {
        let system = watch::system_copy(&self.dirs.windows, t.is_wow64(), base_name(&path));
        let queued = self.sig.as_ref().is_some_and(|s| s.submit_named(base as u64, class, path.clone(), Some(system)));
        if !queued && self.sig.is_some() {
            self.waiting.push((base, class, path));
        } else if !queued {
            // No signature thread: the module is reported with its state unknown.
            let name = base_name(&path).to_owned();
            self.unchecked.push(signature::Checked { base: base as u64, class, state: ModuleSignature::Unspecified, name, path, digest: String::new(), shadows_system: false });
        }
    }

    fn drain(&mut self, ctx: &Ctx<'_>) {
        for c in std::mem::take(&mut self.unchecked) {
            self.report(ctx, &c);
        }
        for _ in 0..8 {
            let Some(c) = self.sig.as_ref().and_then(|s| s.poll()) else { break };
            self.report(ctx, &c);
        }
    }
}

impl Job for ExtModules {
    fn name(&self) -> &'static str {
        "ext_modules"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(5)),
            period_idle: Some(Duration::from_secs(2)),
            max_step: Duration::from_micros(600),
            max_cpu_per_run: Duration::from_millis(20),
            share: 0.15,
            priority: 3,
        }
    }
    fn begin(&mut self) {
        self.cur = self.watch.target();
        self.idx = 0;
        self.new_any = false;
        match &self.cur {
            Some(t) => {
                self.settled_at_begin = self.watch.settled(t.pid());
                t.modules(&mut self.mods);
            }
            None => self.mods.clear(),
        }
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        self.drain(ctx);
        let Some(t) = self.cur.clone() else { return Step::Done };
        // Files the signature thread had no room for on an earlier pass.
        if let Some((base, class, path)) = self.waiting.pop() {
            self.submit(&t, base, class, path);
        }
        for _ in 0..4 {
            let Some(&base) = self.mods.get(self.idx) else {
                self.watch.pass(self.new_any);
                return Step::Done;
            };
            self.idx += 1;
            // Keyed by process too: the target can change when a launcher hands over to the game.
            let key = base as u64 ^ (t.pid() as u64) << 40;
            if !matches!(t.query(base), Some(m) if m.Type == MEM_IMAGE) {
                if self.seen.first(key ^ 0x4e49) {
                    ctx.report(FindingCode::ModuleNotImage as u32, base as u64, 0);
                }
                continue;
            }
            if self.watch.has_module(base) {
                continue;
            }
            let Some(path) = t.module_path(base) else { continue };
            let class = self.dirs.classify(&path);
            self.new_any = true;
            self.watch.add_module(Module {
                base,
                size: t.module_size(base),
                name: base_name(&path).to_lowercase(),
                class,
                sig: None,
                after_start: self.settled_at_begin,
                seen_secs: self.watch.secs(),
                addon: class == Some(ModulePathClass::GameDir) && path.to_lowercase().replace('/', "\\").contains("\\addons\\"),
            });
            if let Some(class) = class {
                self.submit(&t, base, class, path);
            }
        }
        Step::Continue
    }
}

/// Counts committed executable regions that no image backs, and looks at the start of each
/// such allocation for a PE header. From outside, the engine's own loader (older GoldSrc
/// builds map `hw.dll` themselves), script JITs and graphics drivers are indistinguishable
/// from foreign code, so the count is one summary, sent when it changes. An allocation that
/// begins with a PE header is an image mapped by hand; each is reported once, with whether
/// it was there when the picture was taken.
pub struct ExtMemory {
    watch: Arc<Watch>,
    cur: Option<Arc<Target>>,
    addr: usize,
    count: u64,
    bytes: u64,
    flags: u64,
    reported: Option<(u32, u64)>,
    headers: Vec<(usize, u64)>,
    images: Vec<(usize, u64)>,
    /// A whole pass over this process was made after the picture was taken. What that pass
    /// and the earlier ones showed is the start; only later passes can show something new.
    saw_start: Option<u32>,
    after_picture: bool,
    after_start: bool,
    seen: Seen,
}

const MAX_HEADERS: usize = 256;
const PE_HEADER: u64 = UnbackedFlags::MzHeader as u64 | UnbackedFlags::PeSignature as u64;

impl ExtMemory {
    pub fn new(watch: Arc<Watch>) -> Self {
        Self {
            watch,
            cur: None,
            addr: 0,
            count: 0,
            bytes: 0,
            flags: 0,
            reported: None,
            headers: Vec::new(),
            images: Vec::new(),
            saw_start: None,
            after_picture: false,
            after_start: false,
            seen: Seen::new(256),
        }
    }

    fn header_flags(&mut self, t: &Target, base: usize) -> u64 {
        if let Some(&(_, f)) = self.headers.iter().find(|(b, _)| *b == base) {
            return f;
        }
        let mut f = 0u64;
        let mut dos = [0u8; 0x40];
        if t.read(base, &mut dos) {
            if &dos[..2] == b"MZ" {
                f |= UnbackedFlags::MzHeader as u64;
            }
            let lfanew = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap()) as usize;
            let mut sig = [0u8; 4];
            if (0x40..0x1000).contains(&lfanew) && t.read(base + lfanew, &mut sig) && &sig == b"PE\0\0" {
                f |= UnbackedFlags::PeSignature as u64;
            }
        }
        if self.headers.len() >= MAX_HEADERS {
            self.headers.clear();
        }
        self.headers.push((base, f));
        f
    }

    fn finish(&mut self, ctx: &Ctx<'_>) -> Step {
        let Some(t) = self.cur.take() else { return Step::Done };
        if self.reported != Some((t.pid(), self.count)) {
            self.reported = Some((t.pid(), self.count));
            ctx.report(FindingCode::ExternalExecRegions as u32, self.count, self.bytes & ((1 << 48) - 1) | self.flags << 48);
        }
        for (base, size) in std::mem::take(&mut self.images) {
            if !self.seen.first(base as u64 ^ (t.pid() as u64) << 40) {
                continue;
            }
            let mut head = [0u8; 0x400];
            if !t.read(base, &mut head) {
                continue;
            }
            let id = format!("{:016x}", fnv1a(&[&head]));
            let flags = observed_flags(&self.watch, self.after_start, &format!("mapped:{id}"));
            ctx.report_detail(FindingCode::ExternalMappedImage as u32, base as u64, size.min(u32::MAX as u64) | flags << 32, &id);
        }
        if self.after_picture && self.saw_start != Some(t.pid()) {
            self.saw_start = Some(t.pid());
            self.watch.whole("mapped");
        }
        Step::Done
    }
}

impl Job for ExtMemory {
    fn name(&self) -> &'static str {
        "ext_memory"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(10)),
            period_idle: Some(Duration::from_secs(5)),
            max_step: Duration::from_micros(600),
            max_cpu_per_run: Duration::from_millis(40),
            share: 0.2,
            priority: 2,
        }
    }
    fn begin(&mut self) {
        self.cur = self.watch.target();
        if self.cur.as_ref().map(|t| t.pid()) != self.reported.map(|(pid, _)| pid) {
            self.headers.clear();
        }
        self.after_picture = self.cur.as_ref().is_some_and(|t| self.watch.settled(t.pid()));
        self.after_start = self.after_picture && self.saw_start == self.cur.as_ref().map(|t| t.pid());
        self.images.clear();
        (self.addr, self.count, self.bytes, self.flags) = (0, 0, 0, 0);
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        let Some(t) = self.cur.clone() else { return Step::Done };
        for _ in 0..48 {
            let Some(m) = t.query(self.addr) else {
                // The walk ends where the address space does; a dead process ends it early and
                // must not be reported as "no executable memory".
                if !t.alive() {
                    self.cur = None;
                }
                return self.finish(ctx);
            };
            if m.State == MEM_COMMIT && m.Type != MEM_IMAGE && win::is_exec(m.Protect) {
                self.count += 1;
                self.bytes += m.RegionSize as u64;
                if m.Type == MEM_PRIVATE {
                    self.flags |= UnbackedFlags::Private as u64;
                }
                if win::is_writable(m.Protect) {
                    self.flags |= UnbackedFlags::Writable as u64;
                }
                let base = m.AllocationBase as usize;
                let header = self.header_flags(&t, base);
                self.flags |= header;
                if header & PE_HEADER == PE_HEADER {
                    if let Some((_, size)) = self.images.iter_mut().find(|(b, _)| *b == base) {
                        *size += m.RegionSize as u64;
                    } else if self.images.len() < 64 {
                        self.images.push((base, m.RegionSize as u64));
                    }
                }
            }
            let next = (m.BaseAddress as usize).wrapping_add(m.RegionSize);
            if next <= self.addr || next >= t.top() {
                return self.finish(ctx);
            }
            self.addr = next;
        }
        Step::Continue
    }
}

struct CodeRegion {
    addr: usize,
    len: usize,
    /// The picture: the region's bytes as they were on the first pass after the game had
    /// finished starting. Filled front to back.
    snap: Vec<u8>,
}

struct CodeModule {
    base: usize,
    name: String,
    regions: Vec<CodeRegion>,
}

const CODE_CHUNK: usize = 16 * 1024;
const MAX_CODE_PER_MODULE: usize = 24 << 20;
const MAX_CODE_MODULES: usize = 12;
/// Passes a change waits for the signature of the module its jump leads to.
const MAX_DEFER: u8 = 3;
const MAX_PATCHES: usize = 128;

/// Code of the watched libraries (for a GoldSrc game: the renderer library, the engine and
/// the client library) compared with a copy taken once the game had finished starting. A
/// library's code does not change while it runs, so a difference is something rewriting it:
/// an inline hook, whose jump is followed to the module or memory it leads to, or a patch.
/// Only pages that are executable and not writable are watched, which leaves out packed
/// libraries that rewrite themselves. What was rewritten before the copy was taken is in
/// the copy and is not seen.
pub struct ExtCode {
    watch: Arc<Watch>,
    cur: Option<Arc<Target>>,
    pid: u32,
    mods: Vec<CodeModule>,
    mi: usize,
    ri: usize,
    off: usize,
    buf: Vec<u8>,
    deferred: Vec<(usize, u8)>,
    /// Reported changes: address, the bytes that were there before, and how many.
    patches: Vec<(usize, [u8; PATCH], usize)>,
    seen: Seen,
}

impl ExtCode {
    pub fn new(watch: Arc<Watch>) -> Self {
        Self { watch, cur: None, pid: 0, mods: Vec::new(), mi: 0, ri: 0, off: 0, buf: vec![0; CODE_CHUNK], deferred: Vec::new(), patches: Vec::new(), seen: Seen::new(256) }
    }

    fn regions(t: &Target, m: &Module) -> Vec<CodeRegion> {
        let mut out = Vec::new();
        let (mut addr, end, mut total) = (m.base, m.base.saturating_add(m.size), 0usize);
        while addr < end && total < MAX_CODE_PER_MODULE {
            let Some(q) = t.query(addr) else { break };
            let (start, len) = (q.BaseAddress as usize, q.RegionSize);
            if len == 0 || q.AllocationBase as usize != m.base {
                break;
            }
            if q.State == MEM_COMMIT && q.Type == MEM_IMAGE && win::is_exec(q.Protect) && !win::is_writable(q.Protect) {
                let len = len.min(end.saturating_sub(start)).min(MAX_CODE_PER_MODULE - total);
                total += len;
                out.push(CodeRegion { addr: start, len, snap: Vec::new() });
            }
            addr = start.saturating_add(len);
        }
        out
    }

    /// Reports the change at `addr`; false to look again on the next pass.
    fn changed(&mut self, ctx: &Ctx<'_>, t: &Target, module: &str, addr: usize, code: &[u8]) -> bool {
        let decode = |code: &[u8], at: usize| {
            if t.is_wow64() {
                watch::jump32(code, at as u32, |a| t.read_u32(a))
            } else {
                hook::decode(code, at as u64, |a| t.read_u64(a))
            }
        };
        // A hook often jumps to a small relay outside any module first, and from there into
        // the module that placed it: follow the relay.
        let mut patch = decode(code, addr);
        for _ in 0..3 {
            let Patch::Jump(target) = patch else { break };
            let mut relay = [0u8; 16];
            if self.watch.module_at(target as usize).is_some() || matches!(t.query(target as usize), Some(q) if q.Type == MEM_IMAGE) || !t.read(target as usize, &mut relay) {
                break;
            }
            match decode(&relay, target as usize) {
                next @ Patch::Jump(_) => patch = next,
                _ => break,
            }
        }
        let addons = (self.watch.addons_loaded() as u64) << 25;
        let (kind, target, about, to) = match patch {
            Patch::Jump(target) => match self.watch.module_at(target as usize) {
                Some(m) => {
                    if m.class.is_some() && m.sig.is_none() && self.defer(addr) {
                        return false;
                    }
                    let class = m.class.map_or(0, |c| c as u64 + 1);
                    (CodeChangeKind::JumpModule, target, class << 8 | (m.sig.unwrap_or(ModuleSignature::Unspecified) as u64) << 16 | (m.after_start as u64) << 24, m.name)
                }
                // An image the module scan has not come to yet: wait for it.
                None if matches!(t.query(target as usize), Some(q) if q.Type == MEM_IMAGE) && self.defer(addr) => return false,
                None => (CodeChangeKind::JumpUnbacked, target, 0, "?".to_owned()),
            },
            Patch::Breakpoint => (CodeChangeKind::Breakpoint, 0, 0, String::new()),
            Patch::Unknown => (CodeChangeKind::Bytes, 0, 0, String::new()),
        };
        if self.seen.first(fnv1a(&[&t.pid().to_le_bytes(), &(addr as u64).to_le_bytes()])) {
            ctx.report_detail(FindingCode::ExternalCodeChange as u32, addr as u64, target & 0xffff_ffff | (kind as u64 | about | addons) << 32, &format!("{module}>{to}"));
        }
        true
    }

    fn defer(&mut self, addr: usize) -> bool {
        match self.deferred.iter_mut().find(|(a, _)| *a == addr) {
            Some((_, n)) if *n >= MAX_DEFER => false,
            Some((_, n)) => {
                *n += 1;
                true
            }
            None => {
                if self.deferred.len() >= 64 {
                    self.deferred.clear();
                }
                self.deferred.push((addr, 1));
                true
            }
        }
    }

    fn chunk(&mut self, ctx: &Ctx<'_>, t: &Target) {
        let (addr, len, have, name) = {
            let m = &self.mods[self.mi];
            let r = &m.regions[self.ri];
            (r.addr, r.len, r.snap.len(), m.name.clone())
        };
        let n = CODE_CHUNK.min(len - self.off);
        let at = addr + self.off;
        let mut buf = std::mem::take(&mut self.buf);
        if !t.read(at, &mut buf[..n]) {
            // Unreadable now: stop watching the region from here on.
            let r = &mut self.mods[self.mi].regions[self.ri];
            r.len = self.off.min(r.snap.len());
            r.snap.truncate(r.len);
        } else if self.off >= have {
            self.mods[self.mi].regions[self.ri].snap.extend_from_slice(&buf[..n]);
        } else {
            let runs = {
                let snap = &self.mods[self.mi].regions[self.ri].snap[self.off..self.off + n];
                watch::diff_runs(&buf[..n], snap)
            };
            for (i, j) in runs {
                let mut was = [0u8; PATCH];
                let k = (j - i).min(PATCH);
                was[..k].copy_from_slice(&self.mods[self.mi].regions[self.ri].snap[self.off + i..self.off + i + k]);
                let restored = self.patches.iter().position(|p| p.0 == at + i && p.2 == k && p.1[..k] == buf[i..i + k]);
                let accept = match restored {
                    // The bytes that were there before an earlier change are back: a hook
                    // that was taken out again (overlays do this) is not a second change.
                    Some(p) => {
                        self.patches.swap_remove(p);
                        true
                    }
                    None => {
                        let mut code = [0u8; 16];
                        let have = (n - i).min(16);
                        code[..have].copy_from_slice(&buf[i..i + have]);
                        let have = if have < 16 && t.read(at + i, &mut code) { 16 } else { have };
                        let reported = self.changed(ctx, t, &name, at + i, &code[..have]);
                        if reported {
                            if self.patches.len() >= MAX_PATCHES {
                                self.patches.remove(0);
                            }
                            self.patches.push((at + i, was, k));
                        }
                        reported
                    }
                };
                if accept {
                    self.mods[self.mi].regions[self.ri].snap[self.off + i..self.off + j].copy_from_slice(&buf[i..j]);
                }
            }
        }
        self.buf = buf;
        self.off += n;
    }
}

impl Job for ExtCode {
    fn name(&self) -> &'static str {
        "ext_code"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(5)),
            period_idle: Some(Duration::from_secs(5)),
            max_step: Duration::from_micros(600),
            max_cpu_per_run: Duration::from_millis(40),
            share: 0.2,
            priority: 2,
        }
    }
    fn begin(&mut self) {
        self.cur = self.watch.target().filter(|t| self.watch.settled(t.pid()));
        (self.mi, self.ri, self.off) = (0, 0, 0);
        let Some(t) = self.cur.clone() else { return };
        if self.pid != t.pid() {
            self.pid = t.pid();
            self.mods.clear();
            self.deferred.clear();
            self.patches.clear();
        }
        for m in self.watch.code_modules() {
            if self.mods.len() < MAX_CODE_MODULES && !self.mods.iter().any(|w| w.base == m.base) {
                let regions = Self::regions(&t, &m);
                self.mods.push(CodeModule { base: m.base, name: m.name, regions });
            }
        }
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        let Some(t) = self.cur.clone() else { return Step::Done };
        for _ in 0..2 {
            let Some(m) = self.mods.get(self.mi) else { return Step::Done };
            match m.regions.get(self.ri) {
                None => (self.mi, self.ri, self.off) = (self.mi + 1, 0, 0),
                Some(r) if self.off >= r.len => (self.ri, self.off) = (self.ri + 1, 0),
                Some(_) => self.chunk(ctx, &t),
            }
        }
        Step::Continue
    }
}

/// Debugger attachment on the game, asked of the kernel through the read-only handle, plus
/// the machine-wide kernel-debugger flag. Hardware breakpoints and the PEB flag are in-process
/// observations and are not available here.
pub struct ExtDebugger {
    cell: Arc<TargetCell>,
    last: (u32, u64),
}

impl ExtDebugger {
    pub fn new(cell: Arc<TargetCell>) -> Self {
        Self { cell, last: (0, 0) }
    }

    fn sample(t: &Target) -> u64 {
        let mut m = 0u64;
        let p = t.handle.0;
        let mut port = 0usize;
        if unsafe { NtQueryInformationProcess(p, ProcessDebugPort, (&mut port as *mut usize).cast(), size_of::<usize>() as u32, std::ptr::null_mut()) } >= 0
            && port != 0
        {
            m |= DebugSignal::DebugPort as u64;
        }
        let mut obj: usize = 0;
        if unsafe { NtQueryInformationProcess(p, ProcessDebugObjectHandle, (&mut obj as *mut usize).cast(), size_of::<usize>() as u32, std::ptr::null_mut()) } >= 0 {
            m |= DebugSignal::DebugObject as u64;
            if obj != 0 {
                unsafe { CloseHandle(obj as _) };
            }
        }
        let mut flags = 1u32;
        if unsafe { NtQueryInformationProcess(p, ProcessDebugFlags, (&mut flags as *mut u32).cast(), 4, std::ptr::null_mut()) } >= 0 && flags == 0 {
            m |= DebugSignal::NoInheritFlag as u64;
        }
        let mut kd = [0u8; 1];
        if win::read_self(0x7FFE_02D4, &mut kd) && kd[0] & 1 != 0 {
            m |= DebugSignal::KernelDebugger as u64;
        }
        m
    }
}

impl Job for ExtDebugger {
    fn name(&self) -> &'static str {
        "ext_debugger"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(10)),
            period_idle: Some(Duration::from_secs(5)),
            max_step: Duration::from_micros(200),
            max_cpu_per_run: Duration::from_millis(2),
            share: 0.02,
            priority: 5,
        }
    }
    fn begin(&mut self) {}
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        let Some(t) = self.cell.live() else { return Step::Done };
        let m = Self::sample(&t);
        if (t.pid(), m) != self.last {
            self.last = (t.pid(), m);
            if m != 0 {
                ctx.report(FindingCode::Debugger as u32, m, 0);
            }
        }
        Step::Done
    }
}

/// The scan set a companion runs against the process `watch` is bound to: the external jobs
/// above plus the existing handle, overlay and driver scanners pointed at the game.
pub fn jobs(watch: Arc<Watch>, dirs: Arc<Dirs>) -> Vec<Box<dyn Job>> {
    let cell = watch.cell.clone();
    vec![
        Box::new(ExtModules::new(watch.clone(), dirs.clone())),
        Box::new(ExtMemory::new(watch.clone())),
        Box::new(ExtCode::new(watch.clone())),
        Box::new(ExtDebugger::new(cell.clone())),
        Box::new(crate::jobs::ExternalHandles::for_target(watch.clone(), dirs)),
        Box::new(crate::jobs::OverlayWindows::for_target(cell)),
        Box::new(crate::jobs::VulnerableDrivers::new()),
    ]
}
