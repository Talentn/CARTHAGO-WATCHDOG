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
//! - no view of what runs inside: thread start addresses, API hooks, patched code pages and
//!   the game's own clocks are not checked, and executable private memory cannot be judged
//!   per region because the engine's own loader and script JITs look the same from outside.
//!
//! The jobs are bound to a [`TargetCell`], which stays empty until the companion has started
//! the game, so the scheduler (and the gateway session) can be up before the game is.

use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use carthago_proto::v1::{DebugSignal, FindingCode, UnbackedFlags};
use carthago_sched::{Ctx, Job, JobBudget, Step};
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessDebugFlags, ProcessDebugObjectHandle, ProcessDebugPort};
use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, HANDLE, HMODULE, WAIT_TIMEOUT};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE};
use windows_sys::Win32::System::ProcessStatus::{K32EnumProcessModulesEx, K32EnumProcesses, K32GetModuleFileNameExW, LIST_MODULES_ALL};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, GetProcessId, IsWow64Process, OpenProcess, WaitForSingleObject,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use crate::paths::Dirs;
use crate::seen::Seen;
use crate::signature;
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

/// Module inventory of the game with each file's signature state. Modules under the Windows
/// directory are skipped, as in the in-process inventory; each other module is reported once
/// by base name, path class and [`carthago_proto::v1::ModuleSignature`].
pub struct ExtModules {
    cell: Arc<TargetCell>,
    dirs: Arc<Dirs>,
    cur: Option<Arc<Target>>,
    mods: Vec<usize>,
    idx: usize,
    seen: Seen,
    sig: Option<signature::Worker>,
}

impl ExtModules {
    pub fn new(cell: Arc<TargetCell>, dirs: Arc<Dirs>) -> Self {
        Self { cell, dirs, cur: None, mods: Vec::new(), idx: 0, seen: Seen::new(1024), sig: signature::Worker::start().ok() }
    }

    fn drain(&self, ctx: &Ctx<'_>) {
        let Some(sig) = &self.sig else { return };
        for _ in 0..8 {
            let Some(c) = sig.poll() else { return };
            ctx.report_detail(FindingCode::ModuleSignature as u32, c.base, signature::pack(c.state, c.class), &c.name);
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
        self.cur = self.cell.live();
        self.idx = 0;
        match &self.cur {
            Some(t) => t.modules(&mut self.mods),
            None => self.mods.clear(),
        }
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        self.drain(ctx);
        let Some(t) = self.cur.clone() else { return Step::Done };
        for _ in 0..4 {
            let Some(&base) = self.mods.get(self.idx) else { return Step::Done };
            self.idx += 1;
            // Keyed by process too: the target can change when a launcher hands over to the game.
            let key = base as u64 ^ (t.pid() as u64) << 40;
            if !matches!(t.query(base), Some(m) if m.Type == MEM_IMAGE) {
                if self.seen.first(key ^ 0x4e49) {
                    ctx.report(FindingCode::ModuleNotImage as u32, base as u64, 0);
                }
                continue;
            }
            if !self.seen.first(key) {
                continue;
            }
            let Some(path) = t.module_path(base) else { continue };
            let Some(class) = self.dirs.classify(&path) else { continue };
            let queued = self.sig.as_ref().is_some_and(|s| s.submit(base as u64, class, path.clone()));
            if !queued {
                // No signature thread or its queue is full: report the module now, state unknown.
                ctx.report_detail(
                    FindingCode::ModuleSignature as u32,
                    base as u64,
                    signature::pack(carthago_proto::v1::ModuleSignature::Unspecified, class),
                    crate::paths::base_name(&path),
                );
            }
        }
        Step::Continue
    }
}

/// Counts committed executable regions that no image backs. From outside, the engine's own
/// loader (older GoldSrc builds map `hw.dll` themselves) and script JITs are
/// indistinguishable from foreign code, so the job reports one summary when the count
/// changes and leaves the judgement to the server.
pub struct ExtMemory {
    cell: Arc<TargetCell>,
    cur: Option<Arc<Target>>,
    addr: usize,
    count: u64,
    bytes: u64,
    flags: u64,
    reported: Option<(u32, u64)>,
    headers: Vec<(usize, u64)>,
}

const MAX_HEADERS: usize = 256;

impl ExtMemory {
    pub fn new(cell: Arc<TargetCell>) -> Self {
        Self { cell, cur: None, addr: 0, count: 0, bytes: 0, flags: 0, reported: None, headers: Vec::new() }
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
        Step::Done
    }
}

impl Job for ExtMemory {
    fn name(&self) -> &'static str {
        "ext_memory"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(15)),
            period_idle: Some(Duration::from_secs(5)),
            max_step: Duration::from_micros(600),
            max_cpu_per_run: Duration::from_millis(40),
            share: 0.2,
            priority: 2,
        }
    }
    fn begin(&mut self) {
        self.cur = self.cell.live();
        if self.cur.as_ref().map(|t| t.pid()) != self.reported.map(|(pid, _)| pid) {
            self.headers.clear();
        }
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
                self.flags |= self.header_flags(&t, m.AllocationBase as usize);
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

/// The scan set a companion runs against the process in `cell`: the external jobs above plus
/// the existing handle, overlay and driver scanners pointed at the game.
pub fn jobs(cell: Arc<TargetCell>, dirs: Arc<Dirs>) -> Vec<Box<dyn Job>> {
    vec![
        Box::new(ExtModules::new(cell.clone(), dirs)),
        Box::new(ExtMemory::new(cell.clone())),
        Box::new(ExtDebugger::new(cell.clone())),
        Box::new(crate::jobs::ExternalHandles::for_target(cell.clone())),
        Box::new(crate::jobs::OverlayWindows::for_target(cell)),
        Box::new(crate::jobs::VulnerableDrivers::new()),
    ]
}
