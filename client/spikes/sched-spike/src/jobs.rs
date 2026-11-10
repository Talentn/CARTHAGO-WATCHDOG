//! Representative detection jobs, each written as an incremental iterator.

use std::time::Duration;

use carthago_sched::{clock, Ctx, Job, JobBudget, Step};
use windows_sys::Wdk::System::Threading::{NtQueryInformationThread, ThreadQuerySetWin32StartAddress};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HMODULE, NTSTATUS};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SCN_MEM_EXECUTE, IMAGE_SECTION_HEADER};
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::System::Memory::{
    VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
};
use windows_sys::Win32::System::ProcessStatus::{
    K32EnumProcessModulesEx, K32GetMappedFileNameW, K32GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, THREAD_QUERY_INFORMATION};

pub const F_MODULE_NOT_IMAGE: u32 = 1;
pub const F_MODULE_NAME_MISMATCH: u32 = 2;
pub const F_UNBACKED_EXEC: u32 = 3;
pub const F_THREAD_START_UNBACKED: u32 = 4;
pub const F_TEXT_MODIFIED: u32 = 5;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    /// Per-process, resumable thread enumeration (unlike the system-wide Toolhelp snapshot).
    fn NtGetNextThread(process: HANDLE, thread: HANDLE, access: u32, attributes: u32, flags: u32, new: *mut HANDLE) -> NTSTATUS;
}

fn query(addr: usize) -> Option<MEMORY_BASIC_INFORMATION> {
    let mut m: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let n = unsafe { VirtualQuery(addr as *const _, &mut m, size_of::<MEMORY_BASIC_INFORMATION>()) };
    (n != 0).then_some(m)
}

fn is_exec(p: u32) -> bool {
    p & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0
}

fn enum_modules(out: &mut Vec<usize>) {
    let mut buf: Vec<HMODULE> = vec![std::ptr::null_mut(); 512];
    loop {
        let mut needed = 0u32;
        let ok = unsafe {
            K32EnumProcessModulesEx(GetCurrentProcess(), buf.as_mut_ptr(), (buf.len() * size_of::<HMODULE>()) as u32, &mut needed, LIST_MODULES_ALL)
        };
        let n = needed as usize / size_of::<HMODULE>();
        if ok == 0 || n <= buf.len() {
            out.clear();
            out.extend(buf[..n.min(buf.len())].iter().map(|&h| h as usize));
            return;
        }
        buf.resize(n, std::ptr::null_mut());
    }
}

fn file_part(s: &[u16]) -> &[u16] {
    match s.iter().rposition(|&c| c == b'\\' as u16) {
        Some(i) => &s[i + 1..],
        None => s,
    }
}

fn eq_ignore_case(a: &[u16], b: &[u16]) -> bool {
    let low = |c: u16| if (b'A' as u16..=b'Z' as u16).contains(&c) { c + 32 } else { c };
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| low(x) == low(y))
}

/// PEB module list vs. VAD: every listed module must be an image mapping of the same file.
pub struct ModuleInventory {
    mods: Vec<usize>,
    idx: usize,
    path: Vec<u16>,
    mapped: Vec<u16>,
}

impl ModuleInventory {
    pub fn new() -> Self {
        Self { mods: Vec::new(), idx: 0, path: Vec::new(), mapped: Vec::new() }
    }
}

impl Job for ModuleInventory {
    fn name(&self) -> &'static str {
        "module_inventory"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(5)),
            period_idle: Some(Duration::from_secs(2)),
            max_step: Duration::from_micros(300),
            max_cpu_per_run: Duration::from_millis(20),
            share: 0.2,
            priority: 3,
        }
    }
    fn begin(&mut self) {
        if self.path.is_empty() {
            self.path.resize(520, 0);
            self.mapped.resize(520, 0);
        }
        enum_modules(&mut self.mods);
        self.idx = 0;
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        for _ in 0..4 {
            let Some(&h) = self.mods.get(self.idx) else { return Step::Done };
            self.idx += 1;
            let mut mi: MODULEINFO = unsafe { std::mem::zeroed() };
            if unsafe { K32GetModuleInformation(GetCurrentProcess(), h as HMODULE, &mut mi, size_of::<MODULEINFO>() as u32) } == 0 {
                continue;
            }
            let base = mi.lpBaseOfDll as usize;
            if !matches!(query(base), Some(m) if m.Type == MEM_IMAGE) {
                ctx.report(F_MODULE_NOT_IMAGE, base as u64, 0);
                continue;
            }
            let n1 = unsafe { GetModuleFileNameW(h as HMODULE, self.path.as_mut_ptr(), self.path.len() as u32) } as usize;
            let n2 = unsafe {
                K32GetMappedFileNameW(GetCurrentProcess(), base as *const _, self.mapped.as_mut_ptr(), self.mapped.len() as u32)
            } as usize;
            if n1 > 0 && n2 > 0 && !eq_ignore_case(file_part(&self.path[..n1]), file_part(&self.mapped[..n2])) {
                ctx.report(F_MODULE_NAME_MISMATCH, base as u64, 0);
            }
        }
        Step::Continue
    }
}

/// VirtualQuery walk flagging executable memory that isn't backed by an image.
pub struct MemoryWalk {
    addr: usize,
}

impl MemoryWalk {
    pub fn new() -> Self {
        Self { addr: 0 }
    }
}

impl Job for MemoryWalk {
    fn name(&self) -> &'static str {
        "memory_region_walk"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(5)),
            period_idle: Some(Duration::from_secs(2)),
            max_step: Duration::from_micros(400),
            max_cpu_per_run: Duration::from_millis(40),
            share: 0.25,
            priority: 2,
        }
    }
    fn begin(&mut self) {
        self.addr = 0;
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        for _ in 0..64 {
            let Some(m) = query(self.addr) else { return Step::Done };
            if m.State == MEM_COMMIT && is_exec(m.Protect) && m.Type != MEM_IMAGE {
                ctx.report(F_UNBACKED_EXEC, m.BaseAddress as u64, m.RegionSize as u64);
            }
            let next = m.BaseAddress as usize + m.RegionSize;
            if next <= self.addr || next >= 0x7FFF_FFFF_0000 {
                return Step::Done;
            }
            self.addr = next;
        }
        Step::Continue
    }
}

/// Thread start addresses must land in image-backed memory.
pub struct ThreadAudit {
    cur: usize,
}

impl ThreadAudit {
    pub fn new() -> Self {
        Self { cur: 0 }
    }
    fn close(&mut self) {
        if self.cur != 0 {
            unsafe { CloseHandle(self.cur as HANDLE) };
            self.cur = 0;
        }
    }
}

impl Drop for ThreadAudit {
    fn drop(&mut self) {
        self.close();
    }
}

impl Job for ThreadAudit {
    fn name(&self) -> &'static str {
        "thread_audit"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(5)),
            period_idle: Some(Duration::from_secs(2)),
            max_step: Duration::from_micros(300),
            max_cpu_per_run: Duration::from_millis(10),
            share: 0.15,
            priority: 3,
        }
    }
    fn begin(&mut self) {
        self.close();
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        for _ in 0..8 {
            let mut next: HANDLE = std::ptr::null_mut();
            let st = unsafe { NtGetNextThread(GetCurrentProcess(), self.cur as HANDLE, THREAD_QUERY_INFORMATION, 0, 0, &mut next) };
            self.close();
            if st < 0 {
                return Step::Done;
            }
            self.cur = next as usize;
            let mut start = 0usize;
            unsafe {
                NtQueryInformationThread(next, ThreadQuerySetWin32StartAddress, &mut start as *mut _ as *mut _, size_of::<usize>() as u32, std::ptr::null_mut())
            };
            if start != 0 && !matches!(query(start), Some(m) if m.Type == MEM_IMAGE) {
                ctx.report(F_THREAD_START_UNBACKED, start as u64, 0);
            }
        }
        Step::Continue
    }
}

/// BLAKE3 over executable sections of every loaded image plus extra registered ranges
/// (the simulated game binary), 64 KiB per step. The first pass records the baseline.
pub struct TextHash {
    extra: Vec<(usize, usize)>,
    ranges: Vec<(usize, usize)>,
    baseline: Vec<[u8; 32]>,
    have_baseline: bool,
    ri: usize,
    off: usize,
    chunk_idx: usize,
    period_gameplay: Option<Duration>,
    pub total_bytes: usize,
}

const CHUNK: usize = 64 * 1024;

impl TextHash {
    pub fn new(extra: Vec<(usize, usize)>, period_gameplay: Option<Duration>) -> Self {
        Self {
            extra,
            ranges: Vec::new(),
            baseline: Vec::new(),
            have_baseline: false,
            ri: 0,
            off: 0,
            chunk_idx: 0,
            period_gameplay,
            total_bytes: 0,
        }
    }

    /// Total bytes one full pass covers.
    pub fn pass_bytes(&mut self) -> usize {
        if self.ranges.is_empty() {
            self.build_ranges();
        }
        self.total_bytes
    }

    fn build_ranges(&mut self) {
        let mut mods = Vec::new();
        enum_modules(&mut mods);
        for base in mods {
            unsafe {
                let dos = &*(base as *const IMAGE_DOS_HEADER);
                if dos.e_magic != 0x5A4D {
                    continue;
                }
                let nt = &*((base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
                if nt.Signature != 0x4550 {
                    continue;
                }
                let first = (nt as *const _ as usize + 24 + nt.FileHeader.SizeOfOptionalHeader as usize) as *const IMAGE_SECTION_HEADER;
                for i in 0..nt.FileHeader.NumberOfSections as usize {
                    let s = &*first.add(i);
                    if s.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && s.Misc.VirtualSize > 0 {
                        self.ranges.push((base + s.VirtualAddress as usize, s.Misc.VirtualSize as usize));
                    }
                }
            }
        }
        self.ranges.extend_from_slice(&self.extra);
        self.total_bytes = self.ranges.iter().map(|r| r.1).sum();
    }
}

impl Job for TextHash {
    fn name(&self) -> &'static str {
        "text_hash"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: self.period_gameplay,
            period_idle: Some(Duration::from_secs(10)),
            max_step: Duration::from_millis(1),
            max_cpu_per_run: Duration::from_millis(400),
            share: 0.4,
            priority: 1,
        }
    }
    fn begin(&mut self) {
        if self.ranges.is_empty() {
            self.build_ranges();
        }
        self.ri = 0;
        self.off = 0;
        self.chunk_idx = 0;
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        let Some(&(start, len)) = self.ranges.get(self.ri) else {
            self.have_baseline = true;
            return Step::Done;
        };
        let addr = start + self.off;
        let mut n = CHUNK.min(len - self.off);
        let readable = match query(addr) {
            Some(m) if m.State == MEM_COMMIT && m.Protect & (PAGE_NOACCESS | PAGE_GUARD) == 0 => {
                n = n.min(m.BaseAddress as usize + m.RegionSize - addr);
                true
            }
            _ => false,
        };
        if readable {
            let h = *blake3::hash(unsafe { std::slice::from_raw_parts(addr as *const u8, n) }).as_bytes();
            if self.have_baseline {
                if self.baseline.get(self.chunk_idx).is_some_and(|b| *b != h) {
                    ctx.report(F_TEXT_MODIFIED, addr as u64, n as u64);
                }
            } else {
                self.baseline.push(h);
            }
        } else if !self.have_baseline {
            self.baseline.push([0; 32]);
        }
        self.chunk_idx += 1;
        self.off += n;
        if self.off >= len {
            self.ri += 1;
            self.off = 0;
        }
        Step::Continue
    }
}

/// Misbehaving module: declares 200 µs steps but spins 8 ms per step.
pub struct SpinHog;

impl Job for SpinHog {
    fn name(&self) -> &'static str {
        "misbehaving_spin_hog"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(1)),
            period_idle: Some(Duration::from_secs(1)),
            max_step: Duration::from_micros(200),
            max_cpu_per_run: Duration::from_millis(50),
            share: 0.1,
            priority: 0,
        }
    }
    fn begin(&mut self) {}
    fn step(&mut self, _: &Ctx<'_>) -> Step {
        let t = clock::now_ns();
        while clock::now_ns() - t < 8_000_000 {
            std::hint::spin_loop();
        }
        Step::Continue
    }
}

/// Misbehaving module: well-sized steps but never finishes and is always due.
pub struct Greedy {
    buf: Vec<u8>,
}

impl Greedy {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }
}

impl Job for Greedy {
    fn name(&self) -> &'static str {
        "misbehaving_greedy"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_millis(50)),
            period_idle: Some(Duration::from_millis(50)),
            max_step: Duration::from_micros(200),
            max_cpu_per_run: Duration::from_millis(30),
            share: 0.3,
            priority: 4,
        }
    }
    fn begin(&mut self) {
        if self.buf.is_empty() {
            self.buf = vec![0x5a; 16 * 1024];
        }
    }
    fn step(&mut self, _: &Ctx<'_>) -> Step {
        let t = clock::now_ns();
        while clock::now_ns() - t < 150_000 {
            std::hint::black_box(blake3::hash(&self.buf));
        }
        Step::Continue
    }
}

pub fn standard(extra: Vec<(usize, usize)>, hash_period: Option<Duration>) -> Vec<Box<dyn Job>> {
    vec![
        Box::new(ModuleInventory::new()),
        Box::new(MemoryWalk::new()),
        Box::new(ThreadAudit::new()),
        Box::new(TextHash::new(extra, hash_period)),
    ]
}
