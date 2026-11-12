use std::time::Duration;

use carthago_proto::v1::{FindingCode, WatchedApi};
use carthago_sched::{Ctx, Job, JobBudget, Step};

use crate::hook::{self, Patch};
use crate::pe::{first_diff, section_pages, Dir, DiskImage, Export, Headers, DIR_IAT};
use crate::seen::{fnv1a, Seen};
use crate::win::{self, File, Mapped};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

const WATCHED: &[(WatchedApi, &str, &str)] = &[
    (WatchedApi::NtdllNtQueryPerformanceCounter, "ntdll.dll", "NtQueryPerformanceCounter"),
    (WatchedApi::NtdllRtlQueryPerformanceCounter, "ntdll.dll", "RtlQueryPerformanceCounter"),
    (WatchedApi::Kernel32QueryPerformanceCounter, "kernel32.dll", "QueryPerformanceCounter"),
    (WatchedApi::KernelbaseGetTickCount64, "kernelbase.dll", "GetTickCount64"),
    (WatchedApi::KernelbaseGetTickCount, "kernelbase.dll", "GetTickCount"),
    (WatchedApi::WinmmTimeGetTime, "winmm.dll", "timeGetTime"),
    (WatchedApi::NtdllNtQuerySystemInformation, "ntdll.dll", "NtQuerySystemInformation"),
    (WatchedApi::NtdllNtQueryVirtualMemory, "ntdll.dll", "NtQueryVirtualMemory"),
    (WatchedApi::NtdllLdrLoadDll, "ntdll.dll", "LdrLoadDll"),
    (WatchedApi::KernelbaseLoadLibraryExW, "kernelbase.dll", "LoadLibraryExW"),
    (WatchedApi::Kernel32LoadLibraryA, "kernel32.dll", "LoadLibraryA"),
    (WatchedApi::Kernel32LoadLibraryW, "kernel32.dll", "LoadLibraryW"),
];

const PROLOGUE: usize = 16;
const HOOKED_MODULES: [&str; 4] = ["ntdll.dll", "kernel32.dll", "kernelbase.dll", "winmm.dll"];

/// Loaded module, by base name, plus its on-disk image.
struct Module {
    name: &'static str,
    base: usize,
    disk: DiskImage<File>,
}

/// Hash lookup in the loader's module table; never triggers a load.
fn find_loaded(name: &str) -> Option<usize> {
    let h = unsafe { GetModuleHandleW(win::wide(name).as_ptr()) };
    (!h.is_null()).then_some(h as usize)
}

fn open_module(name: &'static str, base: usize) -> Option<Module> {
    let disk = DiskImage::open(win::open_module_file(base)?)?;
    Some(Module { name, base, disk })
}

fn jump_target(addr: u64) -> (u64, String) {
    let mut code = [0u8; 16];
    if !win::read_self(addr as usize, &mut code) {
        return (0, String::new());
    }
    match hook::decode(&code, addr, win::read_ptr) {
        Patch::Jump(t) => (t, win::owner_module_name(t)),
        Patch::Breakpoint | Patch::Unknown => (0, String::new()),
    }
}

/// Inline and EAT hooks on a curated API list (plan §6.3, §6.4): timing APIs (speedhacks),
/// loader and query APIs (injectors and hiders). The first 16 bytes in memory are compared
/// with the relocated on-disk bytes, and the in-memory export table entry with the disk one.
/// Inspection only; nothing is ever patched back.
pub struct ApiHooks {
    mods: Vec<Module>,
    idx: usize,
    seen: Seen,
}

impl ApiHooks {
    pub fn new() -> Self {
        Self { mods: Vec::new(), idx: 0, seen: Seen::new(64) }
    }

    fn check(&mut self, api: WatchedApi, module: &str, export: &str, ctx: &Ctx<'_>) {
        let Some(m) = self.mods.iter().find(|m| m.name == module) else { return };
        let Some(Export::Code { rva, eat_slot_rva }) = m.disk.export(export) else { return };
        let addr = m.base as u64 + rva as u64;
        let mut actual = [0u8; PROLOGUE];
        let mut expected = [0u8; PROLOGUE];
        let mem_ok = win::read_self(addr as usize, &mut actual) && m.disk.expected(rva, &mut expected, m.base as u64);
        let eat_rva = Mapped(m.base).read_u32(eat_slot_rva);
        let (target, owner) = if eat_rva.is_some_and(|r| r != rva) {
            let t = m.base as u64 + eat_rva.unwrap() as u64;
            (t, win::owner_module_name(t))
        } else if mem_ok && actual != expected {
            jump_target(addr)
        } else {
            return;
        };
        if self.seen.first(fnv1a(&[export.as_bytes(), &target.to_le_bytes()])) {
            ctx.report_detail(FindingCode::ApiHook as u32, target, api as u64, &owner);
        }
    }
}

trait ReadU32 {
    fn read_u32(&self, rva: u32) -> Option<u32>;
}

impl ReadU32 for Mapped {
    fn read_u32(&self, rva: u32) -> Option<u32> {
        let mut b = [0u8; 4];
        win::read_self(self.0 + rva as usize, &mut b).then(|| u32::from_le_bytes(b))
    }
}

impl Default for ApiHooks {
    fn default() -> Self {
        Self::new()
    }
}

impl Job for ApiHooks {
    fn name(&self) -> &'static str {
        "api_hooks"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(4)),
            period_idle: Some(Duration::from_secs(2)),
            max_step: Duration::from_micros(500),
            max_cpu_per_run: Duration::from_millis(10),
            share: 0.05,
            priority: 4,
        }
    }
    fn begin(&mut self) {
        self.idx = 0;
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        if let Some(&name) = HOOKED_MODULES.get(self.idx) {
            // One module per step; each is opened once per session (winmm only once the game
            // has loaded it).
            self.idx += 1;
            if !self.mods.iter().any(|m| m.name == name) {
                if let Some(mut m) = find_loaded(name).and_then(|b| open_module(name, b)) {
                    m.disk.load_relocs();
                    self.mods.push(m);
                }
            }
            return Step::Continue;
        }
        let Some(&(api, module, export)) = WATCHED.get(self.idx - HOOKED_MODULES.len()) else { return Step::Done };
        self.idx += 1;
        self.check(api, module, export, ctx);
        Step::Continue
    }
}

/// Executable sections of the graphics runtime DLLs compared page by page with their
/// relocated disk images (plan §6.2 internal ESP: `IDXGISwapChain::Present` and
/// `ResizeBuffers` live in dxgi/d3d11/d3d12 code, so an inline hook on them shows up as a
/// patched page). The IAT is masked. vtable hooks on a swap-chain instance are not covered
/// by this check. Expensive, so it runs on a long period during gameplay.
pub struct TextIntegrity {
    targets: &'static [&'static str],
    cur: Option<Module>,
    next_module: usize,
    pages: Vec<(u32, u32)>,
    page: usize,
    masks: Vec<Dir>,
    actual: Vec<u8>,
    expected: Vec<u8>,
    seen: Seen,
}

const PAGE: u32 = 4096;
const GRAPHICS: &[&str] = &["dxgi.dll", "d3d11.dll", "d3d12.dll", "d3d9.dll"];

impl TextIntegrity {
    pub fn new() -> Self {
        Self {
            targets: GRAPHICS,
            cur: None,
            next_module: 0,
            pages: Vec::new(),
            page: 0,
            masks: Vec::new(),
            actual: vec![0; PAGE as usize],
            expected: vec![0; PAGE as usize],
            seen: Seen::new(256),
        }
    }

    fn open_next(&mut self) -> bool {
        while let Some(&name) = self.targets.get(self.next_module) {
            self.next_module += 1;
            let Some(mut m) = find_loaded(name).and_then(|b| open_module(name, b)) else { continue };
            // Trust the section layout on disk, but only if the mapped headers agree.
            let Some(mapped) = Headers::parse(&Mapped(m.base)) else { continue };
            if mapped.sections != m.disk.h.sections || !m.disk.load_relocs() {
                continue;
            }
            self.pages.clear();
            // The headers are the module's own: a section it cannot really have is skipped
            // with the module instead of being walked.
            if !m.disk.h.exec_sections().all(|s| section_pages(&m.disk.h, s, PAGE, &mut self.pages)) {
                self.pages.clear();
                continue;
            }
            self.masks = vec![m.disk.h.dirs[DIR_IAT]];
            self.page = 0;
            self.cur = Some(m);
            return true;
        }
        false
    }

    fn compare_page(&mut self, ctx: &Ctx<'_>) {
        let Some(m) = &self.cur else { return };
        let (rva, len) = self.pages[self.page];
        let (a, e) = (&mut self.actual[..len as usize], &mut self.expected[..len as usize]);
        if !win::read_self(m.base + rva as usize, a) || !m.disk.expected(rva, e, m.base as u64) {
            return;
        }
        let Some(off) = first_diff(a, e, rva, &self.masks) else { return };
        let addr = m.base as u64 + rva as u64 + off as u64;
        let (target, owner) = jump_target(addr);
        let owner = if target != 0 && owner.is_empty() { "?".to_owned() } else { owner };
        if self.seen.first(fnv1a(&[m.name.as_bytes(), &rva.to_le_bytes()])) {
            ctx.report_detail(FindingCode::CodePatch as u32, addr, target, &format!("{}>{}", m.name, owner));
        }
    }
}

impl Default for TextIntegrity {
    fn default() -> Self {
        Self::new()
    }
}

impl Job for TextIntegrity {
    fn name(&self) -> &'static str {
        "text_integrity"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(90)),
            period_idle: Some(Duration::from_secs(20)),
            max_step: Duration::from_micros(400),
            max_cpu_per_run: Duration::from_millis(60),
            share: 0.25,
            priority: 1,
        }
    }
    fn begin(&mut self) {
        self.cur = None;
        self.next_module = 0;
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        if self.cur.is_none() || self.page >= self.pages.len() {
            self.cur = None;
            return if self.open_next() { Step::Continue } else { Step::Done };
        }
        for _ in 0..2 {
            if self.page >= self.pages.len() {
                break;
            }
            self.compare_page(ctx);
            self.page += 1;
        }
        Step::Continue
    }
}
