use std::time::Duration;

use carthago_proto::v1::{DebugSignal, FindingCode};
use carthago_sched::{Ctx, Job, JobBudget, Step};
use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessDebugFlags, ProcessDebugObjectHandle, ProcessDebugPort};
use windows_sys::Win32::Foundation::{CloseHandle, HWND, RECT};
use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, IsDebuggerPresent, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetCurrentThread};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetTopWindow, GetWindow, GetWindowLongPtrW, GetWindowRect, GetWindowThreadProcessId, IsWindowVisible,
    GWL_EXSTYLE, GW_HWNDNEXT, WS_EX_LAYERED, WS_EX_TOPMOST, WS_EX_TRANSPARENT,
};

use crate::drivers;
use crate::seen::{fnv1a, Seen};
use crate::win;

fn window_pid(h: HWND) -> u32 {
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(h, &mut pid) };
    pid
}

fn overlaps(a: &RECT, b: &RECT) -> bool {
    a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom
}

/// Overlay windows (plan §6.2 external ESP): top-level windows of other processes that are
/// layered, click-through and topmost over the game window. Walks the z-order 32 windows per
/// step and only while the game is in the foreground. Reports the owner's image name, never
/// the window title (plan §10).
pub struct OverlayWindows {
    self_pid: u32,
    game: Option<RECT>,
    cur: usize,
    seen: Seen,
}

impl OverlayWindows {
    pub fn new() -> Self {
        Self { self_pid: unsafe { GetCurrentProcessId() }, game: None, cur: 0, seen: Seen::new(128) }
    }
}

impl Default for OverlayWindows {
    fn default() -> Self {
        Self::new()
    }
}

impl Job for OverlayWindows {
    fn name(&self) -> &'static str {
        "overlay_windows"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(10)),
            period_idle: Some(Duration::from_secs(10)),
            max_step: Duration::from_micros(300),
            max_cpu_per_run: Duration::from_millis(10),
            share: 0.05,
            priority: 2,
        }
    }
    fn begin(&mut self) {
        self.game = None;
        self.cur = 0;
        let fg = unsafe { GetForegroundWindow() };
        if fg.is_null() || window_pid(fg) != self.self_pid {
            return;
        }
        let mut r: RECT = unsafe { std::mem::zeroed() };
        if unsafe { GetWindowRect(fg, &mut r) } != 0 {
            self.game = Some(r);
            self.cur = unsafe { GetTopWindow(std::ptr::null_mut()) } as usize;
        }
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        let Some(game) = self.game else { return Step::Done };
        const WANT: isize = (WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST) as isize;
        for _ in 0..32 {
            let h = self.cur as HWND;
            if h.is_null() {
                return Step::Done;
            }
            self.cur = unsafe { GetWindow(h, GW_HWNDNEXT) } as usize;
            let ex = unsafe { GetWindowLongPtrW(h, GWL_EXSTYLE) };
            if ex & WANT != WANT || unsafe { IsWindowVisible(h) } == 0 {
                continue;
            }
            let pid = window_pid(h);
            let mut r: RECT = unsafe { std::mem::zeroed() };
            if pid == self.self_pid || unsafe { GetWindowRect(h, &mut r) } == 0 || !overlaps(&r, &game) {
                continue;
            }
            if self.seen.first(pid as u64) {
                ctx.report_detail(FindingCode::OverlayWindow as u32, pid as u64, ex as u64, &win::process_image_name(pid));
            }
        }
        Step::Continue
    }
}

/// Debugger signals (plan §6.3 tooling signals), reported as telemetry when the set
/// changes; the SDK never crashes or traps on them (plan §8.5).
pub struct DebuggerSignals {
    last: u64,
}

impl DebuggerSignals {
    pub fn new() -> Self {
        Self { last: 0 }
    }

    pub fn sample() -> u64 {
        let mut m = 0u64;
        let p = unsafe { GetCurrentProcess() };
        if unsafe { IsDebuggerPresent() } != 0 {
            m |= DebugSignal::PebBeingDebugged as u64;
        }
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
        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
        if unsafe { GetThreadContext(GetCurrentThread(), &mut ctx) } != 0 && (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) != 0 {
            m |= DebugSignal::HardwareBreakpoint as u64;
        }
        // KUSER_SHARED_DATA.KdDebuggerEnabled; the page is mapped read-only in every process.
        let mut kd = [0u8; 1];
        if win::read_self(0x7FFE_02D4, &mut kd) && kd[0] & 1 != 0 {
            m |= DebugSignal::KernelDebugger as u64;
        }
        m
    }
}

impl Default for DebuggerSignals {
    fn default() -> Self {
        Self::new()
    }
}

impl Job for DebuggerSignals {
    fn name(&self) -> &'static str {
        "debugger_signals"
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
        let m = Self::sample();
        if m != self.last {
            self.last = m;
            if m != 0 {
                ctx.report(FindingCode::Debugger as u32, m, 0);
            }
        }
        Step::Done
    }
}

/// Known-vulnerable drivers loaded on the machine (plan §6.3), from the kernel module list
/// (`SystemModuleInformation`, names only: unprivileged callers get no addresses). Only
/// matches against the embedded list leave the machine.
pub struct VulnerableDrivers {
    buf: Vec<u8>,
    seen: Seen,
}

const SYSTEM_MODULE_INFORMATION: i32 = 11;
/// RTL_PROCESS_MODULE_INFORMATION size on x64.
const MODULE_ENTRY: usize = 296;
const MAX_MODULE_BUF: usize = 1 << 20;

impl VulnerableDrivers {
    pub fn new() -> Self {
        Self { buf: vec![0; 128 * 1024], seen: Seen::new(64) }
    }
}

impl Default for VulnerableDrivers {
    fn default() -> Self {
        Self::new()
    }
}

impl Job for VulnerableDrivers {
    fn name(&self) -> &'static str {
        "vulnerable_drivers"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(120)),
            period_idle: Some(Duration::from_secs(30)),
            max_step: Duration::from_micros(500),
            max_cpu_per_run: Duration::from_millis(4),
            share: 0.03,
            priority: 1,
        }
    }
    fn begin(&mut self) {}
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        let mut need = 0u32;
        let st = unsafe { NtQuerySystemInformation(SYSTEM_MODULE_INFORMATION, self.buf.as_mut_ptr().cast(), self.buf.len() as u32, &mut need) };
        if st < 0 {
            if (need as usize) > self.buf.len() && (need as usize) <= MAX_MODULE_BUF {
                self.buf.resize(need as usize + 4096, 0);
            }
            return Step::Done;
        }
        let n = u32::from_le_bytes(self.buf[..4].try_into().unwrap()) as usize;
        for i in 0..n.min((self.buf.len() - 8) / MODULE_ENTRY) {
            let e = &self.buf[8 + i * MODULE_ENTRY..8 + (i + 1) * MODULE_ENTRY];
            let name_off = u16::from_le_bytes([e[38], e[39]]) as usize;
            let path = &e[40..296];
            let end = path.iter().position(|&c| c == 0).unwrap_or(path.len());
            let Some(file) = path.get(name_off.min(end)..end) else { continue };
            if let Some(hit) = drivers::match_name(file) {
                if self.seen.first(fnv1a(&[hit.as_bytes()])) {
                    ctx.report_detail(FindingCode::VulnerableDriver as u32, 0, 0, hit);
                }
            }
        }
        Step::Done
    }
}
