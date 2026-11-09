//! Phase 0 scan jobs on the budgeted scheduler (from the scheduler spike). Real detection
//! coverage lands in Phase 1 (sn-scan); these exercise the scheduler and the heartbeat path.

use std::time::Duration;

use sn_sched::{Ctx, Job, JobBudget, Step};
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Memory::{
    VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
};
use windows_sys::Win32::System::ProcessStatus::{K32EnumProcessModulesEx, K32GetModuleInformation, LIST_MODULES_ALL, MODULEINFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

pub const F_MODULE_NOT_IMAGE: u32 = 1;
pub const F_UNBACKED_EXEC: u32 = 3;

fn query(addr: usize) -> Option<MEMORY_BASIC_INFORMATION> {
    let mut m: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let n = unsafe { VirtualQuery(addr as *const _, &mut m, size_of::<MEMORY_BASIC_INFORMATION>()) };
    (n != 0).then_some(m)
}

fn is_exec(p: u32) -> bool {
    p & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0
}

/// VirtualQuery walk flagging executable memory that isn't image-backed (manual maps, shellcode).
pub struct MemoryWalk {
    addr: usize,
}

impl MemoryWalk {
    pub fn new() -> Self {
        Self { addr: 0 }
    }
}

impl Default for MemoryWalk {
    fn default() -> Self {
        Self::new()
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
            share: 0.5,
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

/// Every module in the loader list must be an image mapping.
pub struct ModuleInventory {
    mods: Vec<usize>,
    idx: usize,
}

impl ModuleInventory {
    pub fn new() -> Self {
        Self { mods: Vec::new(), idx: 0 }
    }
}

impl Default for ModuleInventory {
    fn default() -> Self {
        Self::new()
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
            share: 0.3,
            priority: 3,
        }
    }
    fn begin(&mut self) {
        let mut buf: Vec<HMODULE> = vec![std::ptr::null_mut(); 512];
        loop {
            let mut needed = 0u32;
            let ok = unsafe {
                K32EnumProcessModulesEx(GetCurrentProcess(), buf.as_mut_ptr(), (buf.len() * size_of::<HMODULE>()) as u32, &mut needed, LIST_MODULES_ALL)
            };
            let n = needed as usize / size_of::<HMODULE>();
            if ok == 0 || n <= buf.len() {
                self.mods.clear();
                self.mods.extend(buf[..n.min(buf.len())].iter().map(|&h| h as usize));
                break;
            }
            buf.resize(n, std::ptr::null_mut());
        }
        self.idx = 0;
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        for _ in 0..8 {
            let Some(&h) = self.mods.get(self.idx) else { return Step::Done };
            self.idx += 1;
            let mut mi: MODULEINFO = unsafe { std::mem::zeroed() };
            if unsafe { K32GetModuleInformation(GetCurrentProcess(), h as HMODULE, &mut mi, size_of::<MODULEINFO>() as u32) } == 0 {
                continue;
            }
            let base = mi.lpBaseOfDll as usize;
            if !matches!(query(base), Some(m) if m.Type == MEM_IMAGE) {
                ctx.report(F_MODULE_NOT_IMAGE, base as u64, 0);
            }
        }
        Step::Continue
    }
}
