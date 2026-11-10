use std::time::Duration;

use sn_proto::v1::{FindingCode, UnbackedFlags};
use sn_sched::{Ctx, Job, JobBudget, Step};
use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE};

use crate::seen::{fnv1a, Seen};
use crate::win;

const USER_TOP: usize = 0x7FFF_FFFF_0000;

/// VirtualQuery walk (plan §6.3 module inventory, VAD side):
/// - executable memory that is not image-backed (manual maps, shellcode), with header and
///   protection flags so the server can tell a mapped PE from a JIT or hook trampoline;
/// - image mappings that are executable but absent from the loader list (unlinked modules).
pub struct MemoryWalk {
    addr: usize,
    loader: Vec<usize>,
    /// Current non-loader image allocation: (allocation base, size so far, has exec).
    pending: Option<(usize, usize, bool)>,
    rechecks: u32,
    seen: Seen,
}

impl MemoryWalk {
    pub fn new() -> Self {
        Self { addr: 0, loader: Vec::new(), pending: None, rechecks: 0, seen: Seen::new(512) }
    }

    fn header_flags(base: usize) -> u64 {
        let mut f = 0u64;
        let Some(m) = win::query(base) else { return 0 };
        if m.State != MEM_COMMIT || !win::is_readable(m.Protect) {
            return 0;
        }
        let mut dos = [0u8; 0x40];
        if !win::read_self(base, &mut dos) {
            return 0;
        }
        if &dos[..2] == b"MZ" {
            f |= UnbackedFlags::MzHeader as u64;
        }
        let lfanew = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap()) as usize;
        let mut sig = [0u8; 4];
        // Wiped-MZ manual maps often keep the NT signature.
        if (0x40..0x1000).contains(&lfanew) && win::read_self(base + lfanew, &mut sig) && &sig == b"PE\0\0" {
            f |= UnbackedFlags::PeSignature as u64;
        }
        f
    }

    fn flush_pending(&mut self, ctx: &Ctx<'_>) {
        let Some((base, size, exec)) = self.pending.take() else { return };
        if !exec || !self.seen.first(fnv1a(&[b"img", &base.to_le_bytes()])) {
            return;
        }
        // The module list was snapshotted at begin(); a module loaded since then is not
        // hidden, so re-check (bounded per pass) before reporting.
        if self.rechecks < 4 {
            self.rechecks += 1;
            win::modules(&mut self.loader);
            self.loader.sort_unstable();
            if self.loader.binary_search(&base).is_ok() {
                return;
            }
        }
        ctx.report_detail(FindingCode::ImageNotInLoader as u32, base as u64, size as u64, &win::mapped_file_base_name(base));
    }

    fn region(&mut self, m: &MEMORY_BASIC_INFORMATION, ctx: &Ctx<'_>) {
        let alloc = m.AllocationBase as usize;
        if self.pending.is_some_and(|(b, _, _)| b != alloc) {
            self.flush_pending(ctx);
        }
        if m.State != MEM_COMMIT {
            return;
        }
        let exec = win::is_exec(m.Protect);
        if m.Type == MEM_IMAGE {
            if let Some(p) = self.pending.as_mut() {
                p.1 += m.RegionSize;
                p.2 |= exec;
            } else if m.BaseAddress as usize == alloc && self.loader.binary_search(&alloc).is_err() {
                self.pending = Some((alloc, m.RegionSize, exec));
            }
            return;
        }
        if exec {
            let base = m.BaseAddress as usize;
            if !self.seen.first(fnv1a(&[b"exec", &base.to_le_bytes()])) {
                return;
            }
            let mut f = Self::header_flags(alloc) | Self::header_flags(base);
            if m.Type == MEM_PRIVATE {
                f |= UnbackedFlags::Private as u64;
            }
            if win::is_writable(m.Protect) {
                f |= UnbackedFlags::Writable as u64;
            }
            let size = (m.RegionSize as u64) & ((1 << 48) - 1);
            ctx.report(FindingCode::UnbackedExec as u32, base as u64, size | f << 48);
        }
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
            share: 0.2,
            priority: 2,
        }
    }
    fn begin(&mut self) {
        self.addr = 0;
        self.pending = None;
        self.rechecks = 0;
        win::modules(&mut self.loader);
        self.loader.sort_unstable();
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        for _ in 0..64 {
            let Some(m) = win::query(self.addr) else {
                self.flush_pending(ctx);
                return Step::Done;
            };
            self.region(&m, ctx);
            let next = m.BaseAddress as usize + m.RegionSize;
            if next <= self.addr || next >= USER_TOP {
                self.flush_pending(ctx);
                return Step::Done;
            }
            self.addr = next;
        }
        Step::Continue
    }
}
