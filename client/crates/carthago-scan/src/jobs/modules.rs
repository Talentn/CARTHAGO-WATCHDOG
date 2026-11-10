use std::sync::Arc;
use std::time::Duration;

use carthago_proto::v1::FindingCode;
use carthago_sched::{Ctx, Job, JobBudget, Step};
use windows_sys::Win32::System::Memory::MEM_IMAGE;

use crate::paths::{base_name, Dirs};
use crate::seen::Seen;
use crate::win;

/// Loader-list inventory (plan §6.3, PEB side): every loader entry must be an image
/// mapping, and each module from outside the Windows directory is reported once by base
/// name and path class (game dir, Program Files, other). An injected DLL shows up here even
/// after its injection thread has exited; overlays (Steam, Discord, RTSS, OBS) are
/// allowlisted on the server.
pub struct ModuleInventory {
    dirs: Arc<Dirs>,
    mods: Vec<usize>,
    idx: usize,
    seen: Seen,
}

impl ModuleInventory {
    pub fn new(dirs: Arc<Dirs>) -> Self {
        Self { dirs, mods: Vec::new(), idx: 0, seen: Seen::new(1024) }
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
            max_step: Duration::from_micros(400),
            max_cpu_per_run: Duration::from_millis(20),
            share: 0.1,
            priority: 3,
        }
    }
    fn begin(&mut self) {
        win::modules(&mut self.mods);
        self.idx = 0;
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        for _ in 0..8 {
            let Some(&base) = self.mods.get(self.idx) else { return Step::Done };
            self.idx += 1;
            if !matches!(win::query(base), Some(m) if m.Type == MEM_IMAGE) {
                if self.seen.first(base as u64 ^ 0x4e49) {
                    ctx.report(FindingCode::ModuleNotImage as u32, base as u64, 0);
                }
                continue;
            }
            if !self.seen.first(base as u64) {
                continue;
            }
            let Some(path) = win::module_path(base) else { continue };
            if let Some(class) = self.dirs.classify(&path) {
                ctx.report_detail(FindingCode::ModuleLoaded as u32, base as u64, class as u64, base_name(&path));
            }
        }
        Step::Continue
    }
}
