//! Carthago Watchdog client detections (architecture plan §6, Phase 1 client list). Every
//! scanner is an incremental [`carthago_sched::Job`] that runs on the budgeted scheduler worker,
//! never on the game thread, and only observes: findings go to the server, which owns all
//! allowlists, thresholds and verdicts (plan §8.6).
//!
//! The PE reader, hook decoder, path classifier and driver list are portable and unit-tested
//! on every platform; the scanners themselves are Windows-only.

pub mod drivers;
pub mod hook;
pub mod paths;
pub mod pe;
pub mod seen;
pub mod time;

#[cfg(windows)]
pub mod input;
#[cfg(windows)]
pub mod jobs;
#[cfg(windows)]
pub mod win;

use std::sync::Arc;

pub use paths::Dirs;

/// The Phase 1 scan set, in no particular order (the scheduler orders by priority).
#[cfg(windows)]
pub fn phase1_jobs(dirs: Arc<Dirs>) -> Vec<Box<dyn carthago_sched::Job>> {
    vec![
        Box::new(jobs::ModuleInventory::new(dirs)),
        Box::new(jobs::MemoryWalk::new()),
        Box::new(jobs::ThreadAudit::new()),
        Box::new(jobs::ApiHooks::new()),
        Box::new(jobs::TextIntegrity::new()),
        Box::new(jobs::ExternalHandles::new()),
        Box::new(jobs::OverlayWindows::new()),
        Box::new(jobs::DebuggerSignals::new()),
        Box::new(jobs::VulnerableDrivers::new()),
    ]
}

#[cfg(not(windows))]
pub fn phase1_jobs(_dirs: Arc<Dirs>) -> Vec<Box<dyn carthago_sched::Job>> {
    Vec::new()
}

/// Directories used to classify module paths: Windows dir, game exe, Program Files.
#[cfg(windows)]
pub fn detect_dirs() -> Dirs {
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let windows = String::from_utf16_lossy(&buf[..n.min(buf.len())]);
    let exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let pf = [std::env::var("ProgramFiles").unwrap_or_default(), std::env::var("ProgramFiles(x86)").unwrap_or_default()];
    Dirs::new(&windows, &exe, &[pf[0].as_str(), pf[1].as_str()])
}

#[cfg(not(windows))]
pub fn detect_dirs() -> Dirs {
    Dirs::default()
}
