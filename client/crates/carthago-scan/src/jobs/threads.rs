use std::time::Duration;

use sn_proto::v1::{FindingCode, WatchedApi};
use sn_sched::{Ctx, Job, JobBudget, Step};
use windows_sys::Wdk::System::Threading::{NtQueryInformationThread, ThreadQuerySetWin32StartAddress};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_IMAGE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetThreadId, THREAD_QUERY_INFORMATION};

use crate::seen::Seen;
use crate::win::{self, NtGetNextThread, Owned};

/// Thread audit (plan §6.3): the Win32 start address of every thread in the process.
/// Flags starts outside any image (shellcode, manual maps) and starts at a loader entry
/// point, the signature of a CreateRemoteThread(LoadLibrary) injection. Uses per-process
/// `NtGetNextThread`, which is resumable; Toolhelp snapshots are system-wide and cost 4-7 ms
/// in one unsliceable call (scheduler spike finding 3).
pub struct ThreadAudit {
    cur: Owned,
    loader_entries: Vec<(usize, WatchedApi)>,
    seen: Seen,
}

// SAFETY: the thread handle is owned by the job and only used on the scheduler worker.
unsafe impl Send for ThreadAudit {}

fn export(module: &str, name: &[u8]) -> Option<usize> {
    let m = unsafe { GetModuleHandleW(win::wide(module).as_ptr()) };
    if m.is_null() {
        return None;
    }
    let mut n = name.to_vec();
    n.push(0);
    unsafe { GetProcAddress(m, n.as_ptr()) }.map(|f| f as usize)
}

impl ThreadAudit {
    /// Resolves loader entry points once; call off the game thread (SDK init).
    pub fn new() -> Self {
        let entries = [
            ("kernel32.dll", &b"LoadLibraryA"[..], WatchedApi::Kernel32LoadLibraryA),
            ("kernel32.dll", b"LoadLibraryW", WatchedApi::Kernel32LoadLibraryW),
            ("kernelbase.dll", b"LoadLibraryExA", WatchedApi::KernelbaseLoadLibraryExA),
            ("kernelbase.dll", b"LoadLibraryExW", WatchedApi::KernelbaseLoadLibraryExW),
            ("ntdll.dll", b"LdrLoadDll", WatchedApi::NtdllLdrLoadDll),
        ];
        let loader_entries = entries.iter().filter_map(|(m, n, id)| export(m, n).map(|a| (a, *id))).collect();
        Self { cur: Owned(std::ptr::null_mut()), loader_entries, seen: Seen::new(1024) }
    }
}

impl Default for ThreadAudit {
    fn default() -> Self {
        Self::new()
    }
}

impl Job for ThreadAudit {
    fn name(&self) -> &'static str {
        "thread_audit"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(5)),
            period_idle: Some(Duration::from_secs(3)),
            max_step: Duration::from_micros(300),
            max_cpu_per_run: Duration::from_millis(10),
            share: 0.05,
            priority: 3,
        }
    }
    fn begin(&mut self) {
        self.cur = Owned(std::ptr::null_mut());
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        for _ in 0..16 {
            let mut next = std::ptr::null_mut();
            let st = unsafe { NtGetNextThread(GetCurrentProcess(), self.cur.0, THREAD_QUERY_INFORMATION, 0, 0, &mut next) };
            if st < 0 {
                self.cur = Owned(std::ptr::null_mut());
                return Step::Done;
            }
            self.cur = Owned(next);
            let mut start = 0usize;
            let st = unsafe {
                NtQueryInformationThread(next, ThreadQuerySetWin32StartAddress, (&mut start as *mut usize).cast(), size_of::<usize>() as u32, std::ptr::null_mut())
            };
            if st < 0 || start == 0 {
                continue;
            }
            let tid = unsafe { GetThreadId(next) } as u64;
            if !self.seen.first(tid << 32 ^ start as u64) {
                continue;
            }
            if let Some((_, api)) = self.loader_entries.iter().find(|(a, _)| *a == start) {
                ctx.report_detail(FindingCode::ThreadStartLoader as u32, start as u64, tid, api.as_str_name());
                continue;
            }
            match win::query(start) {
                Some(m) if m.State == MEM_COMMIT && m.Type == MEM_IMAGE => {}
                _ => ctx.report(FindingCode::ThreadStartUnbacked as u32, start as u64, tid),
            }
        }
        Step::Continue
    }
}
