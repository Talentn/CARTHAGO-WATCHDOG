use std::time::Duration;

use carthago_proto::v1::FindingCode;
use carthago_sched::{Ctx, Job, JobBudget, Step};
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessHandleInformation};
use windows_sys::Win32::Foundation::{DuplicateHandle, HANDLE};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessId, OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::seen::Seen;
use crate::win::{self, NtGetNextProcess, Owned};

/// PROCESS_HANDLE_TABLE_ENTRY_INFO (ntpsapi.h).
#[repr(C)]
#[derive(Clone, Copy)]
struct HandleEntry {
    handle: HANDLE,
    handle_count: usize,
    pointer_count: usize,
    granted_access: u32,
    object_type_index: u32,
    attributes: u32,
    reserved: u32,
}

const HEADER: usize = 2 * size_of::<usize>();
const MAX_SNAPSHOT: usize = 1 << 20;
const MAX_DUPS_PER_STEP: u32 = 128;
/// PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD.
pub const SUSPICIOUS_ACCESS: u32 = 0x10 | 0x20 | 0x08 | 0x02;

fn handle_snapshot(process: HANDLE, buf: &mut Vec<u8>) -> Option<usize> {
    loop {
        let mut need = 0u32;
        let st = unsafe { NtQueryInformationProcess(process, ProcessHandleInformation, buf.as_mut_ptr().cast(), buf.len() as u32, &mut need) };
        if st >= 0 {
            let n = usize::from_le_bytes(buf[..size_of::<usize>()].try_into().unwrap());
            return Some(n.min((buf.len() - HEADER) / size_of::<HandleEntry>()));
        }
        // STATUS_INFO_LENGTH_MISMATCH: grow once to the reported size, bounded.
        let want = (need as usize + 4096).max(buf.len() * 2);
        if st as u32 != 0xC000_0004 || want > MAX_SNAPSHOT {
            return None;
        }
        buf.resize(want, 0);
    }
}

fn entry(buf: &[u8], i: usize) -> HandleEntry {
    let off = HEADER + i * size_of::<HandleEntry>();
    unsafe { std::ptr::read_unaligned(buf[off..off + size_of::<HandleEntry>()].as_ptr().cast()) }
}

/// External handle detection (plan §6.2 external ESP, §6.3 memory editing): walks the
/// processes this user can open (`NtGetNextProcess`, one per step), reads each one's handle
/// table (`ProcessHandleInformation`) and finds process handles to the game that grant
/// memory or thread access. This is what Cheat Engine and external ESP readers hold.
/// Elevated holders can't be opened from the game's medium integrity and are not seen;
/// launchers, overlays and capture tools that hold such handles are allowlisted on the server.
pub struct ExternalHandles {
    cur: Owned,
    self_pid: u32,
    process_type: Option<u32>,
    buf: Vec<u8>,
    seen: Seen,
}

// SAFETY: handles owned by the job, used only on the scheduler worker.
unsafe impl Send for ExternalHandles {}

impl ExternalHandles {
    pub fn new() -> Self {
        Self { cur: Owned(std::ptr::null_mut()), self_pid: unsafe { GetCurrentProcessId() }, process_type: None, buf: vec![0; 64 * 1024], seen: Seen::new(256) }
    }

    /// The object type index of "Process", learned from a handle we open to ourselves.
    fn learn_process_type(&mut self) -> Option<u32> {
        let me = Owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, self.self_pid) });
        if me.is_null() {
            return None;
        }
        let n = handle_snapshot(unsafe { GetCurrentProcess() }, &mut self.buf)?;
        (0..n).map(|i| entry(&self.buf, i)).find(|e| e.handle == me.0).map(|e| e.object_type_index)
    }

    fn scan(&mut self, holder: HANDLE, ctx: &Ctx<'_>) {
        let pid = unsafe { GetProcessId(holder) };
        let Some(ptype) = self.process_type else { return };
        if pid == self.self_pid || pid == 0 {
            return;
        }
        let Some(n) = handle_snapshot(holder, &mut self.buf) else { return };
        let mut dups = 0;
        let mut worst = 0u32;
        for i in 0..n {
            let e = entry(&self.buf, i);
            if e.object_type_index != ptype || e.granted_access & SUSPICIOUS_ACCESS == 0 {
                continue;
            }
            if dups == MAX_DUPS_PER_STEP {
                break;
            }
            dups += 1;
            let mut dup = std::ptr::null_mut();
            let ok = unsafe { DuplicateHandle(holder, e.handle, GetCurrentProcess(), &mut dup, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0) };
            if ok == 0 {
                continue;
            }
            let dup = Owned(dup);
            if unsafe { GetProcessId(dup.0) } == self.self_pid {
                worst |= e.granted_access;
            }
        }
        if worst != 0 && self.seen.first((pid as u64) << 32 | worst as u64) {
            ctx.report_detail(FindingCode::ExternalHandle as u32, pid as u64, worst as u64, &win::process_image_name_of(holder));
        }
    }
}

impl Default for ExternalHandles {
    fn default() -> Self {
        Self::new()
    }
}

impl Job for ExternalHandles {
    fn name(&self) -> &'static str {
        "external_handles"
    }
    fn budget(&self) -> JobBudget {
        JobBudget {
            period_gameplay: Some(Duration::from_secs(10)),
            period_idle: Some(Duration::from_secs(4)),
            max_step: Duration::from_micros(600),
            max_cpu_per_run: Duration::from_millis(30),
            share: 0.15,
            priority: 2,
        }
    }
    fn begin(&mut self) {
        self.cur = Owned(std::ptr::null_mut());
        if self.process_type.is_none() {
            self.process_type = self.learn_process_type();
        }
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        if self.process_type.is_none() {
            return Step::Done;
        }
        let mut next = std::ptr::null_mut();
        let st = unsafe { NtGetNextProcess(self.cur.0, PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, 0, 0, &mut next) };
        if st < 0 {
            self.cur = Owned(std::ptr::null_mut());
            return Step::Done;
        }
        self.cur = Owned(next);
        self.scan(next, ctx);
        Step::Continue
    }
}
