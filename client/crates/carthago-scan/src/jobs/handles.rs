use std::time::Duration;

use carthago_proto::v1::{FindingCode, HolderFlags};
use carthago_sched::{Ctx, Job, JobBudget, Step};
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessHandleInformation};
use windows_sys::Win32::Foundation::{DuplicateHandle, HANDLE};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessId, OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::external::{observed_flags, Watch};
use crate::paths::Dirs;
use crate::seen::Seen;
use crate::signature;
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
///
/// In-process the watched process is the scanner's own. A companion watches another process
/// ([`ExternalHandles::for_target`]) and skips itself as a holder.
pub struct ExternalHandles {
    cur: Owned,
    self_pid: u32,
    /// The process whose handles are being looked for.
    game_pid: u32,
    watch: Option<std::sync::Arc<Watch>>,
    process_type: Option<u32>,
    buf: Vec<u8>,
    seen: Seen,
    /// A companion also says what the holder is: where its program file lies and whether
    /// it is signed. In-process the name alone is sent, as before.
    about: Option<(std::sync::Arc<Dirs>, signature::Worker)>,
    waiting: Vec<(u64, String)>,
    /// Holders whose program file is being looked at, with whether they turned up after
    /// the picture of the started game was taken.
    pending: Vec<(u64, bool)>,
    /// A whole pass over the processes was made for this game after its picture was taken.
    saw_start: Option<u32>,
    after_picture: bool,
    after_start: bool,
}

// SAFETY: handles owned by the job, used only on the scheduler worker.
unsafe impl Send for ExternalHandles {}

impl ExternalHandles {
    pub fn new() -> Self {
        let self_pid = unsafe { GetCurrentProcessId() };
        Self {
            cur: Owned(std::ptr::null_mut()),
            self_pid,
            game_pid: self_pid,
            watch: None,
            process_type: None,
            buf: vec![0; 64 * 1024],
            seen: Seen::new(256),
            about: None,
            waiting: Vec::new(),
            pending: Vec::new(),
            saw_start: None,
            after_picture: false,
            after_start: false,
        }
    }

    /// Watches the companion's target process instead of the scanner's own. Idle until the
    /// target is set.
    pub fn for_target(watch: std::sync::Arc<Watch>, dirs: std::sync::Arc<Dirs>) -> Self {
        Self { game_pid: 0, watch: Some(watch), about: signature::Worker::start().ok().map(|w| (dirs, w)), ..Self::new() }
    }

    /// Sends the holders whose program file has been looked at.
    fn drain(&mut self, ctx: &Ctx<'_>) {
        let Some((dirs, worker)) = &self.about else { return };
        if let Some((key, path)) = self.waiting.pop() {
            if !worker.submit(key, carthago_proto::v1::ModulePathClass::Other, path.clone()) {
                self.waiting.push((key, path));
            }
        }
        for _ in 0..4 {
            let Some(c) = worker.poll() else { break };
            let class = dirs.classify(&c.path).map_or(0, |c| c as u64 + 1);
            let after_start = match self.pending.iter().position(|(k, _)| *k == c.base) {
                Some(i) => self.pending.swap_remove(i).1,
                None => false,
            };
            let when = match &self.watch {
                Some(w) => observed_flags(w, after_start, &format!("holder:{}:{}", c.name.to_lowercase(), c.digest)),
                None => 0,
            };
            let about = c.state as u64 | class << 8 | HolderFlags::Known as u64 | when << 24;
            ctx.report_detail(FindingCode::ExternalHandle as u32, c.base >> 32, c.base & 0xffff_ffff | about << 32, &c.name);
        }
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
        if pid == self.self_pid || pid == self.game_pid || pid == 0 {
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
            if unsafe { GetProcessId(dup.0) } == self.game_pid {
                worst |= e.granted_access;
            }
        }
        if worst != 0 && self.seen.first((pid as u64) << 32 | worst as u64) {
            let key = (pid as u64) << 32 | worst as u64;
            let path = win::process_image_path_of(holder);
            match &self.about {
                Some((_, worker)) if !path.is_empty() => {
                    if self.pending.len() >= 256 {
                        self.pending.clear();
                    }
                    self.pending.push((key, self.after_start));
                    if !worker.submit(key, carthago_proto::v1::ModulePathClass::Other, path.clone()) && self.waiting.len() < 64 {
                        self.waiting.push((key, path));
                    }
                }
                _ => ctx.report_detail(FindingCode::ExternalHandle as u32, pid as u64, worst as u64, crate::paths::base_name(&path)),
            }
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
        if let Some(watch) = &self.watch {
            self.game_pid = watch.target().map_or(0, |t| t.pid());
            // The first whole pass after the picture of the started game was taken, and the
            // passes before it, show the start. Only later passes can show a new holder.
            self.after_picture = self.game_pid != 0 && watch.settled(self.game_pid);
            self.after_start = self.after_picture && self.saw_start == Some(self.game_pid);
        }
        if self.process_type.is_none() {
            self.process_type = self.learn_process_type();
        }
    }
    fn step(&mut self, ctx: &Ctx<'_>) -> Step {
        self.drain(ctx);
        if self.process_type.is_none() || self.game_pid == 0 {
            // Where other processes cannot be listed at all, there is nothing to record.
            if let Some(w) = self.watch.as_ref().filter(|_| self.process_type.is_none() && self.after_picture) {
                w.whole("holder");
            }
            return Step::Done;
        }
        let mut next = std::ptr::null_mut();
        let st = unsafe { NtGetNextProcess(self.cur.0, PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, 0, 0, &mut next) };
        if st < 0 {
            self.cur = Owned(std::ptr::null_mut());
            if let Some(w) = self.watch.as_ref().filter(|_| self.after_picture && self.saw_start != Some(self.game_pid)) {
                self.saw_start = Some(self.game_pid);
                w.whole("holder");
            }
            return Step::Done;
        }
        self.cur = Owned(next);
        self.scan(next, ctx);
        Step::Continue
    }
}
