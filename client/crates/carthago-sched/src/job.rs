use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::time::Duration;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    Gameplay = 0,
    Menu = 1,
    Loading = 2,
}

impl Activity {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Menu,
            2 => Self::Loading,
            _ => Self::Gameplay,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Continue,
    Done,
}

/// Budget metadata a job (or streamed module) declares; the scheduler enforces it.
#[derive(Debug, Clone, Copy)]
pub struct JobBudget {
    /// Time between full passes in gameplay; `None` = never runs during gameplay.
    pub period_gameplay: Option<Duration>,
    /// Time between full passes in menu/loading.
    pub period_idle: Option<Duration>,
    /// Declared worst-case CPU of one `step()`. Exceeding it (with grace) is a strike.
    pub max_step: Duration,
    /// CPU allowed for one full pass; exceeding it aborts the pass.
    pub max_cpu_per_run: Duration,
    /// Fraction of the global CPU budget this job may consume.
    pub share: f64,
    /// Higher runs first among due jobs (cheap, high-signal checks get high priority).
    pub priority: u8,
}

impl JobBudget {
    pub(crate) fn period(&self, a: Activity) -> Option<Duration> {
        match a {
            Activity::Gameplay => self.period_gameplay,
            Activity::Menu | Activity::Loading => self.period_idle,
        }
    }
}

/// Short inline text attached to a finding (a module or process base name). Fixed size so
/// findings stay `Copy` and moving them through `tick()` never allocates.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Detail {
    len: u8,
    buf: [u8; Detail::CAP],
}

impl Detail {
    pub const CAP: usize = 47;
    pub const EMPTY: Detail = Detail { len: 0, buf: [0; Detail::CAP] };

    /// Truncates on a UTF-8 boundary.
    pub fn new(s: &str) -> Self {
        let mut n = s.len().min(Self::CAP);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        let mut d = Self::EMPTY;
        d.buf[..n].copy_from_slice(&s.as_bytes()[..n]);
        d.len = n as u8;
        d
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for Detail {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl std::fmt::Debug for Detail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Finding {
    pub job: &'static str,
    pub code: u32,
    pub a: u64,
    pub b: u64,
    pub detail: Detail,
    /// SHA-256 of the file a module finding is about, when the job has it.
    pub file_sha256: Option<[u8; 32]>,
}

pub struct Ctx<'a> {
    pub(crate) job: &'static str,
    pub(crate) tx: &'a SyncSender<Finding>,
    pub(crate) dropped: &'a AtomicU64,
}

impl Ctx<'_> {
    /// Never blocks: under backpressure the finding is dropped and counted.
    pub fn report(&self, code: u32, a: u64, b: u64) {
        self.report_detail(code, a, b, "");
    }

    pub fn report_detail(&self, code: u32, a: u64, b: u64, detail: &str) {
        self.report_file(code, a, b, detail, None);
    }

    /// A finding about a file, with the file's SHA-256.
    pub fn report_file(&self, code: u32, a: u64, b: u64, detail: &str, file_sha256: Option<[u8; 32]>) {
        let f = Finding { job: self.job, code, a, b, detail: Detail::new(detail), file_sha256 };
        if let Err(TrySendError::Full(_)) = self.tx.try_send(f) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// An incremental scanner. Each `step()` must do a small, bounded unit of work
/// ("walk the next 64 regions") and return; the scheduler owns the loop.
pub trait Job: Send {
    fn name(&self) -> &'static str;
    fn budget(&self) -> JobBudget;
    /// Start (or restart after an abort) a full pass.
    fn begin(&mut self);
    fn step(&mut self, ctx: &Ctx<'_>) -> Step;
}

/// Runs one job synchronously on the calling thread, outside any budget, until it returns
/// `Done` or `max_steps` steps have run. For tests and tools that exercise a scanner without
/// the scheduler; returns the findings and whether the pass completed.
pub fn drive(job: &mut dyn Job, max_steps: usize) -> (Vec<Finding>, bool) {
    let (tx, rx) = std::sync::mpsc::sync_channel(4096);
    let dropped = AtomicU64::new(0);
    let ctx = Ctx { job: job.name(), tx: &tx, dropped: &dropped };
    job.begin();
    let mut done = false;
    for _ in 0..max_steps {
        if job.step(&ctx) == Step::Done {
            done = true;
            break;
        }
    }
    drop(tx);
    (rx.into_iter().collect(), done)
}

#[cfg(test)]
mod tests {
    use super::Detail;

    #[test]
    fn detail_truncates_on_char_boundary() {
        assert_eq!(Detail::new("cheat.dll").as_str(), "cheat.dll");
        let long = "é".repeat(40);
        let d = Detail::new(&long);
        assert!(d.as_str().len() <= Detail::CAP);
        assert!(d.as_str().chars().all(|c| c == 'é'));
        assert!(Detail::EMPTY.is_empty());
    }
}
