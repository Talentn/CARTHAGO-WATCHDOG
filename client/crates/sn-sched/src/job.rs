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
    pub(crate) fn from_u8(v: u8) -> Self {
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

#[derive(Debug, Clone, Copy)]
pub struct Finding {
    pub job: &'static str,
    pub code: u32,
    pub a: u64,
    pub b: u64,
}

pub struct Ctx<'a> {
    pub(crate) job: &'static str,
    pub(crate) tx: &'a SyncSender<Finding>,
    pub(crate) dropped: &'a AtomicU64,
}

impl Ctx<'_> {
    /// Never blocks: under backpressure the finding is dropped and counted.
    pub fn report(&self, code: u32, a: u64, b: u64) {
        if let Err(TrySendError::Full(_)) = self.tx.try_send(Finding { job: self.job, code, a, b }) {
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
