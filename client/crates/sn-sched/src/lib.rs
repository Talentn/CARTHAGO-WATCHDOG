//! Budgeted scan scheduler (architecture plan §3.4).
//!
//! One below-normal-priority worker thread runs incremental [`Job`]s in resumable slices
//! (≤ 3 ms each), paid for from a global CPU token bucket plus a per-job share bucket.
//! Jobs that overrun their declared step budget are backed off exponentially and then
//! quarantined. The game thread only calls [`Scheduler::tick`].

pub mod bucket;
pub mod clock;
mod job;
mod scheduler;
mod stats;
mod sys;

pub use job::{drive, Activity, Ctx, Detail, Finding, Job, JobBudget, Step};
pub use scheduler::{Config, Scheduler};
pub use stats::{Histogram, JobStats, SchedStats};
