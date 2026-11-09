use std::os::windows::io::{AsRawHandle, RawHandle};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering::Relaxed};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::bucket::TokenBucket;
use crate::clock::{self, cycles_to_ns, thread_cycles};
use crate::job::{Activity, Ctx, Finding, Job, JobBudget, Step};
use crate::stats::{JobStats, SchedStats};
use crate::sys;

#[derive(Debug, Clone)]
pub struct Config {
    /// Global CPU budget during gameplay, as a fraction of one core.
    pub cpu_fraction_gameplay: f64,
    /// Global CPU budget in menu/loading.
    pub cpu_fraction_idle: f64,
    pub bucket_capacity: Duration,
    /// Slices stop starting new steps once wall or CPU time would pass this.
    pub slice_target: Duration,
    /// No single step may exceed this (G2: ≤ 3 ms per scan slice).
    pub slice_hard_cap: Duration,
    /// Don't start a slice with less than this many tokens available.
    pub min_slice: Duration,
    pub quarantine_strikes: u32,
    pub max_backoff: Duration,
    /// After a frame hitch is observed in `tick()`, defer new slices for this long.
    pub hitch_guard: Option<Duration>,
    pub idle_max_sleep: Duration,
    pub below_normal_priority: bool,
    pub eco_qos: bool,
    /// `None` = highest logical processor in the process affinity mask.
    pub ideal_processor: Option<u8>,
    /// Runs first on the worker thread (instrumentation hooks).
    pub worker_init: Option<fn()>,
    pub findings_capacity: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cpu_fraction_gameplay: 0.008,
            cpu_fraction_idle: 0.03,
            bucket_capacity: Duration::from_millis(6),
            slice_target: Duration::from_millis(2),
            slice_hard_cap: Duration::from_millis(3),
            min_slice: Duration::from_micros(200),
            quarantine_strikes: 3,
            max_backoff: Duration::from_secs(600),
            hitch_guard: Some(Duration::from_millis(100)),
            idle_max_sleep: Duration::from_millis(50),
            below_normal_priority: true,
            eco_qos: true,
            ideal_processor: None,
            worker_init: None,
            findings_capacity: 256,
        }
    }
}

impl Config {
    fn cpu_fraction(&self, a: Activity) -> f64 {
        match a {
            Activity::Gameplay => self.cpu_fraction_gameplay,
            Activity::Menu | Activity::Loading => self.cpu_fraction_idle,
        }
    }
}

struct Shared {
    stop: AtomicBool,
    activity: AtomicU8,
    hitch_until_ns: AtomicU64,
    frames: AtomicU64,
    dropped: AtomicU64,
    /// Incremented at slice start and end: odd = a slice is running.
    slice_seq: AtomicU64,
    stats: Mutex<SchedStats>,
}

/// Handle owned by the game thread. `tick()` is the only per-frame call.
pub struct Scheduler {
    shared: Arc<Shared>,
    rx: Receiver<Finding>,
    worker: Option<JoinHandle<()>>,
    last_tick_ns: u64,
    frame_ema_ns: f64,
    hitch_guard_ns: u64,
    findings: Vec<Finding>,
}

impl Scheduler {
    pub fn start(cfg: Config, jobs: Vec<Box<dyn Job>>) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel(cfg.findings_capacity);
        let stats = SchedStats {
            jobs: jobs.iter().map(|j| JobStats { name: j.name(), ..Default::default() }).collect(),
            ..Default::default()
        };
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            activity: AtomicU8::new(Activity::Gameplay as u8),
            hitch_until_ns: AtomicU64::new(0),
            frames: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            slice_seq: AtomicU64::new(0),
            stats: Mutex::new(stats),
        });
        let hitch_guard_ns = cfg.hitch_guard.map_or(0, |d| d.as_nanos() as u64);
        let sh = shared.clone();
        let worker = std::thread::Builder::new()
            .name("sn-sched".into())
            .stack_size(256 * 1024)
            .spawn(move || worker_main(cfg, jobs, sh, tx))?;
        Ok(Self {
            shared,
            rx,
            worker: Some(worker),
            last_tick_ns: 0,
            frame_ema_ns: 0.0,
            hitch_guard_ns,
            findings: Vec::with_capacity(64),
        })
    }

    /// Per-frame call from the game thread: a QPC read, a few atomics and a bounded,
    /// non-blocking drain of findings. Never blocks or allocates.
    #[inline]
    pub fn tick(&mut self) -> usize {
        let now = clock::now_ns();
        let prev = std::mem::replace(&mut self.last_tick_ns, now);
        if prev != 0 && self.hitch_guard_ns != 0 {
            let dt = now.saturating_sub(prev) as f64;
            if self.frame_ema_ns == 0.0 {
                self.frame_ema_ns = dt;
            } else {
                if dt > self.frame_ema_ns * 1.5 && dt > self.frame_ema_ns + 2e6 {
                    self.shared.hitch_until_ns.store(now + self.hitch_guard_ns, Relaxed);
                }
                self.frame_ema_ns += (dt - self.frame_ema_ns) / 32.0;
            }
        }
        self.shared.frames.fetch_add(1, Relaxed);
        let mut n = 0;
        while n < 16 {
            match self.rx.try_recv() {
                Ok(f) => {
                    if self.findings.len() < self.findings.capacity() {
                        self.findings.push(f);
                    } else {
                        self.shared.dropped.fetch_add(1, Relaxed);
                    }
                    n += 1;
                }
                Err(_) => break,
            }
        }
        n
    }

    pub fn set_activity(&self, a: Activity) {
        self.shared.activity.store(a as u8, Relaxed);
        if let Some(w) = &self.worker {
            w.thread().unpark();
        }
    }

    /// Findings collected by `tick()` since the last call (heartbeat batching).
    pub fn take_findings(&mut self) -> std::vec::Drain<'_, Finding> {
        self.findings.drain(..)
    }

    pub fn stats(&self) -> SchedStats {
        let mut s = self.shared.stats.lock().unwrap().clone();
        s.findings_dropped = self.shared.dropped.load(Relaxed);
        s
    }

    /// Slice sequence counter for overhead attribution: odd while a slice runs; a frame
    /// overlapped scanning if the value was odd at its start or changed during it.
    pub fn slice_seq(&self) -> u64 {
        self.shared.slice_seq.load(Relaxed)
    }

    pub fn worker_handle(&self) -> Option<RawHandle> {
        self.worker.as_ref().map(|w| w.as_raw_handle())
    }

    pub fn stop(mut self) -> SchedStats {
        self.shutdown();
        self.stats()
    }

    fn shutdown(&mut self) {
        if let Some(w) = self.worker.take() {
            self.shared.stop.store(true, Relaxed);
            w.thread().unpark();
            let _ = w.join();
        }
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct Slot {
    job: Box<dyn Job>,
    name: &'static str,
    budget: JobBudget,
    bucket: TokenBucket,
    next_due_ns: u64,
    in_run: bool,
    run_cpu_ns: u64,
    run_start_ns: u64,
    strikes: u32,
    quarantined: bool,
    throttle_noted: bool,
}

enum SliceEnd {
    Yield,
    Done,
    RunBudget,
    Overrun,
}

fn rand_below(state: &mut u64, n: u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    if n == 0 { 0 } else { *state % n }
}

/// ±20% jitter so scans don't line up with anything periodic in the game.
fn jittered(p: Duration, rng: &mut u64) -> u64 {
    let p = p.as_nanos() as u64;
    p - p / 5 + rand_below(rng, 2 * p / 5 + 1)
}

fn overrun_threshold_ns(b: &JobBudget, hard_cap_ns: u64) -> u64 {
    let m = b.max_step.as_nanos() as u64;
    (2 * m).max(m + 250_000).min(hard_cap_ns)
}

fn park_ns(ns: u64) {
    std::thread::park_timeout(Duration::from_nanos(ns.max(100_000)));
}

fn worker_main(cfg: Config, jobs: Vec<Box<dyn Job>>, sh: Arc<Shared>, tx: SyncSender<Finding>) {
    let t0 = clock::now_ns();
    sys::configure_worker(cfg.below_normal_priority, cfg.eco_qos, cfg.ideal_processor.or_else(sys::last_allowed_processor));
    if let Some(f) = cfg.worker_init {
        f();
    }
    let cpn = clock::cycles_per_ns();
    let mut now = clock::now_ns();
    {
        let mut st = sh.stats.lock().unwrap();
        st.cycles_per_ns = cpn;
        st.worker_init_ns = now - t0;
        st.worker_init_cpu_ns = cycles_to_ns(thread_cycles());
    }

    let slice_target_ns = cfg.slice_target.as_nanos() as u64;
    let hard_cap_ns = cfg.slice_hard_cap.as_nanos() as u64;
    let min_slice = cfg.min_slice.as_nanos() as f64;
    let idle_max_ns = cfg.idle_max_sleep.as_nanos() as u64;

    let mut rng = now | 1;
    let mut activity = Activity::from_u8(sh.activity.load(Relaxed));
    let mut global = TokenBucket::new(cfg.cpu_fraction(activity), cfg.bucket_capacity.as_nanos() as f64, now);
    let mut slots: Vec<Slot> = jobs
        .into_iter()
        .map(|job| {
            let budget = job.budget();
            let first = budget.period(activity).map_or(0, |p| rand_below(&mut rng, p.min(Duration::from_secs(2)).as_nanos() as u64));
            Slot {
                name: job.name(),
                job,
                budget,
                bucket: TokenBucket::new(budget.share * cfg.cpu_fraction(activity), hard_cap_ns as f64, now),
                next_due_ns: now + first,
                in_run: false,
                run_cpu_ns: 0,
                run_start_ns: 0,
                strikes: 0,
                quarantined: false,
                throttle_noted: false,
            }
        })
        .collect();

    loop {
        if sh.stop.load(Relaxed) {
            break;
        }
        now = clock::now_ns();
        sh.stats.lock().unwrap().worker_cpu_ns = cycles_to_ns(thread_cycles());

        let a = Activity::from_u8(sh.activity.load(Relaxed));
        if a != activity {
            activity = a;
            global.set_rate(cfg.cpu_fraction(a));
            for s in &mut slots {
                s.bucket.set_rate(s.budget.share * cfg.cpu_fraction(a));
                if let Some(p) = s.budget.period(a) {
                    s.next_due_ns = s.next_due_ns.min(now + p.as_nanos() as u64);
                }
            }
        }
        global.refill(now);
        for s in &mut slots {
            s.bucket.refill(now);
        }

        let hitch_until = sh.hitch_until_ns.load(Relaxed);
        if now < hitch_until && !global.is_full() {
            sh.stats.lock().unwrap().hitch_deferrals += 1;
            park_ns((hitch_until - now).min(idle_max_ns));
            continue;
        }

        let mut pick: Option<(usize, u8, u64)> = None;
        let mut wake = now + idle_max_ns;
        for (i, s) in slots.iter_mut().enumerate() {
            if s.quarantined || s.budget.period(activity).is_none() {
                continue;
            }
            if s.next_due_ns > now {
                wake = wake.min(s.next_due_ns);
                continue;
            }
            if s.bucket.tokens() < min_slice {
                if !s.throttle_noted {
                    s.throttle_noted = true;
                    sh.stats.lock().unwrap().jobs[i].share_throttled += 1;
                }
                wake = wake.min(now + s.bucket.ns_until(min_slice));
                continue;
            }
            let better = match pick {
                None => true,
                Some((_, prio, due)) => s.budget.priority > prio || (s.budget.priority == prio && s.next_due_ns < due),
            };
            if better {
                pick = Some((i, s.budget.priority, s.next_due_ns));
            }
        }

        let Some((i, _, _)) = pick else {
            sh.stats.lock().unwrap().wakeups += 1;
            park_ns(wake.saturating_sub(now));
            continue;
        };
        if global.tokens() < min_slice {
            let mut st = sh.stats.lock().unwrap();
            st.global_throttled += 1;
            st.wakeups += 1;
            drop(st);
            park_ns(global.ns_until(min_slice).min(idle_max_ns));
            continue;
        }

        let s = &mut slots[i];
        s.throttle_noted = false;
        let slice_budget_ns = (slice_target_ns as f64).min(global.tokens()).min(s.bucket.tokens()) as u64;
        let overrun_ns = overrun_threshold_ns(&s.budget, hard_cap_ns);
        let max_step_ns = s.budget.max_step.as_nanos() as u64;
        let max_run_ns = s.budget.max_cpu_per_run.as_nanos() as u64;
        let ctx = Ctx { job: s.name, tx: &tx, dropped: &sh.dropped };

        sh.slice_seq.fetch_add(1, Relaxed);
        let w0 = clock::now_ns();
        let c0 = thread_cycles();
        if !s.in_run {
            s.job.begin();
            s.in_run = true;
            s.run_cpu_ns = 0;
            s.run_start_ns = w0;
        }
        let mut c_prev = c0;
        let mut steps = 0u64;
        let mut max_step_seen = 0u64;
        let mut end = SliceEnd::Yield;
        loop {
            let r = s.job.step(&ctx);
            let c = thread_cycles();
            let step_ns = cycles_to_ns(c - c_prev);
            c_prev = c;
            steps += 1;
            max_step_seen = max_step_seen.max(step_ns);
            if step_ns > overrun_ns {
                end = SliceEnd::Overrun;
                break;
            }
            if r == Step::Done {
                end = SliceEnd::Done;
                break;
            }
            let slice_cpu = cycles_to_ns(c - c0);
            if s.run_cpu_ns + slice_cpu > max_run_ns {
                end = SliceEnd::RunBudget;
                break;
            }
            if slice_cpu + max_step_ns > slice_budget_ns
                || (clock::now_ns() - w0) + max_step_ns > slice_target_ns
                || sh.stop.load(Relaxed)
            {
                break;
            }
        }
        let slice_cpu = cycles_to_ns(thread_cycles() - c0);
        let w1 = clock::now_ns();
        sh.slice_seq.fetch_add(1, Relaxed);
        global.charge(slice_cpu);
        s.bucket.charge(slice_cpu);
        s.run_cpu_ns += slice_cpu;

        let mut st = sh.stats.lock().unwrap();
        st.slices += 1;
        st.slice_cpu.record(slice_cpu);
        st.slice_wall.record(w1 - w0);
        st.charged_cpu_ns += slice_cpu;
        let js = &mut st.jobs[i];
        js.slices += 1;
        js.steps += steps;
        js.cpu_ns += slice_cpu;
        js.max_step_cpu_ns = js.max_step_cpu_ns.max(max_step_seen);
        let period = s.budget.period(activity).unwrap_or(cfg.max_backoff);
        match end {
            SliceEnd::Yield => {}
            SliceEnd::Done => {
                s.in_run = false;
                s.strikes = s.strikes.saturating_sub(1);
                js.runs_completed += 1;
                js.last_pass_cpu_ns = s.run_cpu_ns;
                js.last_pass_wall_ns = w1 - s.run_start_ns;
                s.next_due_ns = w1 + jittered(period, &mut rng);
            }
            SliceEnd::RunBudget => {
                s.in_run = false;
                js.runs_aborted_budget += 1;
                s.next_due_ns = w1 + jittered(period, &mut rng);
            }
            SliceEnd::Overrun => {
                s.in_run = false;
                s.strikes += 1;
                js.overruns += 1;
                if s.strikes >= cfg.quarantine_strikes {
                    s.quarantined = true;
                } else {
                    let backoff = period.saturating_mul(1 << s.strikes).min(cfg.max_backoff);
                    s.next_due_ns = w1 + backoff.as_nanos() as u64;
                }
            }
        }
        js.strikes = s.strikes;
        js.quarantined = s.quarantined;
    }
    sh.stats.lock().unwrap().worker_cpu_ns = cycles_to_ns(thread_cycles());
}
