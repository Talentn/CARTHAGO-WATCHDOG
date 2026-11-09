//! Phase 0 risk spike 2: does the budgeted scheduler hold the G2 budgets under a game loop?
//!
//!   sched-spike bench [--quick] [--block-secs N] [--pairs N] [--demo-secs N]
//!                     [--profiles desktop,lowend-2c,lowend-1c] [--slice-us N] [--out DIR]
//!   sched-spike hog --threads N --duty F --mask HEX [--eco]   (internal: background load)

mod alloc;
mod game;
mod jobs;
mod sysutil;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sn_sched::clock::{self, now_ns};
use sn_sched::{Config, Job, SchedStats, Scheduler};
use windows_sys::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

use game::{Game, GameCfg};

#[global_allocator]
static ALLOC: alloc::Counting = alloc::Counting;

const TICK_BUDGET_NS: u64 = 20_000;
const CPU_BUDGET_PCT: f64 = 1.0;
const SLICE_BUDGET_NS: u64 = 3_000_000;
const FRAME_DELTA_BUDGET_PCT: f64 = 1.0;
const RAM_BUDGET: u64 = 25 * 1024 * 1024;
const INIT_BUDGET_NS: u64 = 50_000_000;

struct Profile {
    name: &'static str,
    desc: &'static str,
    mask: Option<usize>,
    eco: bool,
    game: GameCfg,
    hog_threads: usize,
    hog_duty: f64,
}

fn profiles() -> Vec<Profile> {
    vec![
        Profile {
            name: "desktop",
            desc: "this PC, all logical CPUs, 144 fps target, main + 3 game workers at 30% of frame (single-thread calibrated; ~60-70% of frame once 4 threads share the memory system)",
            mask: None,
            eco: false,
            game: GameCfg { fps: 144.0, workers: 3, work_fraction: 0.3 },
            hog_threads: 0,
            hog_duty: 0.0,
        },
        Profile {
            name: "lowend-2c",
            desc: "simulated low-end laptop: 2 physical cores (CPU 4,6, no SMT siblings), process EcoQoS (lower clocks), 60 fps, main + 1 worker at 40% of frame, background load 2 threads x 25% duty in another process",
            mask: Some(0b0101_0000),
            eco: true,
            game: GameCfg { fps: 60.0, workers: 1, work_fraction: 0.4 },
            hog_threads: 2,
            hog_duty: 0.25,
        },
        Profile {
            name: "lowend-1c",
            desc: "worst case: 1 logical CPU (CPU 6), process EcoQoS, 60 fps, main thread only at 40% of frame, background load 1 thread x 20% duty",
            mask: Some(0b0100_0000),
            eco: true,
            game: GameCfg { fps: 60.0, workers: 0, work_fraction: 0.4 },
            hog_threads: 1,
            hog_duty: 0.2,
        },
    ]
}

static SLICE_TARGET_US: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(2000);

fn sched_config() -> Config {
    let us = SLICE_TARGET_US.load(std::sync::atomic::Ordering::Relaxed);
    Config { worker_init: Some(alloc::tag_current_thread), slice_target: Duration::from_micros(us), ..Config::default() }
}

struct Opts {
    block_secs: f64,
    pairs: usize,
    demo_secs: f64,
    profiles: Vec<String>,
    out: PathBuf,
}

fn parse_opts(args: &[String]) -> Result<Opts> {
    let mut o = Opts {
        block_secs: 8.0,
        pairs: 8,
        demo_secs: 30.0,
        profiles: profiles().iter().map(|p| p.name.to_string()).collect(),
        out: PathBuf::from("sched-spike-report"),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().context(format!("{a} needs a value"));
        match a.as_str() {
            "--quick" => {
                o.block_secs = 5.0;
                o.pairs = 2;
                o.demo_secs = 20.0;
            }
            "--block-secs" => o.block_secs = val()?.parse()?,
            "--pairs" => o.pairs = val()?.parse()?,
            "--demo-secs" => o.demo_secs = val()?.parse()?,
            "--slice-us" => SLICE_TARGET_US.store(val()?.parse()?, std::sync::atomic::Ordering::Relaxed),
            "--profiles" => o.profiles = val()?.split(',').map(str::to_string).collect(),
            "--out" => o.out = PathBuf::from(val()?),
            other => bail!("unknown option {other}"),
        }
    }
    Ok(o)
}

#[derive(Default)]
struct Block {
    on: bool,
    frames: Vec<u32>,
    /// Per frame (ON blocks): did a scheduler slice run during this frame?
    overlap: Vec<bool>,
    /// Per frame (ON blocks): was a slice already running when the frame started?
    /// Unlike `overlap`, this isn't biased towards long frames.
    started_in_slice: Vec<bool>,
    ticks: Vec<u32>,
    missed: u64,
    wall_ns: u64,
    proc_cpu_ns: u64,
    worker_cycles_ns: u64,
    worker_times_ns: u64,
    heap_peak: usize,
    allocs: u64,
    private_delta: i64,
    ws_delta: i64,
    init_main_ns: u64,
    findings: u64,
    stats: Option<SchedStats>,
}

fn run_block(game: &mut Game, secs: f64, make_jobs: Option<&dyn Fn() -> Vec<Box<dyn Job>>>) -> Block {
    let mut b = Block { on: make_jobs.is_some(), ..Default::default() };
    let est = (secs * game.cfg.fps * 1.1) as usize;
    b.frames.reserve(est);
    alloc::reset();
    let (p0, w0) = sysutil::mem();
    let mut sched = make_jobs.map(|mk| {
        let t = now_ns();
        let cfg = sched_config();
        let s = alloc::with_tag(|| Scheduler::start(cfg, mk()).expect("start scheduler"));
        b.init_main_ns = now_ns() - t;
        b.ticks.reserve(est);
        s
    });
    let (mut pmax, mut wmax) = (p0, w0);
    let cpu0 = sysutil::process_cpu_ns();
    let start = now_ns();
    let end = start + (secs * 1e9) as u64;
    let mut next_mem = start;
    let ticks = &mut b.ticks;
    let mut findings = 0u64;
    while now_ns() < end {
        let seq0 = sched.as_ref().map_or(0, |s| s.slice_seq());
        let mut seq1 = seq0;
        let (fs, ft) = game.frame(|| {
            if let Some(s) = sched.as_mut() {
                seq1 = s.slice_seq();
                let t = now_ns();
                s.tick();
                ticks.push((now_ns() - t) as u32);
                findings += s.take_findings().count() as u64;
            }
        });
        b.frames.push(ft as u32);
        if b.on {
            b.overlap.push(seq0 % 2 == 1 || seq1 != seq0);
            b.started_in_slice.push(seq0 % 2 == 1);
        }
        if ft > game.period_ns {
            b.missed += 1;
        }
        let now = now_ns();
        if now >= next_mem {
            let (p, w) = sysutil::mem();
            pmax = pmax.max(p);
            wmax = wmax.max(w);
            next_mem = now + 250_000_000;
        }
        game.pace(fs);
    }
    b.wall_ns = now_ns() - start;
    b.proc_cpu_ns = sysutil::process_cpu_ns() - cpu0;
    b.findings = findings;
    b.private_delta = pmax as i64 - p0 as i64;
    b.ws_delta = wmax as i64 - w0 as i64;
    if let Some(s) = sched {
        let h = s.worker_handle().unwrap();
        b.worker_cycles_ns = (sysutil::thread_cycles(h) as f64 / clock::cycles_per_ns()) as u64;
        b.worker_times_ns = sysutil::thread_times_ns(h);
        b.stats = Some(s.stop());
        (b.heap_peak, b.allocs) = alloc::snapshot();
    }
    b
}

#[derive(Debug, Clone, Copy, Default)]
struct Dist {
    n: usize,
    mean: f64,
    p50: f64,
    p99: f64,
    p999: f64,
    max: f64,
}

fn dist(v: impl IntoIterator<Item = u32>) -> Dist {
    let mut v: Vec<u32> = v.into_iter().collect();
    if v.is_empty() {
        return Dist::default();
    }
    v.sort_unstable();
    let q = |p: f64| v[(((v.len() - 1) as f64) * p).round() as usize] as f64;
    Dist {
        n: v.len(),
        mean: v.iter().map(|&x| x as f64).sum::<f64>() / v.len() as f64,
        p50: q(0.5),
        p99: q(0.99),
        p999: q(0.999),
        max: *v.last().unwrap() as f64,
    }
}

fn dist_json(d: &Dist, unit_div: f64) -> Value {
    json!({ "n": d.n, "mean": d.mean / unit_div, "p50": d.p50 / unit_div, "p99": d.p99 / unit_div,
            "p999": d.p999 / unit_div, "max": d.max / unit_div })
}

fn pct_delta(on: f64, off: f64) -> f64 {
    (on - off) / off * 100.0
}

fn spawn_hog(p: &Profile, mask: usize) -> Result<Option<Child>> {
    if p.hog_threads == 0 {
        return Ok(None);
    }
    let mut c = Command::new(std::env::current_exe()?);
    c.args(["hog", "--threads", &p.hog_threads.to_string(), "--duty", &p.hog_duty.to_string(), "--mask", &format!("{mask:x}")]);
    if p.eco {
        c.arg("--eco");
    }
    Ok(Some(c.spawn()?))
}

fn hog(args: &[String]) -> Result<()> {
    let (mut threads, mut duty, mut mask, mut eco) = (1usize, 0.5f64, 0usize, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--threads" => threads = it.next().context("--threads")?.parse()?,
            "--duty" => duty = it.next().context("--duty")?.parse()?,
            "--mask" => mask = usize::from_str_radix(it.next().context("--mask")?, 16)?,
            "--eco" => eco = true,
            _ => bail!("unknown hog option {a}"),
        }
    }
    if mask != 0 {
        sysutil::set_affinity(mask);
    }
    if eco {
        sysutil::set_process_eco(true);
    }
    for _ in 0..threads {
        std::thread::spawn(move || {
            let busy = (duty * 10e6) as u64;
            loop {
                let t = now_ns();
                while now_ns() - t < busy {
                    std::hint::spin_loop();
                }
                std::thread::sleep(Duration::from_nanos(10_000_000 - busy));
            }
        });
    }
    loop {
        std::thread::park();
    }
}

struct Ctx {
    extra: Vec<(usize, usize)>,
    desktop_units_per_ms: f64,
}

fn standard_jobs(extra: &[(usize, usize)]) -> Vec<Box<dyn Job>> {
    jobs::standard(extra.to_vec(), Some(Duration::from_secs(60)))
}

fn run_profile(p: &Profile, o: &Opts, cx: &mut Ctx, md: &mut String) -> Result<Value> {
    eprintln!("== profile {} ==", p.name);
    let (orig_mask, sys_mask) = sysutil::affinity();
    let mask = p.mask.map(|m| m & sys_mask).unwrap_or(orig_mask);
    if p.mask.is_some() && !sysutil::set_affinity(mask) {
        bail!("SetProcessAffinityMask({mask:#x}) failed");
    }
    let eco_ok = p.eco && sysutil::set_process_eco(true);
    // Size the game's work for the contended, throttled machine, not the idle one.
    let mut hog = spawn_hog(p, mask)?;
    if hog.is_some() || p.eco {
        std::thread::sleep(Duration::from_millis(1500));
    }
    let upms = game::calibrate_units_per_ms();
    if p.name == "desktop" {
        cx.desktop_units_per_ms = upms;
    }
    let mut game = Game::new(p.game, upms);
    let warm = run_block(&mut game, 2.0, None);
    drop(warm);

    let extra = cx.extra.clone();
    let mk = move || standard_jobs(&extra);
    let mut blocks = Vec::new();
    for i in 0..o.pairs {
        let order = if i % 2 == 0 { [false, true] } else { [true, false] };
        for on in order {
            eprintln!("  block {} scheduler {}", blocks.len(), if on { "ON" } else { "off" });
            blocks.push(run_block(&mut game, o.block_secs, on.then_some(&mk as &dyn Fn() -> Vec<Box<dyn Job>>)));
        }
    }
    drop(game);
    if let Some(h) = hog.as_mut() {
        let _ = h.kill();
        let _ = h.wait();
    }
    if p.eco {
        sysutil::set_process_eco(false);
    }
    if p.mask.is_some() {
        sysutil::set_affinity(orig_mask);
    }

    let on: Vec<&Block> = blocks.iter().filter(|b| b.on).collect();
    let off: Vec<&Block> = blocks.iter().filter(|b| !b.on).collect();
    let tick = dist(on.iter().flat_map(|b| b.ticks.iter().copied()));
    let f_on = dist(on.iter().flat_map(|b| b.frames.iter().copied()));
    let f_off = dist(off.iter().flat_map(|b| b.frames.iter().copied()));
    let half = off.len() / 2;
    let f_off_a = dist(off[..half].iter().flat_map(|b| b.frames.iter().copied()));
    let f_off_b = dist(off[half..].iter().flat_map(|b| b.frames.iter().copied()));
    let noise_p99 = pct_delta(f_off_b.p99, f_off_a.p99).abs();
    let noise_mean = pct_delta(f_off_b.mean, f_off_a.mean).abs();
    let missed = |bs: &[&Block]| {
        let m: u64 = bs.iter().map(|b| b.missed).sum();
        let n: usize = bs.iter().map(|b| b.frames.len()).sum();
        m as f64 / n as f64 * 100.0
    };
    let on_wall: u64 = on.iter().map(|b| b.wall_ns).sum();
    let worker_pct = on.iter().map(|b| b.worker_cycles_ns).sum::<u64>() as f64 / on_wall as f64 * 100.0;
    let worker_times_pct = on.iter().map(|b| b.worker_times_ns).sum::<u64>() as f64 / on_wall as f64 * 100.0;
    let stats: Vec<&SchedStats> = on.iter().filter_map(|b| b.stats.as_ref()).collect();
    let charged_pct = stats.iter().map(|s| s.charged_cpu_ns).sum::<u64>() as f64 / on_wall as f64 * 100.0;
    let proc_pct = |bs: &[&Block]| {
        bs.iter().map(|b| b.proc_cpu_ns).sum::<u64>() as f64 / bs.iter().map(|b| b.wall_ns).sum::<u64>() as f64 * 100.0
    };
    let slice_cpu_max = stats.iter().map(|s| s.slice_cpu.max_ns).max().unwrap_or(0);
    let slice_wall_max = stats.iter().map(|s| s.slice_wall.max_ns).max().unwrap_or(0);
    let slice_wall_p99 = stats.iter().map(|s| s.slice_wall.percentile_ns(99.0)).max().unwrap_or(0);
    let slices_over_cpu: u64 = stats.iter().map(|s| s.slice_cpu.count_above(SLICE_BUDGET_NS)).sum();
    let slices_over_wall: u64 = stats.iter().map(|s| s.slice_wall.count_above(SLICE_BUDGET_NS)).sum();
    let slices: u64 = stats.iter().map(|s| s.slices).sum();
    let heap_peak = on.iter().map(|b| b.heap_peak).max().unwrap_or(0) as u64;
    let private_delta = on.iter().map(|b| b.private_delta).max().unwrap_or(0);
    let private_delta_off = off.iter().map(|b| b.private_delta).max().unwrap_or(0);
    let ws_delta = on.iter().map(|b| b.ws_delta).max().unwrap_or(0);
    let init_main = on.iter().map(|b| b.init_main_ns).max().unwrap_or(0);
    let worker_init = stats.iter().map(|s| s.worker_init_ns).max().unwrap_or(0);
    let findings: u64 = on.iter().map(|b| b.findings).sum();
    let hitch: u64 = stats.iter().map(|s| s.hitch_deferrals).sum();
    let p99_delta = pct_delta(f_on.p99, f_off.p99);
    let mean_delta = pct_delta(f_on.mean, f_off.mean);

    let pass_tick = tick.p99 <= TICK_BUDGET_NS as f64;
    let pass_cpu = worker_pct <= CPU_BUDGET_PCT;
    let pass_slice = slice_cpu_max <= SLICE_BUDGET_NS;
    let ram = heap_peak.max(private_delta.max(0) as u64);
    let pass_ram = ram <= RAM_BUDGET;
    let pass_frame = p99_delta <= FRAME_DELTA_BUDGET_PCT;
    let pass_init = init_main + stats.iter().map(|s| s.worker_init_cpu_ns).max().unwrap_or(0) <= INIT_BUDGET_NS;
    let pf = |b: bool| if b { "PASS" } else { "FAIL" };
    // An on/off delta only means something relative to the off/off (A/A) spread.
    let frame_verdict = if noise_p99 <= FRAME_DELTA_BUDGET_PCT {
        pf(pass_frame).to_string()
    } else if p99_delta <= noise_p99 {
        format!("NO DETECTABLE IMPACT (delta inside {noise_p99:.1}% A/A noise)")
    } else {
        "FAIL".to_string()
    };
    let block_p99_median = |bs: &[&Block]| {
        let mut v: Vec<f64> = bs.iter().map(|b| dist(b.frames.iter().copied()).p99).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = v.len();
        if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 }
    };
    let frames_where = |want: bool| {
        on.iter().flat_map(move |b| b.frames.iter().zip(&b.overlap).filter(move |(_, &o)| o == want).map(|(&f, _)| f))
    };
    let f_ovl = dist(frames_where(true));
    let f_clean = dist(frames_where(false));
    let started_where = |want: bool| {
        on.iter().flat_map(move |b| b.frames.iter().zip(&b.started_in_slice).filter(move |(_, &o)| o == want).map(|(&f, _)| f))
    };
    let f_sin = dist(started_where(true));
    let f_sout = dist(started_where(false));
    let bp_on = block_p99_median(&on);
    let bp_off = block_p99_median(&off);
    let worker_init_cpu = stats.iter().map(|s| s.worker_init_cpu_ns).max().unwrap_or(0);

    let last = stats.last().copied();
    let _ = writeln!(md, "## Profile `{}`\n\n{}\n", p.name, p.desc);
    let _ = writeln!(
        md,
        "Affinity mask `{mask:#x}`, EcoQoS {}, game work rate calibrated under this profile's load: {:.0} units/ms ({:.0}% of desktop), {} pairs x {} s blocks (ABBA order).\n",
        if p.eco { if eco_ok { "on" } else { "requested but refused" } } else { "off" },
        upms,
        upms / cx.desktop_units_per_ms.max(1.0) * 100.0,
        o.pairs,
        o.block_secs
    );
    let _ = writeln!(md, "| Budget (G2) | Target | Measured | Result |\n|---|---|---|---|");
    let _ = writeln!(md, "| `tick()` cost | p99 ≤ 20 µs | p50 {:.2} µs, p99 {:.2} µs, p99.9 {:.2} µs, max {:.1} µs ({} ticks) | {} |", tick.p50 / 1e3, tick.p99 / 1e3, tick.p999 / 1e3, tick.max / 1e3, tick.n, pf(pass_tick));
    let _ = writeln!(md, "| Background CPU (worker thread, cycle-accurate) | ≤ 1% of one core | {worker_pct:.3}% (GetThreadTimes: {worker_times_pct:.3}%, charged to buckets: {charged_pct:.3}%) | {} |", pf(pass_cpu));
    let _ = writeln!(md, "| Scan slice | ≤ 3 ms | CPU max {:.2} ms; wall max {:.2} ms, wall p99 ≤ {:.2} ms; {slices_over_cpu} / {slices} slices over 3 ms CPU, {slices_over_wall} over 3 ms wall | {} |", slice_cpu_max as f64 / 1e6, slice_wall_max as f64 / 1e6, slice_wall_p99 as f64 / 1e6, pf(pass_slice));
    let _ = writeln!(md, "| Memory | ≤ 25 MB (whole SDK) | scheduler+jobs heap peak {:.1} KiB ({} allocs); private bytes delta on {:.2} MiB vs off {:.2} MiB; working-set delta {:.2} MiB | {} |", heap_peak as f64 / 1024.0, on.iter().map(|b| b.allocs).max().unwrap_or(0), private_delta as f64 / 1048576.0, private_delta_off as f64 / 1048576.0, ws_delta as f64 / 1048576.0, pf(pass_ram));
    let _ = writeln!(md, "| Frame time p99 delta | ≤ 1% | off p99 {:.3} ms → on {:.3} ms ({p99_delta:+.2}%); mean {:.3} → {:.3} ms ({mean_delta:+.2}%); median per-block p99 {:.3} → {:.3} ms ({:+.2}%); A/A noise p99 {noise_p99:.2}%, mean {noise_mean:.2}% | {frame_verdict} |", f_off.p99 / 1e6, f_on.p99 / 1e6, f_off.mean / 1e6, f_on.mean / 1e6, bp_off / 1e6, bp_on / 1e6, pct_delta(bp_on, bp_off));
    let _ = writeln!(md, "| Frame attribution (same ON blocks) | slice-overlapped frames ≈ clean frames | {} frames overlapped a slice ({:.1}%): mean {:.3} ms, p50 {:.3}, p99 {:.3}; {} clean: mean {:.3}, p50 {:.3}, p99 {:.3} (mean {:+.2}%, p50 {:+.2}%, p99 {:+.2}%) | info |",
        f_ovl.n, f_ovl.n as f64 / (f_ovl.n + f_clean.n).max(1) as f64 * 100.0, f_ovl.mean / 1e6, f_ovl.p50 / 1e6, f_ovl.p99 / 1e6,
        f_clean.n, f_clean.mean / 1e6, f_clean.p50 / 1e6, f_clean.p99 / 1e6,
        pct_delta(f_ovl.mean, f_clean.mean), pct_delta(f_ovl.p50, f_clean.p50), pct_delta(f_ovl.p99, f_clean.p99));
    let _ = writeln!(md, "| Frame attribution, unbiased (frame started while a slice ran) | ≈ other frames | {} frames: mean {:.3} ms, p50 {:.3}; {} others: mean {:.3}, p50 {:.3} (mean {:+.2}%, p50 {:+.2}%) | info |",
        f_sin.n, f_sin.mean / 1e6, f_sin.p50 / 1e6, f_sout.n, f_sout.mean / 1e6, f_sout.p50 / 1e6,
        pct_delta(f_sin.mean, f_sout.mean), pct_delta(f_sin.p50, f_sout.p50));
    let _ = writeln!(md, "| Init | ≤ 50 ms, off main thread | main-thread `start()` {:.2} ms; worker init {:.2} ms wall ({:.2} ms CPU, rest is waiting at below-normal priority) | {} |", init_main as f64 / 1e6, worker_init as f64 / 1e6, worker_init_cpu as f64 / 1e6, pf(pass_init));
    let _ = writeln!(md);
    let _ = writeln!(md, "Frames: off {} (p50 {:.3} ms, p99.9 {:.3} ms, max {:.2} ms, missed deadline {:.2}%), on {} (p50 {:.3} ms, p99.9 {:.3} ms, max {:.2} ms, missed deadline {:.2}%). Process CPU (whole sim, % of one core): off {:.1}%, on {:.1}%. Hitch-guard deferrals: {hitch}. Findings delivered via `tick()`: {findings}.\n",
        f_off.n, f_off.p50 / 1e6, f_off.p999 / 1e6, f_off.max / 1e6, missed(&off),
        f_on.n, f_on.p50 / 1e6, f_on.p999 / 1e6, f_on.max / 1e6, missed(&on), proc_pct(&off), proc_pct(&on));
    if let Some(s) = last {
        let _ = writeln!(md, "Per-job stats (last ON block, {:.0} s):\n\n| Job | Passes | Steps | Last pass CPU | Last pass wall | CPU % of core | Max step | Overruns | Run-budget aborts | Share-throttled |\n|---|---|---|---|---|---|---|---|---|---|", o.block_secs);
        let wall = on.last().unwrap().wall_ns as f64;
        for j in &s.jobs {
            let _ = writeln!(md, "| {} | {} | {} | {:.2} ms | {:.1} ms | {:.4}% | {:.0} µs | {} | {} | {} |", j.name, j.runs_completed, j.steps, j.last_pass_cpu_ns as f64 / 1e6, j.last_pass_wall_ns as f64 / 1e6, j.cpu_ns as f64 / wall * 100.0, j.max_step_cpu_ns as f64 / 1e3, j.overruns, j.runs_aborted_budget, j.share_throttled);
        }
        if let Some(h) = s.jobs.iter().find(|j| j.name == "text_hash" && j.cpu_ns > 0) {
            let _ = writeln!(md, "\nIn-job `text_hash` rate: ≈ {:.0} MB/s per CPU-second ({} steps x ≤ 64 KiB in {:.1} ms CPU, {:.0} µs/step).", h.steps as f64 * 65536.0 / (h.cpu_ns as f64 / 1e9) / 1e6, h.steps, h.cpu_ns as f64 / 1e6, h.cpu_ns as f64 / h.steps as f64 / 1e3);
        }
        let _ = writeln!(md);
    }

    Ok(json!({
        "profile": p.name, "desc": p.desc, "affinity_mask": mask, "eco_qos": eco_ok, "units_per_ms": upms,
        "tick_ns": dist_json(&tick, 1.0),
        "frame_off_ms": dist_json(&f_off, 1e6), "frame_on_ms": dist_json(&f_on, 1e6),
        "frame_p99_delta_pct": p99_delta, "frame_mean_delta_pct": mean_delta,
        "aa_noise_p99_pct": noise_p99, "aa_noise_mean_pct": noise_mean,
        "missed_deadline_pct": { "off": missed(&off), "on": missed(&on) },
        "worker_cpu_pct": worker_pct, "worker_cpu_pct_getthreadtimes": worker_times_pct, "charged_cpu_pct": charged_pct,
        "process_cpu_pct": { "off": proc_pct(&off), "on": proc_pct(&on) },
        "slice": { "cpu_max_ms": slice_cpu_max as f64 / 1e6, "wall_max_ms": slice_wall_max as f64 / 1e6,
                   "wall_p99_ms": slice_wall_p99 as f64 / 1e6, "count": slices, "over_3ms_cpu": slices_over_cpu, "over_3ms_wall": slices_over_wall },
        "memory": { "heap_peak_bytes": heap_peak, "private_delta_on": private_delta, "private_delta_off": private_delta_off, "ws_delta_on": ws_delta },
        "init": { "main_ms": init_main as f64 / 1e6, "worker_wall_ms": worker_init as f64 / 1e6, "worker_cpu_ms": worker_init_cpu as f64 / 1e6 },
        "frame_block_p99_median_ms": { "off": bp_off / 1e6, "on": bp_on / 1e6 },
        "frame_overlapped_ms": dist_json(&f_ovl, 1e6), "frame_clean_ms": dist_json(&f_clean, 1e6),
        "frame_started_in_slice_ms": dist_json(&f_sin, 1e6), "frame_started_outside_slice_ms": dist_json(&f_sout, 1e6),
        "findings": findings, "hitch_deferrals": hitch,
        "pass": { "tick": pass_tick, "cpu": pass_cpu, "slice": pass_slice, "ram": pass_ram, "frame": pass_frame, "init": pass_init },
        "jobs": last.map(|s| s.jobs.iter().map(|j| json!({
            "name": j.name, "passes": j.runs_completed, "last_pass_cpu_ms": j.last_pass_cpu_ns as f64 / 1e6,
            "last_pass_wall_s": j.last_pass_wall_ns as f64 / 1e9, "cpu_ms": j.cpu_ns as f64 / 1e6,
            "max_step_us": j.max_step_cpu_ns as f64 / 1e3, "overruns": j.overruns, "run_budget_aborts": j.runs_aborted_budget,
        })).collect::<Vec<_>>()),
    }))
}

fn run_demo(o: &Opts, cx: &Ctx, md: &mut String) -> Result<Value> {
    eprintln!("== throttle demo ==");
    let desk = &profiles()[0];
    let mut game = Game::new(desk.game, game::calibrate_units_per_ms());
    let extra = cx.extra.clone();
    let mk = move || {
        let mut v = jobs::standard(extra.clone(), Some(Duration::ZERO));
        v.push(Box::new(jobs::SpinHog));
        v.push(Box::new(jobs::Greedy::new()));
        v
    };
    let b = run_block(&mut game, o.demo_secs, Some(&mk as &dyn Fn() -> Vec<Box<dyn Job>>));
    let s = b.stats.as_ref().unwrap();
    let wall = b.wall_ns as f64;
    let worker_pct = b.worker_cycles_ns as f64 / wall * 100.0;
    let charged_pct = s.charged_cpu_ns as f64 / wall * 100.0;
    let hog = s.jobs.iter().find(|j| j.name == "misbehaving_spin_hog").unwrap();
    let greedy = s.jobs.iter().find(|j| j.name == "misbehaving_greedy").unwrap();
    let hash = s.jobs.iter().find(|j| j.name == "text_hash").unwrap();
    let hog_ok = hog.quarantined && hog.overruns == 3;
    let greedy_pct = greedy.cpu_ns as f64 / wall * 100.0;
    let greedy_cap = 0.3 * 0.8;
    let greedy_ok = greedy_pct <= greedy_cap * 1.1 + 0.01;
    let total_ok = worker_pct <= CPU_BUDGET_PCT;
    let pf = |b: bool| if b { "PASS" } else { "FAIL" };

    let _ = writeln!(md, "## Throttling demo ({:.0} s, desktop game load)\n", o.demo_secs);
    let _ = writeln!(md, "Standard jobs with `text_hash` made continuous (always due), plus two misbehaving modules: `misbehaving_spin_hog` declares 200 µs steps but spins 8 ms per step; `misbehaving_greedy` declares share 0.3 and a 30 ms per-pass cap but never finishes and is always due.\n");
    let _ = writeln!(md, "| Check | Expected | Measured | Result |\n|---|---|---|---|");
    let _ = writeln!(md, "| Spin hog | backed off, quarantined after 3 strikes | overruns {}, steps {}, quarantined {}, total CPU {:.1} ms | {} |", hog.overruns, hog.steps, hog.quarantined, hog.cpu_ns as f64 / 1e6, pf(hog_ok));
    let _ = writeln!(md, "| Greedy | ≤ its share (0.3 x 0.8% = {greedy_cap:.2}% of a core), pass cut at 30 ms | {greedy_pct:.3}% of a core, {} run-budget aborts, share-throttled {} times | {} |", greedy.runs_aborted_budget, greedy.share_throttled, pf(greedy_ok));
    let _ = writeln!(md, "| Whole worker | ≤ 1% of one core | {worker_pct:.3}% (charged {charged_pct:.3}%; global bucket throttled {} times) | {} |", s.global_throttled, pf(total_ok));
    let _ = writeln!(md, "| Other jobs still progress | text_hash keeps hashing | text_hash {} passes, ~{:.0} MiB hashed, {:.3}% of a core | {} |", hash.runs_completed, hash.steps as f64 / 16.0, hash.cpu_ns as f64 / wall * 100.0, pf(hash.steps > 0));
    let _ = writeln!(md, "\nSlices over 3 ms CPU: {} of {} (the hog's overrunning steps; a cooperative step cannot be preempted, so each overrun costs one full step before the strike lands). Frame p99 during demo: {:.3} ms, tick p99 {:.2} µs.\n",
        s.slice_cpu.count_above(SLICE_BUDGET_NS), s.slices, dist(b.frames.iter().copied()).p99 / 1e6, dist(b.ticks.iter().copied()).p99 / 1e3);
    let _ = writeln!(md, "| Job | Passes | CPU % of core | Max step | Overruns | Strikes | Quarantined | Run-budget aborts | Share-throttled |\n|---|---|---|---|---|---|---|---|---|");
    for j in &s.jobs {
        let _ = writeln!(md, "| {} | {} | {:.4}% | {:.0} µs | {} | {} | {} | {} | {} |", j.name, j.runs_completed, j.cpu_ns as f64 / wall * 100.0, j.max_step_cpu_ns as f64 / 1e3, j.overruns, j.strikes, j.quarantined, j.runs_aborted_budget, j.share_throttled);
    }
    let _ = writeln!(md);
    Ok(json!({
        "secs": o.demo_secs, "worker_cpu_pct": worker_pct, "charged_cpu_pct": charged_pct, "global_throttled": s.global_throttled,
        "hog": { "overruns": hog.overruns, "steps": hog.steps, "quarantined": hog.quarantined, "cpu_ms": hog.cpu_ns as f64 / 1e6 },
        "greedy": { "cpu_pct": greedy_pct, "cap_pct": greedy_cap, "run_budget_aborts": greedy.runs_aborted_budget, "share_throttled": greedy.share_throttled },
        "text_hash_passes": hash.runs_completed,
        "pass": { "hog_quarantined": hog_ok, "greedy_capped": greedy_ok, "total_cpu": total_ok },
    }))
}

/// BLAKE3 throughput (MB/s) over 64 KiB chunks of `buf` on a fresh thread, optionally EcoQoS.
fn hash_throughput(buf: &'static [u8], eco: bool) -> f64 {
    std::thread::spawn(move || {
        if eco {
            sysutil::set_thread_eco();
        }
        let mut best = 0f64;
        for _ in 0..3 {
            let t = now_ns();
            for c in buf.chunks(64 * 1024) {
                std::hint::black_box(blake3::hash(c));
            }
            best = best.max(buf.len() as f64 / ((now_ns() - t) as f64 / 1e9) / 1e6);
        }
        best
    })
    .join()
    .unwrap()
}

/// Same, but the way the scheduler runs it: ~2 ms bursts separated by 100 ms idle on an
/// EcoQoS thread, rate measured against thread CPU time.
fn hash_throughput_bursty(buf: &'static [u8]) -> f64 {
    std::thread::spawn(move || {
        sysutil::set_thread_eco();
        let (mut bytes, mut cpu) = (0usize, 0u64);
        let mut chunks = buf.chunks(64 * 1024).cycle();
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(100));
            let c0 = clock::thread_cycles();
            let t = now_ns();
            while now_ns() - t < 2_000_000 {
                let c = chunks.next().unwrap();
                std::hint::black_box(blake3::hash(c));
                bytes += c.len();
            }
            cpu += clock::cycles_to_ns(clock::thread_cycles() - c0);
        }
        bytes as f64 / (cpu as f64 / 1e9) / 1e6
    })
    .join()
    .unwrap()
}

/// Intrinsic `tick()` cost with no game load: back-to-back calls.
fn tick_microbench(extra: &[(usize, usize)]) -> f64 {
    let mut s = Scheduler::start(Config { hitch_guard: None, ..Config::default() }, standard_jobs(extra)).unwrap();
    const N: u64 = 2_000_000;
    let t = now_ns();
    for _ in 0..N {
        std::hint::black_box(s.tick());
    }
    let ns = (now_ns() - t) as f64 / N as f64;
    drop(s);
    ns
}

fn bench(args: &[String]) -> Result<()> {
    let o = parse_opts(args)?;
    std::fs::create_dir_all(&o.out)?;
    let cpn = clock::cycles_per_ns();
    let cpu = sysutil::cpu_name();
    let logical = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);

    // The "game binary": 32 MiB of code-like bytes the hashing job covers, plus one RWX
    // page (JIT-style) so the region walk has a real finding to deliver through tick().
    let text: &'static mut [u8] = Box::leak(vec![0u8; 32 << 20].into_boxed_slice());
    let mut x = 0x9E3779B97F4A7C15u64;
    for c in text.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        c.copy_from_slice(&x.to_le_bytes()[..c.len()]);
    }
    unsafe { VirtualAlloc(std::ptr::null(), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };
    let mut cx = Ctx { extra: vec![(text.as_ptr() as usize, text.len())], desktop_units_per_ms: 0.0 };

    let mut snaps: Vec<u32> = (0..9).map(|_| sysutil::toolhelp_thread_snapshot_ns() as u32).collect();
    snaps.sort_unstable();
    let tick_intrinsic = tick_microbench(&cx.extra);
    let text_ro: &'static [u8] = unsafe { std::slice::from_raw_parts(cx.extra[0].0 as *const u8, cx.extra[0].1) };
    let mbps = hash_throughput(text_ro, false);
    let mbps_eco = hash_throughput(text_ro, true);
    let mbps_bursty = hash_throughput_bursty(text_ro);
    let pass_bytes = jobs::TextHash::new(cx.extra.clone(), None).pass_bytes();
    let gameplay_share_cpu = 0.4 * 0.008;

    let mut md = String::new();
    let _ = writeln!(md, "# Scheduler spike report\n");
    let _ = writeln!(md, "CPU: {cpu}, {logical} logical processors. TSC {:.3} cycles/ns. Budget config: gameplay bucket 0.8% of one core (cap 6 ms), slice target {} µs, hard cap 3 ms, worker below-normal + EcoQoS, ideal CPU = last in affinity mask.\n", cpn, sched_config().slice_target.as_micros());
    let _ = writeln!(md, "Intrinsic `tick()` cost (2M back-to-back calls, no game load): **{tick_intrinsic:.1} ns/call**. Per-frame tick samples below include two QPC reads (~100 ns resolution).\n");
    let _ = writeln!(md, "System-wide Toolhelp thread snapshot (what a naive thread audit would call, not sliceable): median {:.2} ms, max {:.2} ms. The spike uses per-process `NtGetNextThread` instead.\n", snaps[4] as f64 / 1e6, snaps[8] as f64 / 1e6);

    let _ = writeln!(md, "Hashing: one `text_hash` pass covers {:.1} MiB (executable sections of all loaded images + 32 MiB simulated game `.text`). BLAKE3 over 64 KiB chunks, sustained: {mbps:.0} MB/s on a normal thread, {mbps_eco:.0} MB/s with EcoQoS; in scheduler-like 2 ms bursts after 100 ms idle (EcoQoS, per CPU-second): {mbps_bursty:.0} MB/s. In-job rates are in each profile's per-job table. At the gameplay share (0.4 x 0.8% = {:.2}% of a core) and the bursty rate, a full pass needs ≈ {:.0} s of wall time.\n",
        pass_bytes as f64 / 1048576.0, gameplay_share_cpu * 100.0, pass_bytes as f64 / (mbps_bursty * 1e6) / gameplay_share_cpu);
    let all = profiles();
    let mut results = Vec::new();
    for name in &o.profiles {
        let p = all.iter().find(|p| p.name == name).with_context(|| format!("unknown profile {name}"))?;
        results.push(run_profile(p, &o, &mut cx, &mut md)?);
    }
    let demo = run_demo(&o, &cx, &mut md)?;

    let report = json!({
        "cpu": cpu, "logical_processors": logical, "cycles_per_ns": cpn, "tick_intrinsic_ns": tick_intrinsic,
        "toolhelp_snapshot_ms": { "median": snaps[4] as f64 / 1e6, "max": snaps[8] as f64 / 1e6 },
        "hash": { "pass_bytes": pass_bytes, "mbps": mbps, "mbps_eco": mbps_eco, "mbps_bursty_eco": mbps_bursty,
                  "gameplay_pass_secs": pass_bytes as f64 / (mbps_bursty * 1e6) / gameplay_share_cpu },
        "opts": { "block_secs": o.block_secs, "pairs": o.pairs, "demo_secs": o.demo_secs },
        "profiles": results, "throttle_demo": demo,
    });
    std::fs::write(o.out.join("report.md"), &md)?;
    std::fs::write(o.out.join("report.json"), serde_json::to_string_pretty(&report)?)?;
    println!("{md}");
    eprintln!("wrote {}", o.out.join("report.md").display());
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("bench") => bench(&args[1..]),
        Some("hog") => hog(&args[1..]),
        _ => {
            eprintln!("usage: sched-spike bench [--quick] [--block-secs N] [--pairs N] [--demo-secs N] [--profiles a,b] [--out DIR]");
            std::process::exit(2);
        }
    }
}
