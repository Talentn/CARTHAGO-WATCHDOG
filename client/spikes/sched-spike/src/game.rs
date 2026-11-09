//! Simulated game: a main thread plus a fork/join worker pool doing fixed CPU + cache work
//! each frame, paced to a target frame rate. Frame time = start of frame to end of tick.

use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use sn_sched::clock::now_ns;

const BUF_WORDS: usize = 1 << 17; // 1 MiB per thread

pub fn work(buf: &mut [u64], units: u64, seed: u64) -> u64 {
    let mask = buf.len() - 1;
    let mut x = seed | 1;
    let mut idx = 0usize;
    for _ in 0..units {
        for _ in 0..16 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            idx = (idx + (x >> 33) as usize) & mask;
            buf[idx] ^= x;
        }
    }
    black_box(x)
}

/// Work units per millisecond on one thread under the current affinity / QoS.
pub fn calibrate_units_per_ms() -> f64 {
    let mut buf = vec![0u64; BUF_WORDS];
    work(&mut buf, 20_000, 1);
    let mut rates: Vec<f64> = (0..5)
        .map(|i| {
            let t = now_ns();
            work(&mut buf, 50_000, i);
            50_000.0 / ((now_ns() - t) as f64 / 1e6)
        })
        .collect();
    rates.sort_by(|a, b| a.partial_cmp(b).unwrap());
    rates[2]
}

#[derive(Debug, Clone, Copy)]
pub struct GameCfg {
    pub fps: f64,
    pub workers: usize,
    /// Per-thread work as a fraction of the frame period.
    pub work_fraction: f64,
}

struct Shared {
    gen: Mutex<u64>,
    cv: Condvar,
    remaining: AtomicUsize,
    stop: AtomicBool,
    units: AtomicU64,
}

pub struct Game {
    pub cfg: GameCfg,
    pub period_ns: u64,
    shared: Arc<Shared>,
    handles: Vec<JoinHandle<()>>,
    units: u64,
    buf: Vec<u64>,
    seed: u64,
}

impl Game {
    pub fn new(cfg: GameCfg, units_per_ms: f64) -> Self {
        let period_ns = (1e9 / cfg.fps) as u64;
        let units = (period_ns as f64 / 1e6 * cfg.work_fraction * units_per_ms) as u64;
        let shared = Arc::new(Shared {
            gen: Mutex::new(0),
            cv: Condvar::new(),
            remaining: AtomicUsize::new(0),
            stop: AtomicBool::new(false),
            units: AtomicU64::new(units),
        });
        let handles = (0..cfg.workers)
            .map(|w| {
                let sh = shared.clone();
                std::thread::Builder::new()
                    .name(format!("game-worker-{w}"))
                    .spawn(move || {
                        let mut buf = vec![0u64; BUF_WORDS];
                        let mut seen = 0u64;
                        loop {
                            {
                                let mut g = sh.gen.lock().unwrap();
                                while *g == seen && !sh.stop.load(Ordering::Relaxed) {
                                    g = sh.cv.wait(g).unwrap();
                                }
                                seen = *g;
                            }
                            if sh.stop.load(Ordering::Relaxed) {
                                break;
                            }
                            work(&mut buf, sh.units.load(Ordering::Relaxed), seen ^ w as u64);
                            sh.remaining.fetch_sub(1, Ordering::Release);
                        }
                    })
                    .unwrap()
            })
            .collect();
        Self { cfg, period_ns, shared, handles, units, buf: vec![0u64; BUF_WORDS], seed: 1 }
    }

    /// Runs one frame; `tick` is called on the main thread at the end of the frame.
    /// Returns (frame start ns, frame time ns).
    pub fn frame(&mut self, tick: impl FnOnce()) -> (u64, u64) {
        let t0 = now_ns();
        let n = self.handles.len();
        if n > 0 {
            self.shared.remaining.store(n, Ordering::Release);
            *self.shared.gen.lock().unwrap() += 1;
            self.shared.cv.notify_all();
        }
        self.seed += 1;
        work(&mut self.buf, self.units, self.seed);
        let mut spins = 0u32;
        while self.shared.remaining.load(Ordering::Acquire) != 0 {
            if spins < 2000 {
                std::hint::spin_loop();
                spins += 1;
            } else {
                std::thread::yield_now();
            }
        }
        tick();
        (t0, now_ns() - t0)
    }

    pub fn pace(&self, frame_start: u64) {
        let deadline = frame_start + self.period_ns;
        let now = now_ns();
        if deadline > now + 700_000 {
            std::thread::sleep(Duration::from_nanos(deadline - now - 500_000));
        }
        while now_ns() < deadline {
            std::thread::yield_now();
        }
    }
}

impl Drop for Game {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        {
            let _g = self.shared.gen.lock().unwrap();
            self.shared.cv.notify_all();
        }
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}
