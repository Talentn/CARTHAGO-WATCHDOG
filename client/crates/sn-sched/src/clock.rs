//! Monotonic wall clock (QPC) and per-thread CPU accounting (`QueryThreadCycleTime`).
//!
//! `GetThreadTimes` only advances at clock-interrupt granularity (~15.6 ms), which is
//! useless for charging 100 µs steps, so CPU is charged in thread cycles and converted
//! to nanoseconds with a one-time calibration against QPC.

use std::sync::OnceLock;

use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows_sys::Win32::System::Threading::GetCurrentThread;
use windows_sys::Win32::System::WindowsProgramming::QueryThreadCycleTime;

static NS_PER_QPC_TICK: OnceLock<f64> = OnceLock::new();
static CYCLES_PER_NS: OnceLock<f64> = OnceLock::new();

#[inline]
fn ns_per_tick() -> f64 {
    *NS_PER_QPC_TICK.get_or_init(|| {
        let mut f = 0i64;
        unsafe { QueryPerformanceFrequency(&mut f) };
        1e9 / f as f64
    })
}

/// Monotonic nanoseconds since boot.
#[inline]
pub fn now_ns() -> u64 {
    let mut c = 0i64;
    unsafe { QueryPerformanceCounter(&mut c) };
    (c as f64 * ns_per_tick()) as u64
}

/// Cycles charged to the calling thread so far.
#[inline]
pub fn thread_cycles() -> u64 {
    let mut c = 0u64;
    unsafe { QueryThreadCycleTime(GetCurrentThread(), &mut c) };
    c
}

/// Thread cycles per nanosecond, calibrated once per process by spinning against QPC.
/// Preemption during a probe can only lower the ratio, so the maximum of several probes is kept.
pub fn cycles_per_ns() -> f64 {
    *CYCLES_PER_NS.get_or_init(|| {
        let mut best = 0f64;
        for _ in 0..3 {
            let w0 = now_ns();
            let c0 = thread_cycles();
            while now_ns() - w0 < 4_000_000 {
                std::hint::spin_loop();
            }
            let dc = thread_cycles() - c0;
            let dw = now_ns() - w0;
            best = best.max(dc as f64 / dw as f64);
        }
        best
    })
}

#[inline]
pub fn cycles_to_ns(cycles: u64) -> u64 {
    (cycles as f64 / cycles_per_ns()) as u64
}
