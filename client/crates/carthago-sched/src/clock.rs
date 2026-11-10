//! Monotonic wall clock (QPC) and per-thread CPU accounting (`QueryThreadCycleTime`).
//!
//! `GetThreadTimes` only advances at clock-interrupt granularity (~15.6 ms), which is
//! useless for charging 100 µs steps, so CPU is charged in thread cycles and converted
//! to nanoseconds with a one-time calibration against QPC.
//!
//! Non-Windows builds (CI and the Linux unit tests) use `CLOCK_MONOTONIC` and
//! `CLOCK_THREAD_CPUTIME_ID`, whose "cycles" are already nanoseconds.

use std::sync::OnceLock;

static CYCLES_PER_NS: OnceLock<f64> = OnceLock::new();

#[cfg(windows)]
mod imp {
    use std::sync::OnceLock;

    use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
    use windows_sys::Win32::System::Threading::GetCurrentThread;
    use windows_sys::Win32::System::WindowsProgramming::QueryThreadCycleTime;

    static NS_PER_QPC_TICK: OnceLock<f64> = OnceLock::new();

    #[inline]
    fn ns_per_tick() -> f64 {
        *NS_PER_QPC_TICK.get_or_init(|| {
            let mut f = 0i64;
            unsafe { QueryPerformanceFrequency(&mut f) };
            1e9 / f as f64
        })
    }

    #[inline]
    pub fn now_ns() -> u64 {
        let mut c = 0i64;
        unsafe { QueryPerformanceCounter(&mut c) };
        (c as f64 * ns_per_tick()) as u64
    }

    #[inline]
    pub fn thread_cycles() -> u64 {
        let mut c = 0u64;
        unsafe { QueryThreadCycleTime(GetCurrentThread(), &mut c) };
        c
    }

    pub const CALIBRATE: bool = true;
}

#[cfg(not(windows))]
mod imp {
    #[inline]
    fn read(clock: libc::clockid_t) -> u64 {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(clock, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }

    #[inline]
    pub fn now_ns() -> u64 {
        read(libc::CLOCK_MONOTONIC)
    }

    #[inline]
    pub fn thread_cycles() -> u64 {
        read(libc::CLOCK_THREAD_CPUTIME_ID)
    }

    pub const CALIBRATE: bool = false;
}

/// Monotonic nanoseconds since boot.
#[inline]
pub fn now_ns() -> u64 {
    imp::now_ns()
}

/// Cycles charged to the calling thread so far.
#[inline]
pub fn thread_cycles() -> u64 {
    imp::thread_cycles()
}

/// Thread cycles per nanosecond, calibrated once per process by spinning against QPC.
/// One 2 ms probe: the earlier 3 × 4 ms spin was most of the worker's first-minute CPU in
/// the Phase 0 overhead numbers. Preemption during the probe can only lower the ratio, which
/// over-charges jobs (the safe direction for the budget).
pub fn cycles_per_ns() -> f64 {
    *CYCLES_PER_NS.get_or_init(|| {
        if !imp::CALIBRATE {
            return 1.0;
        }
        let w0 = now_ns();
        let c0 = thread_cycles();
        while now_ns() - w0 < 2_000_000 {
            std::hint::spin_loop();
        }
        let dc = thread_cycles() - c0;
        let dw = now_ns() - w0;
        dc as f64 / dw as f64
    })
}

#[inline]
pub fn cycles_to_ns(cycles: u64) -> u64 {
    (cycles as f64 / cycles_per_ns()) as u64
}
