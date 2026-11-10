//! Time-source sample for the speedhack cross-check (plan §6.4). The three clocks are read
//! back to back; the server compares their rates with each other and with its own clock.
//! QPC and GetTickCount64 go through the hookable APIs on purpose (that is the clock the
//! game sees); InterruptTime is read straight from KUSER_SHARED_DATA at 0x7FFE0008, which no
//! user-mode hook can intercept.

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimeSample {
    pub qpc_ns: u64,
    pub tick_count_ms: u64,
    pub interrupt_time_100ns: u64,
}

#[cfg(windows)]
pub fn sample() -> TimeSample {
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;
    TimeSample { qpc_ns: sn_sched::clock::now_ns(), tick_count_ms: unsafe { GetTickCount64() }, interrupt_time_100ns: interrupt_time() }
}

/// KSYSTEM_TIME at KUSER_SHARED_DATA+0x08: re-read until High1Time == High2Time.
#[cfg(windows)]
fn interrupt_time() -> u64 {
    const KSYSTEM_TIME: usize = 0x7FFE_0008;
    let p = KSYSTEM_TIME as *const u32;
    for _ in 0..16 {
        // SAFETY: KUSER_SHARED_DATA is mapped read-only at this fixed address in every
        // Windows process; volatile reads because the kernel updates it concurrently.
        let (high1, low, high2) = unsafe { (p.add(1).read_volatile(), p.read_volatile(), p.add(2).read_volatile()) };
        if high1 == high2 {
            return (high1 as u64) << 32 | low as u64;
        }
    }
    0
}

#[cfg(not(windows))]
pub fn sample() -> TimeSample {
    let ns = sn_sched::clock::now_ns();
    TimeSample { qpc_ns: ns, tick_count_ms: ns / 1_000_000, interrupt_time_100ns: ns / 100 }
}
