use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD};
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, GetProcessAffinityMask, GetProcessTimes, GetThreadTimes, ProcessPowerThrottling,
    SetProcessAffinityMask, SetProcessInformation, SetThreadInformation, ThreadPowerThrottling,
    PROCESS_POWER_THROTTLING_CURRENT_VERSION, PROCESS_POWER_THROTTLING_EXECUTION_SPEED, PROCESS_POWER_THROTTLING_STATE,
    THREAD_POWER_THROTTLING_CURRENT_VERSION, THREAD_POWER_THROTTLING_EXECUTION_SPEED, THREAD_POWER_THROTTLING_STATE,
};
use windows_sys::Win32::System::WindowsProgramming::QueryThreadCycleTime;

fn ft_ns(f: FILETIME) -> u64 {
    (((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64) * 100
}

pub fn affinity() -> (usize, usize) {
    let (mut p, mut s) = (0usize, 0usize);
    unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut p, &mut s) };
    (p, s)
}

pub fn set_affinity(mask: usize) -> bool {
    unsafe { SetProcessAffinityMask(GetCurrentProcess(), mask) != 0 }
}

/// EcoQoS for the whole process: Windows 11 lowers clocks / prefers efficiency cores.
pub fn set_process_eco(on: bool) -> bool {
    let st = PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ControlMask: if on { PROCESS_POWER_THROTTLING_EXECUTION_SPEED } else { 0 },
        StateMask: if on { PROCESS_POWER_THROTTLING_EXECUTION_SPEED } else { 0 },
    };
    unsafe {
        SetProcessInformation(
            GetCurrentProcess(),
            ProcessPowerThrottling,
            &st as *const _ as *const core::ffi::c_void,
            size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        ) != 0
    }
}

pub fn set_thread_eco() {
    let st = THREAD_POWER_THROTTLING_STATE {
        Version: THREAD_POWER_THROTTLING_CURRENT_VERSION,
        ControlMask: THREAD_POWER_THROTTLING_EXECUTION_SPEED,
        StateMask: THREAD_POWER_THROTTLING_EXECUTION_SPEED,
    };
    unsafe {
        SetThreadInformation(
            GetCurrentThread(),
            ThreadPowerThrottling,
            &st as *const _ as *const core::ffi::c_void,
            size_of::<THREAD_POWER_THROTTLING_STATE>() as u32,
        )
    };
}

/// (private bytes, working set bytes)
pub fn mem() -> (u64, u64) {
    let mut c: PROCESS_MEMORY_COUNTERS_EX = unsafe { std::mem::zeroed() };
    c.cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
    unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c as *mut _ as *mut PROCESS_MEMORY_COUNTERS, c.cb) };
    (c.PrivateUsage as u64, c.WorkingSetSize as u64)
}

pub fn process_cpu_ns() -> u64 {
    let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut a, mut b, mut k, mut u) = (z, z, z, z);
    unsafe { GetProcessTimes(GetCurrentProcess(), &mut a, &mut b, &mut k, &mut u) };
    ft_ns(k) + ft_ns(u)
}

pub fn thread_times_ns(h: HANDLE) -> u64 {
    let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut a, mut b, mut k, mut u) = (z, z, z, z);
    unsafe { GetThreadTimes(h, &mut a, &mut b, &mut k, &mut u) };
    ft_ns(k) + ft_ns(u)
}

pub fn thread_cycles(h: HANDLE) -> u64 {
    let mut c = 0u64;
    unsafe { QueryThreadCycleTime(h, &mut c) };
    c
}

/// Cost of the system-wide Toolhelp thread snapshot a naive thread audit would use.
pub fn toolhelp_thread_snapshot_ns() -> u64 {
    let t = carthago_sched::clock::now_ns();
    let h = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    let dt = carthago_sched::clock::now_ns() - t;
    unsafe { CloseHandle(h) };
    dt
}

pub fn cpu_name() -> String {
    let key: Vec<u16> = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\0".encode_utf16().collect();
    let val: Vec<u16> = "ProcessorNameString\0".encode_utf16().collect();
    let mut buf = [0u16; 128];
    let mut len = (buf.len() * 2) as u32;
    let r = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), val.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len)
    };
    if r != 0 {
        return "unknown".into();
    }
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..n]).trim().to_string()
}
