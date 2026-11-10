#[cfg(windows)]
mod imp {
    use windows_sys::Win32::System::Kernel::PROCESSOR_NUMBER;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, GetProcessAffinityMask, SetThreadDescription, SetThreadIdealProcessorEx,
        SetThreadInformation, SetThreadPriority, ThreadPowerThrottling, THREAD_POWER_THROTTLING_CURRENT_VERSION,
        THREAD_POWER_THROTTLING_EXECUTION_SPEED, THREAD_POWER_THROTTLING_STATE, THREAD_PRIORITY_BELOW_NORMAL,
    };

    /// Highest logical processor in the process affinity mask; the game's main thread tends to
    /// start low, so the worker prefers the far end.
    pub(crate) fn last_allowed_processor() -> Option<u8> {
        let (mut proc_mask, mut sys_mask) = (0usize, 0usize);
        if unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut proc_mask, &mut sys_mask) } == 0 || proc_mask == 0 {
            return None;
        }
        Some((usize::BITS - 1 - proc_mask.leading_zeros()) as u8)
    }

    pub(crate) fn configure_worker(below_normal: bool, eco_qos: bool, ideal: Option<u8>) {
        unsafe {
            let h = GetCurrentThread();
            let name: Vec<u16> = "carthago-sched".encode_utf16().chain(Some(0)).collect();
            SetThreadDescription(h, name.as_ptr());
            if below_normal {
                SetThreadPriority(h, THREAD_PRIORITY_BELOW_NORMAL);
            }
            if let Some(n) = ideal {
                let pn = PROCESSOR_NUMBER { Group: 0, Number: n, Reserved: 0 };
                SetThreadIdealProcessorEx(h, &pn, std::ptr::null_mut());
            }
            if eco_qos {
                let st = THREAD_POWER_THROTTLING_STATE {
                    Version: THREAD_POWER_THROTTLING_CURRENT_VERSION,
                    ControlMask: THREAD_POWER_THROTTLING_EXECUTION_SPEED,
                    StateMask: THREAD_POWER_THROTTLING_EXECUTION_SPEED,
                };
                SetThreadInformation(
                    h,
                    ThreadPowerThrottling,
                    &st as *const _ as *const core::ffi::c_void,
                    size_of::<THREAD_POWER_THROTTLING_STATE>() as u32,
                );
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub(crate) fn last_allowed_processor() -> Option<u8> {
        None
    }

    pub(crate) fn configure_worker(_below_normal: bool, _eco_qos: bool, _ideal: Option<u8>) {}
}

pub(crate) use imp::*;
