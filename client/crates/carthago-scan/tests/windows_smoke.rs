//! Runs every scanner once in this test process and plants artifacts the scanners must find:
//! RWX private memory holding a PE header, a thread started inside it, and an inline hook on
//! kernelbase!GetTickCount. Windows-only.
#![cfg(windows)]

use std::sync::{Arc, Mutex};

use carthago_scan::{detect_dirs, jobs, phase1_jobs};
use sn_proto::v1::{FindingCode, UnbackedFlags, WatchedApi};
use sn_sched::{drive, Finding};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use windows_sys::Win32::System::Threading::{CreateThread, TerminateThread};

/// Tests patch process-wide state (an API prologue), so they must not overlap.
static SERIAL: Mutex<()> = Mutex::new(());

fn of(code: FindingCode, fs: &[Finding]) -> Vec<Finding> {
    fs.iter().filter(|f| f.code == code as u32).copied().collect()
}

#[test]
fn every_phase1_job_completes_a_pass() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for mut j in phase1_jobs(Arc::new(detect_dirs())) {
        let (_, done) = drive(j.as_mut(), 1_000_000);
        assert!(done, "{} did not finish a pass", j.name());
    }
}

#[test]
fn planted_artifacts_are_found() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        // A fake manual map: RWX private region with MZ/PE headers and a spinning thread.
        let base = VirtualAlloc(std::ptr::null(), 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) as *mut u8;
        assert!(!base.is_null());
        base.write(b'M');
        base.add(1).write(b'Z');
        base.add(0x3c).cast::<u32>().write_unaligned(0x80);
        std::ptr::copy_nonoverlapping([b'P', b'E', 0, 0].as_ptr(), base.add(0x80), 4);
        let code = base.add(0x1000);
        std::ptr::copy_nonoverlapping([0xF3u8, 0x90, 0xEB, 0xFC].as_ptr(), code, 4); // pause; jmp -4
        let thread = CreateThread(std::ptr::null(), 0, Some(std::mem::transmute::<*mut u8, unsafe extern "system" fn(*mut core::ffi::c_void) -> u32>(code)), std::ptr::null(), 0, std::ptr::null_mut());
        assert!(!thread.is_null());

        let (mem, _) = drive(&mut jobs::MemoryWalk::new(), 1_000_000);
        let exec = of(FindingCode::UnbackedExec, &mem);
        let ours = exec.iter().find(|f| f.a == base as u64).expect("planted region reported");
        let flags = ours.b >> 48;
        assert_ne!(flags & UnbackedFlags::MzHeader as u64, 0);
        assert_ne!(flags & UnbackedFlags::PeSignature as u64, 0);
        assert_ne!(flags & UnbackedFlags::Private as u64, 0);
        assert_ne!(flags & UnbackedFlags::Writable as u64, 0);

        let (thr, _) = drive(&mut jobs::ThreadAudit::new(), 1_000_000);
        assert!(of(FindingCode::ThreadStartUnbacked, &thr).iter().any(|f| f.a == code as u64), "thread start reported: {thr:?}");
        TerminateThread(thread, 0);

        // Inline hook: jmp [rip+0] with an absolute target, from GetTickCount into the region.
        let kb = GetModuleHandleW(carthago_scan::win::wide("kernelbase.dll").as_ptr());
        let f = GetProcAddress(kb, c"GetTickCount".as_ptr().cast()).unwrap() as *mut u8;
        let mut saved = [0u8; 14];
        std::ptr::copy_nonoverlapping(f, saved.as_mut_ptr(), 14);
        let mut old = 0u32;
        assert_ne!(VirtualProtect(f.cast(), 14, PAGE_EXECUTE_READWRITE, &mut old), 0);
        let mut patch = [0xFFu8, 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        patch[6..].copy_from_slice(&(code as u64).to_le_bytes());
        std::ptr::copy_nonoverlapping(patch.as_ptr(), f, 14);
        let (hooks, _) = drive(&mut jobs::ApiHooks::new(), 1000);
        std::ptr::copy_nonoverlapping(saved.as_ptr(), f, 14);
        VirtualProtect(f.cast(), 14, old, &mut old);

        let h = of(FindingCode::ApiHook, &hooks);
        let hit = h.iter().find(|f| f.b == WatchedApi::KernelbaseGetTickCount as u64).unwrap_or_else(|| panic!("hook reported: {hooks:?}"));
        assert_eq!(hit.a, code as u64, "jump target decoded");
        assert!(hit.detail.is_empty(), "target is not image-backed");
        assert!(h.iter().all(|f| f.b == WatchedApi::KernelbaseGetTickCount as u64), "no other API flagged: {h:?}");
    }
}

#[test]
fn clean_process_has_no_code_findings() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (hooks, done) = drive(&mut jobs::ApiHooks::new(), 1000);
    assert!(done);
    assert!(of(FindingCode::ApiHook, &hooks).is_empty(), "{hooks:?}");
    let (dbg, _) = drive(&mut jobs::DebuggerSignals::new(), 10);
    assert!(dbg.is_empty() || std::env::var_os("CARTHAGO_EXPECT_DEBUGGER").is_some(), "{dbg:?}");
}
