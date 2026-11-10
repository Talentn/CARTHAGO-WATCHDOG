//! Runs every scanner once in this (clean) test process: each job must finish a pass within
//! its budget, and an unmodified process must produce no code-integrity findings. Detection
//! logic itself is covered by the portable unit tests over synthetic PE images and byte
//! patterns (pe.rs, hook.rs); no test here modifies process memory. Windows-only.
#![cfg(windows)]

use std::sync::{Arc, Mutex};

use carthago_scan::{detect_dirs, jobs, phase1_jobs};
use sn_proto::v1::FindingCode;
use sn_sched::{drive, Finding};

/// The jobs read process-wide state; keep the passes from overlapping so timings stay comparable.
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
fn clean_process_has_no_code_findings() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (hooks, done) = drive(&mut jobs::ApiHooks::new(), 1000);
    assert!(done);
    assert!(of(FindingCode::ApiHook, &hooks).is_empty(), "{hooks:?}");
    let (dbg, _) = drive(&mut jobs::DebuggerSignals::new(), 10);
    assert!(dbg.is_empty() || std::env::var_os("CARTHAGO_EXPECT_DEBUGGER").is_some(), "{dbg:?}");
}
