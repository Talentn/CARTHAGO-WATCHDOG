//! `carthago-cs16.exe`: the Watchdog companion for Counter-Strike 1.6, a game the SDK cannot
//! be built into. It sits beside the game instead of inside it:
//!
//! 1. opens a session with the gateway (TPM attestation, pinned TLS), exactly as the SDK does;
//! 2. starts `hl.exe` as an ordinary child process and drops its own access to it down to
//!    query + read + wait;
//! 3. heartbeats while the game runs, carrying what the read-only scanners in
//!    `carthago_scan::external` see;
//! 4. writes the session token to a file so the telemetry bridge can bind the local player's
//!    match slot to this session.
//!
//! It never injects into, patches, suspends or terminates the game, and it ignores kick
//! messages: a kick only ends the session.

#[cfg(not(windows))]
fn main() {
    eprintln!("carthago-cs16 runs on Windows only");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    std::process::exit(win::run());
}

#[cfg(windows)]
mod win {
    use std::io::Write;
    use std::path::Path;
    use std::sync::mpsc::channel;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use carthago_core::{Config, MitigationProfile, Runtime, SessionReady, State};
    use carthago_cs16_companion::{command_line, parse_args, parse_keys, Game, Options, SessionFile, USAGE};
    use carthago_scan::external::{Target, TargetCell};
    use carthago_sched::Activity;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};

    struct Log {
        file: Mutex<Option<std::fs::File>>,
        t0: Instant,
    }

    impl Log {
        fn line(&self, level: &str, msg: &str) {
            let line = format!("[{:9.3}] {level:5} {msg}", self.t0.elapsed().as_secs_f64());
            println!("{line}");
            if let Some(f) = self.file.lock().unwrap().as_mut() {
                let _ = writeln!(f, "{line}");
                let _ = f.flush();
            }
        }
        fn info(&self, msg: &str) {
            self.line("info", msg);
        }
        fn warn(&self, msg: &str) {
            self.line("warn", msg);
        }
        fn error(&self, msg: &str) {
            self.line("error", msg);
        }
    }

    fn launch(exe: &Path, args: &[String]) -> std::io::Result<Target> {
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let app = wide(&exe.to_string_lossy());
        let mut cmd = wide(&command_line(exe, args));
        let cwd = exe.parent().filter(|p| !p.as_os_str().is_empty()).map(|p| wide(&p.to_string_lossy()));
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // An ordinary start: no debugging, no suspension, no inherited handles.
        let ok = unsafe {
            CreateProcessW(
                app.as_ptr(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                0,
                std::ptr::null(),
                cwd.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                &si,
                &mut pi,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        unsafe { CloseHandle(pi.hThread) };
        unsafe { Target::from_created(pi.hProcess) }
    }

    fn begin(rt: &Runtime, player: &str) -> Result<SessionReady, String> {
        let (tx, rx) = channel();
        if !rt.begin_session(
            player.to_owned(),
            Box::new(move |r| {
                let _ = tx.send(r);
            }),
        ) {
            return Err("the SDK thread is not running".into());
        }
        rx.recv_timeout(Duration::from_secs(90)).map_err(|_| "no answer from the gateway within 90 s".to_owned())?
    }

    fn session_file(o: &Options, rt: &Runtime, ready: &SessionReady, pid: u32, state: &str) -> SessionFile {
        SessionFile {
            session_id: rt.session_id().unwrap_or_default(),
            token: rt.token().unwrap_or_default(),
            player_hash: o.player.clone(),
            trust_level: ready.trust_level,
            attest_flags: ready.attest_flags,
            game_pid: pid,
            state: state.into(),
        }
    }

    pub fn run() -> i32 {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        let o = match parse_args(&argv) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("carthago-cs16: {e}\n\n{USAGE}");
                return 1;
            }
        };
        let log = Arc::new(Log { file: Mutex::new(o.log.as_ref().and_then(|p| std::fs::File::create(p).ok())), t0: Instant::now() });
        let keys = match std::fs::read_to_string(&o.keys).map_err(|e| format!("{}: {e}", o.keys.display())).and_then(|j| parse_keys(&j)) {
            Ok(k) => k,
            Err(e) => {
                log.error(&e);
                return 1;
            }
        };
        if o.gateway.starts_with("wss://") && keys.tls_pins.is_empty() {
            log.error("the gateway published no TLS key pins; refusing an unpinned wss:// connection");
            return 1;
        }
        let exe_for_dirs = match &o.game {
            Game::Launch { exe, .. } => {
                if !exe.is_file() {
                    log.error(&format!("{} not found", exe.display()));
                    return 1;
                }
                exe.to_string_lossy().into_owned()
            }
            Game::Attach(pid) => carthago_scan::win::process_image_name(*pid),
        };

        let cell = TargetCell::new();
        let dirs = Arc::new(carthago_scan::dirs_for(&exe_for_dirs));
        let (job_cell, sdk_log) = (cell.clone(), log.clone());
        let rt = match Runtime::start(Config {
            tenant_id: o.tenant.clone(),
            build_id: o.build.clone(),
            gateway_url: o.gateway.clone(),
            server_identity: keys.server_identity,
            tls_pins: keys.tls_pins,
            allow_tpm: o.allow_tpm,
            log: Some(Arc::new(move |level, msg| sdk_log.line(["debug", "info", "warn", "error"][level.min(3) as usize], msg))),
            // The mitigation profile hardens the process it runs in. That is this companion,
            // not the game, so it would protect nothing that matters here.
            mitigations: MitigationProfile::Off,
            input_monitor: o.input_monitor,
            jobs: Some(Box::new(move || carthago_scan::external::jobs(job_cell, dirs))),
        }) {
            Ok(rt) => rt,
            Err(e) => {
                log.error(&format!("could not start the SDK runtime: {e}"));
                return 1;
            }
        };
        // A companion cannot see menus or loading screens; it keeps the strictest budgets
        // for as long as the game runs.
        rt.set_activity(Activity::Gameplay);

        log.info(&format!("connecting to {} as player {:?} (tenant {}, build {})", o.gateway, o.player, o.tenant, o.build));
        let mut ready = match begin(&rt, &o.player) {
            Ok(r) => r,
            Err(e) => {
                log.error(&format!("no session: {e}. The game was not started."));
                rt.shutdown();
                return 2;
            }
        };
        log.info(&format!(
            "SESSION session_id={} trust_level={} attest_flags={:#x} [{}]",
            rt.session_id().unwrap_or_default(),
            ready.trust_level,
            ready.attest_flags,
            carthago_crypto::trust::flag_names(ready.attest_flags).join(",")
        ));

        let target = match &o.game {
            Game::Launch { exe, args } => {
                log.info(&format!("starting {}", command_line(exe, args)));
                launch(exe, args)
            }
            Game::Attach(pid) => Target::open(*pid),
        };
        let target = match target {
            Ok(t) => Arc::new(t),
            Err(e) => {
                log.error(&format!("could not start or open the game: {e}"));
                rt.shutdown();
                return 3;
            }
        };
        let pid = target.pid();
        log.info(&format!(
            "GAME pid={pid} {} watched with read-only access (query, read memory, wait)",
            if target.is_wow64() { "32-bit" } else { "64-bit" }
        ));
        cell.set(target.clone());
        if o.input_monitor {
            carthago_scan::input::watch_pid(pid);
        }
        let write_session = |ready: &SessionReady, state: &str| {
            if let Some(p) = &o.session_file {
                if let Err(e) = session_file(&o, &rt, ready, pid, state).write(p) {
                    log.warn(&format!("could not write {}: {e}", p.display()));
                }
            }
        };
        write_session(&ready, "active");

        let started = Instant::now();
        let mut last_status = Instant::now();
        let mut last_token = rt.token();
        let mut reconnects = 0u32;
        let mut retry_at: Option<Instant> = None;
        let exit = loop {
            if target.wait_exit(Duration::from_millis(16)) {
                break 0;
            }
            rt.tick();
            if o.max_secs.is_some_and(|m| started.elapsed().as_secs() >= m) {
                log.info("--max-secs reached; leaving the game running and ending the session");
                break 0;
            }
            let st = rt.status();
            let down = [State::Kicked as u32, State::Failed as u32, State::Disconnected as u32].contains(&st.state);
            if down && retry_at.is_none() {
                if st.state == State::Kicked as u32 {
                    log.warn("the gateway ended the session. The game is left running; this companion never closes it.");
                }
                if reconnects >= 5 {
                    log.error("the session could not be re-established after 5 attempts; the game keeps running unwatched");
                    break 4;
                }
                reconnects += 1;
                retry_at = Some(Instant::now() + Duration::from_secs(3 * reconnects as u64));
            }
            if retry_at.is_some_and(|t| Instant::now() >= t) {
                retry_at = None;
                log.info(&format!("reconnecting (attempt {reconnects} of 5)"));
                match begin(&rt, &o.player) {
                    Ok(r) => {
                        ready = r;
                        log.info(&format!("SESSION session_id={} trust_level={} (reconnected)", rt.session_id().unwrap_or_default(), ready.trust_level));
                        write_session(&ready, "active");
                        last_token = rt.token();
                    }
                    Err(e) => log.warn(&format!("reconnect failed: {e}")),
                }
            }
            let token = rt.token();
            if token != last_token && !down {
                last_token = token;
                write_session(&ready, "active");
            }
            if last_status.elapsed() >= Duration::from_secs(10) {
                last_status = Instant::now();
                if st.heartbeats_acked > 0 {
                    reconnects = 0;
                }
                log.info(&format!(
                    "STATUS state={} heartbeats={}/{} acked, last ack {} ms ago, scanner cpu {:.1} ms in {} slices, signature checks {} files {:.1} ms",
                    ["idle", "connecting", "active", "kicked", "failed", "disconnected"][st.state.min(5) as usize],
                    st.heartbeats_acked,
                    st.heartbeats_sent,
                    if st.last_ack_age_ms == u64::MAX { -1 } else { st.last_ack_age_ms as i64 },
                    st.sched_worker_cpu_ns as f64 / 1e6,
                    st.sched_slices,
                    carthago_scan::signature::files_checked(),
                    carthago_scan::signature::cpu_ns() as f64 / 1e6,
                ));
            }
        };

        match target.exit_code() {
            Some(code) => log.info(&format!("GAME exited with code {code:#x} after {} s", started.elapsed().as_secs())),
            None => log.info("leaving while the game is still running"),
        }
        cell.clear();
        write_session(&ready, "ended");
        // One last heartbeat so findings from the final seconds are not lost.
        rt.heartbeat_now();
        let st0 = rt.status();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && rt.status().heartbeats_acked == st0.heartbeats_acked && st0.state == State::Active as u32 {
            std::thread::sleep(Duration::from_millis(50));
        }
        let st = rt.status();
        log.info(&format!(
            "DONE heartbeats={}/{} acked, scanner cpu {:.1} ms over {} s",
            st.heartbeats_acked,
            st.heartbeats_sent,
            st.sched_worker_cpu_ns as f64 / 1e6,
            started.elapsed().as_secs()
        ));
        rt.shutdown();
        exit
    }
}
