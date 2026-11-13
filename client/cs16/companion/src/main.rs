//! `carthago-cs16.exe`: the Watchdog companion for Counter-Strike 1.6, a game the SDK cannot
//! be built into. It sits beside the game instead of inside it:
//!
//! 1. opens a session with the gateway (TPM attestation, pinned TLS), exactly as the SDK does;
//! 2. starts the game program (`hl.exe`, or `cstrike.exe` in builds that name it so) as an
//!    ordinary child process and drops its own access to it down to query + read + wait. If
//!    that program turns out to be a launcher, it finds the game process the launcher
//!    started (same folder, engine module loaded) and watches that one instead;
//! 3. heartbeats while the game runs, carrying what the read-only scanners in
//!    `carthago_scan::external` see;
//! 4. writes the session token to a file so the telemetry bridge can bind the local player's
//!    match slot to this session;
//! 5. shows a full-screen alert, in a window of its own, when the gateway reports that the
//!    session was flagged.
//!
//! It never injects into, patches or suspends the game, and it ignores kick messages: a kick
//! only ends the session. It leaves the game running whatever the gateway says, unless it
//! was started with `--end-match-on-detect`: then a flagged session makes it ask the game
//! to close, and end the process it started itself if the game does not.

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
mod alert;

#[cfg(windows)]
mod win {
    use std::io::Write;
    use std::path::Path;
    use std::sync::mpsc::channel;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use carthago_core::{Config, MitigationProfile, Notice, Runtime, SessionReady, State};
    use carthago_cs16_companion::{
        alert_text, command_line, exit, never_the_game, parse_args, parse_keys, Game, Options, SessionFile, ENGINE_MODULES, USAGE,
    };
    use carthago_scan::external::{find_started_game, Target, TargetCell};
    use carthago_sched::Activity;
    use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, HANDLE};
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, GetCurrentProcess, TerminateProcess, PROCESS_INFORMATION, PROCESS_TERMINATE, STARTUPINFOW,
    };

    use crate::alert::{self, Alert};

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

    /// The right to end the process this companion created, kept only when it was started
    /// with `--end-match-on-detect`. It carries no other access to the game.
    struct Closer {
        pid: u32,
        handle: HANDLE,
    }

    impl Drop for Closer {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.handle) };
        }
    }

    fn launch(exe: &Path, args: &[String], keep_closer: bool) -> std::io::Result<(Target, Option<Closer>)> {
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
            let e = std::io::Error::last_os_error();
            // ERROR_ELEVATION_REQUIRED: the program's manifest asks for administrator rights.
            if e.raw_os_error() == Some(740) {
                return Err(std::io::Error::other(format!(
                    "{} asks for administrator rights; start this from a window opened with \"Run as administrator\"",
                    exe.display()
                )));
            }
            return Err(e);
        }
        unsafe { CloseHandle(pi.hThread) };
        let mut closer = None;
        if keep_closer {
            let (me, mut h) = (unsafe { GetCurrentProcess() }, std::ptr::null_mut());
            if unsafe { DuplicateHandle(me, pi.hProcess, me, &mut h, PROCESS_TERMINATE, 0, 0) } != 0 {
                closer = Some(Closer { pid: pi.dwProcessId, handle: h });
            }
        }
        unsafe { Target::from_created(pi.hProcess) }.map(|t| (t, closer))
    }

    /// `--end-match-on-detect`: asks the watched game to close, as its window's close button
    /// does. A game that does not is ended only if it is the process this companion created.
    fn end_game(log: &Log, target: &Target, closer: Option<&Closer>) {
        if !target.alive() {
            return;
        }
        let asked = alert::ask_to_close(target.pid());
        log.warn(&format!("END MATCH asked the game (pid={}) to close ({asked} window{})", target.pid(), if asked == 1 { "" } else { "s" }));
        if target.wait_exit(Duration::from_secs(5)) {
            log.info("END MATCH the game closed");
            return;
        }
        match closer {
            Some(c) if c.pid == target.pid() => {
                unsafe { TerminateProcess(c.handle, 0) };
                log.warn("END MATCH the game did not close within 5 s; ended the process this companion started");
            }
            _ => log.warn("END MATCH the game did not close within 5 s. This companion did not start that process itself, so it is left running."),
        }
    }

    /// What happens when the gateway flags the session: a log line, the alert screen, and
    /// with `--end-match-on-detect` the end of the game.
    fn on_notice(log: &Log, o: &Options, n: &Notice, target: &Target, closer: Option<&Closer>, alerts: &mut Vec<std::thread::JoinHandle<()>>) {
        log.warn(&format!(
            "ALERT notice={} category={} severity={} test={}: {}",
            n.notice_id_hex(),
            n.category_name(),
            n.severity_name(),
            n.is_test(),
            n.reason()
        ));
        if o.alert {
            let text = alert_text(n.reason(), n.is_test(), &o.player, &n.session_id_hex(), n.issued_at_ms, o.end_match_on_detect);
            alerts.push(alert::show(Alert { text, seconds: o.alert_secs, game_pid: Some(target.pid()) }));
            log.info("ALERT screen shown in this program's own window (Esc, a click or the timer closes it)");
        }
        if o.end_match_on_detect {
            end_game(log, target, closer);
        } else if target.alive() {
            log.info("ALERT only: the game is left running (--end-match-on-detect was not given)");
        }
    }

    /// `--test-alert`: the alert screen as a preview, without a gateway or a game.
    fn preview(o: &Options) -> i32 {
        let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
        let test = Notice {
            notice_id: [0; 16],
            session_id: [0; 16],
            tenant_id: o.tenant.clone(),
            player_id_hash: o.player.clone(),
            issued_at_ms: now_ms,
            category: carthago_core::notice::CATEGORY_TEST,
            severity: carthago_core::notice::SEVERITY_NOTICE,
            signed: Vec::new(),
        };
        println!("ALERT preview: showing the alert screen now. Esc or a click closes it{}.", match o.alert_secs {
            0 => String::new(),
            s => format!("; it closes by itself after {s} s"),
        });
        let text = alert_text(test.reason(), true, &o.player, "", now_ms, o.end_match_on_detect);
        let _ = alert::show(Alert { text, seconds: o.alert_secs, game_pid: None }).join();
        println!("ALERT preview: closed. Nothing was detected and nothing was started.");
        exit::OK
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
                return exit::USAGE;
            }
        };
        if o.test_alert {
            return preview(&o);
        }
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
        let (notice_tx, notices) = channel::<Notice>();
        rt.set_notice_callback(Some(Box::new(move |n| {
            let _ = notice_tx.send(n.clone());
        })));
        let mut alerts = Vec::new();
        let mut alerts_raised = 0u32;

        log.info(&format!("connecting to {} as player {:?} (tenant {}, build {})", o.gateway, o.player, o.tenant, o.build));
        let mut ready = match begin(&rt, &o.player) {
            Ok(r) => r,
            Err(e) => {
                log.error(&format!("no session: {e}. The game was not started."));
                rt.shutdown();
                return exit::NO_SESSION;
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
                launch(exe, args, o.end_match_on_detect)
            }
            Game::Attach(pid) => Target::open(*pid).map(|t| (t, None)),
        };
        let (mut target, closer) = match target {
            Ok((t, closer)) => (Arc::new(t), closer),
            Err(e) => {
                log.error(&format!("could not start or open the game: {e}"));
                rt.shutdown();
                return exit::NOT_STARTED;
            }
        };
        let bits = |t: &Target| if t.is_wow64() { "32-bit" } else { "64-bit" };
        log.info(&format!("GAME pid={} {} watched with read-only access (query, read memory, wait)", target.pid(), bits(&target)));
        if o.end_match_on_detect {
            log.info(match closer {
                Some(_) => "--end-match-on-detect: if the session is flagged, the game is asked to close; the right to end the process started here is kept for that",
                None => "--end-match-on-detect: if the session is flagged, the game is asked to close",
            });
        }
        cell.set(target.clone());
        if o.input_monitor {
            carthago_scan::input::watch_pid(target.pid());
        }
        let write_session = |ready: &SessionReady, pid: u32, state: &str| {
            if let Some(p) = &o.session_file {
                if let Err(e) = session_file(&o, &rt, ready, pid, state).write(p) {
                    log.warn(&format!("could not write {}: {e}", p.display()));
                }
            }
        };
        write_session(&ready, target.pid(), "active");

        // The started program is the game once an engine module is loaded in it. Until then
        // it may be a launcher: a process in the same folder that has an engine module
        // loaded is the game it started, and the watch moves to that process.
        // The folder is taken from the path Windows reports for the started process, which
        // is the form other processes' paths are reported in; the argument is the fallback
        // for a program that has already ended.
        let started_exe = match &o.game {
            Game::Launch { exe, .. } => Some(Some(target.image_path()).filter(|p| !p.is_empty()).unwrap_or_else(|| {
                std::fs::canonicalize(exe).unwrap_or_else(|_| exe.clone()).to_string_lossy().into_owned()
            })),
            Game::Attach(_) => None,
        };
        let look_for_game = |skip: u32| started_exe.as_ref().and_then(|exe| find_started_game(exe, &ENGINE_MODULES, &[skip], &|name| !never_the_game(name)));
        let mut is_game = started_exe.is_none();
        let mut target_since = Instant::now();
        let mut last_look = Instant::now();
        // Set when the watched process has ended and a successor is still being looked for.
        let mut ended: Option<(Instant, Duration)> = None;

        let started = Instant::now();
        let mut last_status = Instant::now();
        let mut last_token = rt.token();
        let mut reconnects = 0u32;
        let mut retry_at: Option<Instant> = None;
        let exit = loop {
            if ended.is_some() {
                std::thread::sleep(Duration::from_millis(16));
            } else if target.wait_exit(Duration::from_millis(16)) {
                // A launcher ends within seconds and the game needs a moment to load its
                // engine; a game that ends has no successor, bar one that restarts itself.
                let grace = match (is_game, target_since.elapsed() < Duration::from_secs(60)) {
                    (false, true) => Duration::from_secs(20),
                    _ => Duration::from_millis(1500),
                };
                if !is_game {
                    log.info(&format!(
                        "GAME pid={} ended after {:.1} s without loading the engine; looking for the game it started",
                        target.pid(),
                        target_since.elapsed().as_secs_f64()
                    ));
                }
                ended = Some((Instant::now(), grace));
                last_look = Instant::now() - Duration::from_secs(1);
            }
            let look_every = if ended.is_some() { Duration::from_millis(250) } else { Duration::from_secs(1) };
            if (ended.is_some() || (!is_game && target_since.elapsed() < Duration::from_secs(120))) && last_look.elapsed() >= look_every {
                last_look = Instant::now();
                if let Some(m) = (ended.is_none()).then(|| target.loaded_module(&ENGINE_MODULES)).flatten() {
                    is_game = true;
                    log.info(&format!("GAME pid={} has {m} loaded: the started program is the game itself", target.pid()));
                } else if let Some((t, m)) = look_for_game(target.pid()) {
                    let name = Path::new(&t.image_path()).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    log.info(&format!(
                        "GAME pid={} {} ({name}, {m} loaded) was started by pid={}; now watching it with read-only access",
                        t.pid(),
                        bits(&t),
                        target.pid()
                    ));
                    target = Arc::new(t);
                    cell.set(target.clone());
                    if o.input_monitor {
                        carthago_scan::input::watch_pid(target.pid());
                    }
                    write_session(&ready, target.pid(), "active");
                    (is_game, target_since, ended) = (true, Instant::now(), None);
                }
            }
            if ended.is_some_and(|(at, grace)| at.elapsed() >= grace) {
                if !is_game && target_since.elapsed() < Duration::from_secs(15) + ended.map_or(Duration::ZERO, |(_, g)| g) {
                    log.error(&format!(
                        "the started program ended after a few seconds (exit code {:#x}) and no game process with {} loaded appeared in its folder",
                        target.exit_code().unwrap_or(0),
                        ENGINE_MODULES.join(" or ")
                    ));
                    break exit::GAME_NEVER_RAN;
                }
                break exit::OK;
            }
            rt.tick();
            while let Ok(n) = notices.try_recv() {
                alerts_raised += 1;
                on_notice(&log, &o, &n, &target, closer.as_ref(), &mut alerts);
            }
            if o.max_secs.is_some_and(|m| started.elapsed().as_secs() >= m) {
                log.info("--max-secs reached; leaving the game running and ending the session");
                break exit::OK;
            }
            let st = rt.status();
            let down = [State::Kicked as u32, State::Failed as u32, State::Disconnected as u32].contains(&st.state);
            if down && retry_at.is_none() {
                if st.state == State::Kicked as u32 {
                    log.warn("the gateway ended the session. The game is left running; a kick never closes it.");
                }
                if reconnects >= 5 {
                    log.error("the session could not be re-established after 5 attempts; the game keeps running unwatched");
                    break exit::SESSION_LOST;
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
                        write_session(&ready, target.pid(), "active");
                        last_token = rt.token();
                    }
                    Err(e) => log.warn(&format!("reconnect failed: {e}")),
                }
            }
            let token = rt.token();
            if token != last_token && !down {
                last_token = token;
                write_session(&ready, target.pid(), "active");
            }
            if last_status.elapsed() >= Duration::from_secs(10) {
                last_status = Instant::now();
                if st.heartbeats_acked > 0 {
                    reconnects = 0;
                }
                if !is_game && ended.is_none() && target_since.elapsed() >= Duration::from_secs(60) && target_since.elapsed() < Duration::from_secs(70) {
                    log.warn(&format!(
                        "pid={} has not loaded {} after 60 s and no other game process is in its folder; watching the started program as it is",
                        target.pid(),
                        ENGINE_MODULES.join(" or ")
                    ));
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
        write_session(&ready, target.pid(), "ended");
        // One last heartbeat so findings from the final seconds are not lost.
        rt.heartbeat_now();
        let st0 = rt.status();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && rt.status().heartbeats_acked == st0.heartbeats_acked && st0.state == State::Active as u32 {
            std::thread::sleep(Duration::from_millis(50));
        }
        // A notice that arrived with the last heartbeat is still shown; there is no game
        // left to close.
        while let Ok(n) = notices.try_recv() {
            alerts_raised += 1;
            on_notice(&log, &Options { end_match_on_detect: false, ..o.clone() }, &n, &target, None, &mut alerts);
        }
        let st = rt.status();
        log.info(&format!(
            "DONE heartbeats={}/{} acked, scanner cpu {:.1} ms over {} s, alerts={alerts_raised}",
            st.heartbeats_acked,
            st.heartbeats_sent,
            st.sched_worker_cpu_ns as f64 / 1e6,
            started.elapsed().as_secs()
        ));
        rt.shutdown();
        if !alerts.is_empty() {
            log.info("waiting for the alert screen to be closed (Esc, a click, or it closes by itself)");
            for a in alerts {
                let _ = a.join();
            }
        }
        exit
    }
}
