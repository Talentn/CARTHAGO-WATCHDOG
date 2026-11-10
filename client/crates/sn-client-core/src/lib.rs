//! Client SDK runtime behind `sentinel.dll` (plan §3.1): one SDK thread owns the device
//! identity and the gateway session (handshake, heartbeats), the budgeted scan scheduler runs
//! on its own worker, and the game thread only calls [`Runtime::tick`].

pub mod device;
pub mod session;

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering::Relaxed};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sn_crypto::VerifyingKey;
use sn_proto::v1 as pb;
use sn_sched::{Activity, Scheduler};
use tungstenite::Message as WsMessage;

use device::DeviceIdentity;

pub use carthago_harden::Profile as MitigationProfile;

pub type LogFn = Arc<dyn Fn(u8, &str) + Send + Sync>;

pub const LOG_DEBUG: u8 = 0;
pub const LOG_INFO: u8 = 1;
pub const LOG_WARN: u8 = 2;
pub const LOG_ERROR: u8 = 3;

pub struct Config {
    pub tenant_id: String,
    pub build_id: String,
    pub gateway_url: String,
    pub server_identity: VerifyingKey,
    pub allow_tpm: bool,
    pub log: Option<LogFn>,
    /// Process mitigation profile applied at init (plan §6.3).
    pub mitigations: MitigationProfile,
    /// Low-level mouse hook for injected-input statistics (plan §6.1).
    pub input_monitor: bool,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle = 0,
    Connecting = 1,
    Active = 2,
    Kicked = 3,
    Failed = 4,
    Disconnected = 5,
}

#[derive(Debug, Clone)]
pub struct SessionReady {
    pub trust_level: u32,
    pub attest_flags: u64,
    pub notes: Vec<String>,
}

pub type ReadyFn = Box<dyn FnOnce(Result<SessionReady, String>) + Send>;
pub type KickFn = Box<dyn Fn(&str) + Send>;

enum Cmd {
    Begin { player_id_hash: String, on_ready: ReadyFn },
}

struct Inner {
    cfg: Config,
    sched: Mutex<Option<Scheduler>>,
    state: AtomicU32,
    token: Mutex<String>,
    trust_level: AtomicU32,
    attest_flags: AtomicU64,
    frames: AtomicU64,
    heartbeats_sent: AtomicU64,
    heartbeats_acked: AtomicU64,
    last_ack: Mutex<Option<Instant>>,
    suppress_heartbeats: AtomicBool,
    heartbeat_now: AtomicBool,
    stop: AtomicBool,
    activity: AtomicU8,
    kick_cb: Mutex<Option<KickFn>>,
    /// Findings produced outside the scheduler (mitigation outcome), sent with the next heartbeat.
    startup_findings: Mutex<Vec<pb::Finding>>,
    #[cfg(windows)]
    input: Mutex<Option<carthago_scan::input::InputMonitor>>,
}

impl Inner {
    fn log(&self, level: u8, msg: &str) {
        if let Some(l) = &self.cfg.log {
            l(level, msg);
        }
    }

    fn set_state(&self, s: State) {
        self.state.store(s as u32, Relaxed);
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Status {
    pub state: u32,
    pub trust_level: u32,
    pub attest_flags: u64,
    pub heartbeats_sent: u64,
    pub heartbeats_acked: u64,
    /// Milliseconds since the last heartbeat ack (`u64::MAX` if none yet).
    pub last_ack_age_ms: u64,
    pub sched_worker_cpu_ns: u64,
    pub sched_slices: u64,
    pub frames: u64,
}

pub struct Runtime {
    inner: Arc<Inner>,
    cmd: Mutex<Option<Sender<Cmd>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Runtime {
    /// Returns immediately; the scheduler, TPM identity and keys are set up on the SDK thread.
    pub fn start(cfg: Config) -> std::io::Result<Self> {
        let inner = Arc::new(Inner {
            cfg,
            sched: Mutex::new(None),
            state: AtomicU32::new(State::Idle as u32),
            token: Mutex::new(String::new()),
            trust_level: AtomicU32::new(0),
            attest_flags: AtomicU64::new(0),
            frames: AtomicU64::new(0),
            heartbeats_sent: AtomicU64::new(0),
            heartbeats_acked: AtomicU64::new(0),
            last_ack: Mutex::new(None),
            suppress_heartbeats: AtomicBool::new(false),
            heartbeat_now: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            activity: AtomicU8::new(Activity::Menu as u8),
            kick_cb: Mutex::new(None),
            startup_findings: Mutex::new(Vec::new()),
            #[cfg(windows)]
            input: Mutex::new(None),
        });
        let (tx, rx) = channel();
        let i = inner.clone();
        let thread = std::thread::Builder::new().name("sn-sdk".into()).spawn(move || sdk_thread(i, rx))?;
        Ok(Self { inner, cmd: Mutex::new(Some(tx)), thread: Mutex::new(Some(thread)) })
    }

    pub fn begin_session(&self, player_id_hash: String, on_ready: ReadyFn) -> bool {
        match self.cmd.lock().unwrap().as_ref() {
            Some(tx) => tx.send(Cmd::Begin { player_id_hash, on_ready }).is_ok(),
            None => false,
        }
    }

    /// Per-frame call: a counter and a non-blocking scheduler tick (skipped, never waited
    /// for, if the SDK thread is collecting heartbeat data at that instant).
    #[inline]
    pub fn tick(&self) {
        self.inner.frames.fetch_add(1, Relaxed);
        if let Ok(mut g) = self.inner.sched.try_lock() {
            if let Some(s) = g.as_mut() {
                s.tick();
            }
        }
    }

    pub fn set_activity(&self, a: Activity) {
        self.inner.activity.store(a as u8, Relaxed);
        if let Some(s) = self.inner.sched.lock().unwrap().as_ref() {
            s.set_activity(a);
        }
    }

    pub fn token(&self) -> Option<String> {
        let t = self.inner.token.lock().unwrap();
        (!t.is_empty()).then(|| t.clone())
    }

    pub fn status(&self) -> Status {
        let i = &self.inner;
        let (cpu, slices) = i.sched.try_lock().ok().and_then(|g| g.as_ref().map(|s| s.stats())).map_or((0, 0), |s| (s.worker_cpu_ns, s.slices));
        Status {
            state: i.state.load(Relaxed),
            trust_level: i.trust_level.load(Relaxed),
            attest_flags: i.attest_flags.load(Relaxed),
            heartbeats_sent: i.heartbeats_sent.load(Relaxed),
            heartbeats_acked: i.heartbeats_acked.load(Relaxed),
            last_ack_age_ms: i.last_ack.lock().unwrap().map_or(u64::MAX, |t| t.elapsed().as_millis() as u64),
            sched_worker_cpu_ns: cpu,
            sched_slices: slices,
            frames: i.frames.load(Relaxed),
        }
    }

    pub fn heartbeat_now(&self) {
        self.inner.heartbeat_now.store(true, Relaxed);
    }

    /// Test hook: stop sending heartbeats while staying connected (simulates a client whose
    /// anti-cheat traffic is blocked), so the gateway's deadline fires.
    pub fn suppress_heartbeats(&self, on: bool) {
        self.inner.suppress_heartbeats.store(on, Relaxed);
    }

    pub fn set_kick_callback(&self, cb: Option<KickFn>) {
        *self.inner.kick_cb.lock().unwrap() = cb;
    }

    pub fn shutdown(&self) {
        self.inner.stop.store(true, Relaxed);
        self.cmd.lock().unwrap().take();
        if let Some(t) = self.thread.lock().unwrap().take() {
            let _ = t.join();
        }
        if let Some(s) = self.inner.sched.lock().unwrap().take() {
            let _ = s.stop();
        }
        #[cfg(windows)]
        if let Some(mut m) = self.inner.input.lock().unwrap().take() {
            m.stop();
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn sched_config() -> sn_sched::Config {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    sn_sched::Config {
        // Scheduler spike: 2 ms slices cost up to one slice of frame time on 1-2 core
        // machines; 0.5 ms slices cut that at the same CPU.
        slice_target: if cores <= 2 { Duration::from_micros(500) } else { Duration::from_millis(2) },
        // Room for a first heartbeat's module inventory; findings are ~90 bytes each.
        findings_capacity: 256,
        ..Default::default()
    }
}

fn harden(inner: &Inner) {
    let profile = inner.cfg.mitigations;
    if profile == MitigationProfile::Off {
        return;
    }
    let o = carthago_harden::apply(profile);
    if o.failed != 0 {
        inner.log(LOG_WARN, &format!("mitigation profile {profile:?}: applied {:#x}, refused {:#x}", o.applied, o.failed));
    }
    inner.startup_findings.lock().unwrap().push(pb::Finding {
        job: "mitigations".into(),
        code: pb::FindingCode::Mitigations as u32,
        a: o.applied,
        b: o.failed,
        detail: String::new(),
    });
}

#[cfg(windows)]
fn start_input_monitor(inner: &Inner) {
    if !inner.cfg.input_monitor {
        return;
    }
    match carthago_scan::input::InputMonitor::start() {
        Ok(m) => *inner.input.lock().unwrap() = Some(m),
        Err(e) => inner.log(LOG_WARN, &format!("input monitor not started: {e}")),
    }
}

fn sdk_thread(inner: Arc<Inner>, rx: Receiver<Cmd>) {
    let t0 = Instant::now();
    harden(&inner);
    let dirs = Arc::new(carthago_scan::detect_dirs());
    match Scheduler::start(sched_config(), carthago_scan::phase1_jobs(dirs)) {
        Ok(s) => {
            s.set_activity(Activity::from_u8(inner.activity.load(Relaxed)));
            *inner.sched.lock().unwrap() = Some(s);
        }
        Err(e) => inner.log(LOG_ERROR, &format!("scheduler start failed: {e}")),
    }
    #[cfg(windows)]
    start_input_monitor(&inner);
    let t_sched = t0.elapsed();
    let device = match DeviceIdentity::open(&inner.cfg.tenant_id, inner.cfg.allow_tpm) {
        Ok((d, why)) => {
            if let Some(why) = why {
                inner.log(LOG_WARN, &format!("using software device key (lower trust level): {why}"));
            }
            Some(d)
        }
        Err(e) => {
            inner.log(LOG_ERROR, &format!("no device identity: {e}"));
            None
        }
    };
    inner.log(LOG_INFO, &format!("SDK ready: scheduler {:.2} ms, device identity {} ms ({})", t_sched.as_secs_f64() * 1e3,
        (t0.elapsed() - t_sched).as_millis(), device.as_ref().map_or("none", |d| if d.is_tpm() { "TPM" } else { "software" })));

    while let Ok(cmd) = rx.recv() {
        match cmd {
            Cmd::Begin { player_id_hash, on_ready } => match &device {
                Some(d) => run_session(&inner, d, player_id_hash, on_ready),
                None => on_ready(Err("no device identity".into())),
            },
        }
        if inner.stop.load(Relaxed) {
            break;
        }
    }
}

fn jitter(base: Duration, rng: &mut u64) -> Duration {
    *rng ^= *rng << 13;
    *rng ^= *rng >> 7;
    *rng ^= *rng << 17;
    let f = 0.8 + (*rng % 4001) as f64 / 10_000.0;
    base.mul_f64(f)
}

/// Findings per heartbeat; the rest wait for the next one (network budget, plan G2).
const HEARTBEAT_FINDINGS: usize = 96;

fn heartbeat(inner: &Inner) -> pb::Heartbeat {
    let t = carthago_scan::time::sample();
    let mut hb = pb::Heartbeat {
        activity: inner.activity.load(Relaxed) as u32,
        time: Some(pb::TimeSample { qpc_ns: t.qpc_ns, tick_count_ms: t.tick_count_ms, interrupt_time_100ns: t.interrupt_time_100ns }),
        ..Default::default()
    };
    hb.findings.append(&mut inner.startup_findings.lock().unwrap());
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut input_cpu_ns = 0;
    #[cfg(windows)]
    if inner.cfg.input_monitor {
        let c = carthago_scan::input::counters();
        hb.input = Some(pb::InputStats { mouse_events: c.mouse_events, injected: c.injected, lower_il_injected: c.lower_il_injected, focused_ms: c.focused_ms });
        input_cpu_ns = carthago_scan::input::thread_cpu_ns();
    }
    if let Some(s) = inner.sched.lock().unwrap().as_mut() {
        let room = HEARTBEAT_FINDINGS.saturating_sub(hb.findings.len());
        let mut taken = s.take_findings();
        hb.findings.extend(
            taken
                .by_ref()
                .take(room)
                .map(|f| pb::Finding { job: f.job.into(), code: f.code, a: f.a, b: f.b, detail: f.detail.as_str().into() }),
        );
        let rest: Vec<sn_sched::Finding> = taken.collect();
        s.requeue_findings(rest);
        let st = s.stats();
        hb.sched = Some(pb::SchedSummary {
            worker_cpu_ns: st.worker_cpu_ns,
            slices: st.slices,
            slice_cpu_max_ns: st.slice_cpu.max_ns,
            frames: inner.frames.load(Relaxed),
            jobs_quarantined: st.jobs.iter().filter(|j| j.quarantined).count() as u32,
            findings_dropped: st.findings_dropped,
            slice_overruns: st.slice_wall.count_above(3_000_000),
            input_thread_cpu_ns: input_cpu_ns,
        });
        hb.coverage = st
            .jobs
            .iter()
            .map(|j| pb::JobCoverage { job: j.name.into(), runs_completed: j.runs_completed, overruns: j.overruns, quarantined: j.quarantined })
            .collect();
    }
    hb
}

fn run_session(inner: &Inner, device: &DeviceIdentity, player_id_hash: String, on_ready: ReadyFn) {
    inner.set_state(State::Connecting);
    let params = session::Params {
        gateway_url: inner.cfg.gateway_url.clone(),
        tenant_id: inner.cfg.tenant_id.clone(),
        build_id: inner.cfg.build_id.clone(),
        player_id_hash,
        server_identity: inner.cfg.server_identity,
    };
    let log = |l: u8, m: &str| inner.log(l, m);
    let mut est = match session::handshake(&params, device, &log) {
        Ok(e) => e,
        Err(e) => {
            inner.set_state(State::Failed);
            inner.log(LOG_ERROR, &format!("handshake failed: {e}"));
            on_ready(Err(e.to_string()));
            return;
        }
    };
    *inner.token.lock().unwrap() = est.session.session_token.clone();
    inner.trust_level.store(est.session.trust_level, Relaxed);
    inner.attest_flags.store(est.session.attest_flags, Relaxed);
    inner.set_state(State::Active);
    inner.log(LOG_INFO, &format!(
        "session established in {} ms (TPM evidence {} ms): trust_level {} attest_flags {:#x} [{}]; heartbeat every ~{:?}, deadline {:?}",
        est.handshake_ms, est.tpm_ms, est.session.trust_level, est.session.attest_flags,
        sn_crypto::trust::flag_names(est.session.attest_flags).join(","), est.heartbeat_interval, est.heartbeat_timeout));
    for n in &est.session.notes {
        inner.log(LOG_INFO, &format!("gateway note: {n}"));
    }
    on_ready(Ok(SessionReady { trust_level: est.session.trust_level, attest_flags: est.session.attest_flags, notes: est.session.notes.clone() }));

    est.ws.get_mut().set_read_timeout(Some(Duration::from_millis(50))).ok();
    let mut rng = (Instant::now().elapsed().as_nanos() as u64) ^ 0x9e37_79b9_7f4a_7c15 ^ std::process::id() as u64;
    let mut next_hb = Instant::now() + jitter(est.heartbeat_interval, &mut rng);
    let mut suppressed_logged = false;
    loop {
        if inner.stop.load(Relaxed) {
            let _ = est.ws.close(None);
            let _ = est.ws.flush();
            inner.set_state(State::Disconnected);
            return;
        }
        let now = Instant::now();
        if now >= next_hb || inner.heartbeat_now.swap(false, Relaxed) {
            next_hb = now + jitter(est.heartbeat_interval, &mut rng);
            if inner.suppress_heartbeats.load(Relaxed) {
                if !suppressed_logged {
                    inner.log(LOG_WARN, "heartbeats suppressed (test hook)");
                    suppressed_logged = true;
                }
            } else {
                let hb = heartbeat(inner);
                if let Err(e) = session::send_heartbeat(&mut est.ws, &mut est.chan, hb) {
                    inner.log(LOG_WARN, &format!("heartbeat send failed: {e}"));
                    inner.set_state(State::Disconnected);
                    return;
                }
                inner.heartbeats_sent.fetch_add(1, Relaxed);
            }
        }
        match est.ws.read() {
            Ok(WsMessage::Binary(b)) => match session::open_server_msg(&mut est.chan, &b) {
                Ok(m) => match m.body {
                    Some(pb::server_msg::Body::HeartbeatAck(ack)) => {
                        inner.heartbeats_acked.fetch_add(1, Relaxed);
                        *inner.last_ack.lock().unwrap() = Some(Instant::now());
                        if !ack.renewed_token.is_empty() {
                            *inner.token.lock().unwrap() = ack.renewed_token;
                            inner.log(LOG_INFO, "session token renewed");
                        }
                    }
                    Some(pb::server_msg::Body::Kicked(k)) => {
                        inner.set_state(State::Kicked);
                        inner.log(LOG_WARN, &format!("gateway ended the session: {}", k.reason));
                        if let Some(cb) = inner.kick_cb.lock().unwrap().as_ref() {
                            cb(&k.reason);
                        }
                        return;
                    }
                    Some(pb::server_msg::Body::Error(e)) => inner.log(LOG_WARN, &format!("gateway error {}: {}", e.code, e.message)),
                    _ => {}
                },
                Err(e) => {
                    inner.log(LOG_ERROR, &format!("bad frame from gateway: {e}"));
                    inner.set_state(State::Disconnected);
                    return;
                }
            },
            Ok(WsMessage::Close(f)) => {
                inner.log(LOG_WARN, &format!("gateway closed the connection: {}", f.map(|f| f.reason.to_string()).unwrap_or_default()));
                inner.set_state(State::Disconnected);
                return;
            }
            Ok(_) => {}
            Err(e) if session::is_timeout(&e) => {}
            Err(e) => {
                inner.log(LOG_WARN, &format!("connection lost: {e}"));
                inner.set_state(State::Disconnected);
                return;
            }
        }
    }
}

/// Windows build number (`CurrentBuildNumber`), for the Hello environment report.
pub fn os_build() -> String {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    let w = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (key, val) = (w(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"), w("CurrentBuildNumber"));
    let mut buf = [0u16; 32];
    let mut size = (buf.len() * 2) as u32;
    let rc = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), val.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut size)
    };
    if rc != 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..(size as usize / 2).saturating_sub(1)])
}
