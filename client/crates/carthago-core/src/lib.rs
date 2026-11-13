//! Client SDK runtime behind `carthago_sentinel.dll` (plan §3.1): one SDK thread owns the device
//! identity and the gateway session (handshake, heartbeats), the budgeted scan scheduler runs
//! on its own worker, and the game thread only calls [`Runtime::tick`].

pub mod device;
pub mod notice;
pub mod session;

use std::collections::VecDeque;
use std::net::{Shutdown, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering::Relaxed};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use carthago_crypto::VerifyingKey;
use carthago_proto::v1 as pb;
use carthago_sched::{Activity, Scheduler};
use tungstenite::Message as WsMessage;

use device::DeviceIdentity;
pub use notice::Notice;

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
    /// Pinned gateway TLS keys (SHA-256 of the SPKI); required for a wss:// gateway_url.
    pub tls_pins: Vec<carthago_net::Pin>,
    pub allow_tpm: bool,
    pub log: Option<LogFn>,
    /// Process mitigation profile applied at init (plan §6.3).
    pub mitigations: MitigationProfile,
    /// Low-level mouse hook for injected-input statistics (plan §6.1).
    pub input_monitor: bool,
    /// Scan jobs to run instead of the in-process Phase 1 set. `None` for a game that links
    /// the SDK; a companion beside a game passes `carthago_scan::external::jobs`.
    pub jobs: Option<JobFactory>,
}

/// Builds the scheduler's job set on the SDK thread.
pub type JobFactory = Box<dyn FnOnce() -> Vec<Box<dyn carthago_sched::Job>> + Send + Sync>;

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
pub type KickFn = Arc<dyn Fn(&str) + Send + Sync>;

/// Everything behind these locks stays valid if a thread panicked while holding one, so a
/// poisoned lock is taken over instead of spreading the panic to the game's threads.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `None` only while another thread holds the lock.
fn try_lock<T>(m: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match m.try_lock() {
        Ok(g) => Some(g),
        Err(TryLockError::Poisoned(e)) => Some(e.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}

/// The session callback, called exactly once: with the outcome, or with an error if the
/// request is dropped unanswered (shutdown, or a panic on the SDK thread), so the game is
/// never left waiting for it.
struct Ready(Option<ReadyFn>);

impl Ready {
    fn call(&mut self, r: Result<SessionReady, String>) {
        if let Some(f) = self.0.take() {
            f(r);
        }
    }
}

impl Drop for Ready {
    fn drop(&mut self) {
        self.call(Err("session request abandoned".into()));
    }
}

pub type NoticeFn = Box<dyn Fn(&Notice) + Send>;

/// Notices kept for [`Runtime::poll_notice`]; the gateway sends one per category.
const NOTICE_QUEUE: usize = 8;

enum Cmd {
    Begin { player_id_hash: String, on_ready: Ready },
}

struct Inner {
    cfg: Config,
    jobs: Mutex<Option<JobFactory>>,
    session_id: Mutex<String>,
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
    /// The socket of the session in progress; shutdown closes it to end a blocked read.
    conn: Mutex<Option<TcpStream>>,
    notice_cb: Mutex<Option<NoticeFn>>,
    notices: Mutex<VecDeque<Notice>>,
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
    pub fn start(mut cfg: Config) -> std::io::Result<Self> {
        let jobs = cfg.jobs.take();
        let inner = Arc::new(Inner {
            cfg,
            jobs: Mutex::new(jobs),
            session_id: Mutex::new(String::new()),
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
            conn: Mutex::new(None),
            notice_cb: Mutex::new(None),
            notices: Mutex::new(VecDeque::new()),
            startup_findings: Mutex::new(Vec::new()),
            #[cfg(windows)]
            input: Mutex::new(None),
        });
        let (tx, rx) = channel();
        let i = inner.clone();
        let thread = std::thread::Builder::new().name("carthago-sdk".into()).spawn(move || sdk_thread(i, rx))?;
        Ok(Self { inner, cmd: Mutex::new(Some(tx)), thread: Mutex::new(Some(thread)) })
    }

    pub fn begin_session(&self, player_id_hash: String, on_ready: ReadyFn) -> bool {
        match lock(&self.cmd).as_ref() {
            Some(tx) => match tx.send(Cmd::Begin { player_id_hash, on_ready: Ready(Some(on_ready)) }) {
                Ok(()) => true,
                // Not accepted: the caller learns it from the return value, not the callback.
                Err(e) => {
                    let Cmd::Begin { mut on_ready, .. } = e.0;
                    on_ready.0.take();
                    false
                }
            },
            None => false,
        }
    }

    /// Per-frame call: a counter and a non-blocking scheduler tick (skipped, never waited
    /// for, if the SDK thread is collecting heartbeat data at that instant).
    #[inline]
    pub fn tick(&self) {
        self.inner.frames.fetch_add(1, Relaxed);
        if let Some(mut g) = try_lock(&self.inner.sched) {
            if let Some(s) = g.as_mut() {
                s.tick();
            }
        }
    }

    pub fn set_activity(&self, a: Activity) {
        self.inner.activity.store(a as u8, Relaxed);
        if let Some(s) = lock(&self.inner.sched).as_ref() {
            s.set_activity(a);
        }
    }

    pub fn token(&self) -> Option<String> {
        let t = lock(&self.inner.token);
        (!t.is_empty()).then(|| t.clone())
    }

    /// Hex id of the established session, as a game server names it when it binds a match
    /// slot to this client.
    pub fn session_id(&self) -> Option<String> {
        let t = lock(&self.inner.session_id);
        (!t.is_empty()).then(|| t.clone())
    }

    pub fn status(&self) -> Status {
        let i = &self.inner;
        let (cpu, slices) = try_lock(&i.sched).and_then(|g| g.as_ref().map(|s| s.stats())).map_or((0, 0), |s| (s.worker_cpu_ns, s.slices));
        Status {
            state: i.state.load(Relaxed),
            trust_level: i.trust_level.load(Relaxed),
            attest_flags: i.attest_flags.load(Relaxed),
            heartbeats_sent: i.heartbeats_sent.load(Relaxed),
            heartbeats_acked: i.heartbeats_acked.load(Relaxed),
            last_ack_age_ms: lock(&i.last_ack).map_or(u64::MAX, |t| t.elapsed().as_millis() as u64),
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
        *lock(&self.inner.kick_cb) = cb;
    }

    /// Called on the SDK thread when the gateway reports that this session was flagged. The
    /// notice has been verified against the pinned server identity key and is about this
    /// session. It is information for the game's own screen; nothing else changes.
    pub fn set_notice_callback(&self, cb: Option<NoticeFn>) {
        *lock(&self.inner.notice_cb) = cb;
    }

    /// The oldest notice not yet taken, for a game that polls from its own thread instead
    /// of using the callback. Notices are queued whether or not a callback is set.
    pub fn poll_notice(&self) -> Option<Notice> {
        lock(&self.inner.notices).pop_front()
    }

    /// Safe to call from any thread, including from a session or kick callback (which run
    /// on the SDK thread), and more than once.
    pub fn shutdown(&self) {
        self.inner.stop.store(true, Relaxed);
        lock(&self.cmd).take();
        // A handshake waiting on a silent gateway would otherwise hold the join below for
        // the socket timeout (30 s per read).
        if let Some(c) = lock(&self.inner.conn).take() {
            let _ = c.shutdown(Shutdown::Both);
        }
        if let Some(t) = lock(&self.thread).take() {
            // Called from a callback: the SDK thread cannot wait for itself. It ends on its
            // own once the callback returns, because `stop` is set.
            if t.thread().id() != std::thread::current().id() {
                let _ = t.join();
            }
        }
        let sched = lock(&self.inner.sched).take();
        if let Some(s) = sched {
            let _ = s.stop();
        }
        #[cfg(windows)]
        {
            let input = lock(&self.inner.input).take();
            if let Some(mut m) = input {
                m.stop();
            }
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn sched_config() -> carthago_sched::Config {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    carthago_sched::Config {
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
    lock(&inner.startup_findings).push(pb::Finding {
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
        Ok(m) => *lock(&inner.input) = Some(m),
        Err(e) => inner.log(LOG_WARN, &format!("input monitor not started: {e}")),
    }
}

fn sdk_thread(inner: Arc<Inner>, rx: Receiver<Cmd>) {
    let t0 = Instant::now();
    harden(&inner);
    let jobs = match lock(&inner.jobs).take() {
        Some(custom) => custom(),
        None => carthago_scan::phase1_jobs(Arc::new(carthago_scan::detect_dirs())),
    };
    match Scheduler::start(sched_config(), jobs) {
        Ok(s) => {
            s.set_activity(Activity::from_u8(inner.activity.load(Relaxed)));
            *lock(&inner.sched) = Some(s);
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
            Cmd::Begin { player_id_hash, mut on_ready } => match &device {
                Some(d) => {
                    // A panic in one session must not end the SDK thread: later sessions
                    // would then be refused for the rest of the process.
                    if catch_unwind(AssertUnwindSafe(|| run_session(&inner, d, player_id_hash, &mut on_ready))).is_err() {
                        inner.set_state(State::Failed);
                        inner.log(LOG_ERROR, "session ended by an internal error");
                    }
                    lock(&inner.conn).take();
                }
                None => on_ready.call(Err("no device identity".into())),
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
    hb.findings.append(&mut lock(&inner.startup_findings));
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut input_cpu_ns = 0;
    #[cfg(windows)]
    if inner.cfg.input_monitor {
        let c = carthago_scan::input::counters();
        hb.input = Some(pb::InputStats { mouse_events: c.mouse_events, injected: c.injected, lower_il_injected: c.lower_il_injected, focused_ms: c.focused_ms });
        input_cpu_ns = carthago_scan::input::thread_cpu_ns();
    }
    if let Some(s) = lock(&inner.sched).as_mut() {
        let room = HEARTBEAT_FINDINGS.saturating_sub(hb.findings.len());
        let mut taken = s.take_findings();
        hb.findings.extend(
            taken
                .by_ref()
                .take(room)
                .map(|f| pb::Finding { job: f.job.into(), code: f.code, a: f.a, b: f.b, detail: f.detail.as_str().into() }),
        );
        let rest: Vec<carthago_sched::Finding> = taken.collect();
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

/// Tells the game its session was ended. The callback is called without the lock held, so
/// it may replace or clear itself, or shut the SDK down.
fn notify_kick(inner: &Inner, reason: &str) {
    let cb = lock(&inner.kick_cb).clone();
    if let Some(cb) = cb {
        cb(reason);
    }
}

fn run_session(inner: &Inner, device: &DeviceIdentity, player_id_hash: String, on_ready: &mut Ready) {
    inner.set_state(State::Connecting);
    let params = session::Params {
        gateway_url: inner.cfg.gateway_url.clone(),
        tenant_id: inner.cfg.tenant_id.clone(),
        build_id: inner.cfg.build_id.clone(),
        player_id_hash,
        server_identity: inner.cfg.server_identity,
        tls_pins: inner.cfg.tls_pins.clone(),
    };
    let log = |l: u8, m: &str| inner.log(l, m);
    let on_tcp = |tcp: &TcpStream| {
        *lock(&inner.conn) = tcp.try_clone().ok();
        if inner.stop.load(Relaxed) {
            let _ = tcp.shutdown(Shutdown::Both);
        }
    };
    let mut est = match session::handshake(&params, device, &log, &on_tcp) {
        Ok(e) => e,
        Err(e) => {
            inner.set_state(State::Failed);
            inner.log(LOG_ERROR, &format!("handshake failed: {e}"));
            on_ready.call(Err(e.to_string()));
            return;
        }
    };
    *lock(&inner.token) = est.session.session_token.clone();
    *lock(&inner.session_id) = est.chan.session_id().iter().map(|b| format!("{b:02x}")).collect();
    inner.trust_level.store(est.session.trust_level, Relaxed);
    inner.attest_flags.store(est.session.attest_flags, Relaxed);
    inner.set_state(State::Active);
    inner.log(LOG_INFO, &format!(
        "session established in {} ms (TPM evidence {} ms): trust_level {} attest_flags {:#x} [{}]; heartbeat every ~{:?}, deadline {:?}",
        est.handshake_ms, est.tpm_ms, est.session.trust_level, est.session.attest_flags,
        carthago_crypto::trust::flag_names(est.session.attest_flags).join(","), est.heartbeat_interval, est.heartbeat_timeout));
    for n in &est.session.notes {
        inner.log(LOG_INFO, &format!("gateway note: {n}"));
    }
    on_ready.call(Ok(SessionReady { trust_level: est.session.trust_level, attest_flags: est.session.attest_flags, notes: est.session.notes.clone() }));

    est.ws.get_ref().set_read_timeout(Some(Duration::from_millis(50))).ok();
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
                        *lock(&inner.last_ack) = Some(Instant::now());
                        if !ack.renewed_token.is_empty() {
                            *lock(&inner.token) = ack.renewed_token;
                            inner.log(LOG_INFO, "session token renewed");
                        }
                    }
                    Some(pb::server_msg::Body::Kicked(k)) => {
                        inner.set_state(State::Kicked);
                        inner.log(LOG_WARN, &format!("gateway ended the session: {}", k.reason));
                        notify_kick(inner, &k.reason);
                        return;
                    }
                    Some(pb::server_msg::Body::EnforcementNotice(n)) => accept_notice(inner, &n, est.chan.session_id()),
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

/// Verifies a notice from the gateway, queues it and tells the game. A notice that does not
/// verify, or is about another session, is dropped.
fn accept_notice(inner: &Inner, n: &pb::EnforcementNotice, session_id: &[u8]) {
    let notice = match Notice::verify_for_session(&inner.cfg.server_identity, n, session_id) {
        Ok(notice) => notice,
        Err(e) => {
            inner.log(LOG_WARN, &format!("ignoring a notice from the gateway: {e}"));
            return;
        }
    };
    inner.log(LOG_WARN, &format!("gateway notice {}: session flagged, category {} severity {}", notice.notice_id_hex(), notice.category_name(), notice.severity_name()));
    {
        let mut q = lock(&inner.notices);
        if q.len() == NOTICE_QUEUE {
            q.pop_front();
        }
        q.push_back(notice.clone());
    }
    if let Some(cb) = lock(&inner.notice_cb).as_ref() {
        cb(&notice);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::mpsc::RecvTimeoutError;

    fn runtime(gateway_url: String) -> Arc<Runtime> {
        let key = hex::decode("290184ec194e65f6578796e87f8cd2c3beaa96857a0d883c19ee85b71781a548").unwrap();
        Arc::new(
            Runtime::start(Config {
                tenant_id: "demo".into(),
                build_id: "test".into(),
                gateway_url,
                server_identity: VerifyingKey::from_bytes(&key.try_into().unwrap()).unwrap(),
                tls_pins: Vec::new(),
                allow_tpm: false,
                log: None,
                mitigations: MitigationProfile::Off,
                input_monitor: false,
                jobs: None,
            })
            .unwrap(),
        )
    }

    /// Runs `f` on its own thread and fails the test if it has not returned in time (a
    /// deadlock would otherwise hang the whole test run).
    fn within<T: Send + 'static>(limit: Duration, what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = channel();
        std::thread::spawn(move || tx.send(f()));
        match rx.recv_timeout(limit) {
            Ok(v) => v,
            Err(RecvTimeoutError::Timeout) => panic!("{what}: still blocked after {limit:?}"),
            Err(RecvTimeoutError::Disconnected) => panic!("{what}: panicked"),
        }
    }

    #[test]
    fn shutdown_does_not_wait_for_a_silent_gateway() {
        // Accepts the connection and never answers the WebSocket upgrade.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted_tx, accepted) = channel();
        std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            accepted_tx.send(()).unwrap();
            let mut buf = [0u8; 4096];
            while c.read(&mut buf).is_ok_and(|n| n > 0) {}
        });
        let rt = runtime(format!("ws://127.0.0.1:{port}/v1/client"));
        let (ready_tx, ready) = channel();
        assert!(rt.begin_session("player".into(), Box::new(move |r| ready_tx.send(r.map(|_| ())).unwrap())));
        accepted.recv_timeout(Duration::from_secs(20)).expect("the client never connected");
        std::thread::sleep(Duration::from_millis(200));

        let t = Instant::now();
        let rt2 = rt.clone();
        within(Duration::from_secs(10), "shutdown during a handshake", move || rt2.shutdown());
        assert!(t.elapsed() < Duration::from_secs(5), "shutdown took {:?}", t.elapsed());
        assert!(ready.recv_timeout(Duration::from_secs(1)).expect("on_ready was never called").is_err());
        assert_eq!(rt.status().state, State::Failed as u32);
    }

    #[test]
    fn a_session_callback_may_shut_the_sdk_down() {
        // Nothing listens on this port: the handshake fails and on_ready runs on the SDK thread.
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let rt = runtime(format!("ws://127.0.0.1:{port}/v1/client"));
        let (done_tx, done) = channel();
        let rt2 = rt.clone();
        assert!(rt.begin_session(
            "player".into(),
            Box::new(move |r| {
                assert!(r.is_err());
                rt2.shutdown();
                done_tx.send(()).unwrap();
            }),
        ));
        done.recv_timeout(Duration::from_secs(30)).expect("shutdown from the session callback did not return");
        assert!(!rt.begin_session("player".into(), Box::new(|_| {})), "a session was accepted after shutdown");
        within(Duration::from_secs(10), "second shutdown", move || rt.shutdown());
    }

    #[test]
    fn the_kick_callback_runs_without_the_lock() {
        let rt = runtime("ws://127.0.0.1:1/v1/client".into());
        let (tx, rx) = channel();
        let rt2 = rt.clone();
        rt.set_kick_callback(Some(Arc::new(move |reason: &str| {
            rt2.set_kick_callback(None);
            tx.send(reason.to_owned()).unwrap();
        })));
        let rt2 = rt.clone();
        within(Duration::from_secs(10), "kick callback that clears itself", move || notify_kick(&rt2.inner, "integrity"));
        assert_eq!(rx.try_recv().unwrap(), "integrity");
        notify_kick(&rt.inner, "again");
        assert!(rx.try_recv().is_err(), "the cleared callback was called again");
        rt.shutdown();
    }

    #[test]
    fn a_dropped_session_request_reports_an_error() {
        let (tx, rx) = channel();
        drop(Ready(Some(Box::new(move |r| tx.send(r.map(|_| ())).unwrap()))));
        assert!(rx.try_recv().unwrap().is_err());

        let (tx, rx) = channel();
        let mut r = Ready(Some(Box::new(move |r| tx.send(r.map(|_| ())).unwrap())));
        r.call(Ok(SessionReady { trust_level: 1, attest_flags: 0, notes: Vec::new() }));
        drop(r);
        assert!(rx.try_recv().unwrap().is_ok());
        assert!(rx.try_recv().is_err(), "the callback ran twice");
    }

    #[test]
    fn a_poisoned_lock_does_not_panic_the_game_thread() {
        let rt = runtime("ws://127.0.0.1:1/v1/client".into());
        let rt2 = rt.clone();
        let _ = std::thread::spawn(move || {
            let _sched = rt2.inner.sched.lock().unwrap();
            let _token = rt2.inner.token.lock().unwrap();
            let _ack = rt2.inner.last_ack.lock().unwrap();
            let _cb = rt2.inner.kick_cb.lock().unwrap();
            panic!("synthetic panic while holding the runtime's locks");
        })
        .join();
        assert!(rt.inner.sched.is_poisoned() && rt.inner.token.is_poisoned());
        rt.tick();
        rt.set_activity(Activity::Gameplay);
        assert_eq!(rt.token(), None);
        assert_eq!(rt.status().last_ack_age_ms, u64::MAX);
        rt.set_kick_callback(None);
        let _ = heartbeat(&rt.inner);
        rt.shutdown();
    }
}
