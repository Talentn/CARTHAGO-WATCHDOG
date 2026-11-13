//! `carthago_sentinel.dll` C ABI (plan §3.1). The header is `sdk/native/include/carthago_sentinel.h`.
//! Every export catches panics; no Rust ownership crosses the boundary; callbacks run on
//! SDK-owned threads.

use std::ffi::{c_char, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};

use carthago_core::{Config, Runtime};
use carthago_crypto::VerifyingKey;
use carthago_sched::Activity;

pub const CARTHAGO_ABI_VERSION: u32 = 1;

pub const CARTHAGO_OK: i32 = 0;
pub const CARTHAGO_ERR_INVALID_ARG: i32 = 1;
pub const CARTHAGO_ERR_NOT_INITIALIZED: i32 = 2;
pub const CARTHAGO_ERR_ALREADY_INITIALIZED: i32 = 3;
pub const CARTHAGO_ERR_BUFFER_TOO_SMALL: i32 = 4;
pub const CARTHAGO_ERR_NO_SESSION: i32 = 5;
pub const CARTHAGO_ERR_ABI_MISMATCH: i32 = 6;
pub const CARTHAGO_ERR_SESSION_FAILED: i32 = 7;
pub const CARTHAGO_ERR_NO_NOTICE: i32 = 8;
pub const CARTHAGO_ERR_INTERNAL: i32 = 99;

pub const CARTHAGO_FLAG_NO_TPM: u32 = 1;
pub const CARTHAGO_FLAG_NO_MITIGATIONS: u32 = 2;
pub const CARTHAGO_FLAG_STRICT_MITIGATIONS: u32 = 4;
pub const CARTHAGO_FLAG_NO_INPUT_MONITOR: u32 = 8;

fn mitigation_profile(flags: u32) -> carthago_core::MitigationProfile {
    use carthago_core::MitigationProfile as P;
    if flags & CARTHAGO_FLAG_NO_MITIGATIONS != 0 {
        P::Off
    } else if flags & CARTHAGO_FLAG_STRICT_MITIGATIONS != 0 {
        P::Strict
    } else {
        P::Basic
    }
}

pub type CarthagoLogFn = unsafe extern "C" fn(level: i32, msg: *const c_char, user: *mut c_void);
pub type CarthagoSessionCb = unsafe extern "C" fn(result: i32, trust_level: u32, attest_flags: u64, user: *mut c_void);
pub type CarthagoKickCb = unsafe extern "C" fn(reason: *const c_char, user: *mut c_void);
pub type CarthagoNoticeCb = unsafe extern "C" fn(notice: *const CarthagoNotice, user: *mut c_void);

pub const CARTHAGO_NOTICE_TEST: u32 = carthago_core::notice::CATEGORY_TEST;
pub const CARTHAGO_NOTICE_GAME_INTEGRITY: u32 = carthago_core::notice::CATEGORY_GAME_INTEGRITY;
pub const CARTHAGO_NOTICE_DEBUGGER: u32 = carthago_core::notice::CATEGORY_DEBUGGER;
pub const CARTHAGO_NOTICE_TIME_MANIPULATION: u32 = carthago_core::notice::CATEGORY_TIME_MANIPULATION;
pub const CARTHAGO_NOTICE_AIM_ASSISTANCE: u32 = carthago_core::notice::CATEGORY_AIM_ASSISTANCE;

pub const CARTHAGO_NOTICE_SEVERITY_NOTICE: u32 = carthago_core::notice::SEVERITY_NOTICE;
pub const CARTHAGO_NOTICE_SEVERITY_HIGH: u32 = carthago_core::notice::SEVERITY_HIGH;
pub const CARTHAGO_NOTICE_SEVERITY_CRITICAL: u32 = carthago_core::notice::SEVERITY_CRITICAL;

/// The gateway's notice that this session was flagged: a category and a severity for the
/// game's own screen. The SDK has verified its signature and that it is about this session.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct CarthagoNotice {
    pub struct_size: u32,
    /// `CARTHAGO_NOTICE_*`; treat unknown values as "flagged".
    pub category: u32,
    /// `CARTHAGO_NOTICE_SEVERITY_*`.
    pub severity: u32,
    pub reserved: u32,
    pub issued_at_ms: u64,
    pub notice_id: [u8; 16],
    pub session_id: [u8; 16],
}

fn c_notice(n: &carthago_core::Notice) -> CarthagoNotice {
    CarthagoNotice {
        struct_size: size_of::<CarthagoNotice>() as u32,
        category: n.category,
        severity: n.severity,
        reserved: 0,
        issued_at_ms: n.issued_at_ms,
        notice_id: n.notice_id,
        session_id: n.session_id,
    }
}

/// The notice `carthago_poll_notice` reported as too large for the caller's buffer; it is
/// handed out again on the next call.
static HELD_NOTICE: std::sync::Mutex<Option<carthago_core::Notice>> = std::sync::Mutex::new(None);

#[repr(C)]
pub struct CarthagoConfig {
    pub abi_version: u32,
    pub struct_size: u32,
    pub tenant_id: *const c_char,
    pub build_id: *const c_char,
    pub gateway_url: *const c_char,
    /// Hex Ed25519 public key of the gateway identity (pinned).
    pub server_identity_key_hex: *const c_char,
    pub log: Option<CarthagoLogFn>,
    pub log_user: *mut c_void,
    pub flags: u32,
    /// Comma-separated hex SHA-256 SPKI pins of the gateway TLS key (current, backup);
    /// required for a wss:// `gateway_url`. Callers built before this field existed pass a
    /// smaller `struct_size` and are limited to ws:// on loopback.
    pub tls_pins_hex: *const c_char,
}

/// The smallest `CarthagoConfig` accepted: the layout before `tls_pins_hex` was added.
const CARTHAGO_CONFIG_MIN_SIZE: usize = std::mem::offset_of!(CarthagoConfig, tls_pins_hex);

#[repr(C)]
#[derive(Default)]
pub struct CarthagoStatus {
    pub struct_size: u32,
    pub state: u32,
    pub trust_level: u32,
    pub reserved: u32,
    pub attest_flags: u64,
    pub heartbeats_sent: u64,
    pub heartbeats_acked: u64,
    pub last_ack_age_ms: u64,
    pub sched_worker_cpu_ns: u64,
    pub sched_slices: u64,
    pub frames: u64,
}

#[derive(Clone, Copy)]
struct UserPtr(*mut c_void);
// SAFETY: opaque user pointers are only handed back to the caller's own callbacks.
unsafe impl Send for UserPtr {}
unsafe impl Sync for UserPtr {}

static RT: RwLock<Option<Arc<Runtime>>> = RwLock::new(None);

fn guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}

unsafe fn str_arg(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok().map(str::to_owned)
}

fn runtime() -> Option<Arc<Runtime>> {
    RT.read().ok()?.clone()
}

/// # Safety
/// `cfg` must point to a valid `CarthagoConfig` whose strings are NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn carthago_init(cfg: *const CarthagoConfig) -> i32 {
    guard(CARTHAGO_ERR_INTERNAL, || {
        let Some(cfg) = (unsafe { cfg.as_ref() }) else { return CARTHAGO_ERR_INVALID_ARG };
        if cfg.abi_version != CARTHAGO_ABI_VERSION || (cfg.struct_size as usize) < CARTHAGO_CONFIG_MIN_SIZE {
            return CARTHAGO_ERR_ABI_MISMATCH;
        }
        let pins_hex = if (cfg.struct_size as usize) >= size_of::<CarthagoConfig>() { unsafe { str_arg(cfg.tls_pins_hex) } } else { None };
        let Ok(tls_pins) = carthago_net::parse_pins(pins_hex.as_deref().unwrap_or("")) else { return CARTHAGO_ERR_INVALID_ARG };
        let (Some(tenant_id), Some(build_id), Some(gateway_url), Some(key_hex)) = (unsafe {
            (str_arg(cfg.tenant_id), str_arg(cfg.build_id), str_arg(cfg.gateway_url), str_arg(cfg.server_identity_key_hex))
        }) else {
            return CARTHAGO_ERR_INVALID_ARG;
        };
        let Some(server_identity) = hex::decode(key_hex.trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        else {
            return CARTHAGO_ERR_INVALID_ARG;
        };
        let mut slot = RT.write().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return CARTHAGO_ERR_ALREADY_INITIALIZED;
        }
        let log = cfg.log.map(|f| {
            let user = UserPtr(cfg.log_user);
            Arc::new(move |level: u8, msg: &str| {
                let user = user;
                if let Ok(c) = CString::new(msg.replace('\0', " ")) {
                    unsafe { f(level as i32, c.as_ptr(), user.0) };
                }
            }) as carthago_core::LogFn
        });
        let config = Config {
            tenant_id,
            build_id,
            gateway_url,
            server_identity,
            tls_pins,
            allow_tpm: cfg.flags & CARTHAGO_FLAG_NO_TPM == 0,
            log,
            mitigations: mitigation_profile(cfg.flags),
            input_monitor: cfg.flags & CARTHAGO_FLAG_NO_INPUT_MONITOR == 0,
            jobs: None,
        };
        match Runtime::start(config) {
            Ok(rt) => {
                *slot = Some(Arc::new(rt));
                CARTHAGO_OK
            }
            Err(_) => CARTHAGO_ERR_INTERNAL,
        }
    })
}

/// Starts the handshake on the SDK thread; `on_ready` runs there when it completes.
///
/// # Safety
/// `player_id_hash` must be a NUL-terminated string (the studio's HMAC of the platform id).
#[no_mangle]
pub unsafe extern "C" fn carthago_begin_session(player_id_hash: *const c_char, on_ready: Option<CarthagoSessionCb>, user: *mut c_void) -> i32 {
    guard(CARTHAGO_ERR_INTERNAL, || {
        let Some(player) = (unsafe { str_arg(player_id_hash) }).filter(|p| !p.is_empty()) else { return CARTHAGO_ERR_INVALID_ARG };
        let Some(rt) = runtime() else { return CARTHAGO_ERR_NOT_INITIALIZED };
        let user = UserPtr(user);
        let ok = rt.begin_session(
            player,
            Box::new(move |r| {
                let user = user;
                if let Some(cb) = on_ready {
                    match r {
                        Ok(s) => unsafe { cb(CARTHAGO_OK, s.trust_level, s.attest_flags, user.0) },
                        Err(_) => unsafe { cb(CARTHAGO_ERR_SESSION_FAILED, 0, 0, user.0) },
                    }
                }
            }),
        );
        if ok {
            CARTHAGO_OK
        } else {
            CARTHAGO_ERR_NOT_INITIALIZED
        }
    })
}

/// Copies the current session token (NUL-terminated). On `CARTHAGO_ERR_BUFFER_TOO_SMALL`, `*len`
/// is set to the required size including the NUL.
///
/// # Safety
/// `len` must be valid; `buf` must have room for `*len` bytes (or be null to query the size).
#[no_mangle]
pub unsafe extern "C" fn carthago_get_session_token(buf: *mut c_char, len: *mut usize) -> i32 {
    guard(CARTHAGO_ERR_INTERNAL, || {
        let Some(len) = (unsafe { len.as_mut() }) else { return CARTHAGO_ERR_INVALID_ARG };
        let Some(rt) = runtime() else { return CARTHAGO_ERR_NOT_INITIALIZED };
        let Some(tok) = rt.token() else { return CARTHAGO_ERR_NO_SESSION };
        let need = tok.len() + 1;
        if buf.is_null() || *len < need {
            *len = need;
            return CARTHAGO_ERR_BUFFER_TOO_SMALL;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(tok.as_ptr(), buf.cast::<u8>(), tok.len());
            *buf.add(tok.len()) = 0;
        }
        *len = tok.len();
        CARTHAGO_OK
    })
}

/// Per-frame call from the game thread. Never blocks and never scans on the caller.
#[no_mangle]
pub extern "C" fn carthago_tick() {
    guard((), || {
        if let Ok(g) = RT.try_read() {
            if let Some(rt) = g.as_ref() {
                rt.tick();
            }
        }
    })
}

/// 0 MENU, 1 LOADING, 2 IN_MATCH, 3 IN_COMBAT.
#[no_mangle]
pub extern "C" fn carthago_set_activity(activity: u32) {
    guard((), || {
        let a = match activity {
            0 => Activity::Menu,
            1 => Activity::Loading,
            _ => Activity::Gameplay,
        };
        if let Some(rt) = runtime() {
            rt.set_activity(a);
        }
    })
}

/// Requests an immediate heartbeat (heartbeats are otherwise automatic and jittered).
#[no_mangle]
pub extern "C" fn carthago_heartbeat_now() -> i32 {
    guard(CARTHAGO_ERR_INTERNAL, || match runtime() {
        Some(rt) => {
            rt.heartbeat_now();
            CARTHAGO_OK
        }
        None => CARTHAGO_ERR_NOT_INITIALIZED,
    })
}

/// # Safety
/// `out` must point to an `CarthagoStatus` with `struct_size` set.
#[no_mangle]
pub unsafe extern "C" fn carthago_get_status(out: *mut CarthagoStatus) -> i32 {
    guard(CARTHAGO_ERR_INTERNAL, || {
        let Some(out) = (unsafe { out.as_mut() }) else { return CARTHAGO_ERR_INVALID_ARG };
        if (out.struct_size as usize) < size_of::<CarthagoStatus>() {
            return CARTHAGO_ERR_ABI_MISMATCH;
        }
        let Some(rt) = runtime() else { return CARTHAGO_ERR_NOT_INITIALIZED };
        let s = rt.status();
        *out = CarthagoStatus {
            struct_size: size_of::<CarthagoStatus>() as u32,
            state: s.state,
            trust_level: s.trust_level,
            reserved: 0,
            attest_flags: s.attest_flags,
            heartbeats_sent: s.heartbeats_sent,
            heartbeats_acked: s.heartbeats_acked,
            last_ack_age_ms: s.last_ack_age_ms,
            sched_worker_cpu_ns: s.sched_worker_cpu_ns,
            sched_slices: s.sched_slices,
            frames: s.frames,
        };
        CARTHAGO_OK
    })
}

/// Informational: the gateway ended this client's session. The game server enforces kicks.
#[no_mangle]
pub extern "C" fn carthago_set_kick_callback(cb: Option<CarthagoKickCb>, user: *mut c_void) {
    guard((), || {
        let Some(rt) = runtime() else { return };
        let user = UserPtr(user);
        rt.set_kick_callback(cb.map(|f| {
            Box::new(move |reason: &str| {
                let user = user;
                if let Ok(c) = CString::new(reason) {
                    unsafe { f(c.as_ptr(), user.0) };
                }
            }) as carthago_core::KickFn
        }));
    })
}

/// The gateway flagged this session. `cb` runs on the SDK thread; `notice` is valid for the
/// duration of the call. Nothing else happens: the session stays up and what the game shows
/// or does is its own decision.
#[no_mangle]
pub extern "C" fn carthago_set_notice_callback(cb: Option<CarthagoNoticeCb>, user: *mut c_void) {
    guard((), || {
        let Some(rt) = runtime() else { return };
        let user = UserPtr(user);
        rt.set_notice_callback(cb.map(|f| {
            Box::new(move |n: &carthago_core::Notice| {
                let user = user;
                let c = c_notice(n);
                unsafe { f(&c, user.0) };
            }) as carthago_core::NoticeFn
        }));
    })
}

/// Takes the oldest notice not yet taken: `CARTHAGO_OK` and `*out` filled, or
/// `CARTHAGO_ERR_NO_NOTICE`. For a game that polls from its own thread; notices are queued
/// whether or not a callback is set. `signed`/`signed_len` are optional: when given, the
/// signed notice is copied there for passing on to the game's server (`*signed_len`: in =
/// buffer size, out = length). On `CARTHAGO_ERR_BUFFER_TOO_SMALL`, `*signed_len` is the
/// size needed and the notice is returned again by the next call.
///
/// # Safety
/// `out` must point to a `CarthagoNotice` with `struct_size` set. `signed`, if not null,
/// must have room for `*signed_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn carthago_poll_notice(out: *mut CarthagoNotice, signed: *mut u8, signed_len: *mut usize) -> i32 {
    guard(CARTHAGO_ERR_INTERNAL, || {
        let Some(out) = (unsafe { out.as_mut() }) else { return CARTHAGO_ERR_INVALID_ARG };
        if (out.struct_size as usize) < size_of::<CarthagoNotice>() {
            return CARTHAGO_ERR_ABI_MISMATCH;
        }
        let Some(rt) = runtime() else { return CARTHAGO_ERR_NOT_INITIALIZED };
        let mut held = HELD_NOTICE.lock().unwrap_or_else(|e| e.into_inner());
        let Some(n) = held.take().or_else(|| rt.poll_notice()) else { return CARTHAGO_ERR_NO_NOTICE };
        if let Some(len) = unsafe { signed_len.as_mut() } {
            if signed.is_null() || *len < n.signed.len() {
                *len = n.signed.len();
                *held = Some(n);
                return CARTHAGO_ERR_BUFFER_TOO_SMALL;
            }
            unsafe { std::ptr::copy_nonoverlapping(n.signed.as_ptr(), signed, n.signed.len()) };
            *len = n.signed.len();
        }
        *out = c_notice(&n);
        CARTHAGO_OK
    })
}

#[no_mangle]
pub extern "C" fn carthago_shutdown() {
    guard((), || {
        let rt = RT.write().unwrap_or_else(|e| e.into_inner()).take();
        HELD_NOTICE.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(rt) = rt {
            rt.shutdown();
        }
    })
}

/// Test hook (feature `dev-hooks`): keep the connection but stop heartbeating.
#[cfg(feature = "dev-hooks")]
#[no_mangle]
pub extern "C" fn carthago_dev_suppress_heartbeats(on: i32) {
    guard((), || {
        if let Some(rt) = runtime() {
            rt.suppress_heartbeats(on != 0);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(key: &CStr) -> CarthagoConfig {
        CarthagoConfig {
            abi_version: CARTHAGO_ABI_VERSION,
            struct_size: size_of::<CarthagoConfig>() as u32,
            tenant_id: c"demo".as_ptr(),
            build_id: c"test".as_ptr(),
            gateway_url: c"ws://127.0.0.1:1/v1/client".as_ptr(),
            server_identity_key_hex: key.as_ptr(),
            log: None,
            log_user: std::ptr::null_mut(),
            flags: CARTHAGO_FLAG_NO_TPM,
            tls_pins_hex: std::ptr::null(),
        }
    }

    #[test]
    fn a_notice_keeps_its_layout_and_values() {
        assert_eq!(size_of::<CarthagoNotice>(), 56);
        assert_eq!(std::mem::offset_of!(CarthagoNotice, issued_at_ms), 16);
        assert_eq!(std::mem::offset_of!(CarthagoNotice, notice_id), 24);
        assert_eq!(std::mem::offset_of!(CarthagoNotice, session_id), 40);
        assert_eq!(
            [CARTHAGO_NOTICE_TEST, CARTHAGO_NOTICE_GAME_INTEGRITY, CARTHAGO_NOTICE_DEBUGGER, CARTHAGO_NOTICE_TIME_MANIPULATION, CARTHAGO_NOTICE_AIM_ASSISTANCE],
            [1, 2, 3, 4, 5]
        );
        assert_eq!([CARTHAGO_NOTICE_SEVERITY_NOTICE, CARTHAGO_NOTICE_SEVERITY_HIGH, CARTHAGO_NOTICE_SEVERITY_CRITICAL], [1, 2, 3]);
        let n = carthago_core::Notice {
            notice_id: [7; 16],
            session_id: [9; 16],
            tenant_id: "demo".into(),
            player_id_hash: "p".into(),
            issued_at_ms: 1_794_225_800_000,
            category: CARTHAGO_NOTICE_AIM_ASSISTANCE,
            severity: CARTHAGO_NOTICE_SEVERITY_HIGH,
            signed: vec![1, 2, 3],
        };
        let c = c_notice(&n);
        assert_eq!((c.struct_size, c.category, c.severity, c.issued_at_ms), (56, 5, 2, 1_794_225_800_000));
        assert_eq!((c.notice_id, c.session_id), ([7; 16], [9; 16]));
    }

    #[test]
    fn rejects_bad_config_and_reports_uninitialized() {
        let good_key = c"290184ec194e65f6578796e87f8cd2c3beaa96857a0d883c19ee85b71781a548";
        unsafe {
            assert_eq!(carthago_init(std::ptr::null()), CARTHAGO_ERR_INVALID_ARG);
            let mut c = cfg(good_key);
            c.abi_version = 2;
            assert_eq!(carthago_init(&c), CARTHAGO_ERR_ABI_MISMATCH);
            let mut c = cfg(good_key);
            c.struct_size = 8;
            assert_eq!(carthago_init(&c), CARTHAGO_ERR_ABI_MISMATCH);
            let mut c = cfg(good_key);
            c.tls_pins_hex = c"not-hex".as_ptr();
            assert_eq!(carthago_init(&c), CARTHAGO_ERR_INVALID_ARG);
            assert_eq!(carthago_init(&cfg(c"zz")), CARTHAGO_ERR_INVALID_ARG);
            let mut c = cfg(good_key);
            c.tenant_id = std::ptr::null();
            assert_eq!(carthago_init(&c), CARTHAGO_ERR_INVALID_ARG);

            let mut len = 0usize;
            assert_eq!(carthago_get_session_token(std::ptr::null_mut(), &mut len), CARTHAGO_ERR_NOT_INITIALIZED);
            assert_eq!(carthago_begin_session(c"p".as_ptr(), None, std::ptr::null_mut()), CARTHAGO_ERR_NOT_INITIALIZED);
            carthago_tick();
            carthago_shutdown();

            assert_eq!(carthago_init(&cfg(good_key)), CARTHAGO_OK);
            assert_eq!(carthago_init(&cfg(good_key)), CARTHAGO_ERR_ALREADY_INITIALIZED);
            assert_eq!(carthago_get_session_token(std::ptr::null_mut(), &mut len), CARTHAGO_ERR_NO_SESSION);
            assert_eq!(carthago_begin_session(c"".as_ptr(), None, std::ptr::null_mut()), CARTHAGO_ERR_INVALID_ARG);
            let mut notice = CarthagoNotice { struct_size: size_of::<CarthagoNotice>() as u32, ..Default::default() };
            assert_eq!(carthago_poll_notice(&mut notice, std::ptr::null_mut(), std::ptr::null_mut()), CARTHAGO_ERR_NO_NOTICE);
            assert_eq!(carthago_poll_notice(std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()), CARTHAGO_ERR_INVALID_ARG);
            notice.struct_size = 8;
            assert_eq!(carthago_poll_notice(&mut notice, std::ptr::null_mut(), std::ptr::null_mut()), CARTHAGO_ERR_ABI_MISMATCH);
            carthago_set_notice_callback(None, std::ptr::null_mut());
            let mut st = CarthagoStatus { struct_size: size_of::<CarthagoStatus>() as u32, ..Default::default() };
            assert_eq!(carthago_get_status(&mut st), CARTHAGO_OK);
            st.struct_size = 4;
            assert_eq!(carthago_get_status(&mut st), CARTHAGO_ERR_ABI_MISMATCH);
            for _ in 0..100 {
                carthago_tick();
            }
            carthago_shutdown();
            assert_eq!(carthago_get_session_token(std::ptr::null_mut(), &mut len), CARTHAGO_ERR_NOT_INITIALIZED);

            // A caller built against the header without tls_pins_hex is still accepted;
            // the garbage past its struct_size is never read.
            let mut c = cfg(good_key);
            c.struct_size = CARTHAGO_CONFIG_MIN_SIZE as u32;
            c.tls_pins_hex = c"not-hex".as_ptr();
            assert_eq!(carthago_init(&c), CARTHAGO_OK);
            carthago_shutdown();
            let mut c = cfg(good_key);
            let pins = CString::new(format!("{},{}", "ab".repeat(32), "cd".repeat(32))).unwrap();
            c.tls_pins_hex = pins.as_ptr();
            assert_eq!(carthago_init(&c), CARTHAGO_OK);
            carthago_shutdown();
        }
    }
}
