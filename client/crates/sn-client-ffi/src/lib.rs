//! `sentinel.dll` C ABI (plan §3.1). The header is `sdk/native/include/sentinel.h`.
//! Every export catches panics; no Rust ownership crosses the boundary; callbacks run on
//! SDK-owned threads.

use std::ffi::{c_char, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};

use sn_client_core::{Config, Runtime};
use sn_crypto::VerifyingKey;
use sn_sched::Activity;

pub const SN_ABI_VERSION: u32 = 1;

pub const SN_OK: i32 = 0;
pub const SN_ERR_INVALID_ARG: i32 = 1;
pub const SN_ERR_NOT_INITIALIZED: i32 = 2;
pub const SN_ERR_ALREADY_INITIALIZED: i32 = 3;
pub const SN_ERR_BUFFER_TOO_SMALL: i32 = 4;
pub const SN_ERR_NO_SESSION: i32 = 5;
pub const SN_ERR_ABI_MISMATCH: i32 = 6;
pub const SN_ERR_SESSION_FAILED: i32 = 7;
pub const SN_ERR_INTERNAL: i32 = 99;

pub const SN_FLAG_NO_TPM: u32 = 1;

pub type SnLogFn = unsafe extern "C" fn(level: i32, msg: *const c_char, user: *mut c_void);
pub type SnSessionCb = unsafe extern "C" fn(result: i32, trust_level: u32, attest_flags: u64, user: *mut c_void);
pub type SnKickCb = unsafe extern "C" fn(reason: *const c_char, user: *mut c_void);

#[repr(C)]
pub struct SnConfig {
    pub abi_version: u32,
    pub struct_size: u32,
    pub tenant_id: *const c_char,
    pub build_id: *const c_char,
    pub gateway_url: *const c_char,
    /// Hex Ed25519 public key of the gateway identity (pinned).
    pub server_identity_key_hex: *const c_char,
    pub log: Option<SnLogFn>,
    pub log_user: *mut c_void,
    pub flags: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct SnStatus {
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
/// `cfg` must point to a valid `SnConfig` whose strings are NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn sn_init(cfg: *const SnConfig) -> i32 {
    guard(SN_ERR_INTERNAL, || {
        let Some(cfg) = (unsafe { cfg.as_ref() }) else { return SN_ERR_INVALID_ARG };
        if cfg.abi_version != SN_ABI_VERSION || (cfg.struct_size as usize) < size_of::<SnConfig>() {
            return SN_ERR_ABI_MISMATCH;
        }
        let (Some(tenant_id), Some(build_id), Some(gateway_url), Some(key_hex)) = (unsafe {
            (str_arg(cfg.tenant_id), str_arg(cfg.build_id), str_arg(cfg.gateway_url), str_arg(cfg.server_identity_key_hex))
        }) else {
            return SN_ERR_INVALID_ARG;
        };
        let Some(server_identity) = hex::decode(key_hex.trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        else {
            return SN_ERR_INVALID_ARG;
        };
        let mut slot = RT.write().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return SN_ERR_ALREADY_INITIALIZED;
        }
        let log = cfg.log.map(|f| {
            let user = UserPtr(cfg.log_user);
            Arc::new(move |level: u8, msg: &str| {
                let user = user;
                if let Ok(c) = CString::new(msg.replace('\0', " ")) {
                    unsafe { f(level as i32, c.as_ptr(), user.0) };
                }
            }) as sn_client_core::LogFn
        });
        let config = Config { tenant_id, build_id, gateway_url, server_identity, allow_tpm: cfg.flags & SN_FLAG_NO_TPM == 0, log };
        match Runtime::start(config) {
            Ok(rt) => {
                *slot = Some(Arc::new(rt));
                SN_OK
            }
            Err(_) => SN_ERR_INTERNAL,
        }
    })
}

/// Starts the handshake on the SDK thread; `on_ready` runs there when it completes.
///
/// # Safety
/// `player_id_hash` must be a NUL-terminated string (the studio's HMAC of the platform id).
#[no_mangle]
pub unsafe extern "C" fn sn_begin_session(player_id_hash: *const c_char, on_ready: Option<SnSessionCb>, user: *mut c_void) -> i32 {
    guard(SN_ERR_INTERNAL, || {
        let Some(player) = (unsafe { str_arg(player_id_hash) }).filter(|p| !p.is_empty()) else { return SN_ERR_INVALID_ARG };
        let Some(rt) = runtime() else { return SN_ERR_NOT_INITIALIZED };
        let user = UserPtr(user);
        let ok = rt.begin_session(
            player,
            Box::new(move |r| {
                let user = user;
                if let Some(cb) = on_ready {
                    match r {
                        Ok(s) => unsafe { cb(SN_OK, s.trust_level, s.attest_flags, user.0) },
                        Err(_) => unsafe { cb(SN_ERR_SESSION_FAILED, 0, 0, user.0) },
                    }
                }
            }),
        );
        if ok {
            SN_OK
        } else {
            SN_ERR_NOT_INITIALIZED
        }
    })
}

/// Copies the current session token (NUL-terminated). On `SN_ERR_BUFFER_TOO_SMALL`, `*len`
/// is set to the required size including the NUL.
///
/// # Safety
/// `len` must be valid; `buf` must have room for `*len` bytes (or be null to query the size).
#[no_mangle]
pub unsafe extern "C" fn sn_get_session_token(buf: *mut c_char, len: *mut usize) -> i32 {
    guard(SN_ERR_INTERNAL, || {
        let Some(len) = (unsafe { len.as_mut() }) else { return SN_ERR_INVALID_ARG };
        let Some(rt) = runtime() else { return SN_ERR_NOT_INITIALIZED };
        let Some(tok) = rt.token() else { return SN_ERR_NO_SESSION };
        let need = tok.len() + 1;
        if buf.is_null() || *len < need {
            *len = need;
            return SN_ERR_BUFFER_TOO_SMALL;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(tok.as_ptr(), buf.cast::<u8>(), tok.len());
            *buf.add(tok.len()) = 0;
        }
        *len = tok.len();
        SN_OK
    })
}

/// Per-frame call from the game thread. Never blocks and never scans on the caller.
#[no_mangle]
pub extern "C" fn sn_tick() {
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
pub extern "C" fn sn_set_activity(activity: u32) {
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
pub extern "C" fn sn_heartbeat_now() -> i32 {
    guard(SN_ERR_INTERNAL, || match runtime() {
        Some(rt) => {
            rt.heartbeat_now();
            SN_OK
        }
        None => SN_ERR_NOT_INITIALIZED,
    })
}

/// # Safety
/// `out` must point to an `SnStatus` with `struct_size` set.
#[no_mangle]
pub unsafe extern "C" fn sn_get_status(out: *mut SnStatus) -> i32 {
    guard(SN_ERR_INTERNAL, || {
        let Some(out) = (unsafe { out.as_mut() }) else { return SN_ERR_INVALID_ARG };
        if (out.struct_size as usize) < size_of::<SnStatus>() {
            return SN_ERR_ABI_MISMATCH;
        }
        let Some(rt) = runtime() else { return SN_ERR_NOT_INITIALIZED };
        let s = rt.status();
        *out = SnStatus {
            struct_size: size_of::<SnStatus>() as u32,
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
        SN_OK
    })
}

/// Informational: the gateway ended this client's session. The game server enforces kicks.
#[no_mangle]
pub extern "C" fn sn_set_kick_callback(cb: Option<SnKickCb>, user: *mut c_void) {
    guard((), || {
        let Some(rt) = runtime() else { return };
        let user = UserPtr(user);
        rt.set_kick_callback(cb.map(|f| {
            Box::new(move |reason: &str| {
                let user = user;
                if let Ok(c) = CString::new(reason) {
                    unsafe { f(c.as_ptr(), user.0) };
                }
            }) as sn_client_core::KickFn
        }));
    })
}

#[no_mangle]
pub extern "C" fn sn_shutdown() {
    guard((), || {
        let rt = RT.write().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(rt) = rt {
            rt.shutdown();
        }
    })
}

/// Test hook (feature `dev-hooks`): keep the connection but stop heartbeating.
#[cfg(feature = "dev-hooks")]
#[no_mangle]
pub extern "C" fn sn_dev_suppress_heartbeats(on: i32) {
    guard((), || {
        if let Some(rt) = runtime() {
            rt.suppress_heartbeats(on != 0);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(key: &CStr) -> SnConfig {
        SnConfig {
            abi_version: SN_ABI_VERSION,
            struct_size: size_of::<SnConfig>() as u32,
            tenant_id: c"demo".as_ptr(),
            build_id: c"test".as_ptr(),
            gateway_url: c"ws://127.0.0.1:1/v1/client".as_ptr(),
            server_identity_key_hex: key.as_ptr(),
            log: None,
            log_user: std::ptr::null_mut(),
            flags: SN_FLAG_NO_TPM,
        }
    }

    #[test]
    fn rejects_bad_config_and_reports_uninitialized() {
        let good_key = c"290184ec194e65f6578796e87f8cd2c3beaa96857a0d883c19ee85b71781a548";
        unsafe {
            assert_eq!(sn_init(std::ptr::null()), SN_ERR_INVALID_ARG);
            let mut c = cfg(good_key);
            c.abi_version = 2;
            assert_eq!(sn_init(&c), SN_ERR_ABI_MISMATCH);
            let mut c = cfg(good_key);
            c.struct_size = 8;
            assert_eq!(sn_init(&c), SN_ERR_ABI_MISMATCH);
            assert_eq!(sn_init(&cfg(c"zz")), SN_ERR_INVALID_ARG);
            let mut c = cfg(good_key);
            c.tenant_id = std::ptr::null();
            assert_eq!(sn_init(&c), SN_ERR_INVALID_ARG);

            let mut len = 0usize;
            assert_eq!(sn_get_session_token(std::ptr::null_mut(), &mut len), SN_ERR_NOT_INITIALIZED);
            assert_eq!(sn_begin_session(c"p".as_ptr(), None, std::ptr::null_mut()), SN_ERR_NOT_INITIALIZED);
            sn_tick();
            sn_shutdown();

            assert_eq!(sn_init(&cfg(good_key)), SN_OK);
            assert_eq!(sn_init(&cfg(good_key)), SN_ERR_ALREADY_INITIALIZED);
            assert_eq!(sn_get_session_token(std::ptr::null_mut(), &mut len), SN_ERR_NO_SESSION);
            assert_eq!(sn_begin_session(c"".as_ptr(), None, std::ptr::null_mut()), SN_ERR_INVALID_ARG);
            let mut st = SnStatus { struct_size: size_of::<SnStatus>() as u32, ..Default::default() };
            assert_eq!(sn_get_status(&mut st), SN_OK);
            st.struct_size = 4;
            assert_eq!(sn_get_status(&mut st), SN_ERR_ABI_MISMATCH);
            for _ in 0..100 {
                sn_tick();
            }
            sn_shutdown();
            assert_eq!(sn_get_session_token(std::ptr::null_mut(), &mut len), SN_ERR_NOT_INITIALIZED);
        }
    }
}
