//! `carthago_sentinel.dll` C ABI (plan §3.1). The header is `sdk/native/include/carthago_sentinel.h`.
//! Every export catches panics; no Rust ownership crosses the boundary; callbacks run on
//! SDK-owned threads.

use std::ffi::{c_char, c_void, CString};
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

/// Longest accepted string arguments. The gateway refuses longer identifiers, and nothing
/// sensible is longer, so an oversized (or unterminated) string is refused here rather than
/// copied into every Hello and log line.
const MAX_ID: usize = 128;
const MAX_URL: usize = 2048;
const MAX_PINS: usize = 2048;

/// A NUL-terminated UTF-8 argument of at most `max` bytes; `None` if it is null, longer, or
/// not UTF-8. At most `max + 1` bytes are read, so a missing terminator is not followed.
unsafe fn str_arg(p: *const c_char, max: usize) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let len = (0..=max).find(|&i| unsafe { *p.add(i) } == 0)?;
    let bytes = unsafe { std::slice::from_raw_parts(p.cast::<u8>(), len) };
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

/// The player id hash is sent to the gateway, logged and shown in the dashboard: printable
/// ASCII without spaces, the rule the gateway enforces (it would refuse the session).
fn is_id(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x21..0x7f).contains(&b))
}

/// Tenant and build names end up in log lines: no control characters.
fn is_name(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

/// Copies the caller's config without reading past the `struct_size` it declares: fields a
/// caller built against an older header does not have read as zero (null).
unsafe fn read_config(p: *const CarthagoConfig) -> Result<CarthagoConfig, i32> {
    if p.is_null() {
        return Err(CARTHAGO_ERR_INVALID_ARG);
    }
    let [abi_version, struct_size] = unsafe { p.cast::<[u32; 2]>().read_unaligned() };
    if abi_version != CARTHAGO_ABI_VERSION || (struct_size as usize) < CARTHAGO_CONFIG_MIN_SIZE {
        return Err(CARTHAGO_ERR_ABI_MISMATCH);
    }
    let mut cfg = std::mem::MaybeUninit::<CarthagoConfig>::zeroed();
    let n = (struct_size as usize).min(size_of::<CarthagoConfig>());
    // SAFETY: the caller declared `struct_size` readable bytes; all-zero is a valid value
    // for every field (integers, null pointers, a `None` callback).
    unsafe {
        std::ptr::copy_nonoverlapping(p.cast::<u8>(), cfg.as_mut_ptr().cast::<u8>(), n);
        Ok(cfg.assume_init())
    }
}

fn runtime() -> Option<Arc<Runtime>> {
    RT.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// # Safety
/// `cfg` must point to a valid `CarthagoConfig` whose strings are NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn carthago_init(cfg: *const CarthagoConfig) -> i32 {
    guard(CARTHAGO_ERR_INTERNAL, || {
        let cfg = match unsafe { read_config(cfg) } {
            Ok(c) => c,
            Err(e) => return e,
        };
        let pins_hex = if cfg.tls_pins_hex.is_null() {
            String::new()
        } else {
            let Some(p) = (unsafe { str_arg(cfg.tls_pins_hex, MAX_PINS) }) else { return CARTHAGO_ERR_INVALID_ARG };
            p
        };
        let Ok(tls_pins) = carthago_net::parse_pins(&pins_hex) else { return CARTHAGO_ERR_INVALID_ARG };
        let (Some(tenant_id), Some(build_id), Some(gateway_url), Some(key_hex)) = (unsafe {
            (str_arg(cfg.tenant_id, MAX_ID), str_arg(cfg.build_id, MAX_ID), str_arg(cfg.gateway_url, MAX_URL), str_arg(cfg.server_identity_key_hex, MAX_ID))
        }) else {
            return CARTHAGO_ERR_INVALID_ARG;
        };
        if tenant_id.is_empty() || !is_name(&tenant_id) || !is_name(&build_id) {
            return CARTHAGO_ERR_INVALID_ARG;
        }
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
        let Some(player) = (unsafe { str_arg(player_id_hash, MAX_ID) }).filter(|p| is_id(p)) else { return CARTHAGO_ERR_INVALID_ARG };
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
        let g = match RT.try_read() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        if let Some(rt) = g.as_ref() {
            rt.tick();
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
        if out.is_null() {
            return CARTHAGO_ERR_INVALID_ARG;
        }
        // Only the size field is read before it is known how much the caller allocated.
        if (unsafe { out.cast::<u32>().read_unaligned() } as usize) < size_of::<CarthagoStatus>() {
            return CARTHAGO_ERR_ABI_MISMATCH;
        }
        let Some(rt) = runtime() else { return CARTHAGO_ERR_NOT_INITIALIZED };
        let s = rt.status();
        let status = CarthagoStatus {
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
        unsafe { out.write_unaligned(status) };
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
            Arc::new(move |reason: &str| {
                let user = user;
                if let Ok(c) = CString::new(reason.replace('\0', " ")) {
                    unsafe { f(c.as_ptr(), user.0) };
                }
            }) as carthago_core::KickFn
        }));
    })
}

#[no_mangle]
pub extern "C" fn carthago_shutdown() {
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
    use std::ffi::CStr;

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
            // The same caller's struct really is shorter: only its own bytes are read.
            let old = std::slice::from_raw_parts((&raw const c).cast::<u8>(), CARTHAGO_CONFIG_MIN_SIZE).to_vec();
            let copy = read_config(old.as_ptr().cast()).ok().unwrap();
            assert!(copy.tls_pins_hex.is_null() && copy.tenant_id == c.tenant_id && copy.flags == c.flags);

            // Oversized or unprintable strings are refused before anything is started.
            let long = CString::new("a".repeat(MAX_ID + 1)).unwrap();
            let longest = CString::new("a".repeat(MAX_ID)).unwrap();
            for bad in [long.as_c_str(), c"line\nbreak", c""] {
                let mut c = cfg(good_key);
                c.tenant_id = bad.as_ptr();
                assert_eq!(carthago_init(&c), CARTHAGO_ERR_INVALID_ARG, "tenant {bad:?}");
            }
            let mut c = cfg(good_key);
            c.build_id = long.as_ptr();
            assert_eq!(carthago_init(&c), CARTHAGO_ERR_INVALID_ARG);
            let url = CString::new(format!("ws://127.0.0.1:1/{}", "a".repeat(MAX_URL))).unwrap();
            let mut c = cfg(good_key);
            c.gateway_url = url.as_ptr();
            assert_eq!(carthago_init(&c), CARTHAGO_ERR_INVALID_ARG);
            let mut c = cfg(good_key);
            c.tenant_id = longest.as_ptr();
            assert_eq!(carthago_init(&c), CARTHAGO_OK);
            for bad in [long.as_c_str(), c"has space", c"\x01"] {
                assert_eq!(carthago_begin_session(bad.as_ptr(), None, std::ptr::null_mut()), CARTHAGO_ERR_INVALID_ARG, "player {bad:?}");
            }
            carthago_shutdown();
            assert_eq!(str_arg(c"abc".as_ptr(), 3).as_deref(), Some("abc"));
            assert_eq!(str_arg(c"abcd".as_ptr(), 3), None);
            assert_eq!(str_arg(std::ptr::null(), 3), None);

            // A status struct smaller than the current one is not written to.
            let mut small = [u32::MAX; 2];
            small[0] = 8;
            assert_eq!(carthago_get_status(small.as_mut_ptr().cast()), CARTHAGO_ERR_ABI_MISMATCH);
            assert_eq!(small, [8, u32::MAX]);
            let mut c = cfg(good_key);
            let pins = CString::new(format!("{},{}", "ab".repeat(32), "cd".repeat(32))).unwrap();
            c.tls_pins_hex = pins.as_ptr();
            assert_eq!(carthago_init(&c), CARTHAGO_OK);
            carthago_shutdown();
        }
    }
}
