//! Authenticode state of a file on disk, for the companion's module inventory. The mapping
//! from a `WinVerifyTrust` result to a [`ModuleSignature`] is portable and unit-tested; the
//! call itself is Windows-only.
//!
//! `WinVerifyTrust` hashes the whole file in one call that cannot be sliced, so it does not
//! run on the budgeted scheduler worker. A dedicated low-priority thread checks one file at
//! a time with a pause between files, each distinct file once, and the module job only
//! exchanges messages with it.

use carthago_proto::v1::ModuleSignature;

const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;
const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B_0001;
const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;
const TRUST_E_SUBJECT_NOT_TRUSTED: u32 = 0x800B_0004;
const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B_0111;
const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
const CERT_E_CHAINING: u32 = 0x800B_010A;
const CERT_E_UNTRUSTEDTESTROOT: u32 = 0x800B_010D;
const CERT_E_REVOKED: u32 = 0x800B_010C;
const CERT_E_EXPIRED: u32 = 0x800B_0101;
const CRYPT_E_SECURITY_SETTINGS: u32 = 0x8009_2026;

/// Maps the `WinVerifyTrust` return value for a file to its signature state.
pub fn state_of(status: i32) -> ModuleSignature {
    match status as u32 {
        0 => ModuleSignature::Valid,
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => ModuleSignature::None,
        TRUST_E_BAD_DIGEST => ModuleSignature::BadDigest,
        TRUST_E_SUBJECT_NOT_TRUSTED | TRUST_E_EXPLICIT_DISTRUST | CERT_E_UNTRUSTEDROOT | CERT_E_CHAINING | CERT_E_UNTRUSTEDTESTROOT
        | CERT_E_REVOKED | CRYPT_E_SECURITY_SETTINGS => ModuleSignature::Untrusted,
        CERT_E_EXPIRED => ModuleSignature::Expired,
        _ => ModuleSignature::Error,
    }
}

/// `b` of a `FINDING_CODE_MODULE_SIGNATURE` finding.
pub fn pack(state: ModuleSignature, class: carthago_proto::v1::ModulePathClass) -> u64 {
    (state as u64 & 0xff) | (class as u64 & 0xff) << 8
}

#[cfg(windows)]
pub use worker::{cpu_ns, files_checked, verify_file, Checked, Worker};

#[cfg(windows)]
mod worker {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
    use std::time::Duration;

    use carthago_proto::v1::{ModulePathClass, ModuleSignature};
    use windows_sys::core::GUID;
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_LOWEST};

    use super::state_of;
    use crate::win;

    static CPU_NS: AtomicU64 = AtomicU64::new(0);
    static CHECKED: AtomicU64 = AtomicU64::new(0);

    /// CPU the signature thread has used so far.
    pub fn cpu_ns() -> u64 {
        CPU_NS.load(Relaxed)
    }

    /// Distinct files verified so far.
    pub fn files_checked() -> u64 {
        CHECKED.load(Relaxed)
    }

    /// WINTRUST_ACTION_GENERIC_VERIFY_V2.
    const ACTION: GUID = GUID { data1: 0x00aa_c56b, data2: 0xcd44, data3: 0x11d0, data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee] };

    /// Verifies the embedded Authenticode signature of a file. No UI, no revocation check and
    /// no network: only what is on this machine decides.
    pub fn verify_file(path: &str) -> ModuleSignature {
        let wide = win::wide(path);
        let mut file: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
        file.cbStruct = size_of::<WINTRUST_FILE_INFO>() as u32;
        file.pcwszFilePath = wide.as_ptr();
        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file };
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        let mut action = ACTION;
        let invalid = -1isize as windows_sys::Win32::Foundation::HWND;
        let status = unsafe { WinVerifyTrust(invalid, &mut action, (&mut data as *mut WINTRUST_DATA).cast()) };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe { WinVerifyTrust(invalid, &mut action, (&mut data as *mut WINTRUST_DATA).cast()) };
        state_of(status)
    }

    struct Request {
        base: u64,
        class: ModulePathClass,
        path: String,
    }

    /// One verified module.
    pub struct Checked {
        pub base: u64,
        pub class: ModulePathClass,
        pub state: ModuleSignature,
        pub name: String,
    }

    /// Handle to the signature thread; dropping it stops the thread after the file in hand.
    pub struct Worker {
        tx: SyncSender<Request>,
        rx: Receiver<Checked>,
    }

    const QUEUE: usize = 64;
    const CACHE: usize = 512;
    /// Pause between files: a first inventory of ~30 modules takes a few seconds and costs a
    /// few tens of milliseconds of CPU in total.
    const PAUSE: Duration = Duration::from_millis(120);

    impl Worker {
        pub fn start() -> std::io::Result<Self> {
            let (tx, req) = sync_channel::<Request>(QUEUE);
            let (res, rx) = sync_channel::<Checked>(QUEUE);
            std::thread::Builder::new().name("carthago-signature".into()).spawn(move || {
                unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST) };
                let mut cache: HashMap<String, ModuleSignature> = HashMap::new();
                while let Ok(r) = req.recv() {
                    let key = r.path.to_lowercase();
                    let state = match cache.get(&key) {
                        Some(s) => *s,
                        None => {
                            let s = verify_file(&r.path);
                            if cache.len() >= CACHE {
                                cache.clear();
                            }
                            cache.insert(key, s);
                            CHECKED.fetch_add(1, Relaxed);
                            CPU_NS.store(carthago_sched::clock::cycles_to_ns(carthago_sched::clock::thread_cycles()), Relaxed);
                            std::thread::sleep(PAUSE);
                            s
                        }
                    };
                    let name = crate::paths::base_name(&r.path).to_owned();
                    if res.send(Checked { base: r.base, class: r.class, state, name }).is_err() {
                        return;
                    }
                }
            })?;
            Ok(Self { tx, rx })
        }

        /// Queues a file; `false` when the queue is full (ask again on a later pass).
        pub fn submit(&self, base: u64, class: ModulePathClass, path: String) -> bool {
            !matches!(self.tx.try_send(Request { base, class, path }), Err(TrySendError::Full(_) | TrySendError::Disconnected(_)))
        }

        /// A finished check, if any. Never blocks.
        pub fn poll(&self) -> Option<Checked> {
            self.rx.try_recv().ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carthago_proto::v1::ModulePathClass;

    #[test]
    fn maps_winverifytrust_results() {
        assert_eq!(state_of(0), ModuleSignature::Valid);
        assert_eq!(state_of(0x800B_0100u32 as i32), ModuleSignature::None);
        assert_eq!(state_of(0x8009_6010u32 as i32), ModuleSignature::BadDigest);
        assert_eq!(state_of(0x800B_0109u32 as i32), ModuleSignature::Untrusted);
        assert_eq!(state_of(0x800B_0111u32 as i32), ModuleSignature::Untrusted);
        assert_eq!(state_of(0x800B_0101u32 as i32), ModuleSignature::Expired);
        assert_eq!(state_of(0x8007_0002u32 as i32), ModuleSignature::Error, "file not found is an error, not 'unsigned'");
    }

    #[test]
    fn packs_state_and_class() {
        let b = pack(ModuleSignature::None, ModulePathClass::GameDir);
        assert_eq!(b & 0xff, ModuleSignature::None as u64);
        assert_eq!(b >> 8 & 0xff, ModulePathClass::GameDir as u64);
    }
}
