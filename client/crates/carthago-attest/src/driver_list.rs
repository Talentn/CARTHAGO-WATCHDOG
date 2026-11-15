//! Windows' own signed list of the kernel drivers loaded since boot, from user mode.
//!
//! `GetRuntimeAttestationReport` (Windows 11 24H2 and 25H2 from the January 2026 update)
//! returns a "Runtime Report Package": the secure kernel's record of every driver image it
//! validated since boot, signed with a key the boot loader measured into the TPM. Nothing
//! here reads the list beyond counting it; the gateway verifies and reads it.
//!
//! Microsoft's page names kernel32.dll; the function has been found exported from
//! kernelbase.dll only, and older Windows has neither. So it is looked up at run time, and
//! a Windows without it is an answer ("no interface"), not an error.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{GetLastError, ERROR_DEVICE_NOT_CONNECTED, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NOT_SUPPORTED};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

/// The largest package passed on. Windows records at most 384 drivers, which is some tens
/// of kilobytes.
pub const MAX_PACKAGE: usize = 256 << 10;

const PACKAGE_VERSION: u16 = 1;
/// Bit 0 of the report bitmap: the driver report.
const DRIVER_REPORT: u64 = 1;
const MAGIC: &[u8; 4] = b"PRTR";
const HEADER: usize = 40;
const NONCE: usize = 32;

/// What asking Windows for the list gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverList {
    /// The package exactly as Windows returned it.
    Package(Vec<u8>),
    /// This Windows has no `GetRuntimeAttestationReport`.
    NoInterface,
    /// Windows keeps no list because memory integrity (HVCI) is off. With the Win32 error.
    HvciOff(u32),
    /// Virtualization-based security is not running. With the Win32 error.
    VbsOff(u32),
    /// Windows refused for another reason. With the Win32 error.
    Failed(u32),
}

/// What a package says about itself, read without checking anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub drivers: u16,
    /// Windows' table was full: later drivers are missing from the list.
    pub overflowed: bool,
}

impl DriverList {
    /// One sentence for a log line, starting in lower case.
    pub fn describe(&self) -> String {
        match self {
            Self::Package(p) => match summary(p) {
                Some(Summary { drivers: 0, .. }) => format!(
                    "Windows returned a signed list with no driver in it ({} bytes): a Windows 11 build from before the January 2026 update",
                    p.len()
                ),
                Some(s) => format!(
                    "Windows returned its signed list of {} kernel drivers loaded since boot ({} bytes){}",
                    s.drivers,
                    p.len(),
                    if s.overflowed { "; the list is incomplete, Windows' table was full" } else { "" }
                ),
                None => format!("Windows returned {} bytes that are not a driver list this build knows", p.len()),
            },
            Self::NoInterface => {
                "this Windows has no signed driver list (GetRuntimeAttestationReport is missing; it came with the January 2026 update of Windows 11 24H2 and 25H2)".into()
            }
            Self::HvciOff(e) => format!("memory integrity (HVCI) is off, so Windows keeps no driver list (error {e})"),
            Self::VbsOff(e) => format!("virtualization-based security is not running, so Windows keeps no driver list (error {e})"),
            Self::Failed(e) => format!("Windows refused the request for its driver list (error {e})"),
        }
    }

    /// Whether Windows returned a list with drivers in it.
    pub fn supported(&self) -> bool {
        matches!(self, Self::Package(p) if summary(p).is_some_and(|s| s.drivers > 0))
    }
}

type GetReport = unsafe extern "system" fn(nonce: *const u8, version: u16, reports: u64, buffer: *mut c_void, size: *mut u32) -> i32;

fn resolve() -> Option<GetReport> {
    for dll in [c"kernelbase.dll", c"kernel32.dll"] {
        // Both are loaded in every Win32 process; nothing is loaded here.
        let module = unsafe { GetModuleHandleA(dll.as_ptr().cast()) };
        if module.is_null() {
            continue;
        }
        if let Some(f) = unsafe { GetProcAddress(module, c"GetRuntimeAttestationReport".as_ptr().cast()) } {
            return Some(unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, GetReport>(f) });
        }
    }
    None
}

fn refused(error: u32) -> DriverList {
    match error {
        ERROR_NOT_SUPPORTED => DriverList::HvciOff(error),
        ERROR_DEVICE_NOT_CONNECTED => DriverList::VbsOff(error),
        e => DriverList::Failed(e),
    }
}

/// Asks Windows for the driver list, with `nonce` in its signed part. It reads; it changes
/// nothing on the PC and needs no elevation.
pub fn driver_list(nonce: &[u8; 32]) -> DriverList {
    match resolve() {
        Some(get) => fetch(|buffer, size| {
            if unsafe { get(nonce.as_ptr(), PACKAGE_VERSION, DRIVER_REPORT, buffer, size) } != 0 {
                0
            } else {
                unsafe { GetLastError() }.max(1)
            }
        }),
        None => DriverList::NoInterface,
    }
}

/// The size query and the fetch around one call of the function: `call(buffer, size)`
/// returns 0 for success, else the Win32 error.
fn fetch(mut call: impl FnMut(*mut c_void, *mut u32) -> u32) -> DriverList {
    let more = |e: u32| e == ERROR_INSUFFICIENT_BUFFER || e == ERROR_MORE_DATA;
    let mut need = 0u32;
    // Builds differ: the size query fails with "insufficient buffer" or succeeds.
    match call(std::ptr::null_mut(), &mut need) {
        0 => {}
        e if more(e) => {}
        e => return refused(e),
    }
    // The list grows when a driver loads between the two calls.
    let mut cap = (need as usize).max(16 << 10) + 4096;
    for _ in 0..4 {
        if cap > MAX_PACKAGE {
            break;
        }
        let mut buf = vec![0u8; cap];
        let mut size = cap as u32;
        match call(buf.as_mut_ptr().cast(), &mut size) {
            0 => {
                buf.truncate(package_len(&buf, size as usize));
                // "Success" with nothing in the buffer is no list.
                return if buf.is_empty() { DriverList::Failed(0) } else { DriverList::Package(buf) };
            }
            e if more(e) => cap = (size as usize).max(cap * 2) + 4096,
            e => return refused(e),
        }
    }
    DriverList::Failed(ERROR_INSUFFICIENT_BUFFER)
}

fn le16(b: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?) as usize)
}

fn le32(b: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize)
}

/// The length of the package in `buf`: what its header says when that is a package that
/// fits, else what the call returned.
fn package_len(buf: &[u8], returned: usize) -> usize {
    match le32(buf, 16) {
        Some(n) if buf.starts_with(MAGIC) && (HEADER + NONCE..=buf.len()).contains(&n) => n,
        _ => returned.min(buf.len()),
    }
}

/// Counts the drivers of a package. `None` when it is not laid out as a package with a
/// driver report.
pub fn summary(pkg: &[u8]) -> Option<Summary> {
    if !pkg.starts_with(MAGIC) {
        return None;
    }
    let (reports, digests, signature) = (le16(pkg, 6)?, le16(pkg, 22)?, le32(pkg, 28)?);
    let mut at = HEADER + NONCE + digests + signature;
    for _ in 0..reports {
        let (kind, size) = (le16(pkg, at)?, le32(pkg, at + 4)?);
        if kind == 0 {
            return Some(Summary { drivers: le16(pkg, at + 8)? as u16, overflowed: le16(pkg, at + 10)? & 1 != 0 });
        }
        if size < 8 {
            return None;
        }
        at = at.checked_add(size)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A package with one driver report of `drivers` entries and no payload behind them.
    fn package(drivers: u16, flags: u16) -> Vec<u8> {
        let report_len = 12 + 56 * drivers as usize;
        let total = 72 + 68 + 256 + report_len;
        let mut p = vec![0u8; total];
        p[..4].copy_from_slice(MAGIC);
        p[4..6].copy_from_slice(&1u16.to_le_bytes());
        p[6..8].copy_from_slice(&1u16.to_le_bytes());
        p[8] = 1;
        p[16..20].copy_from_slice(&(total as u32).to_le_bytes());
        p[20..22].copy_from_slice(&0x800eu16.to_le_bytes());
        p[22..24].copy_from_slice(&68u16.to_le_bytes());
        p[26..28].copy_from_slice(&1u16.to_le_bytes());
        p[28..32].copy_from_slice(&256u32.to_le_bytes());
        p[32..36].copy_from_slice(&(report_len as u32).to_le_bytes());
        let at = 72 + 68 + 256;
        p[at + 4..at + 8].copy_from_slice(&(report_len as u32).to_le_bytes());
        p[at + 8..at + 10].copy_from_slice(&drivers.to_le_bytes());
        p[at + 10..at + 12].copy_from_slice(&flags.to_le_bytes());
        p
    }

    /// The header a real Windows 11 PC returned, as published with the format: 182
    /// drivers in a package of 19793 bytes.
    #[test]
    fn summary_reads_a_published_header() {
        let header: [u8; 40] = [
            0x50, 0x52, 0x54, 0x52, 0x01, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x51, 0x4d, 0, 0, 0x0e, 0x80, 0x44, 0x00, 0, 0, 0x01, 0x00, 0x00, 0x01, 0, 0, 0xc5, 0x4b, 0, 0,
            0, 0, 0, 0,
        ];
        let mut p = vec![0u8; 19793];
        p[..40].copy_from_slice(&header);
        let report = 72 + 68 + 256;
        p[report..report + 12].copy_from_slice(&[0, 0, 0, 0, 0xc5, 0x4b, 0, 0, 0xb6, 0, 0, 0]);
        assert_eq!(summary(&p), Some(Summary { drivers: 182, overflowed: false }));
        assert_eq!(package_len(&p, 20000), 19793);
        assert!(DriverList::Package(p).describe().contains("182 kernel drivers"));
    }

    #[test]
    fn summary_counts_and_refuses_what_is_not_a_package() {
        assert_eq!(summary(&package(3, 1)), Some(Summary { drivers: 3, overflowed: true }));
        assert_eq!(summary(&package(0, 0)), Some(Summary { drivers: 0, overflowed: false }));
        assert!(!DriverList::Package(package(0, 0)).supported());
        assert!(DriverList::Package(package(2, 0)).supported());
        assert_eq!(summary(b"not a package"), None);
        assert_eq!(summary(&package(3, 0)[..100]), None);
        assert_eq!(summary(&[]), None);
        assert!(!DriverList::Package(vec![1, 2, 3]).supported());
    }

    #[test]
    fn fetch_follows_the_size_windows_asks_for() {
        let pkg = package(384, 0);
        // A build whose size query fails with "insufficient buffer", and a list that grew
        // past the first buffer between the calls.
        let mut calls = 0;
        let got = fetch(|buffer, size| {
            calls += 1;
            let have = unsafe { *size } as usize;
            if buffer.is_null() || have < pkg.len() {
                unsafe { *size = if calls == 1 { 1000 } else { pkg.len() as u32 } };
                return ERROR_INSUFFICIENT_BUFFER;
            }
            unsafe { std::ptr::copy_nonoverlapping(pkg.as_ptr(), buffer.cast::<u8>(), pkg.len()) };
            // A size that says nothing: the header's own size is used.
            unsafe { *size = have as u32 };
            0
        });
        assert_eq!(got, DriverList::Package(pkg.clone()));
        assert_eq!(calls, 3);

        // A build whose size query succeeds.
        let got = fetch(|buffer, size| {
            if !buffer.is_null() {
                unsafe { std::ptr::copy_nonoverlapping(pkg.as_ptr(), buffer.cast::<u8>(), pkg.len()) };
            }
            unsafe { *size = pkg.len() as u32 };
            0
        });
        assert_eq!(got, DriverList::Package(pkg));

        assert_eq!(fetch(|_, _| ERROR_NOT_SUPPORTED), DriverList::HvciOff(50));
        assert_eq!(fetch(|_, _| ERROR_DEVICE_NOT_CONNECTED), DriverList::VbsOff(1167));
        assert_eq!(fetch(|_, _| 87), DriverList::Failed(87));
        // Windows keeps asking for more than any list needs.
        let endless = fetch(|_, size| {
            unsafe { *size = 4 << 20 };
            ERROR_INSUFFICIENT_BUFFER
        });
        assert_eq!(endless, DriverList::Failed(ERROR_INSUFFICIENT_BUFFER));
        assert_eq!(
            fetch(|_, size| {
                unsafe { *size = 0 };
                0
            }),
            DriverList::Failed(0)
        );
        // Refused on the second call.
        let mut first = true;
        let refused_later = fetch(|_, _| if std::mem::take(&mut first) { ERROR_INSUFFICIENT_BUFFER } else { ERROR_NOT_SUPPORTED });
        assert_eq!(refused_later, DriverList::HvciOff(50));
    }

    /// On a Windows without the function the answer is "no interface", and nothing fails.
    /// Under Wine, where these tests run, that is the case.
    #[test]
    fn a_windows_without_the_function_says_so() {
        let got = driver_list(&[0u8; 32]);
        if resolve().is_none() {
            assert_eq!(got, DriverList::NoInterface);
            assert!(got.describe().contains("no signed driver list"));
        }
        assert!(matches!(got, DriverList::NoInterface | DriverList::Package(_) | DriverList::HvciOff(_) | DriverList::VbsOff(_) | DriverList::Failed(_)));
    }
}
