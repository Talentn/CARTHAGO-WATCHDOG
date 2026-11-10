//! Known-vulnerable kernel drivers by file name (a subset of the loldrivers.io dataset that
//! cheat loaders use to map unsigned code: BYOVD, the kdmapper pattern). Only matches are
//! reported, never the machine's driver list (plan §10). Several of these ship with
//! legitimate tools (RTCore64 with MSI Afterburner, procexp with Process Explorer), so the
//! server treats a match as a risk signal for review, never a ban reason on its own.

pub const VULNERABLE: &[&str] = &[
    "asio.sys",
    "asio64.sys",
    "asrdrv101.sys",
    "asrdrv102.sys",
    "asrdrv104.sys",
    "asrdrv106.sys",
    "atillk64.sys",
    "aswarpot.sys",
    "bs_def64.sys",
    "cpuz141_x64.sys",
    "dbk32.sys",
    "dbk64.sys",
    "dbutil_2_3.sys",
    "echo_driver.sys",
    "ene.sys",
    "gdrv.sys",
    "glckio2.sys",
    "inpoutx64.sys",
    "iqvw64e.sys",
    "kprocesshacker.sys",
    "mhyprot2.sys",
    "msio64.sys",
    "nicm.sys",
    "ntiolib_x64.sys",
    "phymemx64.sys",
    "procexp152.sys",
    "rtcore64.sys",
    "rwdrv.sys",
    "speedfan.sys",
    "truesight.sys",
    "winio64.sys",
    "winring0x64.sys",
    "zam64.sys",
    "zamguard64.sys",
];

/// Case-insensitive match on a driver's file name (`FullPathName` + `OffsetToFileName`).
pub fn match_name(file_name: &[u8]) -> Option<&'static str> {
    VULNERABLE.iter().copied().find(|v| v.as_bytes().eq_ignore_ascii_case(file_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_case_insensitively() {
        assert_eq!(match_name(b"IQVW64E.SYS"), Some("iqvw64e.sys"));
        assert_eq!(match_name(b"dbk64.sys"), Some("dbk64.sys"));
        assert_eq!(match_name(b"ntoskrnl.exe"), None);
        assert_eq!(match_name(b"dbk64.sys.bak"), None);
    }

    #[test]
    fn list_is_lowercase_and_unique() {
        let mut v: Vec<_> = VULNERABLE.to_vec();
        assert!(v.iter().all(|n| n.chars().all(|c| !c.is_ascii_uppercase())));
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), VULNERABLE.len());
    }
}
