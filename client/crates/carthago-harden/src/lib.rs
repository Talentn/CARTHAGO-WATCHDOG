//! Process mitigation profiles applied by the SDK at init (plan §6.3), for games started
//! without the launcher. A profile only ever tightens policy, and each policy is applied
//! independently, so one that the OS refuses does not block the others. Some policies break
//! engines or overlays, so the studio picks the profile:
//!
//! - `Basic` (default): image loads from remote shares and from low-integrity files are
//!   blocked. Overlays and IMEs keep working.
//! - `Strict`: Basic, plus System32-first DLL search order and disabled legacy extension
//!   points (AppInit DLLs, Winsock LSPs, global window hooks injecting DLLs). Validate it
//!   against the title's IMEs and overlays before shipping it.
//!
//! ACG (dynamic code) and CFG enforcement need a per-engine decision and belong to the
//! launcher profile (Phase 2).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Off,
    Basic,
    Strict,
}

/// Bits in the applied/failed masks (reported to the server as FINDING_CODE_MITIGATIONS).
pub const NO_REMOTE_IMAGES: u64 = 1;
pub const NO_LOW_LABEL_IMAGES: u64 = 2;
pub const PREFER_SYSTEM32_IMAGES: u64 = 4;
pub const EXTENSION_POINTS_DISABLED: u64 = 8;

impl Profile {
    pub fn wanted(self) -> u64 {
        match self {
            Profile::Off => 0,
            Profile::Basic => NO_REMOTE_IMAGES | NO_LOW_LABEL_IMAGES,
            Profile::Strict => NO_REMOTE_IMAGES | NO_LOW_LABEL_IMAGES | PREFER_SYSTEM32_IMAGES | EXTENSION_POINTS_DISABLED,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Outcome {
    pub applied: u64,
    pub failed: u64,
}

#[cfg(windows)]
pub fn apply(profile: Profile) -> Outcome {
    use windows_sys::Win32::System::Threading::{ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, SetProcessMitigationPolicy};

    let want = profile.wanted();
    let mut out = Outcome::default();
    let mut set = |policy, flags: u32, bits: u64| {
        if bits == 0 {
            return;
        }
        // Every policy used here is a single 32-bit flags word.
        let ok = unsafe { SetProcessMitigationPolicy(policy, (&flags as *const u32).cast(), 4) } != 0;
        if ok {
            out.applied |= bits;
        } else {
            out.failed |= bits;
        }
    };
    // PROCESS_MITIGATION_IMAGE_LOAD_POLICY: NoRemoteImages bit 0, NoLowMandatoryLabelImages
    // bit 1, PreferSystem32Images bit 2.
    let img = want & (NO_REMOTE_IMAGES | NO_LOW_LABEL_IMAGES | PREFER_SYSTEM32_IMAGES);
    set(ProcessImageLoadPolicy, img as u32, img);
    set(ProcessExtensionPointDisablePolicy, 1, want & EXTENSION_POINTS_DISABLED);
    out
}

#[cfg(not(windows))]
pub fn apply(profile: Profile) -> Outcome {
    Outcome { applied: 0, failed: profile.wanted() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_only_add_policies() {
        assert_eq!(Profile::Off.wanted(), 0);
        assert_eq!(Profile::Basic.wanted() & !Profile::Strict.wanted(), 0);
        assert_eq!(Profile::Basic.wanted(), NO_REMOTE_IMAGES | NO_LOW_LABEL_IMAGES);
    }

    #[test]
    fn every_wanted_bit_is_accounted_for() {
        for p in [Profile::Off, Profile::Basic] {
            let o = apply(p);
            assert_eq!(o.applied | o.failed, p.wanted(), "{p:?}");
            assert_eq!(o.applied & o.failed, 0);
        }
    }
}
