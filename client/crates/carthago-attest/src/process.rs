//! Token facts for the current process, used to record whether a step ran elevated.

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenElevation,
    TokenIntegrityLevel, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

#[derive(Debug, Clone, Copy)]
pub struct ProcessToken {
    pub elevated: bool,
    /// Mandatory integrity RID: 0x2000 medium, 0x3000 high, 0x4000 system.
    pub integrity_rid: u32,
}

impl ProcessToken {
    pub fn integrity_name(&self) -> &'static str {
        match self.integrity_rid {
            0..=0x0fff => "untrusted/low",
            0x1000..=0x1fff => "low",
            0x2000..=0x2fff => "medium",
            0x3000..=0x3fff => "high",
            _ => "system",
        }
    }
}

pub fn current_token() -> Option<ProcessToken> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok_elev = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        ) != 0;

        let mut buf = vec![0u8; 256];
        let ok_il = GetTokenInformation(token, TokenIntegrityLevel, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut len) != 0;
        let integrity_rid = if ok_il {
            let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let sid = label.Label.Sid;
            let count = *GetSidSubAuthorityCount(sid);
            *GetSidSubAuthority(sid, count.saturating_sub(1) as u32)
        } else {
            0
        };
        CloseHandle(token);
        ok_elev.then_some(ProcessToken { elevated: elevation.TokenIsElevated != 0, integrity_rid })
    }
}
