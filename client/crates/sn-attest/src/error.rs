#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{op} failed: {}", hresult_text(*.code))]
    Win32 { op: String, code: u32 },
    #[error("{op}: TPM returned rc=0x{rc:08X}")]
    Tpm { op: &'static str, rc: u32 },
    #[error("{0}")]
    Parse(String),
}

impl Error {
    pub(crate) fn win32(op: impl Into<String>, code: impl Into<i64>) -> Self {
        Error::Win32 { op: op.into(), code: code.into() as u32 }
    }

    /// True when the failure looks like a privilege problem rather than a missing feature.
    pub fn is_access_denied(&self) -> bool {
        matches!(
            self,
            Error::Win32 { code, .. } if matches!(
                *code,
                0x8007_0005 // E_ACCESSDENIED
                | 0x8009_0010 // NTE_PERM
                | 0x8028_4010 // TBS_E_ACCESS_DENIED
                | 0x8029_0101 // TPM_E_PCP_AUTHENTICATION_FAILED
            )
        )
    }

    pub fn code(&self) -> Option<u32> {
        match self {
            Error::Win32 { code, .. } => Some(*code),
            Error::Tpm { rc, .. } => Some(*rc),
            Error::Parse(_) => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn hresult_text(code: u32) -> String {
    let name = match code {
        0x8007_0005 => "E_ACCESSDENIED",
        0x8009_0010 => "NTE_PERM",
        0x8009_0016 => "NTE_BAD_KEYSET",
        0x8009_0029 => "NTE_NOT_SUPPORTED",
        0x8009_0027 => "NTE_INVALID_PARAMETER",
        0x8009_000F => "NTE_EXISTS",
        0x8028_4010 => "TBS_E_ACCESS_DENIED",
        0x8028_4008 => "TBS_E_TPM_NOT_FOUND",
        0x8028_4005 => "TBS_E_INSUFFICIENT_BUFFER",
        0x8029_0101 => "TPM_E_PCP_AUTHENTICATION_FAILED",
        0x8029_0103 => "TPM_E_PCP_DEVICE_NOT_READY",
        0x8029_0107 => "TPM_E_PCP_NOT_SUPPORTED",
        _ => "",
    };
    format!("0x{code:08X} {name}").trim_end().to_string()
}