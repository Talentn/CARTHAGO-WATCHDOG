//! TPM Base Services (TBS): raw command submission, device info and the WBCL.

use std::ptr;

use windows_sys::Win32::System::TpmBaseServices::{
    Tbsi_GetDeviceInfo, Tbsi_Get_TCG_Log_Ex, Tbsip_Submit_Command, TBS_COMMAND_LOCALITY_ZERO,
    TBS_COMMAND_PRIORITY_NORMAL, TBS_TCGLOG_SRTM_CURRENT, TPM_DEVICE_INFO,
};

use crate::error::{Error, Result};

const TBS_E_INSUFFICIENT_BUFFER: u32 = 0x8028_4005;

/// A TBS context borrowed from the PCP provider; the provider owns and closes it.
#[derive(Clone, Copy)]
pub(crate) struct Channel(pub usize);

impl Channel {
    /// Submits a TPM command and returns the full response after checking the response code.
    pub fn submit(&self, op: &'static str, cmd: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; 4096];
        let mut len = out.len() as u32;
        let rc = unsafe {
            Tbsip_Submit_Command(
                self.0 as *const _,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                cmd.as_ptr(),
                cmd.len() as u32,
                out.as_mut_ptr(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(Error::win32(format!("Tbsip_Submit_Command({op})"), rc));
        }
        out.truncate(len as usize);
        if out.len() < 10 {
            return Err(Error::Parse(format!("{op}: short TPM response ({} bytes)", out.len())));
        }
        let tpm_rc = u32::from_be_bytes(out[6..10].try_into().unwrap());
        if tpm_rc != 0 {
            return Err(Error::Tpm { op, rc: tpm_rc });
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DeviceInfo {
    pub tpm_version: u32,
    pub interface_type: u32,
    pub implementation_revision: u32,
}

impl DeviceInfo {
    pub fn interface_name(&self) -> &'static str {
        match self.interface_type {
            1 => "TIS/FIFO (TPM_IFTYPE_1)",
            2 => "TrustZone (TPM_IFTYPE_TRUSTZONE)",
            3 => "CRB / firmware or Pluton (TPM_IFTYPE_HW)",
            4 => "Emulator (TPM_IFTYPE_EMULATOR)",
            5 => "SPB (TPM_IFTYPE_SPB)",
            _ => "unknown",
        }
    }
}

pub fn device_info() -> Result<DeviceInfo> {
    let mut info = TPM_DEVICE_INFO::default();
    let rc = unsafe {
        Tbsi_GetDeviceInfo(std::mem::size_of::<TPM_DEVICE_INFO>() as u32, &mut info as *mut _ as *mut _)
    };
    if rc != 0 {
        return Err(Error::win32("Tbsi_GetDeviceInfo", rc));
    }
    Ok(DeviceInfo {
        tpm_version: info.tpmVersion,
        interface_type: info.tpmInterfaceType,
        implementation_revision: info.tpmImpRevision,
    })
}

/// The Windows Boot Configuration Log (TCG measured-boot log) for the current boot.
pub fn tcg_log() -> Result<Vec<u8>> {
    let mut len = 0u32;
    let rc = unsafe { Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, ptr::null_mut(), &mut len) };
    if rc != 0 && rc != TBS_E_INSUFFICIENT_BUFFER {
        return Err(Error::win32("Tbsi_Get_TCG_Log_Ex(size)", rc));
    }
    let mut buf = vec![0u8; len as usize];
    let rc = unsafe { Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, buf.as_mut_ptr(), &mut len) };
    if rc != 0 {
        return Err(Error::win32("Tbsi_Get_TCG_Log_Ex", rc));
    }
    buf.truncate(len as usize);
    Ok(buf)
}
