//! EK certificate chain stored in TPM NV (TCG EK Credential Profile 2.2.1.5.2, "Handle
//! Values for EK Certificate Chains"). Intel PTT on 11th gen Core and later keeps the
//! per-device CSME PTT, Kernel and ROM CAs there; the EK certificate's issuer is not
//! otherwise obtainable.

use crate::error::{Error, Result};
use crate::tbs::Channel;
use crate::tpm2;

/// NV index range reserved for EK certificate chains.
pub const FIRST_INDEX: u32 = 0x01C0_0100;
pub const LAST_INDEX: u32 = 0x01C0_01FF;
/// Upper bound on certificates taken from the chain indices; the gateway uses at most 16.
pub const MAX_CERTS: usize = 16;

const DEFAULT_CHUNK: u16 = 512;

/// Certificates found in each EK chain NV index, or why that index could not be read.
pub type IndexCerts = Vec<(u32, Result<Vec<Vec<u8>>>)>;

/// Reads every EK chain index, with a per-index outcome. Only listing the indices can fail
/// as a whole.
pub(crate) fn read(ch: Channel, nv_buffer_max: Option<u32>) -> Result<IndexCerts> {
    let chunk = nv_buffer_max.and_then(|n| u16::try_from(n).ok()).filter(|&n| n > 0).unwrap_or(DEFAULT_CHUNK).min(1024);
    Ok(tpm2::handles(ch, FIRST_INDEX, LAST_INDEX)?
        .into_iter()
        .map(|index| {
            let certs = tpm2::nv_read_public(ch, index)
                .and_then(|public| tpm2::nv_read(ch, index, public, chunk))
                .and_then(|data| split_certificates(&data));
            (index, certs)
        })
        .collect())
}

/// Splits NV contents into DER certificates. An index may hold several concatenated
/// certificates; trailing 0x00 or 0xFF fill (unused NV space) is ignored.
pub fn split_certificates(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut rest = data;
    while let Some(&tag) = rest.first() {
        if tag != 0x30 {
            if rest.iter().all(|&b| b == tag) && (tag == 0x00 || tag == 0xFF) {
                break;
            }
            return Err(Error::Parse(format!("EK chain NV data: unexpected byte 0x{tag:02X} at offset {}", data.len() - rest.len())));
        }
        let len = der_len(rest).ok_or_else(|| Error::Parse(format!("EK chain NV data: bad DER length at offset {}", data.len() - rest.len())))?;
        out.push(rest[..len].to_vec());
        rest = &rest[len..];
    }
    Ok(out)
}

/// Total length (header included) of the DER element at the start of `b`, if it fits.
fn der_len(b: &[u8]) -> Option<usize> {
    let first = *b.get(1)?;
    let (header, body) = match first {
        n if n < 0x80 => (2, n as usize),
        0x81..=0x84 => {
            let k = (first & 0x7F) as usize;
            let bytes = b.get(2..2 + k)?;
            (2 + k, bytes.iter().fold(0usize, |acc, &x| (acc << 8) | x as usize))
        }
        _ => return None,
    };
    let total = header.checked_add(body)?;
    (total <= b.len()).then_some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(len: usize) -> Vec<u8> {
        let mut v = vec![0x30, 0x82, (len >> 8) as u8, len as u8];
        v.extend((0..len).map(|i| i as u8));
        v
    }

    #[test]
    fn splits_concatenated_certificates_and_ignores_fill() {
        let (a, b) = (der(300), der(5));
        let mut data = [a.clone(), b.clone()].concat();
        assert_eq!(split_certificates(&data).unwrap(), vec![a.clone(), b.clone()]);
        data.extend([0xFF; 40]);
        assert_eq!(split_certificates(&data).unwrap(), vec![a.clone(), b]);
        let short = [vec![0x30, 0x03, 1, 2, 3], vec![0; 8]].concat();
        assert_eq!(split_certificates(&short).unwrap(), vec![vec![0x30, 0x03, 1, 2, 3]]);
        assert!(split_certificates(&[]).unwrap().is_empty());
        assert!(split_certificates(&[0xFF; 16]).unwrap().is_empty());
    }

    #[test]
    fn rejects_truncated_or_foreign_data() {
        let a = der(300);
        assert!(split_certificates(&a[..a.len() - 1]).is_err());
        assert!(split_certificates(&[a.clone(), vec![0x04, 0x01, 0x00]].concat()).is_err());
        assert!(split_certificates(&[0x30, 0x80, 0x00, 0x00]).is_err());
        assert!(split_certificates(&[0x30, 0x85, 0, 0, 0, 0, 1]).is_err());
        assert!(split_certificates(&[0xFF, 0x00]).is_err());
    }
}
