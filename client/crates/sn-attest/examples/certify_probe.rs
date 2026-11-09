//! Diagnostic: can this user certify its PCP device key with its AK (TPM2_Certify)?
//! `cargo run -p sn-attest --example certify_probe` from a normal, unelevated shell.

fn main() -> sn_attest::Result<()> {
    let tpm = sn_attest::Tpm::open()?;
    let (ak, created, _) = tpm.load_or_create_ak("sentinel-probe-ak", None)?;
    println!("AK {}", if created { "created" } else { "opened" });
    let (dk, created) = tpm.load_or_create_device_key("sentinel-probe-device")?;
    println!("device key {} ({:?})", if created { "created" } else { "opened" }, dk.algorithm()?);
    let public = tpm.key_public_area(&dk)?;
    println!("TPMT_PUBLIC {} bytes", public.len());
    let cert = tpm.certify_key(&dk, &ak, &[0x5a; 32])?;
    println!("certify ok: attest {} B, signature {} B", cert.attest.len(), cert.signature.len());
    Ok(())
}
