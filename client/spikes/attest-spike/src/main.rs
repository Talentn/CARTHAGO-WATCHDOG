//! Phase 0 risk spike 1 client: TPM device key + AK enrollment + quote + WBCL, verified by
//! the Go verifier in `backend/cmd/attest-spike`.
//!
//! Flow: enroll (EK + AK creation evidence) -> activate credential -> quote over the
//! Windows PCRs bound to the server nonce, plus the WBCL and a device-key signature.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sn_attest::{AttestationKey, Key, Tpm, ALG_SHA256, WINDOWS_ATTEST_PCRS};

mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }

    pub mod vec {
        use super::*;
        use serde::ser::SerializeSeq;
        pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(v.len()))?;
            for item in v {
                seq.serialize_element(&STANDARD.encode(item))?;
            }
            seq.end()
        }
    }
}

#[derive(Serialize)]
struct Step {
    name: &'static str,
    ok: bool,
    ms: u128,
    detail: String,
    error_code: Option<String>,
    access_denied: bool,
}

#[derive(Default)]
struct Steps(Vec<Step>);

impl Steps {
    fn run<T>(&mut self, name: &'static str, f: impl FnOnce() -> sn_attest::Result<T>, detail: impl Fn(&T) -> String) -> sn_attest::Result<T> {
        let t = Instant::now();
        let r = f();
        let ms = t.elapsed().as_millis();
        let step = match &r {
            Ok(v) => Step { name, ok: true, ms, detail: detail(v), error_code: None, access_denied: false },
            Err(e) => Step {
                name,
                ok: false,
                ms,
                detail: e.to_string(),
                error_code: e.code().map(|c| format!("0x{c:08X}")),
                access_denied: e.is_access_denied(),
            },
        };
        println!(
            "  [{}] {:<28} {:>6} ms  {}",
            if step.ok { " ok " } else { "FAIL" },
            step.name,
            step.ms,
            step.detail
        );
        self.0.push(step);
        r
    }
}

#[derive(Serialize)]
struct TpmInfoJson {
    manufacturer: String,
    manufacturer_raw: u32,
    vendor_string: String,
    firmware_version: String,
    kind: String,
    spec: String,
    vendor_tpm_type: u32,
    interface_type: u32,
    interface: String,
    pcp_platform_type: Option<String>,
    pcp_provider_version: Option<String>,
}

#[derive(Serialize)]
struct AkJson {
    #[serde(with = "b64")]
    public: Vec<u8>,
    #[serde(with = "b64")]
    create_data: Vec<u8>,
    #[serde(with = "b64")]
    create_attestation: Vec<u8>,
    #[serde(with = "b64")]
    create_signature: Vec<u8>,
}

#[derive(Serialize)]
struct ClientContext {
    elevated: Option<bool>,
    integrity: String,
    ak_created_this_run: bool,
    device_key_created_this_run: bool,
}

#[derive(Serialize)]
struct EnrollRequest {
    tpm: TpmInfoJson,
    #[serde(with = "b64")]
    ek_public: Vec<u8>,
    #[serde(with = "b64::vec")]
    ek_certs: Vec<Vec<u8>>,
    ak: AkJson,
    device_key_alg: String,
    #[serde(with = "b64")]
    device_key_public: Vec<u8>,
    client: ClientContext,
}

#[derive(Deserialize)]
struct EkChallenge {
    #[serde(with = "b64")]
    object_public: Vec<u8>,
    #[serde(with = "b64")]
    duplicate: Vec<u8>,
    #[serde(with = "b64")]
    in_sym_seed: Vec<u8>,
}

#[derive(Deserialize)]
struct EnrollResponse {
    enrollment_id: String,
    #[serde(with = "b64")]
    activation_blob: Vec<u8>,
    ek_challenge: EkChallenge,
}

#[derive(Serialize)]
struct ActivateRequest<'a> {
    enrollment_id: &'a str,
    method: &'static str,
    #[serde(with = "b64", skip_serializing_if = "Vec::is_empty")]
    secret: Vec<u8>,
    #[serde(with = "b64", skip_serializing_if = "Vec::is_empty")]
    certify_attest: Vec<u8>,
    #[serde(with = "b64", skip_serializing_if = "Vec::is_empty")]
    certify_signature: Vec<u8>,
}

#[derive(Deserialize)]
struct ActivateResponse {
    #[serde(with = "b64")]
    nonce: Vec<u8>,
}

#[derive(Serialize)]
struct PcrJson {
    index: u32,
    #[serde(with = "b64")]
    digest: Vec<u8>,
}

#[derive(Serialize)]
struct AttestRequest<'a> {
    enrollment_id: &'a str,
    #[serde(with = "b64")]
    nonce: Vec<u8>,
    #[serde(with = "b64")]
    quote: Vec<u8>,
    #[serde(with = "b64")]
    quote_signature: Vec<u8>,
    pcrs: Vec<PcrJson>,
    #[serde(with = "b64")]
    event_log: Vec<u8>,
    #[serde(with = "b64")]
    device_signature: Vec<u8>,
    steps: &'a [Step],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Activation {
    /// EK challenge first (works unelevated), then the PCP activation property.
    Auto,
    /// Decryption-EK challenge: TPM2_Import/Load under the EK, then TPM2_Certify of the AK.
    EkCertify,
    /// `PCP_TPM12_IDACTIVATION`; the PCP requires administrator rights for this.
    Pcp,
    /// TPM2_ActivateCredential sent directly over TBS (blocked for standard users).
    TbsActivate,
}

struct Args {
    server: String,
    out: PathBuf,
    ak_name: String,
    device_key_name: String,
    activation: Activation,
}

fn parse_args() -> Result<Args> {
    let mut a = Args {
        server: "http://127.0.0.1:8740".into(),
        out: PathBuf::from("attest-out"),
        ak_name: "sentinel-spike-ak".into(),
        device_key_name: "sentinel-spike-device".into(),
        activation: Activation::Auto,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or_else(|| anyhow!("{flag} needs a value"));
        match flag.as_str() {
            "--server" => a.server = val()?,
            "--out" => a.out = PathBuf::from(val()?),
            "--ak-name" => a.ak_name = val()?,
            "--device-key-name" => a.device_key_name = val()?,
            "--activation" => {
                a.activation = match val()?.as_str() {
                    "auto" => Activation::Auto,
                    "ek-certify" => Activation::EkCertify,
                    "pcp" => Activation::Pcp,
                    "tbs-activate" => Activation::TbsActivate,
                    other => bail!("--activation must be auto, ek-certify, pcp or tbs-activate (got {other})"),
                }
            }
            "-h" | "--help" => {
                println!(
                    "attest-spike [--server URL] [--out DIR] [--ak-name NAME] [--device-key-name NAME] [--activation auto|ek-certify|pcp|tbs-activate]"
                );
                std::process::exit(0);
            }
            other => bail!("unknown argument {other}"),
        }
    }
    Ok(a)
}

fn post<Req: Serialize, Resp: for<'de> Deserialize<'de>>(agent: &ureq::Agent, url: &str, body: &Req) -> Result<Resp> {
    let mut resp = agent.post(url).send_json(body).with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    let text = resp.body_mut().read_to_string()?;
    if !status.is_success() {
        bail!("POST {url}: HTTP {status}: {text}");
    }
    serde_json::from_str(&text).with_context(|| format!("decoding response from {url}"))
}

fn ak_cache_path(name: &str) -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    base.join("Sentinel").join("spike").join(format!("{name}.idbinding"))
}

fn write(out: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    std::fs::write(out.join(name), bytes).with_context(|| format!("writing {name}"))
}

fn main() -> Result<()> {
    let args = parse_args()?;
    std::fs::create_dir_all(&args.out)?;
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
    let mut steps = Steps::default();

    let token = sn_attest::current_token();
    println!(
        "process: elevated={:?} integrity={}",
        token.map(|t| t.elevated),
        token.map(|t| t.integrity_name()).unwrap_or("unknown")
    );

    println!("TPM / PCP:");
    let tpm = steps.run("open PCP provider", Tpm::open, |_| String::new())?;
    let info = steps.run("TPM2_GetCapability", || tpm.info(), |i| {
        format!("{} ({}) fw {} vendor '{}'", i.manufacturer, i.kind, i.firmware_version, i.vendor_string)
    })?;
    let ek_public = steps.run("read EK public (PCP_EKPUB)", || tpm.ek_public(), |b| format!("{} bytes", b.len()))?;
    let mut ek_certs = Vec::new();
    for (prop, result) in tpm.ek_certificates() {
        let label: &'static str = match prop {
            "PCP_RSA_EKNVCERT" => "EK cert (PCP_RSA_EKNVCERT)",
            "PCP_ECC_EKNVCERT" => "EK cert (PCP_ECC_EKNVCERT)",
            _ => "EK cert (PCP_EKNVCERT)",
        };
        if let Ok(certs) = steps.run(label, || result, |c| format!("{} cert(s)", c.len())) {
            for c in certs {
                if !ek_certs.contains(&c) {
                    ek_certs.push(c);
                }
            }
        }
    }
    // The spike server treats certificates that do not match the EK as intermediates.
    if let Ok(indices) = steps.run("EK chain NV indices (0x01C00100..)", || tpm.ek_chain_certificates(), |r| {
        r.iter()
            .map(|(i, c)| match c {
                Ok(c) => format!("0x{i:08X}: {} cert(s)", c.len()),
                Err(e) => format!("0x{i:08X}: {e}"),
            })
            .collect::<Vec<_>>()
            .join("; ")
    }) {
        for (index, certs) in indices {
            for (n, c) in certs.into_iter().flatten().enumerate() {
                write(&args.out, &format!("ek-chain-{index:08x}-{n}.der"), &c)?;
                if !ek_certs.contains(&c) {
                    ek_certs.push(c);
                }
            }
        }
    }

    let cache = ak_cache_path(&args.ak_name);
    let cached = std::fs::read(&cache).ok();
    let (ak, ak_created, binding): (AttestationKey, bool, Vec<u8>) = steps.run(
        "load/create AK (identity key)",
        || tpm.load_or_create_ak(&args.ak_name, cached.as_deref()),
        |(_, created, _)| format!("{} '{}'", if *created { "created" } else { "opened existing" }, args.ak_name),
    )?;
    if let Some(dir) = cache.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&cache, &binding)?;

    let (device_key, dk_created): (Key, bool) = steps.run(
        "load/create device key",
        || tpm.load_or_create_device_key(&args.device_key_name),
        |(_, created)| format!("{} '{}'", if *created { "created" } else { "opened existing" }, args.device_key_name),
    )?;
    let dk_alg = device_key.algorithm()?;
    let dk_export_policy = device_key.u32_property("Export Policy").ok();
    let device_key_public = steps.run("export device key public", || device_key.export_public(), |b| {
        format!("{dk_alg:?}, {} bytes, export policy {:?}", b.len(), dk_export_policy)
    })?;

    let enroll = EnrollRequest {
        tpm: TpmInfoJson {
            manufacturer: info.manufacturer.clone(),
            manufacturer_raw: info.manufacturer_raw,
            vendor_string: info.vendor_string.clone(),
            firmware_version: info.firmware_version.clone(),
            kind: info.kind.to_string(),
            spec: format!("{} level {} rev {} ({})", info.spec_family, info.spec_level, info.spec_revision, info.spec_year),
            vendor_tpm_type: info.vendor_tpm_type,
            interface_type: info.device.interface_type,
            interface: info.device.interface_name().to_string(),
            pcp_platform_type: info.pcp_platform_type.clone(),
            pcp_provider_version: info.pcp_provider_version.clone(),
        },
        ek_public,
        ek_certs,
        ak: AkJson {
            public: ak.params.public.clone(),
            create_data: ak.params.create_data.clone(),
            create_attestation: ak.params.create_attestation.clone(),
            create_signature: ak.params.create_signature.clone(),
        },
        device_key_alg: format!("{dk_alg:?}"),
        device_key_public,
        client: ClientContext {
            elevated: token.map(|t| t.elevated),
            integrity: token.map(|t| t.integrity_name()).unwrap_or("unknown").into(),
            ak_created_this_run: ak_created,
            device_key_created_this_run: dk_created,
        },
    };
    write(&args.out, "enroll-request.json", &serde_json::to_vec_pretty(&enroll)?)?;

    println!("verifier {}:", args.server);
    let enrolled: EnrollResponse = post(&agent, &format!("{}/v1/enroll", args.server), &enroll)?;
    println!("  enrolled as {}", enrolled.enrollment_id);

    let recovered = |s: &Vec<u8>| format!("recovered {}-byte secret", s.len());
    let activation_secret = |secret| ActivateRequest {
        enrollment_id: &enrolled.enrollment_id,
        method: "activate-credential",
        secret,
        certify_attest: Vec::new(),
        certify_signature: Vec::new(),
    };
    let mut proof = None;
    if matches!(args.activation, Activation::Auto | Activation::EkCertify | Activation::TbsActivate) {
        let ek_handle = steps.run("find persistent RSA EK", || tpm.persistent_rsa_ek(), |h| format!("0x{h:08X}"))?;
        if args.activation == Activation::TbsActivate {
            proof = steps
                .run(
                    "ActivateCredential (raw TBS)",
                    || tpm.activate_credential_tbs(&ak, ek_handle, &enrolled.activation_blob),
                    recovered,
                )
                .ok()
                .map(activation_secret);
        } else {
            let c = &enrolled.ek_challenge;
            proof = steps
                .run(
                    "EK challenge: Import/Load/Certify",
                    || tpm.certify_ak_with_ek(&ak, ek_handle, &c.object_public, &c.duplicate, &c.in_sym_seed),
                    |cert| format!("certify attest {} B, HMAC sig {} B", cert.attest.len(), cert.signature.len()),
                )
                .ok()
                .map(|cert| ActivateRequest {
                    enrollment_id: &enrolled.enrollment_id,
                    method: "ek-certify",
                    secret: Vec::new(),
                    certify_attest: cert.attest,
                    certify_signature: cert.signature,
                });
        }
    }
    if proof.is_none() && matches!(args.activation, Activation::Auto | Activation::Pcp) {
        proof = steps
            .run("ActivateCredential (PCP prop)", || ak.activate_credential(&enrolled.activation_blob), recovered)
            .ok()
            .map(activation_secret);
    }
    let proof = proof.ok_or_else(|| anyhow!("could not bind the AK to the EK"))?;
    let activated: ActivateResponse = post(&agent, &format!("{}/v1/activate", args.server), &proof)?;
    println!("  AK bound to EK via {}; server nonce {} bytes", proof.method, activated.nonce.len());

    let nonce = activated.nonce;
    let quote = steps.run(
        "TPM2_Quote (TBS via PCP)",
        || tpm.quote(&ak, &nonce, ALG_SHA256, &WINDOWS_ATTEST_PCRS),
        |q| format!("PCRs {WINDOWS_ATTEST_PCRS:?} sha256, attest {} B, sig {} B", q.attest.len(), q.signature.len()),
    )?;
    let pcrs = steps.run("TPM2_PCR_Read", || tpm.read_pcrs(ALG_SHA256, &WINDOWS_ATTEST_PCRS), |p| format!("{} PCRs", p.len()))?;
    let event_log = steps.run("Tbsi_Get_TCG_Log_Ex (WBCL)", sn_attest::tcg_log, |l| format!("{} bytes", l.len()))?;

    let mut h = Sha256::new();
    h.update(&nonce);
    h.update(&quote.attest);
    let digest: [u8; 32] = h.finalize().into();
    let device_signature = steps.run("device key sign(nonce||quote)", || device_key.sign_sha256(&digest), |s| {
        format!("{} bytes", s.len())
    })?;

    write(&args.out, "wbcl.bin", &event_log)?;
    let attest = AttestRequest {
        enrollment_id: &enrolled.enrollment_id,
        nonce,
        quote: quote.attest,
        quote_signature: quote.signature,
        pcrs: pcrs.into_iter().map(|(index, digest)| PcrJson { index, digest }).collect(),
        event_log,
        device_signature,
        steps: &steps.0,
    };
    write(&args.out, "attest-request.json", &serde_json::to_vec_pretty(&attest)?)?;
    let report: serde_json::Value = post(&agent, &format!("{}/v1/attest", args.server), &attest)?;
    let pretty = serde_json::to_string_pretty(&report)?;
    write(&args.out, "report.json", pretty.as_bytes())?;

    println!("verifier report:\n{pretty}");
    println!("evidence written to {}", args.out.display());
    if report.get("verdict").and_then(|v| v.as_str()) != Some("pass") {
        std::process::exit(2);
    }
    Ok(())
}
