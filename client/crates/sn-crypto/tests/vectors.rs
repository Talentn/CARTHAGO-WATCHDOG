//! Golden vectors shared with backend/internal/protocol (proto/testvectors/).

use prost::Message;
use serde_json::Value;
use sn_crypto::aead::{open, seal, Direction};
use sn_crypto::*;
use sn_proto::v1 as pb;

fn load(name: &str) -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../proto/testvectors/");
    let s = std::fs::read_to_string(format!("{path}{name}")).unwrap_or_else(|e| panic!("{name}: {e}"));
    serde_json::from_str(&s).unwrap()
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

fn hx32(v: &Value) -> [u8; 32] {
    hx(v).try_into().expect("32 bytes")
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

fn unix(v: &Value) -> i64 {
    sn_crypto::time::parse_rfc3339(v.as_str().unwrap()).unwrap()
}

#[test]
fn token_vectors() {
    let v = load("token.json");
    let sk = SigningKey::from_bytes(&hx32(&v["signing_seed"]));
    assert_eq!(sk.verifying_key().as_bytes().to_vec(), hx(&v["public_key"]));
    let mut keys = TokenKeys::new();
    assert_eq!(keys.insert(sk.verifying_key()), s(&v["kid"]));
    let leeway = v["leeway_secs"].as_i64().unwrap();

    for c in v["valid"].as_array().unwrap() {
        let claims: Claims = serde_json::from_value(c["claims"].clone()).unwrap();
        assert_eq!(sign_token(&sk, &claims), s(&c["token"]), "{}: sign", c["name"]);
        let got = keys.verify(&s(&c["token"]), unix(&c["verify_at"]), leeway);
        assert_eq!(got.as_ref(), Ok(&claims), "{}: verify", c["name"]);
    }
    for c in v["invalid"].as_array().unwrap() {
        let err = keys.verify(&s(&c["token"]), unix(&c["verify_at"]), leeway).expect_err(c["name"].as_str().unwrap());
        assert_eq!(err.class(), c["error"].as_str().unwrap(), "{}: {err}", c["name"]);
    }
}

fn hello_from(h: &Value) -> pb::Hello {
    pb::Hello {
        protocol_version: h["protocol_version"].as_u64().unwrap() as u32,
        sdk_version: s(&h["sdk_version"]),
        tenant_id: s(&h["tenant_id"]),
        build_id: s(&h["build_id"]),
        client_eph_pub: hx(&h["client_eph_pub"]),
        device_key: Some(pb::DeviceKey { alg: h["device_key_alg"].as_i64().unwrap() as i32, public_key: hx(&h["device_key_public"]) }),
        player_id_hash: s(&h["player_id_hash"]),
        env: Some(pb::EnvReport {
            os_build: s(&h["env_os_build"]),
            elevated: h["env_elevated"].as_bool().unwrap(),
            tpm_present: h["env_tpm_present"].as_bool().unwrap(),
            tpm_manufacturer: s(&h["env_tpm_manufacturer"]),
        }),
        tpm_enrollment: Some(pb::TpmEnrollment {
            ek_public: hx(&h["enroll_ek_public"]),
            ek_certs: h["enroll_ek_certs"].as_array().unwrap().iter().map(hx).collect(),
            ak_public: hx(&h["enroll_ak_public"]),
            ak_create_data: hx(&h["enroll_ak_create_data"]),
            ak_create_attestation: hx(&h["enroll_ak_create_attestation"]),
            ak_create_signature: hx(&h["enroll_ak_create_signature"]),
            tpm_manufacturer: s(&h["enroll_tpm_manufacturer"]),
            tpm_firmware: s(&h["enroll_tpm_firmware"]),
        }),
        tpm_attestation_available: h["tpm_attestation_available"].as_bool().unwrap(),
        client_ts_ms: h["client_ts_ms"].as_u64().unwrap(),
    }
}

fn challenge_body_from(c: &Value) -> pb::ChallengeBody {
    pb::ChallengeBody {
        server_nonce: hx(&c["server_nonce"]),
        server_eph_pub: hx(&c["server_eph_pub"]),
        session_id: hx(&c["session_id"]),
        server_ts_ms: c["server_ts_ms"].as_u64().unwrap(),
        attest: Some(pb::AttestRequest {
            pcrs: c["attest_pcrs"].as_array().unwrap().iter().map(|p| p.as_u64().unwrap() as u32).collect(),
            ek_challenge: Some(pb::EkChallenge {
                object_public: hx(&c["attest_ek_object_public"]),
                duplicate: hx(&c["attest_ek_duplicate"]),
                in_sym_seed: hx(&c["attest_ek_in_sym_seed"]),
            }),
            certify_device_key: c["attest_certify_device_key"].as_bool().unwrap(),
        }),
        heartbeat_interval_ms: c["heartbeat_interval_ms"].as_u64().unwrap() as u32,
        heartbeat_timeout_ms: c["heartbeat_timeout_ms"].as_u64().unwrap() as u32,
    }
}

#[test]
fn handshake_vectors() {
    let v = load("handshake.json");
    let c_sec = hx32(&v["client_eph_secret"]);
    let s_sec = hx32(&v["server_eph_secret"]);
    assert_eq!(x25519_public(&c_sec).to_vec(), hx(&v["client_eph_pub"]));
    assert_eq!(x25519_public(&s_sec).to_vec(), hx(&v["server_eph_pub"]));

    let ident = SigningKey::from_bytes(&hx32(&v["server_identity_seed"]));
    assert_eq!(ident.verifying_key().as_bytes().to_vec(), hx(&v["server_identity_pub"]));
    assert_eq!(key_id(&ident.verifying_key()), s(&v["server_key_id"]));
    let dev = SigningKey::from_bytes(&hx32(&v["device_ed25519_seed"]));
    assert_eq!(dev.verifying_key().as_bytes().to_vec(), hx(&v["device_ed25519_pub"]));
    assert_eq!(device_id(pb::DeviceKeyAlg::Ed25519Software as u8, dev.verifying_key().as_bytes()), s(&v["device_id"]));

    let hello = hello_from(&v["hello"]);
    assert_eq!(hello.encode_to_vec(), hx(&v["hello_bytes"]), "prost Hello encoding differs from protobuf-go");
    let body = challenge_body_from(&v["challenge_body"]);
    assert_eq!(body.encode_to_vec(), hx(&v["challenge_body_bytes"]), "prost ChallengeBody encoding differs");
    let ch = pb::Challenge::decode(hx(&v["challenge_bytes"]).as_slice()).unwrap();
    assert_eq!(ch.body, hx(&v["challenge_body_bytes"]));
    assert_eq!(ch.encode_to_vec(), hx(&v["challenge_bytes"]));

    let th = transcript_hash(&hx(&v["hello_bytes"]), &ch.body);
    assert_eq!(th.to_vec(), hx(&v["transcript_hash"]));
    use ed25519_dalek::{Signer, Verifier};
    let sig = ident.sign(&challenge_sig_input(&th));
    assert_eq!(sig.to_bytes().to_vec(), ch.server_sig);
    assert_eq!(sig.to_bytes().to_vec(), hx(&v["server_sig"]));
    ident.verifying_key().verify(&challenge_sig_input(&th), &sig).unwrap();

    let shared = x25519(&c_sec, &x25519_public(&s_sec)).unwrap();
    assert_eq!(shared, x25519(&s_sec, &x25519_public(&c_sec)).unwrap());
    assert_eq!(shared.to_vec(), hx(&v["shared_secret"]));
    let keys = derive_keys(&shared, &th);
    assert_eq!(keys.c2s.to_vec(), hx(&v["key_c2s"]));
    assert_eq!(keys.s2c.to_vec(), hx(&v["key_s2c"]));
    let pd = prove_digest(&th);
    assert_eq!(pd.to_vec(), hx(&v["prove_digest"]));
    assert_eq!(quote_nonce(&th).to_vec(), hx(&v["quote_nonce"]));
    assert_eq!(dev.sign(&pd).to_bytes().to_vec(), hx(&v["device_sig"]));

    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let p = &v["p256_verify_only"];
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&hx(&p["public_sec1"])).unwrap();
    let sig = p256::ecdsa::Signature::from_slice(&hx(&p["signature_rs"])).unwrap();
    vk.verify_prehash(&pd, &sig).expect("P-256 prove signature");
    assert_eq!(device_id(pb::DeviceKeyAlg::EcdsaP256Tpm as u8, &hx(&p["public_sec1"])), s(&p["device_id"]));

    assert_eq!(x25519(&c_sec, &[0u8; 32]), Err(Error::LowOrderPoint));
}

fn dir(v: &Value) -> Direction {
    match v.as_u64().unwrap() {
        0 => Direction::ClientToServer,
        _ => Direction::ServerToClient,
    }
}

#[test]
fn aead_vectors() {
    let v = load("aead.json");
    let key = hx32(&v["key"]);
    let sid = hx(&v["session_id"]);
    for c in v["valid"].as_array().unwrap() {
        let (d, seq, pt) = (dir(&c["direction"]), c["seq"].as_u64().unwrap(), hx(&c["plaintext"]));
        assert_eq!(seal(&key, &sid, d, seq, &pt), hx(&c["frame"]), "{}: seal", c["name"]);
        assert_eq!(open(&key, &sid, d, seq, &hx(&c["frame"])).as_ref(), Ok(&pt), "{}: open", c["name"]);
        let reencoded = match c["message_type"].as_str().unwrap() {
            "ClientMsg" => pb::ClientMsg::decode(pt.as_slice()).unwrap().encode_to_vec(),
            "ServerMsg" => pb::ServerMsg::decode(pt.as_slice()).unwrap().encode_to_vec(),
            other => panic!("unknown message type {other}"),
        };
        assert_eq!(reencoded, pt, "{}: prost re-encoding differs from protobuf-go", c["name"]);
    }
    for c in v["invalid"].as_array().unwrap() {
        let err = open(&key, &sid, dir(&c["direction"]), c["seq"].as_u64().unwrap(), &hx(&c["frame"])).expect_err("must fail");
        assert_eq!(err.class(), c["error"].as_str().unwrap(), "{}", c["name"]);
    }
}

#[test]
fn channel_roundtrip_and_replay() {
    let keys = derive_keys(&[7u8; 32], &[9u8; 32]);
    let sid = [1u8; 16];
    let (mut c, mut s) = (Channel::client(&keys, &sid), Channel::server(&keys, &sid));
    let f0 = c.seal_next(b"hello");
    assert_eq!(s.open_next(&f0).unwrap(), (0, b"hello".to_vec()));
    assert_eq!(s.open_next(&f0).unwrap_err().class(), "seq");
    let back = s.seal_next(b"ack");
    assert_eq!(c.open_next(&back).unwrap().1, b"ack");
}
