use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use rcgen::PublicKeyData;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};
use tungstenite::Message;

use super::*;

struct TestServer {
    url: String,
    pin: Pin,
    /// What the server saw: Ok(first text message) or Err(TLS/WebSocket failure).
    seen: mpsc::Receiver<Result<String, String>>,
}

/// One-connection pinned-TLS WebSocket echo server with a fresh self-signed key.
fn tls_server(reply_delay: Duration) -> TestServer {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    // The expected pin comes from the key pair, independently of the client's certificate parsing.
    let pin: Pin = Sha256::digest(ck.signing_key.subject_public_key_info()).into();
    let cert = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let cfg = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let cfg = Arc::new(cfg);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, seen) = mpsc::channel();
    thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let tls = StreamOwned::new(ServerConnection::new(cfg).unwrap(), tcp);
        let mut ws = match tungstenite::accept(tls) {
            Ok(ws) => ws,
            Err(e) => {
                let _ = tx.send(Err(e.to_string()));
                return;
            }
        };
        match ws.read() {
            Ok(Message::Text(t)) => {
                let _ = tx.send(Ok(t.to_string()));
                thread::sleep(reply_delay);
                let _ = ws.send(Message::Text(format!("echo {t}").into()));
                let _ = ws.flush();
                let _ = ws.read();
            }
            other => {
                let _ = tx.send(Err(format!("{other:?}")));
            }
        }
    });
    TestServer { url: format!("wss://localhost:{port}/v1/client"), pin, seen }
}

fn roundtrip(ws: &mut WebSocket<Stream>, msg: &str) -> String {
    ws.send(Message::Text(msg.into())).unwrap();
    loop {
        match ws.read() {
            Ok(Message::Text(t)) => return t.to_string(),
            Ok(_) => {}
            Err(e) if is_timeout(&e) => {}
            Err(e) => panic!("read: {e}"),
        }
    }
}

#[test]
fn correct_pin_connects_over_tls13() {
    let s = tls_server(Duration::ZERO);
    let mut ws = connect(s.url.as_str(), &[s.pin], Duration::from_secs(5)).unwrap();
    match ws.get_ref() {
        Stream::Tls(t) => assert_eq!(t.conn.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3)),
        Stream::Plain(_) => panic!("wss:// produced a plaintext stream"),
    }
    assert_eq!(roundtrip(&mut ws, "hello"), "echo hello");
    assert_eq!(s.seen.recv().unwrap().unwrap(), "hello");
}

#[test]
fn backup_pin_is_accepted() {
    let s = tls_server(Duration::ZERO);
    let mut ws = connect(s.url.as_str(), &[[7u8; 32], s.pin], Duration::from_secs(5)).unwrap();
    assert_eq!(roundtrip(&mut ws, "backup"), "echo backup");
}

#[test]
fn wrong_pin_is_rejected_before_any_application_data() {
    let s = tls_server(Duration::ZERO);
    let mut wrong = s.pin;
    wrong[0] ^= 0x80;
    match connect(s.url.as_str(), &[wrong], Duration::from_secs(5)) {
        Err(NetError::PinMismatch { got }) => assert_eq!(got, hex::encode(s.pin)),
        Err(e) => panic!("expected PinMismatch, got {e}"),
        Ok(_) => panic!("connected with a wrong pin"),
    }
    // The server never received an HTTP upgrade, let alone a WebSocket message.
    assert!(s.seen.recv_timeout(Duration::from_secs(5)).unwrap().is_err());
}

#[test]
fn reads_time_out_and_resume_over_tls() {
    let s = tls_server(Duration::from_millis(300));
    let mut ws = connect(s.url.as_str(), &[s.pin], Duration::from_secs(5)).unwrap();
    ws.get_ref().set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    ws.send(Message::Text("slow".into())).unwrap();
    let mut timeouts = 0;
    let reply = loop {
        match ws.read() {
            Ok(Message::Text(t)) => break t.to_string(),
            Ok(_) => {}
            Err(e) if is_timeout(&e) => timeouts += 1,
            Err(e) => panic!("read: {e}"),
        }
    };
    assert_eq!(reply, "echo slow");
    assert!(timeouts >= 3, "expected the 20 ms read timeout to fire while waiting ({timeouts})");
}

#[test]
fn policy_rejects_unpinned_tls_and_remote_plaintext() {
    assert!(matches!(connect("wss://localhost:1/v1/client", &[], Duration::from_secs(1)), Err(NetError::Policy(_))));
    assert!(matches!(connect("ws://203.0.113.7:8750/v1/client", &[], Duration::from_secs(1)), Err(NetError::Policy(_))));
    assert!(matches!(connect("http://127.0.0.1:1/", &[], Duration::from_secs(1)), Err(NetError::Url(_))));
    assert!(is_loopback("127.0.0.1") && is_loopback("[::1]") && is_loopback("localhost") && !is_loopback("example.com"));
}

#[test]
fn pin_parsing() {
    let a = "11".repeat(32);
    let b = "22".repeat(32);
    assert_eq!(parse_pins(&format!("{a}, {b}")).unwrap(), vec![[0x11; 32], [0x22; 32]]);
    assert!(parse_pins("abcd").is_err());
    assert!(parse_pins("zz").is_err());
    assert!(parse_pins("").unwrap().is_empty());
}

#[test]
fn spki_pin_matches_key_pair() {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let want: Pin = Sha256::digest(ck.signing_key.subject_public_key_info()).into();
    assert_eq!(spki_pin(ck.cert.der()).unwrap(), want);
}
