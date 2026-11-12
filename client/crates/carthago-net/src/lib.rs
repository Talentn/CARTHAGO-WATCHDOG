//! Carthago Watchdog gateway transport (plan §5.1): a synchronous WebSocket over TLS 1.3
//! (rustls, no async runtime) that trusts the gateway only by its pinned public key.
//!
//! A pin is the SHA-256 of the server certificate's DER `SubjectPublicKeyInfo`. Certificate
//! authorities, hostnames and validity dates are not consulted: a matching key is the
//! gateway, anything else is rejected, so an attacker-installed root CA gains nothing. Ship
//! the current key's pin plus a backup so the gateway key can rotate.
//!
//! `ws://` stays available for loopback development only.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, OtherError, SignatureScheme, StreamOwned};
use sha2::{Digest, Sha256};
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::WebSocket;

/// Largest WebSocket message accepted from the gateway. Its messages (Challenge, Session,
/// heartbeat acks, kicks, ingest acks) are a few kilobytes; the library default of 64 MiB
/// would let a peer make the game process buffer more than the client's whole memory budget.
pub const MAX_MESSAGE: usize = 1 << 20;

/// SHA-256 of a DER `SubjectPublicKeyInfo`.
pub type Pin = [u8; 32];

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("bad gateway URL: {0}")]
    Url(String),
    #[error("{0}")]
    Policy(&'static str),
    #[error("connect {addr}: {err}")]
    Connect { addr: String, err: io::Error },
    #[error("gateway public key {got} matches no pinned key")]
    PinMismatch { got: String },
    #[error("TLS: {0}")]
    Tls(String),
    #[error("WebSocket: {0}")]
    WebSocket(String),
}

/// Parses comma- or whitespace-separated hex SHA-256 SPKI pins.
pub fn parse_pins(s: &str) -> Result<Vec<Pin>, String> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|p| !p.is_empty())
        .map(|p| {
            let b = hex::decode(p).map_err(|e| format!("pin {p:?}: {e}"))?;
            <Pin>::try_from(b.as_slice()).map_err(|_| format!("pin {p:?}: want 32 bytes (SHA-256 of the SPKI)"))
        })
        .collect()
}

/// The pin of a DER X.509 certificate.
pub fn spki_pin(cert_der: &[u8]) -> Result<Pin, String> {
    let der = CertificateDer::from(cert_der);
    let cert = webpki::EndEntityCert::try_from(&der).map_err(|e| format!("certificate: {e}"))?;
    Ok(Sha256::digest(cert.subject_public_key_info().as_ref()).into())
}

/// A gateway connection, plain (loopback development) or pinned TLS.
pub enum Stream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Stream {
    pub fn tcp(&self) -> &TcpStream {
        match self {
            Stream::Plain(s) => s,
            Stream::Tls(s) => &s.sock,
        }
    }

    pub fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        self.tcp().set_read_timeout(t)
    }

    pub fn is_tls(&self) -> bool {
        matches!(self, Stream::Tls(_))
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

#[derive(Debug)]
struct PinMismatch(String);

impl std::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server key {} is not pinned", self.0)
    }
}

impl std::error::Error for PinMismatch {}

#[derive(Debug)]
struct PinVerifier {
    pins: Vec<Pin>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = spki_pin(end_entity).map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        // Pins are public values, so a plain comparison leaks nothing worth protecting.
        if self.pins.contains(&got) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(PinMismatch(hex::encode(got)))))))
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS 1.3-only client configuration that accepts exactly the pinned server keys.
pub fn pinned_config(pins: &[Pin]) -> Result<Arc<ClientConfig>, NetError> {
    if pins.is_empty() {
        return Err(NetError::Policy("wss:// requires at least one pinned gateway key"));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinVerifier { pins: pins.to_vec(), provider: provider.clone() });
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| NetError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

fn map_tls_err(e: io::Error) -> NetError {
    if let Some(rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(inner)))) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        if let Some(PinMismatch(got)) = inner.downcast_ref::<PinMismatch>() {
            return NetError::PinMismatch { got: got.clone() };
        }
    }
    NetError::Tls(e.to_string())
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The addresses a plaintext connection may go to. "localhost" is only a name: a hosts file
/// or resolver can point it anywhere, so what counts is the address it resolved to.
fn plaintext_targets(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addrs.into_iter().filter(|a| a.ip().is_loopback()).collect()
}

/// Opens a WebSocket to the gateway. `wss://` performs a pinned TLS 1.3 handshake before
/// any HTTP is sent; `ws://` is refused unless the host is loopback.
pub fn connect<R: IntoClientRequest>(request: R, pins: &[Pin], connect_timeout: Duration) -> Result<WebSocket<Stream>, NetError> {
    connect_observed(request, pins, connect_timeout, &|_| {})
}

/// [`connect`], handing the TCP socket to `on_tcp` before the first byte is exchanged. The
/// TLS and WebSocket handshakes block for up to the 30 s socket timeout each; a caller that
/// keeps a clone of the socket can shut it down from another thread to end them at once.
pub fn connect_observed<R: IntoClientRequest>(
    request: R,
    pins: &[Pin],
    connect_timeout: Duration,
    on_tcp: &dyn Fn(&TcpStream),
) -> Result<WebSocket<Stream>, NetError> {
    let req = request.into_client_request().map_err(|e| NetError::Url(e.to_string()))?;
    let uri = req.uri().clone();
    let host = uri.host().ok_or_else(|| NetError::Url("URL has no host".into()))?.to_owned();
    let tls = match uri.scheme_str() {
        Some("wss") => true,
        Some("ws") if is_loopback(&host) => false,
        Some("ws") => return Err(NetError::Policy("ws:// is allowed on loopback only; use wss:// with a pinned gateway key")),
        _ => return Err(NetError::Url(format!("unsupported scheme in {uri}"))),
    };
    let config = if tls { Some(pinned_config(pins)?) } else { None };
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let bare = host.trim_matches(|c| c == '[' || c == ']').to_owned();
    let mut addrs: Vec<_> = (bare.as_str(), port).to_socket_addrs().map_err(|err| NetError::Connect { addr: format!("{bare}:{port}"), err })?.collect();
    if !tls {
        addrs = plaintext_targets(addrs);
        if addrs.is_empty() {
            return Err(NetError::Policy("ws:// host does not resolve to a loopback address; use wss:// with a pinned gateway key"));
        }
    }
    let mut last = None;
    let mut tcp = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, connect_timeout) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(err) => last = Some(NetError::Connect { addr: addr.to_string(), err }),
        }
    }
    let mut tcp = tcp.ok_or_else(|| last.unwrap_or_else(|| NetError::Url(format!("{bare} did not resolve"))))?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(30))).ok();
    on_tcp(&tcp);

    let stream = match config {
        None => Stream::Plain(tcp),
        Some(cfg) => {
            let name = ServerName::try_from(bare).map_err(|e| NetError::Url(e.to_string()))?;
            let mut conn = ClientConnection::new(cfg, name).map_err(|e| NetError::Tls(e.to_string()))?;
            while conn.is_handshaking() {
                conn.complete_io(&mut tcp).map_err(map_tls_err)?;
            }
            Stream::Tls(Box::new(StreamOwned::new(conn, tcp)))
        }
    };
    let limits = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
    let (ws, _) = tungstenite::client::client_with_config(req, stream, Some(limits)).map_err(|e| NetError::WebSocket(e.to_string()))?;
    Ok(ws)
}

/// True for read-timeout errors that only mean "no frame yet".
pub fn is_timeout(e: &tungstenite::Error) -> bool {
    matches!(e, tungstenite::Error::Io(io) if matches!(io.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut))
}

#[cfg(test)]
mod tests;
