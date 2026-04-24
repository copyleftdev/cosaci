//! mTLS helpers — CA generation, cert issuance, client/server config.
//!
//! Source: closes `hypotheses/mtls-enforcement.md` (Tier 3 C-class).
//! In-process rustls handshake pipeline; no network, no system CA
//! trust store. Harness for exercising CosaCI's mTLS enforcement at
//! the algebraic layer (certificate chain validity) without running
//! real servers.

use std::sync::Arc;

use rcgen::{CertificateParams, DnType, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

const SERVER_NAME: &str = "cosaci.local";

/// A self-signed CA — signs end-entity (client / server) certs.
pub struct TestCa {
    cert_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

/// A CA-signed certificate bundle with its private key. Owned, static
/// lifetime for simple threading.
pub struct IssuedCert {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
}

impl TestCa {
    pub fn generate(name: &str) -> Result<Self, rcgen::Error> {
        let signing_key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&signing_key)?;
        let cert_der = cert.der().clone();
        let issuer = Issuer::new(params, signing_key);
        Ok(Self { cert_der, issuer })
    }

    /// Issue a new end-entity certificate (client or server) bound to
    /// `subject_name`. For server certs this is the SAN; for client
    /// certs it's informational.
    pub fn issue(&self, subject_name: &str) -> Result<IssuedCert, rcgen::Error> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![subject_name.to_string()])?;
        params.distinguished_name.push(DnType::CommonName, subject_name);
        let cert = params.signed_by(&key, &self.issuer)?;
        let cert_der = cert.der().clone();
        let key_der: PrivateKeyDer<'static> =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        Ok(IssuedCert { cert_der, key_der })
    }

    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }
}

/// Build a `RootCertStore` trusting this CA's root.
pub fn root_store_from(ca: &TestCa) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der().clone()).expect("valid CA cert");
    Arc::new(roots)
}

/// Build a server config that requires client authentication against
/// `trust_roots`, using `server_cert` as its identity.
pub fn server_config(
    server_cert: &IssuedCert,
    trust_roots: Arc<RootCertStore>,
) -> Result<Arc<ServerConfig>, String> {
    let verifier = WebPkiClientVerifier::builder(trust_roots)
        .build()
        .map_err(|e| format!("client verifier build: {e}"))?;
    let key = clone_key(&server_cert.key_der);
    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server_cert.cert_der.clone()], key)
        .map_err(|e| format!("with_single_cert: {e}"))?;
    Ok(Arc::new(cfg))
}

/// Build a client config that trusts `trust_roots` for server verification
/// and authenticates with `client_cert`.
pub fn client_config(
    client_cert: &IssuedCert,
    trust_roots: Arc<RootCertStore>,
) -> Result<Arc<ClientConfig>, String> {
    let key = clone_key(&client_cert.key_der);
    let cfg = ClientConfig::builder()
        .with_root_certificates((*trust_roots).clone())
        .with_client_auth_cert(vec![client_cert.cert_der.clone()], key)
        .map_err(|e| format!("with_client_auth_cert: {e}"))?;
    Ok(Arc::new(cfg))
}

/// Build a client config with NO client cert (for testing the
/// "connection with no cert → rejected" claim).
pub fn client_config_no_cert(trust_roots: Arc<RootCertStore>) -> Arc<ClientConfig> {
    let cfg = ClientConfig::builder()
        .with_root_certificates((*trust_roots).clone())
        .with_no_client_auth();
    Arc::new(cfg)
}

/// Run a TLS handshake over in-memory byte buffers. Returns `Ok(())`
/// iff both sides completed the handshake; `Err(_)` captures either
/// side's fatal alert or exhaustion without progress.
pub fn try_handshake(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
) -> Result<(), String> {
    let server_name = ServerName::try_from(SERVER_NAME)
        .map_err(|e| format!("invalid server name: {e}"))?;
    let mut client = ClientConnection::new(client_cfg, server_name)
        .map_err(|e| format!("ClientConnection::new: {e}"))?;
    let mut server =
        ServerConnection::new(server_cfg).map_err(|e| format!("ServerConnection::new: {e}"))?;

    let mut c_to_s: Vec<u8> = Vec::new();
    let mut s_to_c: Vec<u8> = Vec::new();

    for _step in 0..50 {
        // Client → Server
        if client.wants_write() {
            client
                .write_tls(&mut c_to_s)
                .map_err(|e| format!("client write_tls: {e}"))?;
        }
        if !c_to_s.is_empty() {
            let bytes = std::mem::take(&mut c_to_s);
            let mut cursor: &[u8] = &bytes;
            server
                .read_tls(&mut cursor)
                .map_err(|e| format!("server read_tls: {e}"))?;
            server
                .process_new_packets()
                .map_err(|e| format!("server process_new_packets: {e}"))?;
        }

        // Server → Client
        if server.wants_write() {
            server
                .write_tls(&mut s_to_c)
                .map_err(|e| format!("server write_tls: {e}"))?;
        }
        if !s_to_c.is_empty() {
            let bytes = std::mem::take(&mut s_to_c);
            let mut cursor: &[u8] = &bytes;
            client
                .read_tls(&mut cursor)
                .map_err(|e| format!("client read_tls: {e}"))?;
            client
                .process_new_packets()
                .map_err(|e| format!("client process_new_packets: {e}"))?;
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Err("handshake did not converge within step budget".into())
}

/// Clone a `PrivateKeyDer` — `PrivateKeyDer` doesn't implement `Clone`
/// for security reasons, but we need two copies when building both
/// server and client configs that share a key (test harness only).
fn clone_key(k: &PrivateKeyDer<'static>) -> PrivateKeyDer<'static> {
    match k {
        PrivateKeyDer::Pkcs8(pkcs8) => {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.secret_pkcs8_der().to_vec()))
        }
        PrivateKeyDer::Pkcs1(pkcs1) => PrivateKeyDer::Pkcs1(
            rustls::pki_types::PrivatePkcs1KeyDer::from(pkcs1.secret_pkcs1_der().to_vec()),
        ),
        PrivateKeyDer::Sec1(sec1) => PrivateKeyDer::Sec1(
            rustls::pki_types::PrivateSec1KeyDer::from(sec1.secret_sec1_der().to_vec()),
        ),
        _ => panic!("unsupported key variant in test harness"),
    }
}

/// Install the `ring` crypto provider as rustls's process-default. Idempotent.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub const SUBJECT_SERVER: &str = SERVER_NAME;
