//! mTLS helpers — CA generation, cert issuance, client/server config.
//!
//! Source: closes `hypotheses/mtls-enforcement.md` (Tier 3 C-class).
//! In-process rustls handshake pipeline; no network, no system CA
//! trust store. Harness for exercising CosaCI's mTLS enforcement at
//! the algebraic layer (certificate chain validity) without running
//! real servers.

use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rcgen::{
    CertificateParams, CertificateRevocationListParams, DnType, Issuer, KeyIdMethod, KeyPair,
    RevocationReason, RevokedCertParams, SerialNumber,
};
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

const SERVER_NAME: &str = "cosaci.local";

/// A self-signed CA — signs end-entity (client / server) certs and
/// (issue #8) certificate revocation lists.
pub struct TestCa {
    cert_der: CertificateDer<'static>,
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
    /// Monotonic serial counter — each `issue` call burns one. Stored
    /// on the resulting [`IssuedCert`] so tests can later revoke by
    /// serial without re-parsing the DER.
    next_serial: AtomicU64,
}

/// A CA-signed certificate bundle with its private key. Owned, static
/// lifetime for simple threading.
pub struct IssuedCert {
    /// DER-encoded certificate bytes (the cert itself).
    pub cert_der: CertificateDer<'static>,
    /// DER-encoded PKCS#8 private key.
    pub key_der: PrivateKeyDer<'static>,
    /// PEM-encoded certificate (convenience for writing to disk).
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
    /// The serial assigned by the issuing CA. Required to revoke this
    /// cert via [`TestCa::issue_crl`].
    pub serial: u64,
}

impl TestCa {
    /// Generate a new self-signed test CA with the given common name.
    ///
    /// # Errors
    ///
    /// Propagates rcgen errors (key generation, certificate signing).
    pub fn generate(name: &str) -> Result<Self, rcgen::Error> {
        let signing_key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        // Permit CRL signing by this CA — required by rcgen 0.14 when
        // any key_usages are set; we keep the slot empty to stay
        // permissive but still record the intent here.
        let cert = params.self_signed(&signing_key)?;
        let cert_der = cert.der().clone();
        let cert_pem = cert.pem();
        let issuer = Issuer::new(params, signing_key);
        Ok(Self {
            cert_der,
            cert_pem,
            issuer,
            next_serial: AtomicU64::new(1),
        })
    }

    /// Issue a new end-entity certificate (client or server) bound to
    /// `subject_name`. For server certs this is the SAN; for client
    /// certs it's informational. Each call consumes one monotonic
    /// serial number, exposed on the returned [`IssuedCert`] for use
    /// with [`TestCa::issue_crl`].
    pub fn issue(&self, subject_name: &str) -> Result<IssuedCert, rcgen::Error> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![subject_name.to_string()])?;
        params
            .distinguished_name
            .push(DnType::CommonName, subject_name);
        let serial = self.next_serial.fetch_add(1, Ordering::Relaxed);
        params.serial_number = Some(SerialNumber::from(serial));
        let cert = params.signed_by(&key, &self.issuer)?;
        let cert_der = cert.der().clone();
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        let key_der: PrivateKeyDer<'static> =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        Ok(IssuedCert {
            cert_der,
            key_der,
            cert_pem,
            key_pem,
            serial,
        })
    }

    /// Issue a CRL revoking the supplied certificates. The returned
    /// DER bytes are suitable for passing directly to
    /// [`server_config_with_crls`] or for PEM-wrapping (`X509 CRL`
    /// header) and writing to disk for
    /// [`server_config_from_paths_with_crl`].
    ///
    /// # Errors
    ///
    /// Propagates rcgen errors (e.g. invalid signing key usage).
    pub fn issue_crl(
        &self,
        revoked: &[&IssuedCert],
    ) -> Result<CertificateRevocationListDer<'static>, rcgen::Error> {
        use time::{Duration, OffsetDateTime};
        let now = OffsetDateTime::now_utc();
        let revoked_certs: Vec<RevokedCertParams> = revoked
            .iter()
            .map(|c| RevokedCertParams {
                serial_number: SerialNumber::from(c.serial),
                revocation_time: now,
                reason_code: Some(RevocationReason::Unspecified),
                invalidity_date: None,
            })
            .collect();
        let params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + Duration::days(7),
            crl_number: SerialNumber::from(1_u64),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let crl = params.signed_by(&self.issuer)?;
        Ok(crl.der().clone())
    }

    /// DER-encoded CA certificate.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// PEM-encoded CA certificate.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Write the CA's certificate to `path` as PEM.
    ///
    /// # Errors
    ///
    /// I/O errors from `fs::write`.
    pub fn write_pem<P: AsRef<Path>>(&self, cert_path: P) -> std::io::Result<()> {
        fs::write(cert_path, &self.cert_pem)
    }
}

impl IssuedCert {
    /// Write certificate and private key to disk as PEM files.
    ///
    /// # Errors
    ///
    /// I/O errors from `fs::write`.
    pub fn write_pem<P: AsRef<Path>>(&self, cert_path: P, key_path: P) -> std::io::Result<()> {
        fs::write(cert_path, &self.cert_pem)?;
        fs::write(key_path, &self.key_pem)?;
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────
// PEM file loaders
// ────────────────────────────────────────────────────────────────────────

/// Read a PEM-encoded certificate chain into rustls DER form.
///
/// # Errors
///
/// I/O errors from opening / reading the file, or no certs found.
pub fn read_cert_chain<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .filter_map(Result::ok)
        .collect();
    if chain.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no certificates in PEM file",
        ));
    }
    Ok(chain)
}

/// Read a PEM-encoded private key into rustls DER form.
///
/// # Errors
///
/// I/O errors, or no key found in the PEM.
pub fn read_private_key<P: AsRef<Path>>(path: P) -> std::io::Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no private key in PEM file",
        )
    })
}

/// Read PEM-encoded `X509 CRL` blocks into rustls DER form. Returns
/// an empty vector if the file is missing — caller's responsibility
/// to decide whether that's acceptable; the coordinator treats a
/// missing CRL as "no revocations".
///
/// # Errors
///
/// I/O errors other than `NotFound`. A missing path returns `Ok(vec![])`.
pub fn read_crls<P: AsRef<Path>>(
    path: P,
) -> std::io::Result<Vec<CertificateRevocationListDer<'static>>> {
    let file = match fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut reader = BufReader::new(file);
    let crls: Vec<CertificateRevocationListDer<'static>> = rustls_pemfile::crls(&mut reader)
        .filter_map(Result::ok)
        .collect();
    Ok(crls)
}

/// Build a server config from PEM files: trust roots (CA), server
/// certificate chain, server private key. Requires client authentication.
///
/// # Errors
///
/// I/O errors from the PEM files, or rustls config errors.
pub fn server_config_from_paths<P: AsRef<Path>>(
    ca_path: P,
    cert_path: P,
    key_path: P,
) -> Result<Arc<ServerConfig>, String> {
    server_config_from_paths_with_crl::<P>(ca_path, cert_path, key_path, None)
}

/// Same as [`server_config_from_paths`], plus an optional CRL path.
/// When a CRL is supplied, the client cert verifier rejects any client
/// presenting a serial number listed in the CRL during the TLS
/// handshake — before any application data flows.
///
/// A `None` `crl_path` (or a missing file at the supplied path) means
/// "no revocations"; the resulting config is identical to the no-CRL
/// version. Callers that want to enforce strict revocation should
/// require a CRL file to exist.
///
/// # Errors
///
/// I/O errors from the PEM files, or rustls config errors.
pub fn server_config_from_paths_with_crl<P: AsRef<Path>>(
    ca_path: P,
    cert_path: P,
    key_path: P,
    crl_path: Option<P>,
) -> Result<Arc<ServerConfig>, String> {
    let ca_chain = read_cert_chain(ca_path).map_err(|e| format!("read CA: {e}"))?;
    let mut roots = RootCertStore::empty();
    for c in ca_chain {
        roots.add(c).map_err(|e| format!("add CA: {e}"))?;
    }
    let cert_chain = read_cert_chain(cert_path).map_err(|e| format!("read cert: {e}"))?;
    let key = read_private_key(key_path).map_err(|e| format!("read key: {e}"))?;
    let mut builder = WebPkiClientVerifier::builder(Arc::new(roots));
    if let Some(p) = crl_path {
        let crls = read_crls(p).map_err(|e| format!("read CRL: {e}"))?;
        if !crls.is_empty() {
            builder = builder.with_crls(crls);
        }
    }
    let verifier = builder
        .build()
        .map_err(|e| format!("client verifier: {e}"))?;
    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|e| format!("with_single_cert: {e}"))?;
    Ok(Arc::new(cfg))
}

/// Build a client config from PEM files: trust roots, client cert
/// chain, client private key.
///
/// # Errors
///
/// I/O errors from the PEM files, or rustls config errors.
pub fn client_config_from_paths<P: AsRef<Path>>(
    ca_path: P,
    cert_path: P,
    key_path: P,
) -> Result<Arc<ClientConfig>, String> {
    let ca_chain = read_cert_chain(ca_path).map_err(|e| format!("read CA: {e}"))?;
    let mut roots = RootCertStore::empty();
    for c in ca_chain {
        roots.add(c).map_err(|e| format!("add CA: {e}"))?;
    }
    let cert_chain = read_cert_chain(cert_path).map_err(|e| format!("read cert: {e}"))?;
    let key = read_private_key(key_path).map_err(|e| format!("read key: {e}"))?;
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .map_err(|e| format!("with_client_auth_cert: {e}"))?;
    Ok(Arc::new(cfg))
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
    server_config_with_crls(server_cert, trust_roots, &[])
}

/// Same as [`server_config`], plus a slice of CRLs that the client
/// cert verifier will consult during the handshake. Any client whose
/// cert serial is listed in any supplied CRL is rejected before
/// application data flows. Pass an empty slice for no revocations.
pub fn server_config_with_crls(
    server_cert: &IssuedCert,
    trust_roots: Arc<RootCertStore>,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<Arc<ServerConfig>, String> {
    let mut builder = WebPkiClientVerifier::builder(trust_roots);
    if !crls.is_empty() {
        builder = builder.with_crls(crls.to_vec());
    }
    let verifier = builder
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
//
// `Arc<RootCertStore>` is taken by value to match the existing
// public API and the symmetry with `server_config`. We clone the
// inner store (rustls's builder consumes by value); the Arc itself
// is moved in for that purpose. Pedantic flags this as "passed by
// value but not consumed", but consuming via `Arc::try_unwrap` would
// be more cumbersome than informative.
#[allow(clippy::needless_pass_by_value)]
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
#[must_use]
#[allow(clippy::needless_pass_by_value)]
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
    let server_name =
        ServerName::try_from(SERVER_NAME).map_err(|e| format!("invalid server name: {e}"))?;
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

/// Canonical Subject Alternative Name used for server certs in this
/// crate's helpers — matches the `ServerName` clients connect against.
pub const SUBJECT_SERVER: &str = SERVER_NAME;
