//! Tokio-rustls helpers (issue #50 follow-on, PR 2 of N).
//!
//! Thin adapters that wrap the sync rustls config builders in
//! [`super::tls`] into `tokio_rustls::{TlsAcceptor, TlsConnector}`
//! values. The async coord (lands in the next PR) reuses
//! exactly the same cert / key / CA paths the sync coord
//! consumes — no new file format, no separate keystore.
//!
//! The handshake is driven by `tokio-rustls`'s `accept` /
//! `connect` futures, which give back a `TlsStream<TcpStream>`
//! that implements `tokio::io::AsyncRead` + `AsyncWrite` —
//! exactly the handle the async envelope I/O in
//! [`super::proto_async`] takes.

use std::path::Path;
use std::sync::Arc;

use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::tls::{
    client_config_from_paths, install_crypto_provider, server_config_from_paths_with_crl,
};

/// Build a `TlsAcceptor` from the same `(ca_path, cert_path,
/// key_path, optional crl_path)` triple the sync coord consumes
/// via [`super::tls::server_config_from_paths_with_crl`].
///
/// `crl_path = None` disables CRL revocation checks (default).
/// Pass `Some(path)` to load a CRL — same shape as the sync
/// path expects.
///
/// # Errors
///
/// Returns the underlying `server_config_from_paths_with_crl`
/// error (cert / key / CA / CRL parse failures, key mismatch).
pub fn acceptor_from_paths<P: AsRef<Path>>(
    ca_path: P,
    cert_path: P,
    key_path: P,
    crl_path: Option<P>,
) -> std::io::Result<TlsAcceptor> {
    install_crypto_provider();
    let cfg = server_config_from_paths_with_crl(ca_path, cert_path, key_path, crl_path)
        .map_err(std::io::Error::other)?;
    Ok(TlsAcceptor::from(Arc::new(
        Arc::try_unwrap(cfg).unwrap_or_else(|arc| (*arc).clone()),
    )))
}

/// Build a `TlsConnector` from the same `(ca_path, cert_path,
/// key_path)` triple the sync client consumes via
/// [`super::tls::client_config_from_paths`].
///
/// # Errors
///
/// Returns the underlying `client_config_from_paths` error.
pub fn connector_from_paths<P: AsRef<Path>>(
    ca_path: P,
    cert_path: P,
    key_path: P,
) -> std::io::Result<TlsConnector> {
    install_crypto_provider();
    let cfg =
        client_config_from_paths(ca_path, cert_path, key_path).map_err(std::io::Error::other)?;
    Ok(TlsConnector::from(Arc::new(
        Arc::try_unwrap(cfg).unwrap_or_else(|arc| (*arc).clone()),
    )))
}
