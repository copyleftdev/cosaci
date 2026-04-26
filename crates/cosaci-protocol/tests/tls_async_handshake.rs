//! End-to-end async-TLS + async-envelope round-trip test
//! (issue #50 follow-on, PR 2 of N).
//!
//! Exercises the new `tls_async::{acceptor_from_paths,
//! connector_from_paths}` helpers + the `proto_async`
//! envelope read/write over a real `tokio::net::TcpStream` pair
//! wrapped in tokio-rustls. Closes the integration boundary
//! between the new async wire layer and a real mTLS
//! handshake: if this test passes, the eventual coord
//! rewrite has all the primitives it needs.

use std::sync::Arc;

use cosaci_protocol::proto::Envelope;
use cosaci_protocol::proto_async::{read_envelope_async, write_envelope_async};
use cosaci_protocol::tls::{SUBJECT_SERVER, TestCa, install_crypto_provider};
use cosaci_protocol::tls_async::{acceptor_from_paths, connector_from_paths};
use rustls::pki_types::ServerName;
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};

struct Certs {
    ca: std::path::PathBuf,
    server_cert: std::path::PathBuf,
    server_key: std::path::PathBuf,
    client_cert: std::path::PathBuf,
    client_key: std::path::PathBuf,
}

fn write_certs(dir: &TempDir) -> Certs {
    let ca = TestCa::generate("cosaci-tls-async-ca").expect("CA");
    let ca_path = dir.path().join("ca.pem");
    ca.write_pem(&ca_path).expect("write CA");

    let server_issued = ca.issue(SUBJECT_SERVER).expect("server cert");
    let server_cert = dir.path().join("server.pem");
    let server_key = dir.path().join("server.key.pem");
    server_issued
        .write_pem(&server_cert, &server_key)
        .expect("write server cert");

    let client_issued = ca.issue("client-test").expect("client cert");
    let client_cert = dir.path().join("client.pem");
    let client_key = dir.path().join("client.key.pem");
    client_issued
        .write_pem(&client_cert, &client_key)
        .expect("write client cert");

    Certs {
        ca: ca_path,
        server_cert,
        server_key,
        client_cert,
        client_key,
    }
}

#[test]
fn async_mtls_handshake_then_envelope_roundtrip() {
    install_crypto_provider();
    let dir = TempDir::new().expect("tempdir");
    let certs = write_certs(&dir);
    let ca = certs.ca.clone();
    let server_cert = certs.server_cert.clone();
    let server_key = certs.server_key.clone();
    let client_cert = certs.client_cert.clone();
    let client_key = certs.client_key.clone();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("rt");

    rt.block_on(async move {
        // Bind the listener on a free port and capture the
        // resolved SocketAddr so the client knows where to
        // connect.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        // Server task: one connection, async-read Envelope,
        // async-write response, close.
        let no_crl: Option<&std::path::PathBuf> = None;
        let acceptor =
            acceptor_from_paths(&ca, &server_cert, &server_key, no_crl).expect("acceptor");
        let server = tokio::spawn(async move {
            let (tcp, _peer) = listener.accept().await.expect("accept");
            let mut tls = acceptor.accept(tcp).await.expect("tls accept");
            let req = read_envelope_async(&mut tls).await.expect("server read");
            // Sanity: server saw the envelope the client sent.
            assert!(matches!(req, Envelope::AdminListAgents));
            write_envelope_async(&mut tls, &Envelope::AdminWelcome)
                .await
                .expect("server write");
            // Drop closes the connection cleanly.
        });

        // Client task: connect, async-write request, async-read
        // response.
        let connector = connector_from_paths(&ca, &client_cert, &client_key).expect("connector");
        let client = tokio::spawn(async move {
            let tcp = TcpStream::connect(addr).await.expect("client connect");
            let server_name: ServerName<'static> =
                ServerName::try_from(SUBJECT_SERVER.to_string()).expect("server name");
            let mut tls = connector
                .connect(server_name, tcp)
                .await
                .expect("tls connect");
            write_envelope_async(&mut tls, &Envelope::AdminListAgents)
                .await
                .expect("client write");
            let resp = read_envelope_async(&mut tls).await.expect("client read");
            assert!(matches!(resp, Envelope::AdminWelcome));
        });

        // Both tasks must complete without panic.
        let (s, c) = tokio::join!(server, client);
        s.expect("server task");
        c.expect("client task");

        // `Arc::strong_count` against the connector's inner
        // config is 1 here unless something held a reference
        // — sanity-only.
        let _ = Arc::new(()); // suppress unused warning
    });
}
