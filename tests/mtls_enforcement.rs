//! Property-based tests for mTLS enforcement via `cosaci::tls`.
//!
//! Closes Tier 3 C-class `hypotheses/mtls-enforcement.md` — the real-TLS
//! harness claim. Uses rustls 0.23 over in-memory byte buffers (no
//! network, no root); rcgen 0.14 to generate a local CA and issue
//! certs. The three enforcement properties (valid accepted, no cert
//! rejected, wrong CA rejected) are each exercised through a real
//! handshake that either completes or aborts with an alert.
//!
//! Rotation is still deferred (live hot-rotate of server cert needs
//! orchestration not present in this in-memory harness). Issue #8
//! closes the **CRL** half: a revoked client cert produces a failed
//! handshake even though the cert is otherwise valid (signed by the
//! trusted CA, not expired, correct usage).

use cosaci::tls::{
    SUBJECT_SERVER, TestCa, client_config, client_config_no_cert, install_crypto_provider,
    root_store_from, server_config, server_config_with_crls, try_handshake,
};

// One-shot crypto-provider installation for all tests in this module.
fn ensure_provider() {
    install_crypto_provider();
}

#[hegel::test]
fn valid_client_cert_handshakes_successfully(_tc: hegel::TestCase) {
    ensure_provider();

    let ca = TestCa::generate("cosaci-test-ca").expect("CA");
    let server_cert = ca.issue(SUBJECT_SERVER).expect("server cert");
    let client_cert = ca.issue("client-1").expect("client cert");
    let roots = root_store_from(&ca);

    let s_cfg = server_config(&server_cert, roots.clone()).expect("server config");
    let c_cfg = client_config(&client_cert, roots).expect("client config");

    let result = try_handshake(s_cfg, c_cfg);
    assert!(
        result.is_ok(),
        "valid client cert failed handshake: {:?}",
        result.err()
    );
}

#[hegel::test]
fn no_client_cert_is_rejected(_tc: hegel::TestCase) {
    ensure_provider();

    let ca = TestCa::generate("cosaci-test-ca").expect("CA");
    let server_cert = ca.issue(SUBJECT_SERVER).expect("server cert");
    let roots = root_store_from(&ca);

    let s_cfg = server_config(&server_cert, roots.clone()).expect("server config");
    // Client config with no cert — should be rejected by mTLS-required server.
    let c_cfg = client_config_no_cert(roots);

    let result = try_handshake(s_cfg, c_cfg);
    assert!(
        result.is_err(),
        "handshake succeeded without client cert (mTLS not enforced)"
    );
}

#[hegel::test]
fn client_cert_from_wrong_ca_is_rejected(_tc: hegel::TestCase) {
    ensure_provider();

    // Two independent CAs — `trusted` is the server's root; `rogue`
    // is a separate untrusted authority that signs the client cert.
    let trusted_ca = TestCa::generate("cosaci-trusted-ca").expect("trusted CA");
    let rogue_ca = TestCa::generate("cosaci-rogue-ca").expect("rogue CA");

    let server_cert = trusted_ca.issue(SUBJECT_SERVER).expect("server cert");
    let rogue_client_cert = rogue_ca.issue("rogue-client").expect("rogue client cert");

    let server_roots = root_store_from(&trusted_ca);
    // Client only trusts the TRUSTED CA for verifying the server, but
    // presents a cert signed by the ROGUE CA — server should reject.
    let client_roots = root_store_from(&trusted_ca);

    let s_cfg = server_config(&server_cert, server_roots).expect("server config");
    let c_cfg = client_config(&rogue_client_cert, client_roots).expect("client config");

    let result = try_handshake(s_cfg, c_cfg);
    assert!(
        result.is_err(),
        "handshake accepted client cert from untrusted CA"
    );
}

// Issue #8 — revoked client cert is rejected.
//
// Same trusted CA, same valid cert chain — but the cert's serial
// appears in a CRL the server consults during the handshake. Must
// reject before any application data flows.
#[hegel::test]
fn revoked_client_cert_is_rejected(_tc: hegel::TestCase) {
    ensure_provider();

    let ca = TestCa::generate("cosaci-test-ca").expect("CA");
    let server_cert = ca.issue(SUBJECT_SERVER).expect("server cert");
    let revoked_client_cert = ca.issue("revoked-client").expect("client cert");
    let roots = root_store_from(&ca);

    let crl = ca.issue_crl(&[&revoked_client_cert]).expect("issue CRL");

    let s_cfg = server_config_with_crls(&server_cert, roots.clone(), &[crl])
        .expect("server config with CRL");
    let c_cfg = client_config(&revoked_client_cert, roots).expect("client config");

    let result = try_handshake(s_cfg, c_cfg);
    assert!(result.is_err(), "handshake accepted a revoked client cert");
}

// Issue #8 — non-revoked client cert still works when a CRL is in use.
//
// Verifies that the CRL plumbing doesn't break the happy path: a
// valid client whose serial is NOT in the CRL connects successfully.
#[hegel::test]
fn non_revoked_client_cert_succeeds_with_crl(_tc: hegel::TestCase) {
    ensure_provider();

    let ca = TestCa::generate("cosaci-test-ca").expect("CA");
    let server_cert = ca.issue(SUBJECT_SERVER).expect("server cert");
    let revoked = ca.issue("revoked-client").expect("revoked cert");
    let live = ca.issue("live-client").expect("live cert");
    let roots = root_store_from(&ca);

    // CRL revokes only `revoked`; `live` should pass.
    let crl = ca.issue_crl(&[&revoked]).expect("issue CRL");

    let s_cfg = server_config_with_crls(&server_cert, roots.clone(), &[crl])
        .expect("server config with CRL");
    let c_cfg = client_config(&live, roots).expect("client config");

    let result = try_handshake(s_cfg, c_cfg);
    assert!(
        result.is_ok(),
        "valid (non-revoked) client cert was rejected with CRL active: {:?}",
        result.err()
    );
}
