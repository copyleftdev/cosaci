//! Sync↔async wire compatibility tests for `cosaci-protocol`
//! (issue #50 follow-on, runtime-rewrite groundwork).
//!
//! Asserts that the byte stream produced by `proto::write_envelope`
//! is bit-equal to the one produced by
//! `proto_async::write_envelope_async` for the same `Envelope`,
//! and that all four directional combinations
//! (sync-write→sync-read, sync-write→async-read,
//! async-write→sync-read, async-write→async-read) round-trip
//! losslessly.
//!
//! That property is what lets the eventual tokio rewrite of the
//! coordinator inter-operate on-the-wire with sync clients
//! (today's agents, today's webhook listener, today's
//! cosaci-admin) during the gradual cut-over — no flag-day
//! migration needed.

use std::io::Cursor;

use cosaci_protocol::proto::{Envelope, read_envelope, write_envelope};
use cosaci_protocol::proto_async::{read_envelope_async, write_envelope_async};

/// A small zoo of `Envelope` values exercising the variant
/// shapes the wire actually carries: simple unit-like
/// (`AdminWelcome`), small-payload (`GetJob`,
/// `JobNotFound { job_id }`), and admin-shaped envelopes with
/// arrays + signatures. We don't materialize the full set —
/// `Register`, `JobSeed`, `Assign`, `SubmitAttestation` need
/// non-trivial cosaci-core types — but the variants we cover
/// are sufficient to falsify a sync↔async byte mismatch since
/// the framing is the same for all variants.
fn sample_envelopes() -> Vec<Envelope> {
    vec![
        Envelope::RegisterAck,
        Envelope::Shutdown,
        Envelope::AdminWelcome,
        Envelope::AdminListAgents,
        Envelope::AdminGetLogRoot,
        Envelope::AdminListTenants,
        Envelope::GetJob { job_id: 0 },
        Envelope::GetJob { job_id: u64::MAX },
        Envelope::JobNotFound { job_id: 42 },
        Envelope::LogRoot {
            root: None,
            length: 0,
        },
        Envelope::LogRoot {
            root: Some([0xab; 32]),
            length: 1234,
        },
        Envelope::AdminError {
            reason: "unauthorized".to_string(),
        },
        Envelope::AdminError {
            reason: String::new(),
        },
        Envelope::AdminError {
            reason: "x".repeat(1024),
        },
        Envelope::AdminLogRoot {
            root: Some([0xcd; 32]),
            length: u64::MAX,
        },
        Envelope::AdminRevokeAck,
        Envelope::AdminRevokeTenantAck,
        Envelope::AdminRevokeAgent { runner_id: 7 },
        Envelope::AdminRevokeTenant { tenant_id: 42 },
    ]
}

/// Assert that `e` round-trips byte-equal through both paths
/// (the inverse direction is the more interesting property,
/// covered below).
#[test]
fn sync_write_produces_same_bytes_as_async_write() {
    let envs = sample_envelopes();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    for e in envs {
        let mut sync_buf = Vec::new();
        write_envelope(&mut sync_buf, &e).expect("sync write");

        let async_buf = rt.block_on(async {
            let mut buf: Vec<u8> = Vec::new();
            write_envelope_async(&mut buf, &e)
                .await
                .expect("async write");
            buf
        });

        assert_eq!(sync_buf, async_buf, "byte mismatch for envelope: {e:?}");
    }
}

/// Sync-write, async-read.
#[test]
fn sync_write_async_read_roundtrips() {
    let envs = sample_envelopes();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    for e in envs {
        let mut buf = Vec::new();
        write_envelope(&mut buf, &e).expect("sync write");

        let decoded = rt.block_on(async {
            let mut cursor = Cursor::new(buf);
            read_envelope_async(&mut cursor).await.expect("async read")
        });

        // Envelope doesn't impl PartialEq universally (some
        // payload types like Attestation may not), but for our
        // sample set we can compare via re-encoded bytes.
        let mut re_encoded = Vec::new();
        write_envelope(&mut re_encoded, &decoded).expect("re-encode");
        let mut original_encoded = Vec::new();
        write_envelope(&mut original_encoded, &e).expect("orig encode");
        assert_eq!(
            re_encoded, original_encoded,
            "sync-write → async-read mismatch for: {e:?}"
        );
    }
}

/// Async-write, sync-read.
#[test]
fn async_write_sync_read_roundtrips() {
    let envs = sample_envelopes();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    for e in envs {
        let buf = rt.block_on(async {
            let mut buf: Vec<u8> = Vec::new();
            write_envelope_async(&mut buf, &e)
                .await
                .expect("async write");
            buf
        });

        let mut cursor = Cursor::new(buf);
        let decoded = read_envelope(&mut cursor).expect("sync read");

        let mut re_encoded = Vec::new();
        write_envelope(&mut re_encoded, &decoded).expect("re-encode");
        let mut original_encoded = Vec::new();
        write_envelope(&mut original_encoded, &e).expect("orig encode");
        assert_eq!(
            re_encoded, original_encoded,
            "async-write → sync-read mismatch for: {e:?}"
        );
    }
}

/// Async-write, async-read.
#[test]
fn async_write_async_read_roundtrips() {
    let envs = sample_envelopes();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    for e in envs {
        let decoded = rt.block_on(async {
            let mut buf: Vec<u8> = Vec::new();
            write_envelope_async(&mut buf, &e)
                .await
                .expect("async write");
            let mut cursor = Cursor::new(buf);
            read_envelope_async(&mut cursor).await.expect("async read")
        });

        let mut re_encoded = Vec::new();
        write_envelope(&mut re_encoded, &decoded).expect("re-encode");
        let mut original_encoded = Vec::new();
        write_envelope(&mut original_encoded, &e).expect("orig encode");
        assert_eq!(
            re_encoded, original_encoded,
            "async round-trip mismatch for: {e:?}"
        );
    }
}

/// Async-read on a truncated stream returns an UnexpectedEof
/// error (not a panic, not a hang). Same shape as the sync
/// path.
#[test]
fn async_read_on_truncated_stream_returns_eof() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Build a real envelope's bytes, then truncate to 3 bytes
    // (less than the 4-byte length prefix).
    let mut buf = Vec::new();
    write_envelope(&mut buf, &Envelope::Shutdown).expect("encode");
    buf.truncate(3);

    let result = rt.block_on(async {
        let mut cursor = Cursor::new(buf);
        read_envelope_async(&mut cursor).await
    });
    assert!(
        matches!(
            &result,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof
        ),
        "expected UnexpectedEof, got: {result:?}"
    );
}

/// Async-write rejects an envelope whose CBOR encoding would
/// exceed `MAX_ENVELOPE_BYTES_PUB`. Same shape as sync.
#[test]
fn async_write_rejects_oversize_envelope() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let oversize = Envelope::AdminError {
        reason: "x".repeat(20 * 1024 * 1024), // 20 MiB > 16 MiB cap
    };
    let result = rt.block_on(async {
        let mut buf: Vec<u8> = Vec::new();
        write_envelope_async(&mut buf, &oversize).await
    });
    assert!(
        matches!(
            &result,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData
        ),
        "expected InvalidData, got: {result:?}"
    );
}
