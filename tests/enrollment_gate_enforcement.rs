//! Property tests for `cosaci-state::enrollment`.
//!
//! Encodes the falsifiable claims of
//! `hypotheses/enrollment-gate-enforcement.md` (issue #45, class A).
//! Five properties:
//!
//!   1. An enrolled `(runner_id, signing_fp, vrf_fp)` triple passes
//!      `is_enrolled`.
//!   2. A non-enrolled `runner_id` is rejected.
//!   3. A matching `runner_id` with a flipped byte of `signing_fp` or
//!      `vrf_fp` is rejected (impersonation).
//!   4. An empty `EnrollmentSet` rejects every input.
//!   5. The v0.3 text-file format round-trips: record → write → parse
//!      yields a byte-identical record.
//!
//! The gate is pure data; tests operate directly on `EnrollmentSet`.

use cosaci::enrollment::{EnrolledRecord, EnrollmentSet, fingerprint, fingerprint_hex};
use hegel::{TestCase, generators};

// ────────────────────────────────────────────────────────────────────────
// Hegel generators
// ────────────────────────────────────────────────────────────────────────

fn draw_pubkey(tc: &TestCase) -> [u8; 32] {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut out = [0_u8; 32];
    out.copy_from_slice(&v);
    out
}

fn draw_record(tc: &TestCase, runner_id: u64) -> EnrolledRecord {
    let signing_pk = draw_pubkey(tc);
    let vrf_pk = draw_pubkey(tc);
    EnrolledRecord {
        runner_id,
        signing_fp: fingerprint(&signing_pk),
        vrf_fp: fingerprint(&vrf_pk),
        enrolled_at_unix_ns: tc.draw(generators::integers::<i64>()),
        initial_reputation_milli: tc
            .draw(generators::integers::<u16>().min_value(0).max_value(1000)),
    }
}

fn draw_set(tc: &TestCase, max_records: usize) -> EnrollmentSet {
    let n = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(max_records),
    );
    let mut set = EnrollmentSet::new();
    for i in 0..n {
        let runner_id = (i as u64) + 1;
        set.insert(draw_record(tc, runner_id));
    }
    set
}

// ────────────────────────────────────────────────────────────────────────
// Property 1 — enrolled triple passes.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn enrolled_triple_passes(tc: TestCase) {
    let mut set = EnrollmentSet::new();
    let runner_id: u64 = tc.draw(generators::integers::<u64>().min_value(1));
    let record = draw_record(&tc, runner_id);
    set.insert(record);
    assert!(
        set.is_enrolled(runner_id, &record.signing_fp, &record.vrf_fp),
        "enrolled triple should pass"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 2 — unenrolled runner_id rejected.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn unenrolled_runner_id_rejected(tc: TestCase) {
    let set = draw_set(&tc, 16);
    // Pick a runner_id that's definitely absent.
    let absent = (set.len() as u64) + 1024;
    let signing_fp = fingerprint(&draw_pubkey(&tc));
    let vrf_fp = fingerprint(&draw_pubkey(&tc));
    assert!(
        !set.is_enrolled(absent, &signing_fp, &vrf_fp),
        "unenrolled runner_id {absent} must be rejected"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 3a — matching runner_id, wrong signing_fp ⇒ reject.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn wrong_signing_fp_rejected(tc: TestCase) {
    let mut set = EnrollmentSet::new();
    let runner_id: u64 = tc.draw(generators::integers::<u64>().min_value(1));
    let record = draw_record(&tc, runner_id);
    set.insert(record);

    let mut tampered = record.signing_fp;
    let byte_index = tc.draw(generators::integers::<usize>().min_value(0).max_value(31));
    let bit_mask: u8 = tc.draw(generators::integers::<u8>().min_value(1).max_value(255));
    tampered[byte_index] ^= bit_mask;
    assert!(
        !set.is_enrolled(runner_id, &tampered, &record.vrf_fp),
        "tampered signing_fp must be rejected"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 3b — matching runner_id, wrong vrf_fp ⇒ reject.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn wrong_vrf_fp_rejected(tc: TestCase) {
    let mut set = EnrollmentSet::new();
    let runner_id: u64 = tc.draw(generators::integers::<u64>().min_value(1));
    let record = draw_record(&tc, runner_id);
    set.insert(record);

    let mut tampered = record.vrf_fp;
    let byte_index = tc.draw(generators::integers::<usize>().min_value(0).max_value(31));
    let bit_mask: u8 = tc.draw(generators::integers::<u8>().min_value(1).max_value(255));
    tampered[byte_index] ^= bit_mask;
    assert!(
        !set.is_enrolled(runner_id, &record.signing_fp, &tampered),
        "tampered vrf_fp must be rejected"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 4 — empty set rejects everyone.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn empty_set_rejects_everyone(tc: TestCase) {
    let set = EnrollmentSet::new();
    let runner_id: u64 = tc.draw(generators::integers::<u64>());
    let signing_fp = fingerprint(&draw_pubkey(&tc));
    let vrf_fp = fingerprint(&draw_pubkey(&tc));
    assert!(
        !set.is_enrolled(runner_id, &signing_fp, &vrf_fp),
        "empty enrollment set must reject every input"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 5 — record round-trips through the v0.3 text format.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn record_round_trips_through_file_format(tc: TestCase) {
    let runner_id: u64 = tc.draw(generators::integers::<u64>());
    let record = draw_record(&tc, runner_id);
    let line = format!(
        "{} {} {} {} {}",
        record.runner_id,
        fingerprint_hex(&record.signing_fp),
        fingerprint_hex(&record.vrf_fp),
        record.enrolled_at_unix_ns,
        record.initial_reputation()
    );
    let parsed = EnrollmentSet::parse(&line).expect("parse round-trip");
    assert_eq!(parsed.len(), 1);
    let r2 = parsed.get(record.runner_id).expect("enrolled");
    assert_eq!(r2.runner_id, record.runner_id);
    assert_eq!(r2.signing_fp, record.signing_fp);
    assert_eq!(r2.vrf_fp, record.vrf_fp);
    assert_eq!(r2.enrolled_at_unix_ns, record.enrolled_at_unix_ns);
    // initial_reputation: f32 stored as milli-u16, so round-trip is
    // exact for any value originally sourced from milli units.
    assert_eq!(r2.initial_reputation_milli, record.initial_reputation_milli);
}

// ────────────────────────────────────────────────────────────────────────
// Smoke: parser handles comments + blank lines + a real-looking file.
// ────────────────────────────────────────────────────────────────────────
#[test]
fn smoke_parses_comments_and_blanks() {
    let text = "\
        # CosaCI enrollment file\n\
        \n\
        # one runner per line\n\
        1 \
        0000000000000000000000000000000000000000000000000000000000000001 \
        0000000000000000000000000000000000000000000000000000000000000002 \
        1700000000000000000 0.5\n\
        \n\
        2 \
        00000000000000000000000000000000000000000000000000000000000000aa \
        00000000000000000000000000000000000000000000000000000000000000bb \
        1700000000000000000 1.0\n";
    let set = EnrollmentSet::parse(text).expect("parse");
    assert_eq!(set.len(), 2);
    let r1 = set.get(1).expect("runner 1");
    assert_eq!(r1.signing_fp[31], 0x01);
    assert_eq!(r1.vrf_fp[31], 0x02);
    let r2 = set.get(2).expect("runner 2");
    assert_eq!(r2.signing_fp[31], 0xaa);
    assert_eq!(r2.vrf_fp[31], 0xbb);
}

#[test]
fn smoke_parser_rejects_malformed_line() {
    let text = "1 nothex nothex 0 0.0\n";
    assert!(EnrollmentSet::parse(text).is_err());

    let text = "1 \
        0000000000000000000000000000000000000000000000000000000000000001 \
        0000000000000000000000000000000000000000000000000000000000000002 \
        notnum 0.0\n";
    assert!(EnrollmentSet::parse(text).is_err());

    // Reputation out of range.
    let text = "1 \
        0000000000000000000000000000000000000000000000000000000000000001 \
        0000000000000000000000000000000000000000000000000000000000000002 \
        0 1.5\n";
    assert!(EnrollmentSet::parse(text).is_err());
}
