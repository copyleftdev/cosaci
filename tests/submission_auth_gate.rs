//! Property tests for `cosaci_state::submission_auth`.
//!
//! Encodes the falsifiable claims of
//! `hypotheses/submission-auth-gate.md` (issue #46, class A).

mod common;

use common::TestClock;
use cosaci::rate_limit::RateLimiter;
use cosaci::signing::Keypair;
use cosaci::submission_auth::{AuthCheck, JobSubmissionPayload, canonical_bytes, verify_and_admit};
use cosaci::tenant::{TenantRecord, TenantRegistry, fingerprint};
use hegel::{TestCase, generators};

// ────────────────────────────────────────────────────────────────────────
// Hegel draw helpers
// ────────────────────────────────────────────────────────────────────────

fn draw_seed(tc: &TestCase) -> [u8; 32] {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut s = [0_u8; 32];
    s.copy_from_slice(&v);
    s
}

fn draw_payload(tc: &TestCase, tenant_id: u64) -> JobSubmissionPayload {
    let kind = if tc.draw(generators::booleans()) {
        "add".to_string()
    } else {
        "mul".to_string()
    };
    let a: i32 = tc.draw(
        generators::integers::<i32>()
            .min_value(-1000)
            .max_value(1000),
    );
    let b: i32 = tc.draw(
        generators::integers::<i32>()
            .min_value(-1000)
            .max_value(1000),
    );
    let deadline_secs: u32 = tc.draw(generators::integers::<u32>().min_value(1).max_value(3600));
    let nonce: u128 = tc.draw(generators::integers::<u128>());
    JobSubmissionPayload {
        tenant_id,
        kind,
        a,
        b,
        deadline_secs,
        nonce,
    }
}

/// Build a single-tenant registry + signing keypair + a fresh
/// rate limiter so each property test runs against a known-good
/// initial state.
fn fresh_setup(
    tc: &TestCase,
    capacity: u64,
    refill_per_sec: u64,
) -> (TenantRegistry, Keypair, RateLimiter<TestClock>) {
    let tenant_id: u64 = tc.draw(
        generators::integers::<u64>()
            .min_value(1)
            .max_value(1_000_000),
    );
    let seed = draw_seed(tc);
    let kp = Keypair::from_seed(seed);
    let pk = kp.verifying_key().to_bytes();

    let mut reg = TenantRegistry::new();
    reg.insert(TenantRecord {
        tenant_id,
        signing_fp: fingerprint(&pk),
        rate_capacity: capacity,
        rate_refill_per_sec: refill_per_sec,
        registered_at_unix_ns: 0,
    })
    .expect("insert");

    let clock = TestClock::default();
    // Outer caller picks the bucket params on the limiter's
    // defaults; they're unused on the auth path
    // (`accept_with_config` overrides) but the type still needs
    // them.
    let limiter = RateLimiter::new(clock, capacity, refill_per_sec);
    (reg, kp, limiter)
}

// ────────────────────────────────────────────────────────────────────────
// Property 1 — well-formed submission accepted.
//
// Baseline: a payload signed by the tenant's key, against a fresh
// bucket, must return `Ok`. If this fails, every other property
// is moot.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn well_formed_submission_is_admitted(tc: TestCase) {
    let (reg, kp, mut limiter) = fresh_setup(&tc, 100, 10);
    let tenant_id = reg.iter().next().unwrap().tenant_id;
    let payload = draw_payload(&tc, tenant_id);

    let bytes = canonical_bytes(&payload).expect("encode");
    let sig = kp.sign(&bytes).to_bytes();
    let pk = kp.verifying_key().to_bytes();

    let verdict = verify_and_admit(&payload, &pk, &sig, &reg, &mut limiter);
    assert_eq!(
        verdict,
        AuthCheck::Ok,
        "well-formed submission was rejected"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 2 — unknown tenant rejected before rate-limit spend.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn unknown_tenant_rejected(tc: TestCase) {
    let (reg, kp, mut limiter) = fresh_setup(&tc, 100, 10);
    let known_id = reg.iter().next().unwrap().tenant_id;
    // Pick a tenant_id that's NOT in the registry.
    let bogus_id: u64 = tc.draw(generators::integers::<u64>().min_value(known_id + 1));

    let payload = draw_payload(&tc, bogus_id);
    let bytes = canonical_bytes(&payload).expect("encode");
    let sig = kp.sign(&bytes).to_bytes();
    let pk = kp.verifying_key().to_bytes();

    let pre = limiter.tokens_of(known_id);
    let verdict = verify_and_admit(&payload, &pk, &sig, &reg, &mut limiter);
    assert_eq!(verdict, AuthCheck::UnknownTenant);

    // Bucket of the legitimate tenant must be untouched.
    let post = limiter.tokens_of(known_id);
    assert_eq!(pre, post, "unknown-tenant rejection drained legit bucket");
}

// ────────────────────────────────────────────────────────────────────────
// Property 3 — wrong pubkey rejected as BadSignature.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn wrong_pubkey_is_bad_signature(tc: TestCase) {
    let (reg, kp, mut limiter) = fresh_setup(&tc, 100, 10);
    let tenant_id = reg.iter().next().unwrap().tenant_id;
    let payload = draw_payload(&tc, tenant_id);

    // Build a *different* keypair and use its pubkey, but sign
    // with the legitimate key. Both fingerprint mismatch and
    // signature-verify-fail flow into the same verdict.
    let attacker_seed = {
        let mut s = draw_seed(&tc);
        // Force ≠ legit seed.
        s[0] ^= 0xff;
        s
    };
    let attacker_kp = Keypair::from_seed(attacker_seed);
    let attacker_pk = attacker_kp.verifying_key().to_bytes();
    let bytes = canonical_bytes(&payload).expect("encode");
    let sig = kp.sign(&bytes).to_bytes();

    let pre = limiter.tokens_of(tenant_id);
    let verdict = verify_and_admit(&payload, &attacker_pk, &sig, &reg, &mut limiter);
    assert_eq!(verdict, AuthCheck::BadSignature);
    assert_eq!(
        pre,
        limiter.tokens_of(tenant_id),
        "bad-signature attempt drained legit bucket"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 4 — payload tampering rejected.
//
// Sign a payload, then mutate one field before submission. The
// mutated payload's canonical bytes don't match the signature,
// so verification fails.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn tampered_payload_is_bad_signature(tc: TestCase) {
    let (reg, kp, mut limiter) = fresh_setup(&tc, 100, 10);
    let tenant_id = reg.iter().next().unwrap().tenant_id;
    let payload = draw_payload(&tc, tenant_id);

    let bytes = canonical_bytes(&payload).expect("encode");
    let sig = kp.sign(&bytes).to_bytes();
    let pk = kp.verifying_key().to_bytes();

    // Mutate. We pick *which* field deterministically from a Hegel
    // draw so the shrinker can isolate the minimum mutation.
    let which = tc.draw(generators::integers::<u8>().min_value(0).max_value(4));
    let mut tampered = payload.clone();
    match which {
        0 => tampered.kind = "totally-different-kind".to_string(),
        1 => tampered.a = tampered.a.wrapping_add(1),
        2 => tampered.b = tampered.b.wrapping_add(1),
        3 => tampered.deadline_secs = tampered.deadline_secs.wrapping_add(1),
        _ => tampered.nonce = tampered.nonce.wrapping_add(1),
    }

    let pre = limiter.tokens_of(tenant_id);
    let verdict = verify_and_admit(&tampered, &pk, &sig, &reg, &mut limiter);
    assert_eq!(verdict, AuthCheck::BadSignature);
    assert_eq!(
        pre,
        limiter.tokens_of(tenant_id),
        "tampered submission drained bucket"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 5 — rate-limit exhaustion.
//
// For a tenant with capacity C, the (C+1)-th valid submission in
// a single tick returns RateLimited.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn capacity_plus_one_is_rate_limited(tc: TestCase) {
    let capacity: u64 = tc.draw(generators::integers::<u64>().min_value(1).max_value(8));
    let (reg, kp, mut limiter) = fresh_setup(&tc, capacity, 0);
    let tenant_id = reg.iter().next().unwrap().tenant_id;
    let pk = kp.verifying_key().to_bytes();

    // Drain the bucket with `capacity` valid submissions, each
    // with a fresh nonce so they sign distinct payloads.
    for i in 0..capacity {
        let payload = JobSubmissionPayload {
            tenant_id,
            kind: "add".to_string(),
            a: 1,
            b: 2,
            deadline_secs: 60,
            nonce: u128::from(i),
        };
        let bytes = canonical_bytes(&payload).expect("encode");
        let sig = kp.sign(&bytes).to_bytes();
        let v = verify_and_admit(&payload, &pk, &sig, &reg, &mut limiter);
        assert_eq!(v, AuthCheck::Ok, "capacity {capacity}, drain step {i}");
    }

    // The (C+1)-th submission must be RateLimited.
    let payload = JobSubmissionPayload {
        tenant_id,
        kind: "add".to_string(),
        a: 1,
        b: 2,
        deadline_secs: 60,
        nonce: u128::from(capacity),
    };
    let bytes = canonical_bytes(&payload).expect("encode");
    let sig = kp.sign(&bytes).to_bytes();
    let v = verify_and_admit(&payload, &pk, &sig, &reg, &mut limiter);
    assert_eq!(v, AuthCheck::RateLimited);
}

// ────────────────────────────────────────────────────────────────────────
// Property 6 — tenant isolation.
//
// Tenant A's submissions never affect tenant B's bucket. Drain
// A to RateLimited, then assert B can still submit normally.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn tenant_buckets_are_isolated(tc: TestCase) {
    let cap_a: u64 = 2;
    let cap_b: u64 = 2;

    let id_a: u64 = tc.draw(
        generators::integers::<u64>()
            .min_value(1)
            .max_value(1_000_000),
    );
    let id_b: u64 = tc.draw(generators::integers::<u64>().min_value(id_a + 1));

    let seed_a = draw_seed(&tc);
    let mut seed_b = draw_seed(&tc);
    if seed_a == seed_b {
        seed_b[0] ^= 0xaa;
    }
    let kp_a = Keypair::from_seed(seed_a);
    let kp_b = Keypair::from_seed(seed_b);
    let pk_a = kp_a.verifying_key().to_bytes();
    let pk_b = kp_b.verifying_key().to_bytes();

    let mut reg = TenantRegistry::new();
    reg.insert(TenantRecord {
        tenant_id: id_a,
        signing_fp: fingerprint(&pk_a),
        rate_capacity: cap_a,
        rate_refill_per_sec: 0,
        registered_at_unix_ns: 0,
    })
    .expect("insert A");
    reg.insert(TenantRecord {
        tenant_id: id_b,
        signing_fp: fingerprint(&pk_b),
        rate_capacity: cap_b,
        rate_refill_per_sec: 0,
        registered_at_unix_ns: 0,
    })
    .expect("insert B");

    let mut limiter = RateLimiter::new(TestClock::default(), 1, 0);

    let mk = |id, n| JobSubmissionPayload {
        tenant_id: id,
        kind: "add".to_string(),
        a: 1,
        b: 2,
        deadline_secs: 60,
        nonce: n,
    };

    // Drain A.
    for n in 0..cap_a {
        let p = mk(id_a, u128::from(n));
        let bytes = canonical_bytes(&p).expect("encode");
        let sig = kp_a.sign(&bytes).to_bytes();
        assert_eq!(
            verify_and_admit(&p, &pk_a, &sig, &reg, &mut limiter),
            AuthCheck::Ok
        );
    }
    // A is now RateLimited.
    let p = mk(id_a, 999);
    let bytes = canonical_bytes(&p).expect("encode");
    let sig = kp_a.sign(&bytes).to_bytes();
    assert_eq!(
        verify_and_admit(&p, &pk_a, &sig, &reg, &mut limiter),
        AuthCheck::RateLimited
    );

    // B must still admit.
    let p_b = mk(id_b, 0);
    let bytes_b = canonical_bytes(&p_b).expect("encode B");
    let sig_b = kp_b.sign(&bytes_b).to_bytes();
    assert_eq!(
        verify_and_admit(&p_b, &pk_b, &sig_b, &reg, &mut limiter),
        AuthCheck::Ok,
        "tenant A's exhaustion bled into tenant B's bucket"
    );
}
