//! Property tests for `cosaci_webhook` (issue #52).
//!
//! Encodes the falsifiable claims of
//! `hypotheses/webhook-auth-gate.md` (class A): provider
//! signature verification, freshness window, and
//! `.cosaci.toml` round-trip.

use cosaci::webhook::manifest::{PipelineSection, StepSection, TenantSection, emit_manifest};
use cosaci::webhook::{
    CosaciToml, SignatureError, is_fresh, parse_manifest, verify_github_signature,
    verify_gitlab_token,
};
use hegel::{TestCase, generators};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

fn github_signature_for(body: &[u8], secret: &[u8]) -> String {
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("hmac key");
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    format!("sha256={}", lower_hex(&bytes))
}

// ────────────────────────────────────────────────────────────────────────
// GitHub signature verification
// ────────────────────────────────────────────────────────────────────────

#[hegel::test]
fn github_honest_signature_accepts(tc: TestCase) {
    let body: Vec<u8> = tc.draw(generators::binary().min_size(0).max_size(512));
    let secret: Vec<u8> = tc.draw(generators::binary().min_size(8).max_size(64));
    let header = github_signature_for(&body, &secret);
    assert_eq!(verify_github_signature(&body, &header, &secret), Ok(()));
}

#[hegel::test]
fn github_wrong_secret_rejects(tc: TestCase) {
    let body: Vec<u8> = tc.draw(generators::binary().min_size(0).max_size(512));
    let secret: Vec<u8> = tc.draw(generators::binary().min_size(8).max_size(64));
    let mut other_secret: Vec<u8> = tc.draw(generators::binary().min_size(8).max_size(64));
    if other_secret == secret {
        other_secret.push(0xff);
    }
    let header = github_signature_for(&body, &secret);
    assert_eq!(
        verify_github_signature(&body, &header, &other_secret),
        Err(SignatureError::BadSignature)
    );
}

#[hegel::test]
fn github_tampered_body_rejects(tc: TestCase) {
    let mut body: Vec<u8> = tc.draw(generators::binary().min_size(1).max_size(512));
    let secret: Vec<u8> = tc.draw(generators::binary().min_size(8).max_size(64));
    let header = github_signature_for(&body, &secret);
    let idx = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(body.len() - 1),
    );
    body[idx] ^= 0xff;
    assert_eq!(
        verify_github_signature(&body, &header, &secret),
        Err(SignatureError::BadSignature)
    );
}

#[hegel::test]
fn github_malformed_header_returns_malformed(tc: TestCase) {
    let body: Vec<u8> = tc.draw(generators::binary().min_size(0).max_size(64));
    let secret: Vec<u8> = tc.draw(generators::binary().min_size(8).max_size(64));
    let which = tc.draw(generators::integers::<u8>().min_value(0).max_value(3));
    let bad_header = match which {
        0 => "no-prefix-just-hex".to_string(),
        1 => "sha256=not-hex-at-all-but-right-length-padding-padding-padding".to_string(),
        2 => "sha256=tooshort".to_string(),
        // sha1 prefix instead of sha256 — caught by the strip_prefix check.
        _ => format!("sha1={}", "0".repeat(64)),
    };
    assert_eq!(
        verify_github_signature(&body, &bad_header, &secret),
        Err(SignatureError::Malformed)
    );
}

// ────────────────────────────────────────────────────────────────────────
// GitLab token verification
// ────────────────────────────────────────────────────────────────────────

#[hegel::test]
fn gitlab_matching_token_accepts(tc: TestCase) {
    let token: String = (0..tc.draw(generators::integers::<usize>().min_value(1).max_value(64)))
        .map(|i| ((i % 26) as u8 + b'a') as char)
        .collect();
    assert_eq!(verify_gitlab_token(&token, &token), Ok(()));
}

#[hegel::test]
fn gitlab_different_token_rejects(tc: TestCase) {
    let token: String = (0..tc.draw(generators::integers::<usize>().min_value(1).max_value(64)))
        .map(|i| ((i % 26) as u8 + b'a') as char)
        .collect();
    let mut other = token.clone();
    other.push('!'); // Always distinct (different length).
    assert_eq!(
        verify_gitlab_token(&other, &token),
        Err(SignatureError::BadSignature)
    );
}

#[test]
fn gitlab_empty_header_or_secret_is_malformed() {
    assert_eq!(
        verify_gitlab_token("", "secret"),
        Err(SignatureError::Malformed)
    );
    assert_eq!(
        verify_gitlab_token("token", ""),
        Err(SignatureError::Malformed)
    );
    assert_eq!(verify_gitlab_token("", ""), Err(SignatureError::Malformed));
}

// ────────────────────────────────────────────────────────────────────────
// Freshness window
// ────────────────────────────────────────────────────────────────────────

#[hegel::test]
fn fresh_inside_window_accepts(tc: TestCase) {
    let now: u64 = tc.draw(
        generators::integers::<u64>()
            .min_value(1_000_000)
            .max_value(2_000_000),
    );
    let window: u64 = tc.draw(generators::integers::<u64>().min_value(1).max_value(3600));
    let offset: u64 = tc.draw(generators::integers::<u64>().min_value(0).max_value(window));
    let above = tc.draw(generators::booleans());
    let event_ts = if above { now + offset } else { now - offset };
    assert!(is_fresh(event_ts, now, window));
}

#[hegel::test]
fn fresh_outside_window_rejects(tc: TestCase) {
    let now: u64 = tc.draw(
        generators::integers::<u64>()
            .min_value(1_000_000)
            .max_value(2_000_000),
    );
    let window: u64 = tc.draw(generators::integers::<u64>().min_value(1).max_value(3600));
    let extra: u64 = tc.draw(generators::integers::<u64>().min_value(1).max_value(86400));
    let above = tc.draw(generators::booleans());
    let event_ts = if above {
        now + window + extra
    } else {
        now - window - extra
    };
    assert!(!is_fresh(event_ts, now, window));
}

#[test]
fn fresh_boundary_at_window_accepts() {
    let now: u64 = 1_700_000_000;
    let w: u64 = 60;
    assert!(is_fresh(now, now, w));
    assert!(is_fresh(now + w, now, w));
    assert!(is_fresh(now - w, now, w));
    assert!(!is_fresh(now + w + 1, now, w));
    assert!(!is_fresh(now - w - 1, now, w));
}

// ────────────────────────────────────────────────────────────────────────
// .cosaci.toml round-trip
// ────────────────────────────────────────────────────────────────────────

fn draw_step(tc: &TestCase) -> StepSection {
    if tc.draw(generators::booleans()) {
        StepSection::SourceFetch {
            url: format!(
                "https://example.test/repo-{}.git",
                tc.draw(generators::integers::<u32>())
            ),
            reference: format!("{:040x}", tc.draw(generators::integers::<u128>())),
        }
    } else {
        StepSection::ExecWasm {
            module_path: format!(
                "build/wasm/m-{}.wasm",
                tc.draw(generators::integers::<u32>())
            ),
            args_cbor_hex: format!("{:04x}", tc.draw(generators::integers::<u32>())),
        }
    }
}

fn draw_manifest(tc: &TestCase) -> CosaciToml {
    let n_pipelines = tc.draw(generators::integers::<usize>().min_value(0).max_value(3));
    let mut pipelines = Vec::with_capacity(n_pipelines);
    for p in 0..n_pipelines {
        let n_events = tc.draw(generators::integers::<usize>().min_value(0).max_value(3));
        let on_events: Vec<String> = (0..n_events).map(|i| format!("event-{p}-{i}")).collect();
        let n_steps = tc.draw(generators::integers::<usize>().min_value(0).max_value(3));
        let steps: Vec<StepSection> = (0..n_steps).map(|_| draw_step(tc)).collect();
        pipelines.push(PipelineSection {
            name: format!("pipeline-{p}"),
            on_events,
            steps,
        });
    }
    CosaciToml {
        tenant: TenantSection {
            id: tc.draw(
                generators::integers::<u64>()
                    .min_value(1)
                    .max_value(1_000_000),
            ),
        },
        pipelines,
    }
}

#[hegel::test]
fn manifest_round_trips_via_toml(tc: TestCase) {
    let manifest = draw_manifest(&tc);
    let emitted = emit_manifest(&manifest).expect("emit");
    let reparsed = parse_manifest(&emitted).expect("reparse");
    assert_eq!(manifest, reparsed, "round-trip parse(emit(m)) != m");
}

#[test]
fn manifest_minimal_example_parses() {
    let src = r#"
[tenant]
id = 42

[[pipeline]]
name = "ci"
on   = ["push", "pull_request.synchronize"]

  [[pipeline.step]]
  type = "source-fetch"
  url  = "https://example.test/repo.git"
  reference = "main"

  [[pipeline.step]]
  type = "exec-wasm"
  module_path = "build/ci.wasm"
  args_cbor_hex = "8200"
"#;
    let m = parse_manifest(src).expect("parse");
    assert_eq!(m.tenant.id, 42);
    assert_eq!(m.pipelines.len(), 1);
    assert_eq!(m.pipelines[0].name, "ci");
    assert_eq!(m.pipelines[0].steps.len(), 2);
}

#[test]
fn manifest_unknown_step_type_is_schema_error() {
    let src = r#"
[tenant]
id = 1

[[pipeline]]
name = "ci"

  [[pipeline.step]]
  type = "totally-made-up"
"#;
    let err = parse_manifest(src).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("schema") || msg.contains("unknown"),
        "expected schema/unknown error, got: {msg}"
    );
}
