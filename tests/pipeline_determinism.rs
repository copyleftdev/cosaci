//! Property-based tests for `cosaci_jobs::Pipeline` execution.
//!
//! Encodes the falsifiable claims of `hypotheses/pipeline-determinism.md`
//! (SPEC.md §6.2, class A). The pipeline DSL is the prerequisite for the
//! whole trust chain — if two runners can disagree on a `PipelineResult`
//! for the same `Pipeline`, every downstream property collapses.

use std::collections::BTreeMap;

use cosaci::jobs::{
    Limits, Pipeline, PipelineResult, Step, StepStatus, canonical_encoding, execute_pipeline,
};
use cosaci::wasm_runtime::{canned_add_module, canned_mul_module, encode_args};
use hegel::{TestCase, generators};

// ----------------------------------------------------------------------------
// Draw helpers
// ----------------------------------------------------------------------------

fn draw_i32_args(tc: &TestCase) -> (i32, i32) {
    let a = tc.draw(
        generators::integers::<i32>()
            .min_value(-1000)
            .max_value(1000),
    );
    let b = tc.draw(
        generators::integers::<i32>()
            .min_value(-1000)
            .max_value(1000),
    );
    (a, b)
}

/// Draw a single-step ExecWasm pipeline using the canned add module.
/// Module choice + args are randomized per Hegel draw.
fn draw_wasm_pipeline(tc: &TestCase) -> Pipeline {
    let use_mul = tc.draw(generators::booleans());
    let module = if use_mul {
        canned_mul_module().expect("canned mul")
    } else {
        canned_add_module().expect("canned add")
    };
    let (a, b) = draw_i32_args(tc);
    let args_cbor = encode_args(a, b).expect("encode args");
    Pipeline {
        steps: vec![Step::ExecWasm {
            module,
            args_cbor,
            limits: Limits::default(),
        }],
    }
}

// ----------------------------------------------------------------------------
// Property 1 — CBOR round-trip stability.
//
// `decode(encode(p)) == p` byte-equal for any pipeline. This is the wire
// property; if it fails, two runners encoding the same pipeline value get
// different bytes on the wire and committee selection itself is non-
// deterministic.
// ----------------------------------------------------------------------------
#[hegel::test]
fn pipeline_cbor_roundtrip(tc: TestCase) {
    let p = draw_wasm_pipeline(&tc);

    let encoded = canonical_encoding(&p).expect("encode");
    let decoded: Pipeline = ciborium::from_reader(encoded.as_slice()).expect("decode");

    assert_eq!(p, decoded, "decode(encode(p)) != p");

    // Re-encode the decoded value and confirm byte-equality with the
    // first encoding. Catches non-canonical serialization paths.
    let re_encoded = canonical_encoding(&decoded).expect("re-encode");
    assert_eq!(
        encoded, re_encoded,
        "re-encoding decoded pipeline produced different bytes"
    );
}

// ----------------------------------------------------------------------------
// Property 2 — repeated-execution stability.
//
// `execute_pipeline(&p)` called multiple times produces byte-equal
// `PipelineResult`s. This is the within-runner determinism floor.
// ----------------------------------------------------------------------------
#[hegel::test]
fn pipeline_execution_is_deterministic(tc: TestCase) {
    let p = draw_wasm_pipeline(&tc);

    let r1 = execute_pipeline(&p).expect("first run");
    let r2 = execute_pipeline(&p).expect("second run");
    let r3 = execute_pipeline(&p).expect("third run");

    assert_eq!(r1, r2, "second run diverged from first");
    assert_eq!(r2, r3, "third run diverged from second");
    assert_eq!(
        r1.final_artifact_hash, r2.final_artifact_hash,
        "final_artifact_hash unstable across executions"
    );
}

// ----------------------------------------------------------------------------
// Property 3 — distinguishable-input mutation propagates.
//
// Hegel found a real counterexample on an earlier draft of this property:
// the mul module with b=0 maps any (a, 0) → 0, so mutating a from 0 to 1
// preserves the output and the output hash. That's not a bug — it's the
// intentional content-addressing of execution outputs. Two pipelines with
// different INPUTS that produce the same OUTPUT are equivalent at the
// artifact layer.
//
// What we *can* guarantee: when the mutation actually changes the
// observed output (i.e., the executor is non-lossy on this input),
// the final_artifact_hash changes too. This is the regression check
// for "the DSL faithfully forwards executor outputs into the artifact
// hash"; the universal "mutation always propagates" claim is false in
// general and stays out of the spec.
//
// We pin the test to the add module on small inputs, where `a → a+1`
// is bijective (no wrap inside [-1000, 1000]).
// ----------------------------------------------------------------------------
#[hegel::test]
fn output_changing_mutation_propagates(tc: TestCase) {
    let (a, b) = draw_i32_args(&tc);
    let module = canned_add_module().expect("canned add");
    let args = encode_args(a, b).expect("encode");

    let baseline_pipeline = Pipeline {
        steps: vec![Step::ExecWasm {
            module: module.clone(),
            args_cbor: args,
            limits: Limits::default(),
        }],
    };

    // Bijective mutation: a + 1 ≠ a in [-1000, 1000], and add is
    // non-lossy under that step.
    let mutated_args = encode_args(a + 1, b).expect("encode mutated");
    let mutated_pipeline = Pipeline {
        steps: vec![Step::ExecWasm {
            module,
            args_cbor: mutated_args,
            limits: Limits::default(),
        }],
    };

    let baseline = execute_pipeline(&baseline_pipeline).expect("baseline run");
    let mutated = execute_pipeline(&mutated_pipeline).expect("mutated run");

    assert_ne!(
        baseline.final_artifact_hash, mutated.final_artifact_hash,
        "output-changing mutation didn't propagate to artifact hash"
    );
}

// ----------------------------------------------------------------------------
// Property 4 — NotImplemented step determinism.
//
// Steps whose executor isn't implemented in this build still produce a
// stable hash on every runner: the canonical hash of the step value
// itself. This lets a partially-implemented coordinator produce
// consistent attestations without aborting the pipeline.
//
// The original encoding of this test used `Step::SourceFetch` since
// that was a NotImplemented variant in v0.3-pre-#40. With #40 landed,
// SourceFetch now executes (or fails with `git not found` /
// `clone failed`); the NotImplemented surface is now `Step::ExecNative`
// (lands in #43 + #54 follow-ons).
// ----------------------------------------------------------------------------
#[hegel::test]
fn not_implemented_steps_are_deterministic(tc: TestCase) {
    let cmd_len = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let argv: Vec<String> = (0..cmd_len)
        .map(|i| format!("arg-{i}-{}", tc.draw(generators::integers::<u32>())))
        .collect();

    let p = Pipeline {
        steps: vec![Step::ExecNative {
            command: argv.clone(),
            env: BTreeMap::new(),
            limits: Limits::default(),
        }],
    };

    let r1 = execute_pipeline(&p).expect("first run");
    let r2 = execute_pipeline(&p).expect("second run");

    // Status reflects "not yet implemented" — distinct from a real
    // failure so the coordinator can tell them apart.
    assert!(matches!(r1.steps[0].status, StepStatus::NotImplemented));
    assert!(matches!(r2.steps[0].status, StepStatus::NotImplemented));

    // Hash and full result are byte-equal across runs.
    assert_eq!(r1, r2, "NotImplemented step diverged across runs");
}

// ----------------------------------------------------------------------------
// Property 5 — empty pipeline produces a stable, non-trivial hash.
//
// A zero-step pipeline still has a defined `PipelineResult`. Its
// `final_artifact_hash` is the canonical hash of an empty step list.
// Two runners agreeing the pipeline did nothing must produce the same
// hash; this is the boundary case for the determinism property.
// ----------------------------------------------------------------------------
#[hegel::test]
fn empty_pipeline_is_deterministic(_tc: TestCase) {
    let p = Pipeline { steps: vec![] };
    let r1 = execute_pipeline(&p).expect("first run");
    let r2 = execute_pipeline(&p).expect("second run");

    assert!(r1.steps.is_empty());
    assert_eq!(r1, r2);

    // The empty-pipeline hash is deterministic but not all-zero — it's
    // SHA-256 of the canonical CBOR encoding of `Vec<StepOutput>::new()`.
    let zero: [u8; 32] = [0; 32];
    assert_ne!(
        r1.final_artifact_hash, zero,
        "empty pipeline produced an all-zero artifact hash; canonical encoding likely degenerate"
    );
}

// ----------------------------------------------------------------------------
// Smoke — ExecWasm executes correctly via the pipeline DSL.
// (Not a Hegel property; pure regression check that the DSL doesn't lose
// the existing wasm_runtime guarantees.)
// ----------------------------------------------------------------------------
#[test]
fn exec_wasm_step_returns_success() {
    let module = canned_add_module().expect("canned add");
    let args = encode_args(21, 21).expect("encode");
    let p = Pipeline {
        steps: vec![Step::ExecWasm {
            module,
            args_cbor: args,
            limits: Limits::default(),
        }],
    };
    let r: PipelineResult = execute_pipeline(&p).expect("run");
    assert_eq!(r.steps.len(), 1);
    assert_eq!(r.steps[0].step_index, 0);
    assert!(matches!(r.steps[0].status, StepStatus::Success));
}
