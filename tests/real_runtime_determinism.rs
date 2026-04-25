//! Property-based tests for WASM execution determinism via `cosaci::wasm_runtime`.
//!
//! Closes the WASM subset of `hypotheses/real-runtime-determinism.md`
//! (Tier 3, C-class). Exercises a real wasmtime execution — fresh
//! `Engine` and `Store` each call — and asserts output hashes match
//! across repeated runs and independent engine instances.
//!
//! Firecracker and Docker runtime determinism remain deferred
//! (system-level infra requirements).

use cosaci::wasm_runtime::{canned_add_module, execute_add, module_hash, output_hash};
use hegel::generators;

// Property 1 — same input → same output across repeated executions.
#[hegel::test]
fn output_is_deterministic_across_repeats(tc: hegel::TestCase) {
    let a = tc.draw(generators::integers::<i32>());
    let b = tc.draw(generators::integers::<i32>());

    let r1 = execute_add(a, b).expect("first run");
    let r2 = execute_add(a, b).expect("second run");
    let r3 = execute_add(a, b).expect("third run");

    assert_eq!(r1, r2, "second run diverged");
    assert_eq!(r2, r3, "third run diverged");
    let mh = module_hash(&canned_add_module().expect("canned"));
    assert_eq!(
        output_hash(&mh, r1),
        output_hash(&mh, r2),
        "output hash unstable across repeats"
    );
}

// Property 2 — matches host-native i32 addition (within wrapping semantics).
#[hegel::test]
fn output_matches_native_semantics(tc: hegel::TestCase) {
    let a = tc.draw(generators::integers::<i32>());
    let b = tc.draw(generators::integers::<i32>());
    let wasm_result = execute_add(a, b).expect("execute");
    let native_result = a.wrapping_add(b);
    assert_eq!(
        wasm_result, native_result,
        "WASM add diverged from native wrapping_add for ({}, {})",
        a, b
    );
}

// Property 3 — different input → (almost always) different output hash.
// For `a.wrapping_add(b)`, identical outputs from different inputs are
// only possible when the two input pairs sum to the same value. The
// test's assertion is: when result differs, hash differs.
#[hegel::test]
fn different_results_give_different_hashes(tc: hegel::TestCase) {
    let a1 = tc.draw(generators::integers::<i32>());
    let b1 = tc.draw(generators::integers::<i32>());
    let a2 = tc.draw(generators::integers::<i32>());
    let b2 = tc.draw(generators::integers::<i32>());

    let r1 = execute_add(a1, b1).expect("run 1");
    let r2 = execute_add(a2, b2).expect("run 2");

    if r1 != r2 {
        let mh = module_hash(&canned_add_module().expect("canned"));
        assert_ne!(output_hash(&mh, r1), output_hash(&mh, r2));
    }
}

// Property — different modules with the same i32 result produce
// different output hashes (the module-hash binding from issue #6).
#[hegel::test]
fn different_modules_disambiguate_outputs(tc: hegel::TestCase) {
    use cosaci::wasm_runtime::{canned_mul_module, encode_args, execute};
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

    let add_wasm = canned_add_module().expect("add module");
    let mul_wasm = canned_mul_module().expect("mul module");
    let args = encode_args(a, b).expect("encode args");

    let add_result = execute(&add_wasm, &args).expect("add run");
    let mul_result = execute(&mul_wasm, &args).expect("mul run");

    let h_add = output_hash(&module_hash(&add_wasm), add_result);
    let h_mul = output_hash(&module_hash(&mul_wasm), mul_result);

    // Two different modules must always produce different output hashes,
    // even on inputs where add(a,b) == mul(a,b) (e.g. a=0).
    assert_ne!(
        h_add, h_mul,
        "module-hash binding failed: {:?} vs {:?}",
        h_add, h_mul
    );
}

// Property 4 — fresh engines produce the same output (no ambient state).
#[hegel::test]
fn fresh_engines_agree(tc: hegel::TestCase) {
    let a = tc.draw(generators::integers::<i32>());
    let b = tc.draw(generators::integers::<i32>());

    // Each call to execute_add creates a fresh Engine + Module + Store —
    // so this tests that engine-level state doesn't leak across calls.
    let results: Vec<i32> = (0..5).map(|_| execute_add(a, b).expect("run")).collect();
    assert!(
        results.windows(2).all(|w| w[0] == w[1]),
        "different engines diverged: {:?}",
        results
    );
}
