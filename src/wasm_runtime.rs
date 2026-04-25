//! WebAssembly runtime harness for `real-runtime-determinism` (Tier 3, C).
//!
//! Wraps `wasmtime` to execute canned WAT modules deterministically
//! and hash the observable output. The card's full claim covers all
//! three of CosaCI's sandbox runtimes (WASM / Firecracker / Docker);
//! v0.1 closes the **WASM subset** — Firecracker needs KVM and Docker
//! needs a system daemon, both requiring privileges we don't have
//! in the filter's test environment.

use sha2::{Digest, Sha256};
use wasmtime::{Engine, Instance, Module, Store};

/// The canned test module (`add(a, b) -> i32`). Simple, self-contained,
/// deterministic by construction.
pub const CANNED_WAT: &str = r#"
(module
    (func $add (export "add") (param $a i32) (param $b i32) (result i32)
        local.get $a
        local.get $b
        i32.add)
)
"#;

/// Execute the `add` export with `(a, b)` inputs and return the i32 result.
///
/// # Errors
///
/// Returns a string error if module compilation, instantiation, or call
/// fails — all of which indicate the harness is broken rather than the
/// test claim being false.
pub fn execute_add(a: i32, b: i32) -> Result<i32, String> {
    let engine = Engine::default();
    let module = Module::new(&engine, CANNED_WAT).map_err(|e| format!("module: {e}"))?;
    let mut store: Store<()> = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[]).map_err(|e| format!("instance: {e}"))?;
    let add = instance
        .get_typed_func::<(i32, i32), i32>(&mut store, "add")
        .map_err(|e| format!("get_typed_func: {e}"))?;
    add.call(&mut store, (a, b))
        .map_err(|e| format!("call: {e}"))
}

/// SHA-256 of the little-endian bytes of the result. The observable
/// determinism claim is stated in terms of this hash — two runners
/// should produce the same hash for the same input.
#[must_use]
pub fn output_hash(result: i32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(result.to_le_bytes());
    hasher.finalize().into()
}
