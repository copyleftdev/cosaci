//! WebAssembly runtime harness for `real-runtime-determinism` (Tier 3, C).
//!
//! Wraps `wasmtime` to execute user-supplied WASM modules deterministically
//! and hash the observable output. The card's full claim covers all
//! three of CosaCI's sandbox runtimes (WASM / Firecracker / Docker);
//! v0.2 closes the **WASM subset** with arbitrary-payload support —
//! Firecracker needs KVM and Docker needs a system daemon, both
//! requiring privileges we don't have in the filter's test environment.
//!
//! # ABI (v0.2)
//!
//! A CosaCI WASM payload is a binary `.wasm` module that exports:
//!
//! ```text
//! (func (export "add") (param i32 i32) (result i32))
//! ```
//!
//! The two `i32` arguments are CBOR-decoded from `args_cbor` as a
//! tuple `(i32, i32)`. The `i32` return value is the observable
//! output. Future ABI revisions may pass arguments via linear memory
//! to support richer types; the current shape is the minimum needed
//! to demonstrate that the protocol carries arbitrary modules.
//!
//! ## Why this shape
//!
//! - **Stable** — i32 arity is universally supported by every WASM
//!   compiler. No memory layout to negotiate.
//! - **Trivially hashable** — a 4-byte LE return value plus the SHA-256
//!   of the module bytes uniquely identifies an execution.
//! - **Falsifiable** — `output_hash(module_a, k)` and `output_hash(module_b, k)`
//!   produce distinct hashes when `module_a != module_b`, so two
//!   committee members running different modules cannot quorum on the
//!   same output.

use sha2::{Digest, Sha256};
use wasmtime::{Engine, Instance, Module, Store};

/// The canned `add(a, b) -> i32` module in WAT form. Used by demos and
/// tests when no externally-supplied module is available. Production
/// jobs ship their own compiled `.wasm` payload.
pub const CANNED_WAT: &str = r#"
(module
    (func $add (export "add") (param $a i32) (param $b i32) (result i32)
        local.get $a
        local.get $b
        i32.add)
)
"#;

/// The canned `mul(a, b) -> i32` module — same `add` export name,
/// different implementation. Provided so demos can rotate between
/// distinct modules and exercise the module-hash-in-output-hash
/// contract.
pub const CANNED_MUL_WAT: &str = r#"
(module
    (func $add (export "add") (param $a i32) (param $b i32) (result i32)
        local.get $a
        local.get $b
        i32.mul)
)
"#;

/// Compile a WAT source into a `.wasm` byte vector. Convenience for
/// tests and demos that ship WAT inline; the wire protocol always
/// carries binary `.wasm` bytes.
///
/// # Errors
///
/// Returns a string error if the WAT fails to parse.
pub fn wat_to_wasm(wat: &str) -> Result<Vec<u8>, String> {
    wat::parse_str(wat).map_err(|e| format!("wat: {e}"))
}

/// Bytes of the canned add module (`add(a,b) -> a+b`).
///
/// # Errors
///
/// Returns a string error if the canned WAT fails to parse — only
/// possible if the const above is broken.
pub fn canned_add_module() -> Result<Vec<u8>, String> {
    wat_to_wasm(CANNED_WAT)
}

/// Bytes of the canned mul module (`add(a,b) -> a*b`). Same export
/// name as `canned_add_module` — only the implementation differs.
///
/// # Errors
///
/// Returns a string error if the canned WAT fails to parse.
pub fn canned_mul_module() -> Result<Vec<u8>, String> {
    wat_to_wasm(CANNED_MUL_WAT)
}

/// SHA-256 of the WASM module bytes. Two distinct modules produce
/// distinct hashes; the same module produces the same hash regardless
/// of how many times it crosses the wire.
#[must_use]
pub fn module_hash(wasm: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(wasm);
    h.finalize().into()
}

/// CBOR-encode `(a, b)` as the canonical args blob that [`execute`]
/// expects.
///
/// # Errors
///
/// Returns a string error if CBOR encoding fails (effectively never
/// for two i32s).
pub fn encode_args(a: i32, b: i32) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(&(a, b), &mut buf).map_err(|e| format!("cbor encode args: {e}"))?;
    Ok(buf)
}

/// Execute the `add` export of a WASM module against CBOR-encoded
/// `(i32, i32)` arguments. Returns the i32 result.
///
/// # Errors
///
/// Returns a string error if the module fails to compile, instantiate,
/// the `add` export is missing or has the wrong signature, the args
/// fail to decode as `(i32, i32)`, or the call traps.
pub fn execute(wasm: &[u8], args_cbor: &[u8]) -> Result<i32, String> {
    let (a, b): (i32, i32) =
        ciborium::from_reader(args_cbor).map_err(|e| format!("cbor decode args: {e}"))?;

    let engine = Engine::default();
    let module = Module::new(&engine, wasm).map_err(|e| format!("module: {e}"))?;
    let mut store: Store<()> = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[]).map_err(|e| format!("instance: {e}"))?;
    let add = instance
        .get_typed_func::<(i32, i32), i32>(&mut store, "add")
        .map_err(|e| format!("get_typed_func add: {e}"))?;
    add.call(&mut store, (a, b))
        .map_err(|e| format!("call: {e}"))
}

/// Convenience: compile + run the canned `add(a, b)` module. Tests
/// and the in-process demo use this when they don't need to exercise
/// the full bytes-on-the-wire path.
///
/// # Errors
///
/// See [`execute`].
pub fn execute_add(a: i32, b: i32) -> Result<i32, String> {
    let wasm = canned_add_module()?;
    let args = encode_args(a, b)?;
    execute(&wasm, &args)
}

/// SHA-256 of `module_hash || result.to_le_bytes()`. Binds the output
/// hash to the specific module that produced it, so two committee
/// members executing **different** modules can never quorum on the
/// same output even if they happen to compute the same `i32` result.
#[must_use]
pub fn output_hash(module_hash: &[u8; 32], result: i32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(module_hash);
    h.update(result.to_le_bytes());
    h.finalize().into()
}
