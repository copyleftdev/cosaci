#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! `cosaci-wasm` — WebAssembly runtime harness for CosaCI payloads.
//!
//! Wraps `wasmtime` (cranelift + runtime). Heavy: pulls dozens of
//! transitive crates, isolated here so non-runner consumers don't pay
//! the cost.

pub mod wasm_runtime;
