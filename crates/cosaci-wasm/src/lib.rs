#![forbid(unsafe_code)]

//! `cosaci-wasm` — WebAssembly runtime harness for CosaCI payloads.
//!
//! Wraps `wasmtime` (cranelift + runtime). Heavy: pulls dozens of
//! transitive crates, isolated here so non-runner consumers don't pay
//! the cost.

pub mod wasm_runtime;
