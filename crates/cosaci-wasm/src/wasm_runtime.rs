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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use wasmtime::{Config, Engine, Instance, Module, ResourceLimiter, Store, Trap};

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
/// Equivalent to [`execute_with_limits`] with [`ExecLimits::unlimited`].
///
/// # Errors
///
/// Returns a string error if the module fails to compile, instantiate,
/// the `add` export is missing or has the wrong signature, the args
/// fail to decode as `(i32, i32)`, or the call traps.
pub fn execute(wasm: &[u8], args_cbor: &[u8]) -> Result<i32, String> {
    match execute_with_limits(wasm, args_cbor, ExecLimits::unlimited())? {
        ExecOutcome::Ok(v) => Ok(v),
        ExecOutcome::LimitExceeded(kind) => Err(format!(
            "limit exceeded ({kind:?}) under unlimited budget — should be impossible"
        )),
    }
}

// ────────────────────────────────────────────────────────────────────────
// Resource-limited execution (issue #43)
// ────────────────────────────────────────────────────────────────────────

/// Per-step resource budget. Zero means unlimited for each axis.
///
/// Used by [`execute_with_limits`]; `cosaci-jobs` translates its
/// `Limits` struct into this shape (cpu_seconds → fuel via a fixed
/// fuel-per-second constant; memory_mb → bytes; wall_seconds →
/// `Duration`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecLimits {
    /// Wasmtime fuel budget (≈ instruction count). `0` = unlimited.
    pub fuel: u64,
    /// Linear-memory cap in bytes. `0` = unlimited. Enforced via a
    /// per-store [`ResourceLimiter`] that returns an error on
    /// `memory.grow` attempts past the cap, causing the WASM call to
    /// trap.
    pub memory_bytes: usize,
    /// Wall-clock deadline. `Duration::ZERO` = unlimited. Enforced via
    /// wasmtime epoch interruption: a separate timer thread increments
    /// the engine's epoch after `wall` elapses, and the running call
    /// traps with [`Trap::Interrupt`].
    pub wall: Duration,
}

impl ExecLimits {
    /// All limits unlimited — equivalent to no enforcement at all.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            fuel: 0,
            memory_bytes: 0,
            wall: Duration::ZERO,
        }
    }
}

/// Which resource limit a call exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecLimitKind {
    /// Fuel budget exhausted (cpu).
    Cpu,
    /// Linear-memory cap exceeded.
    Memory,
    /// Wall-clock deadline reached.
    Wall,
}

/// Outcome of a limit-checked execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecOutcome {
    /// Call returned normally with this `i32` value.
    Ok(i32),
    /// Call was terminated because it exceeded the indicated limit.
    LimitExceeded(ExecLimitKind),
}

/// Per-store context that holds the byte-cap limiter state. Wasmtime
/// calls [`ResourceLimiter::memory_growing`] before every `memory.grow`;
/// returning `Err` traps the call.
struct LimitsCtx {
    max_bytes: usize,
}

impl ResourceLimiter for LimitsCtx {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if self.max_bytes > 0 && desired > self.max_bytes {
            return Err(wasmtime::Error::msg(format!(
                "cosaci-wasm memory cap exceeded: requested {desired} > cap {}",
                self.max_bytes
            )));
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(true)
    }
}

/// Execute the `add` export under a resource budget. Returns
/// [`ExecOutcome::Ok`] on normal return, [`ExecOutcome::LimitExceeded`]
/// when the call hits one of the configured limits. Returns
/// `Err(String)` only for non-limit errors (compile, instantiate,
/// missing export, real WASM trap unrelated to limits).
///
/// # Errors
///
/// String error on module-compile, instantiation, or non-limit traps.
/// CBOR-decode failure on `args_cbor`.
pub fn execute_with_limits(
    wasm: &[u8],
    args_cbor: &[u8],
    limits: ExecLimits,
) -> Result<ExecOutcome, String> {
    let (a, b): (i32, i32) =
        ciborium::from_reader(args_cbor).map_err(|e| format!("cbor decode args: {e}"))?;

    let mut config = Config::new();
    if limits.fuel > 0 {
        config.consume_fuel(true);
    }
    let wall_active = !limits.wall.is_zero();
    if wall_active {
        config.epoch_interruption(true);
    }
    let engine = Engine::new(&config).map_err(|e| format!("engine: {e}"))?;
    let module = Module::new(&engine, wasm).map_err(|e| format!("module: {e}"))?;

    let ctx = LimitsCtx {
        max_bytes: limits.memory_bytes,
    };
    let mut store: Store<LimitsCtx> = Store::new(&engine, ctx);
    store.limiter(|s| s);
    if limits.fuel > 0 {
        store
            .set_fuel(limits.fuel)
            .map_err(|e| format!("set_fuel: {e}"))?;
    }
    if wall_active {
        store.set_epoch_deadline(1);
    }

    // Wall-clock interrupter. Spawned only if wall is bounded; signals
    // the engine after `limits.wall` elapses, or sooner if `stop` is
    // raised (the call returned before the deadline).
    let wall_thread: Option<(thread::JoinHandle<()>, Arc<AtomicBool>)> = if wall_active {
        let engine_clone = engine.clone();
        let wall = limits.wall;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = stop.clone();
        let handle = thread::spawn(move || {
            let start = Instant::now();
            while !stop_c.load(Ordering::Relaxed) {
                if start.elapsed() >= wall {
                    engine_clone.increment_epoch();
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        Some((handle, stop))
    } else {
        None
    };

    let instance = Instance::new(&mut store, &module, &[]).map_err(|e| format!("instance: {e}"))?;
    let add = instance
        .get_typed_func::<(i32, i32), i32>(&mut store, "add")
        .map_err(|e| format!("get_typed_func add: {e}"))?;
    let res = add.call(&mut store, (a, b));

    if let Some((handle, stop)) = wall_thread {
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }

    match res {
        Ok(v) => Ok(ExecOutcome::Ok(v)),
        Err(e) => {
            if let Some(trap) = e.downcast_ref::<Trap>() {
                match trap {
                    Trap::OutOfFuel => return Ok(ExecOutcome::LimitExceeded(ExecLimitKind::Cpu)),
                    Trap::Interrupt => return Ok(ExecOutcome::LimitExceeded(ExecLimitKind::Wall)),
                    _ => {}
                }
            }
            // The byte-cap limiter raises an `anyhow::Error` whose
            // message we tag with a sentinel string; match on it to
            // surface the Memory kind.
            let msg = format!("{e:#}");
            if msg.contains("cosaci-wasm memory cap exceeded") {
                return Ok(ExecOutcome::LimitExceeded(ExecLimitKind::Memory));
            }
            Err(format!("call: {msg}"))
        }
    }
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
