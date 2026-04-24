---
id: real-runtime-determinism
source: SPEC.md §6.1b
class: C
status: pending
blocked_on: "real runtime harness (WASM/WASI runtime + Firecracker microVM + optional Docker)"
---

# real-runtime-determinism

**Claim:** When two runners execute the same command under the same pinned environment on the same runtime, the output bytes (`stdout`, `stderr`, produced files) are bitwise identical.

**Why class C:** the claim is about real runtime behavior, not abstract algebra. Testing requires:
- Real WASM runtime (e.g., wasmtime, wasmer) with deterministic flags.
- Real Firecracker microVM with pinned kernel, snapshotted rootfs.
- Real Docker with pinned image digest, cgroup-isolated.

Any of these can be mocked, but mocking defeats the claim — the card exists precisely to test that the runtime honors the determinism contract, not our wrapper's belief about it.

**What survives the filter now:** `det-exec-verifier` (class A) tests the *combination algebra* — given identical hashes, the verifier produces identical Merkle roots. That card is load-bearing: if the verifier has a bug, no amount of runtime determinism saves us. This card is load-bearing in the other direction: if runtime determinism fails, the verifier's correct algebra produces divergent roots for honest runners — legitimate jobs fail quorum.

**How to unblock:**
1. Pick a WASM runtime, pin version, enable deterministic flags (e.g., wasmtime `--cranelift-flag enable_nan_canonicalization=true`).
2. Build a minimal harness that runs a canned WASM module and diffs `stdout`/`stderr`/file outputs across two runs, two machines, two runtime builds.
3. Repeat for Firecracker with a pinned rootfs tarball.
4. Either put the harness behind a `#[ignore]` test invoked via a separate job, or gate it on `HEGEL_RUNTIME_HARNESS=1` env var.

**Notes:** Known determinism hazards to probe: float NaN payloads, system-time access, thread scheduling, uninitialized memory, symbol randomization (ASLR), filesystem readdir order.
