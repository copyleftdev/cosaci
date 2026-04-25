---
id: resource-limit-enforcement
class: A
section: §6.3
status: passing
test: tests/resource_limit_enforcement.rs
depends_on: pipeline-determinism ✓ + wasmtime 44 (fuel + memory limiter + epoch)
---

# Resource limit enforcement (WASM half)

A WASM step that exceeds any configured `Limits` axis terminates
deterministically with `StepStatus::LimitExceeded { which }`. Two
runners executing the same step against the same limits and module
must agree on whether the limit was hit and which one.

The native (cgroups) half of issue #43 is class C, gated on a Linux
harness, and tracked separately.

## Statement

For any WASM module + args + `Limits` triple:

1. **Unlimited compliance.** With every axis at `0` (unlimited), a
   compliant module runs to `Success`.

2. **Cpu enforcement.** A spinning module under tight `cpu_seconds`
   terminates with `LimitExceeded(Cpu)` deterministically.

3. **Memory enforcement.** A `memory.grow`-aggressive module under a
   memory cap below the requested growth terminates with
   `LimitExceeded(Memory)`.

4. **Wall enforcement.** A spinning module with `cpu_seconds = 0`
   (fuel disabled) and tight `wall_seconds` terminates with
   `LimitExceeded(Wall)`.

5. **Compliant within budget.** A compliant module with adequate
   budget runs to `Success`.

6. **Output-hash distinguishes limit kind.** The step's `output_hash`
   for a `LimitExceeded(K)` outcome is the SHA-256 of the canonical
   CBOR encoding of `(step, K)`. Two runners that hit the same
   `(step, K)` agree; flipping `K` diverges the hash.

## Class

**A** for the WASM half (pointwise universal — wasmtime is in-process,
deterministic, no external harness).

The native half (cgroups v2 / setrlimit) is **C**: enforcement
correctness can only be observed on a real Linux kernel with cgroups
v2 mounted. That work is gated on `HEGEL_LINUX_HARNESS=1` and lives in
a separate test file (lands in a follow-on PR).

## Mapping `Limits` → wasmtime primitives

- `cpu_seconds` × `FUEL_PER_CPU_SECOND` (1 × 10⁹) → wasmtime fuel.
  One fuel unit ≈ one wasmtime instruction; modern x86 dispatches
  ~10⁹ simple WASM ops per second, so the multiplier is conservative
  for compute-bound modules. I/O- or trap-bound modules consume fuel
  faster in wall-time terms.
- `memory_mb` × 1024 × 1024 → bytes. A custom `ResourceLimiter`
  returns `Err` from `memory_growing` when the requested size exceeds
  the cap; wasmtime traps the call.
- `wall_seconds` → `Duration`. A timer thread increments the engine's
  epoch after the wall elapses; wasmtime's epoch interruption traps
  the running call.

## Falsification candidates

- Forgetting to enable fuel consumption in `Config` — `set_fuel`
  becomes a no-op and Property 2 falsifies (the call runs forever
  until the wall thread fires Wall).
- Using `StoreLimits::memory_size` (returns `Ok(false)` from
  `memory_growing`) instead of an `Err`-returning limiter —
  `memory.grow` returns `-1`, the module continues, and Property 3
  falsifies (the call hits Cpu or Wall instead).
- Forgetting the wall thread — Property 4 falsifies (the call spins
  forever).
- Hashing only the step bytes (omitting `LimitKind`) — Property 6
  falsifies (Cpu and Wall agree).

## Coverage

- `unlimited_budget_runs_to_success` — Property 1
- `tight_fuel_on_spinning_module_yields_cpu` — Property 2
- `tight_memory_on_grow_module_yields_memory` — Property 3
- `tight_wall_on_spinning_module_yields_wall` — Property 4
- `adequate_budget_on_compliant_module_yields_success` — Property 5
- `output_hash_for_limit_exceeded_distinguishes_kind` — Property 6
- `pipeline_surfaces_limit_exceeded_for_wall` — end-to-end via
  `execute_pipeline`

## Performance bound

The per-step overhead of resource-limited execution vs. unlimited:

- Fuel accounting adds ~1-2% to instruction-bound workloads (wasmtime
  benchmark).
- The wall-thread costs one OS thread per active step, with a 10ms
  sleep granularity. Acceptable for v0.3; future work (#47, #50) may
  consolidate into a single timer wheel.
- Memory-limiter overhead is a single comparison per `memory.grow`,
  negligible.
