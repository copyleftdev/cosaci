---
id: capability-match
source: SPEC.md §5.2b
class: A
status: passing
test: tests/capability_match.rs
first_passing: 2026-04-24
---

# capability-match

**Claim:** Given `job.requirements` and `runner.capabilities`, the predicate `matches(runner, job)` returns true iff: `runner.cpu ≥ job.cpu_req`, `runner.memory ≥ job.memory_req`, `runner.platform == job.platform_req`, and `runner.runtimes ⊇ job.runtime_req`.

**Property (pointwise):**
- **Reflexive:** a runner always matches a job whose requirements are taken from its own capabilities.
- **Monotone in capabilities:** strictly increasing any single runner capability never changes a `true` result to `false`.
- **Anti-monotone in requirements:** strictly decreasing any single job requirement never changes a `true` to `false`.
- **Platform is exact match:** mismatched platform → `false` regardless of other fields.

**Test shape:** Hegel draws (runner, job); assert the four properties above by constructing mutated pairs.

**Notes:** Runtime set is a subset check, not equality — `{wasm, firecracker, docker} ⊇ {wasm}`.
