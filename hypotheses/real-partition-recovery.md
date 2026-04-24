---
id: real-partition-recovery
source: SPEC.md §12.3
class: C
status: pending
blocked_on: "netem / Jepsen-style network fault harness"
---

# real-partition-recovery

**Claim:** Under real-network partition modes (TCP RST, asymmetric drops, clock skew, selective blackhole, packet duplication/reordering), the system recovers correctly and preserves the invariants tested abstractly in `partition-invariants` (class A).

**Why class C:** partition-invariants tests the system under a *modeled* partition (test double drops messages). Real networks exhibit failure modes the model doesn't: asymmetric reachability (A can reach B, B can't reach A), clock skew correlated with partition, half-open connections surviving past socket timeout.

**How to unblock:**
1. Pick a fault-injection tool: `netem`, `toxiproxy`, Jepsen, or (more rigorous) `chaoslab` — see available MCP server.
2. Scenarios to inject: symmetric partition + heal, asymmetric partition, clock skew ±30s, packet reorder/duplicate, 100% drop followed by burst delivery.
3. After each scenario, assert `partition-invariants` properties over collected system state.
4. Gate behind `HEGEL_NET_HARNESS=1`; run less frequently than Hegel tests (harness is slow).

**What survives the filter now:** `partition-invariants` (A) and `gossip-convergence-invariant` (A) are the abstract properties. This card closes the sim-to-real gap.

**Notes:** Consider delegating to `mcp__chaoslab__chaoslab_run_experiment` once it's proven — the chaos-lab MCP server is already available in the environment.
