# CosaCI Hypotheses — Audit Trail (SSOT)

Each row is one falsifiable claim from `SPEC.md`. A claim lives as a card at `hypotheses/<id>.md` and (if class A or B-stat) a test at `tests/<id>.rs`. Status flow: `pending` → `encoded` → `passing` → `falsified`. Shrunk counterexamples are *successful falsifications*, not failures — they are the filter working.

**Class key:**
- **A** — pointwise universal; `#[hegel::test]` asserts per-draw.
- **B-stat** — averaged over distribution; Hegel draws distribution params, inner loop samples, assert mean.
- **C** — blocked on external harness (real Docker / WASM / FC / TLS / netem / TPM).
- **D** — boundary; cannot be made executable at the Hegel layer (integration test domain or meta-aggregate).

**Primitive refs (see `memory/project_scale_primitives.md`):**
P1 = sharded Raft + gossip  ·  P2 = pubkey + stake-weighted  ·  P3 = VRF  ·  P4 = Merkle-anchored log  ·  P5 = WASM-primary  ·  P6 = stake+slashing.

---

## Tier 0 — Core algebra (27 cards, all A)

| ID | § | Class | Status | Test | Depends_on |
|---|---|---|---|---|---|
| `registry-algebra` | §5.2a | A | **passing** | `tests/registry_algebra.rs` | — |
| `capability-match` | §5.2b | A | **passing** | `tests/capability_match.rs` | — |
| `lease-lifecycle` | §5.3 / §7.2 | A | **passing** | `tests/lease_lifecycle.rs` | Clock trait ✓ |
| `quorum-math` | §8.1 | A | **passing** | `tests/quorum_math.rs` | P2 |
| `result-aggregation` | §8.2 | A | **passing** | `tests/result_aggregation.rs` + `tests/aggregator_retry_bound.rs` | — |
| `reputation-monotonicity` | §8.3a | A | **passing** | `tests/reputation_monotonicity.rs` | — |
| `replay-protection` | §9.1 | A | **passing** | `tests/replay_protection.rs` + `tests/bloom_fp_rate.rs` | Clock ✓ + bloom ✓ |
| `tamper-rejection` | §9.1 | A | **passing** | `tests/tamper_rejection.rs` | ed25519-dalek 2.2.0 |
| `attestation-roundtrip` | §10.1 | A | **passing** | `tests/attestation_canonicalization.rs::roundtrip_equality` | serde + ciborium |
| `attestation-canonicalization` | §10.2 | A | **passing** | `tests/attestation_canonicalization.rs` | ciborium + sha2 + serde-big-array |
| `status-lifecycle` | §11.2 | A | **passing** | `tests/status_lifecycle.rs` | — |
| `det-exec-verifier` | §6.1a | A | **passing** | `tests/det_exec_verifier.rs` | rs_merkle 1.5 |
| `pipeline-determinism` | §6.2 | A | **passing** | `tests/pipeline_determinism.rs` | cosaci-jobs (#39) |
| `capability-aware-committee` | §5.2b + §7.1 | A | **passing** | `tests/capability_aware_committee.rs` | capability-match + vrf (#34) |
| `resource-limit-enforcement` | §6.3 | A | **passing** | `tests/resource_limit_enforcement.rs` | wasmtime fuel + ResourceLimiter + epoch (#43) |
| `retrieval-soundness` | §10.4 | A | **passing** | `tests/retrieval_soundness.rs` | merkle-log + persistence (#44) |
| `enrollment-gate-enforcement` | §5.1 | A | **passing** | `tests/enrollment_gate_enforcement.rs` | sha2 + signing + vrf pubkey shapes (#45) |
| `slashing-faithfulness` | §8.4 | A | **passing** | `tests/slashing_faithfulness.rs` | quorum-math + tamper-rejection (#35) |
| `partial-committee-tolerance` | §8.5 | A | **passing** | `tests/partial_committee_tolerance.rs` | quorum-math (#61) |
| `egress-policy-evaluation` | §6.4 | A | **passing** | `tests/egress_policy_evaluation.rs` | cosaci-jobs (#54, partial) |
| `crash-recovery-soundness` | §10.5 | A | **passing** | `tests/crash_recovery_soundness.rs` | serde_json + tempfile (#51, partial) |
| `source-fetch-determinism` | §6.2.1 | A | **passing** | `tests/source_fetch_determinism.rs` + `tests/source_fetch_integration.rs` | tempfile + git (#40) |
| `submission-auth-gate` | §13 | A | **passing** | `tests/submission_auth_gate.rs` | tenant-rate-limit + ed25519-dalek + ciborium (#46) |
| `concurrent-job-isolation` | §7.4 | A | **passing** | `tests/concurrent_job_isolation.rs` | quorum-math + merkle-log-append-only (#50, partial) |
| `webhook-auth-gate` | §13.2 | A | **passing** | `tests/webhook_auth_gate.rs` | hmac 0.13 + toml 1.1 (#52, partial) |
| `admin-auth-gate` | §13 (admin extension) | A | **passing** | `tests/admin_auth_gate.rs` | submission-auth-gate + mtls (#53 follow-on) |
| `pipeline-submission` | §13 (v0.5 lift) / §6.2 | A | **passing** | `tests/submission_auth_gate.rs` | submission-auth-gate + pipeline-determinism (#106) |

## Tier 1 — Scale primitives (9 cards, all A)

| ID | § | Class | Status | Test | Depends_on |
|---|---|---|---|---|---|
| `coordinator-shard-algebra` | §4.1.1 | A | **passing** | `tests/coordinator_shard_algebra.rs` + `tests/shard_incremental_handoff.rs` | hand-rolled + handoff + replicas |
| `vrf-assignment-uniformity` | §7.1 | A | **passing** | `tests/vrf_assignment_uniformity.rs` | schnorrkel 0.11 + merlin 3.0 |
| `merkle-log-append-only` | §10.2 | A | **passing** | `tests/merkle_log_append_only.rs` + `tests/merkle_log_mmr_peaks.rs` | rs_merkle 1.5 + MMR peaks |
| `merkle-log-persistence` | §10.5 | A | **passing** | `tests/merkle_log_persistence.rs` | tempfile + FileStore (#33) |
| `tenant-rate-limit` | §13 (new) | A | **passing** | `tests/tenant_rate_limit.rs` | hand-rolled token bucket |
| `partition-invariants` | §12.3 | A | **passing** | `tests/partition_invariants.rs` + `tests/replicated_cluster_split_brain.rs` | Clock ✓ + gate + 2-replica model |
| `confidentiality-algebra` | §9 (new) | A | **passing** | `tests/confidentiality_algebra.rs` | chacha20poly1305 0.10 |
| `flaky-confidence-monotonicity` | §12.2a | A | **passing** | `tests/flaky_confidence_monotonicity.rs` | — |
| `gossip-convergence-invariant` | §12.3 | A | **passing** | `tests/gossip_convergence_invariant.rs` | hand-rolled LWW CRDT |

## Tier 2 — Statistical claims (6 cards, all B-stat)

| ID | § | Class | Status | Test | Depends_on |
|---|---|---|---|---|---|
| `adversarial-reputation-ranking` | §8.3b | B-stat | **passing** | `tests/adversarial_reputation_ranking.rs` | rand 0.10 / ChaCha8 |
| `sybil-resistance` | §9.1 | B-stat | **passing** | `tests/sybil_resistance.rs` | quorum ✓ + rand_chacha |
| `flaky-detection-recall` | §12.2b | B-stat | **passing** | `tests/flaky_detection_recall.rs` | flake ✓ + rand_chacha |
| `scheduling-fairness` | §7.1 | B-stat | **passing** | `tests/scheduling_fairness.rs` | sha2 stand-in + rand_chacha |
| `collusion-probability` | §7.1 / §9.1 | B-stat | **passing** | `tests/collusion_probability.rs` | sha2 stand-in + rand_chacha |
| `gossip-propagation-time` | §12.3 | B-stat | **passing** | `tests/gossip_propagation_time.rs` | hand-rolled gossip sim |

## Tier 3 — External-harness cards (4 cards, class C)

| ID | § | Class | Status | Harness |
|---|---|---|---|---|
| `real-runtime-determinism` | §6.1b | C | **passing** † | wasmtime 44 (WASM subset) |
| `mtls-enforcement` | §5.2c | C | **passing** † | rustls 0.23 + rcgen 0.14 |
| `real-partition-recovery` | §12.3 | C | pending | netem / jepsen-style harness |
| `tee-attestation` | §15 | C | pending | TPM / SGX / SEV harness |

## Tier 4 — Boundary / meta (3 cards, all D)

| ID | § | Class | Status | Kind |
|---|---|---|---|---|
| `github-checks-integration` | §11.1 | D | **passing** | `tests/github_checks_fixtures.rs` (fixture-replay) |
| `latency-sla` | §16 | D | **passing** † | criterion 0.7 (baseline only) |
| `survives-adversarial-execution` | §16 | D | **passing** † | aggregate: all reachable corroborations closed |

---

**Totals:** 35 A + 6 B-stat + 4 C + 3 D = **48 cards** · **46 passing**.

- All A and B-stat cards: **41/41 passing** with no deferred sub-claims.
- Tier 3 (C-class): 2/4 passing — `mtls-enforcement` (rustls in-memory harness), `real-runtime-determinism` (wasmtime WASM subset). Remaining 2 (`real-partition-recovery`, `tee-attestation`) are genuinely blocked on infrastructure unavailable in the filter's environment (netem/Jepsen and TPM/SGX/SEV).
- Tier 4 (D-class): **3/3 passing** — `latency-sla` (criterion baselines), `survives-adversarial-execution` (meta-aggregate), `github-checks-integration` (fixture-replay contract test against GitHub's documented Checks API schema; live API integration is out-of-scope `/schedule`-able routine).

**First-pass execution order:** Tier 0 cards have zero scale-primitive dependency and land the most per line-of-test. Recommend `quorum-math`, `attestation-canonicalization`, `tamper-rejection` as the first three — they are the load-bearing trust chain and any defect there invalidates downstream claims.
