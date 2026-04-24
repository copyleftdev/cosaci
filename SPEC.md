# **CosaCI — Distributed Attested CI Mesh**

**Version:** 0.1 Draft
**Class:** Internal Distributed Systems / CI Orchestration / Trust Fabric

> **Scope note (2026-04-24):** target is public-infrastructure scale (1M users / 1M runners / 10⁸ jobs/day) from day 1, not internal-org MVP. §§4, 7, 8, 10, 12 are interpreted under the six primitive commitments recorded in `memory/project_scale_primitives.md`:
> (1) sharded small-Raft groups + gossip; (2) pubkey + stake-weighted quorum; (3) VRF per-job assignment; (4) local append-only log + periodic Merkle-root anchoring; (5) WASM/WASI primary, Firecracker escalation; (6) stake+slashing economics, payment-deferred.

---

# 1. **Abstract** {#s1}

CosaCI is a **distributed, attested CI execution system** that replaces centralized CI runners with a **mesh of organization-owned compute nodes (engineer machines)**.

It guarantees:

* **Deterministic execution**
* **Sandbox isolation**
* **Signed attestations**
* **Quorum-based validation**
* **Reproducibility verification**

Unlike traditional CI systems (e.g. GitHub Actions), CosaCI does not trust infrastructure providers—it derives trust from **independent execution + cryptographic proof**.

---

# 2. **Design Goals**

## 2.1 Functional {#s2-1}

* Execute CI jobs across distributed internal machines
* Support PR-based validation workflows
* Provide GitHub-compatible check statuses
* Enable multi-runner quorum validation
* Produce cryptographically signed results

## 2.2 Non-Functional {#s2-2}

* **Zero-trust execution**
* **Deterministic reproducibility**
* **Horizontal scalability**
* **Fault tolerance**
* **Minimal attack surface on engineer machines**

---

# 3. **System Model**

## 3.1 Actors {#s3-1}

| Actor           | Description                         |
| --------------- | ----------------------------------- |
| Coordinator     | Central control plane (sharded)     |
| Agent (Runner)  | Engineer machine executing jobs     |
| SCM             | Git provider (GitHub, GitLab, etc.) |
| Attestation Log | Append-only verification store      |

## 3.2 High-Level Flow {#s3-2}

```text
PR Opened → Coordinator → Job Creation
          → Scheduler (VRF) → Runner Assignment
          → Agents Execute in Sandbox (WASM/FC)
          → Signed Results → Coordinator shard
          → Quorum Verification (stake-weighted)
          → Merkle root anchored → Bulletin
          → Status → SCM
```

---

# 4. **Architecture**

## 4.1 Components

### 4.1.1 Coordinator {#s4-1-1}

Sharded by `job_id` hash. Each shard is a small Raft group. Cross-shard coordination via gossip anti-entropy.

Responsibilities:

* Job orchestration
* Runner scheduling (via VRF)
* Lease management
* Result aggregation
* Quorum validation (stake-weighted)
* SCM integration

### 4.1.2 Agent {#s4-1-2}

Runs on each engineer machine:

* Maintains outbound connection to assigned shard
* Accepts VRF-assigned leases
* Executes jobs in sandbox
* Streams logs
* Signs results

### 4.1.3 Sandbox Runtime {#s4-1-3}

Supported isolation layers:

| Runtime     | Trust Level | Default use                      |
| ----------- | ----------- | -------------------------------- |
| WASM/WASI   | High        | **Default for 90% of jobs**      |
| Firecracker | Very High   | Native-syscall jobs; escalation  |
| Docker      | Medium      | Legacy / fallback only           |

### 4.1.4 Attestation System {#s4-1-4}

* Ed25519 signing
* Environment hashing
* Output hashing
* Provenance recording
* Canonical serialization (hash stability is load-bearing)

---

# 5. **Protocol Specification**

## 5.1 Transport {#s5-1}

* HTTP/2 or WebSocket over TLS
* Mutual TLS (mTLS) required

## 5.2 Agent Registration {#s5-2}

```json
POST /register

{
  "runner_id": "uuid",
  "public_key": "base64",
  "stake": 0,
  "capabilities": {
    "cpu": 8,
    "memory_mb": 16384,
    "platform": "linux-x86_64",
    "runtimes": ["wasm", "firecracker", "docker"]
  }
}
```

Sub-claims:
* **§5.2a** — registry algebra (register / deregister / lookup; lease-only-to-registered)
* **§5.2b** — capability matching predicate
* **§5.2c** — mTLS enforcement

## 5.3 Job Lease {#s5-3}

```json
{
  "lease_id": "uuid",
  "job_id": "uuid",
  "commit": "sha",
  "repo": "owner/repo",
  "command": ["cargo", "test"],
  "timeout": 600,
  "sandbox": "wasm",
  "assignment_vrf_proof": "base64",
  "constraints": {
    "network": "disabled",
    "fs": "readonly"
  }
}
```

## 5.4 Result Submission {#s5-4}

```json
POST /result

{
  "job_id": "uuid",
  "runner_id": "uuid",
  "status": "passed",
  "duration_ms": 41233,
  "stdout_hash": "sha256",
  "stderr_hash": "sha256",
  "env_hash": "sha256",
  "signature": "ed25519"
}
```

---

# 6. **Execution Model**

## 6.1 Deterministic Execution {#s6-1}

Requirements:

* Pinned WASM bytecode (canonical form)
* Locked dependency graphs
* No external network access (default)
* Time normalization (virtual clock)

Sub-claims:
* **§6.1a** — determinism verifier algebra (Merkle root of env + cmd + output stable, order-insensitive)
* **§6.1b** — runner determinism (identical env → identical output bytes); blocked_on real runtime harness.

## 6.2 Sandbox Constraints {#s6-2}

```text
Filesystem: readonly
Network: disabled
CPU: limited
Memory: capped
Syscalls: filtered (WASI allowlist; seccomp for Firecracker)
```

---

# 7. **Scheduling**

## 7.1 Strategy {#s7-1}

* **VRF-based assignment** (draft-irtf-cfrg-vrf): deterministic given (runner_pubkey, seed), unpredictable to assignees, verifiable post-hoc
* Capability matching over VRF-selected subset
* Stake-weighted priority
* **Anti-collusion:** collusion probability bound by VRF uniformity + stake distribution

## 7.2 Lease Semantics {#s7-2}

* TTL-based leases (requires injectable Clock)
* Automatic reassignment on timeout
* Idempotent execution model

---

# 8. **Consensus Model**

## 8.1 Quorum Policy {#s8-1}

```yaml
required_runners: 5
pass_threshold: 4
fail_fast: true
retry_on_disagreement: true
weighting: stake
```

## 8.2 Result Aggregation {#s8-2}

```text
If stake-weighted passes ≥ threshold → PASS
If stake-weighted fails ≥ threshold → FAIL
Else → RETRY or ESCALATE
```

## 8.3 Byzantine Considerations {#s8-3}

* **§8.3a** — reputation monotone in agreement rate (pointwise universal)
* **§8.3b** — adversarial ranking effectiveness (averaged over adversary rate p)
* Sybil resistance: stake-weighted quorum; see §SYBIL
* Optional weighted quorum

---

# 9. **Security Model**

## 9.1 Threats {#s9-1}

| Threat            | Mitigation                                |
| ----------------- | ----------------------------------------- |
| Malicious runner  | Quorum + slashing                         |
| Host compromise   | Sandbox (WASM/FC)                         |
| Replay attack     | Nonce + TTL + bloom-index across window   |
| Tampered output   | Hash + Ed25519 signature                  |
| Data exfiltration | Network isolation                         |
| Sybil             | Stake-weighted quorum                     |
| Collusion         | VRF-assignment unpredictability           |

## 9.2 Trust Model {#s9-2}

```text
Trust = (Reproducibility × Independent Execution × Signatures × Stake-Weighted Quorum)
```

---

# 10. **Attestation Format**

## 10.1 Structure {#s10-1}

```json
{
  "type": "cosaci.attestation.v1",
  "job_id": "uuid",
  "commit": "sha",
  "runner_id": "uuid",
  "result": "passed",
  "environment_hash": "sha256",
  "artifact_hash": "sha256",
  "timestamp": "ISO8601",
  "signature": "ed25519"
}
```

## 10.2 Hashing & Log {#s10-2}

* SHA-256 for content integrity
* **Canonical serialization** (hash stability across field orderings is load-bearing)
* Merkle trees for multi-artifact jobs
* Append-only attestation log per shard
* **Periodic Merkle-root anchoring** to a public bulletin (gist / S3 / on-chain; agnostic)

---

# 11. **Git Integration**

## 11.1 Integration Mechanism {#s11-1}

* GitHub App (primary)
* Webhook ingestion
* Status API updates

## 11.2 Status Lifecycle {#s11-2}

```text
pending → running → quorum-verifying → success/failure
```

---

# 12. **Failure Handling**

## 12.1 Node Failure {#s12-1}

* Lease expiration
* Job reassignment

## 12.2 Flaky Tests {#s12-2}

* **§12.2a** — flake confidence monotone in disagreement count (pointwise)
* **§12.2b** — detection recall ≥ r at injected flakiness rate p (averaged)
* Cross-runner comparison
* Statistical anomaly detection

## 12.3 Network Partitions {#s12-3}

* No split-brain lease: same job cannot have two active leases across partition
* Gossip anti-entropy converges on heal
* Injectable partition model for DST

---

# 13. **Observability** {#s13}

* Distributed log streaming
* Job timeline tracing
* Runner health metrics
* Attestation audit queries

---

# 14. **MVP Scope** {#s14}

### Included

* WASM/WASI sandbox
* Sharded coordinator (Raft-per-shard + gossip)
* VRF-based assignment
* Stake-weighted quorum (2-of-3 minimum)
* Append-only log + Merkle anchoring
* GitHub check integration

### Excluded (v1)

* Payment (slashing only)
* Cross-org federation
* TEE hardware attestation
* Full economic-incentive simulation

---

# 15. **Future Work** {#s15}

* TEE hardware attestation (TPM / SGX / SEV)
* Payment / marketplace layer
* Formal verification of quorum math (TLA+)
* Peer-to-peer removal of shard coordinators
* Cross-org federation

---

# 16. **Key Insight** {#s16}

This system is not just CI.

It is:

> **A distributed proof system that a commit survives adversarial execution at public scale.**

That's fundamentally stronger than:

```text
"CI passed on one machine"
```

Instead you get:

```text
"N independent stake-weighted machines agreed this commit is valid under identical constraints, with VRF-verified anti-collusion and a Merkle-anchored audit trail."
```

---

# 17. **Final Positioning** {#s17}

**CosaCI is not a cheaper GitHub Actions.**

It is:

> **A trust-minimized, public-infrastructure-scale execution fabric for software verification.**

---

**Truth-filter methodology:** every falsifiable claim in this document is encoded as a Hegel property test. See `hypotheses/index.md` for the audit table and `hypotheses/<id>.md` for each card. `cargo test` = spec corroboration. Shrunk counterexamples = successful falsifications.
