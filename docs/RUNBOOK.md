# CosaCI Operator Runbook (v0.3)

> **Audience.** You're a sysadmin / SRE standing up CosaCI on
> infrastructure your team already runs, or responding to an
> incident at 2 AM. The library has the primitives; this document
> turns them into procedures someone can perform under stress.
>
> **Scope.** This runbook covers what's deployable in the v0.3
> tag. Sections marked **PARTIAL** or **DEFERRED** point to the
> tracking issue for the missing piece — when it ships, the
> corresponding section gets concrete commands.

## Table of contents

1. [Bootstrap a fresh deployment](#1-bootstrap-a-fresh-deployment)
2. [Adding a runner](#2-adding-a-runner)
3. [Cert rotation](#3-cert-rotation)
4. [CRL update / runner revocation](#4-crl-update--runner-revocation)
5. [Disaster recovery](#5-disaster-recovery)
6. [Debugging a stuck job](#6-debugging-a-stuck-job)
7. [Slashing review](#7-slashing-review)
8. [Capacity planning](#8-capacity-planning)

---

## 1. Bootstrap a fresh deployment

End-state: 1 coordinator + 3 runners attesting their first job.

### 1a. Prerequisites

- Linux host(s) with Docker 24+ **OR** systemd 245+. Examples below
  show both. Pick one — they're interchangeable.
- `openssl` for cert generation if you're going systemd-native.
  Docker users let `Dockerfile.bootstrap` handle it.
- TCP port `7878` open between coordinator and runners (mTLS).

### 1b. Compose path (fastest)

```bash
git clone https://github.com/copyleftdev/cosaci
cd cosaci
docker compose -f contrib/docker-compose.yml up --build
```

The `bootstrap` service generates a demo CA + server cert + 5 agent
certs into a Docker volume; coordinator + 5 agents start in
sequence. The compose stack is the **non-Rust equivalent of**
`cargo run -p cosaci-demo --bin demo_networked` — it's the smoke
test for the full mesh.

Expected output (last few lines, after agents register):

```
coord    | [coordinator] fleet assembled (5 agents, all VRF-attested)
coord    | [coordinator] job 1 outcome Pass (threshold 200, committee stake 300)
coord    | [coordinator] job 1 anchored at position 0 root [...]
```

If `outcome Pass` and `anchored at position 0 root` appear, the
deployment is healthy. To stop and clean up: `docker compose down -v`
(the `-v` removes the demo certs volume).

### 1c. systemd path (production-shaped)

For a real deployment, you provision certs from your own PKI rather
than the demo bootstrap. Here we generate them with `openssl`; in
practice your PKI / Vault / SmallStep / step-ca will do this.

```bash
# 1. Build release binaries on a build host:
cargo build --release -p cosaci-coordinator -p cosaci-agent

# 2. Install binaries + units on the coordinator host:
sudo install -Dm0755 target/release/coordinator /usr/local/bin/cosaci-coordinator
sudo install -Dm0644 contrib/systemd/cosaci-coordinator.service \
    /etc/systemd/system/cosaci-coordinator.service
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/cosaci cosaci
sudo install -d -o cosaci -g cosaci /var/lib/cosaci /etc/cosaci

# 3. Generate the CA + server cert. (Use your real PKI here.)
sudo bash contrib/docker/bootstrap.sh # writes to /certs/ by default
sudo install -Dm0644 -o cosaci -g cosaci /certs/ca.pem        /etc/cosaci/ca.pem
sudo install -Dm0644 -o cosaci -g cosaci /certs/server.pem    /etc/cosaci/server.pem
sudo install -Dm0600 -o cosaci -g cosaci /certs/server.key.pem /etc/cosaci/server.key.pem

# 4. Pre-enroll the first three agents (issue #45).
sudo touch /etc/cosaci/enrollment.txt
sudo chown cosaci:cosaci /etc/cosaci/enrollment.txt
# Append one line per runner; see Section 2 for fingerprint computation.

# 5. Start the coordinator:
sudo systemctl daemon-reload
sudo systemctl enable --now cosaci-coordinator
sudo journalctl -u cosaci-coordinator -f
```

You should see:

```
[coordinator] listening on 0.0.0.0:7878 (mTLS)
[coordinator] enrollment gate enabled (3 runner(s) loaded from /etc/cosaci/enrollment.txt)
```

The coordinator is now waiting for `--fleet` agents to register.
Continue with Section 2 to bring runners online.

### 1d. End-state check

After agents register and the first job runs:

```bash
# Coordinator host:
sudo journalctl -u cosaci-coordinator | grep "outcome Pass"
# Should print at least one line.

# Read-API check (issue #44):
# (The read API is exposed when --read-addr is set; the systemd
# unit doesn't set it by default. Add it to /etc/cosaci/coordinator.env
# as COSACI_READ_ADDR=0.0.0.0:7879 if you want external auditors.)
```

---

## 2. Adding a runner

End-state: a new agent with a known fingerprint pair joins the
committee pool on next start.

### 2a. Generate the runner's keypair

The agent derives its keys from a runtime seed. For production,
use a real keypair generator (HSM, Vault, hardware token). For
the demo / dev workflow, the agent's `--id` is the seed.

```bash
# On the runner host, build the agent binary:
cargo build --release -p cosaci-agent

# Generate keypair + capture fingerprints. The agent prints both
# fingerprints at registration; you can also derive them
# programmatically by re-running the agent's seed code. For v0.3,
# the simplest path: start the agent with --id N and copy the
# fingerprints from its registration log.
```

> **v0.3 admin CLI (#53):** filesystem-only — `cosaci-admin enroll`
> writes directly to `enrollment.txt`, `cosaci-admin revoke`
> removes a record, `cosaci-admin agents list` shows the current
> set. The wire-protocol form (talking to a running coordinator
> over TLS) lands when `#46` (AuthN) + the Admin* envelope
> variants ship; v0.3 operators run the CLI on the coordinator
> host with read/write access to the enrollment file.

### 2b. Compute the fingerprints

The fingerprints are SHA-256 of each pubkey:

- `signing_fp = SHA-256(ed25519_verifying_key_bytes)` (32 bytes →
  64 lowercase hex chars)
- `vrf_fp     = SHA-256(schnorrkel_sr25519_pubkey_bytes)`

The simplest way to capture them in v0.3:

1. Run the agent once against the (possibly empty) enrollment
   file. The coordinator rejects with:
   `[coordinator] rejecting unenrolled agent runner_id=N from peer
   (signing_fp=…, vrf_fp=…)`.
2. Copy the two `…` hex strings into the enroll command below.

### 2c. Enroll the runner

```bash
sudo cosaci-admin agents enroll \
    --enrollment /etc/cosaci/enrollment.txt \
    --runner-id     <N> \
    --signing-fp    <signing_fp_hex> \
    --vrf-fp        <vrf_fp_hex> \
    --reputation    1.0
```

The CLI:

- Refuses if `runner_id` is already enrolled (use `revoke` first
  if you mean to replace).
- Validates fingerprint hex (64 chars each).
- Writes atomically (tempfile + rename) — an interrupted run
  leaves either the original or the new file, never partial.

To list current enrollments:

```bash
sudo cosaci-admin agents list --enrollment /etc/cosaci/enrollment.txt
```

To revoke:

```bash
sudo cosaci-admin agents revoke \
    --enrollment /etc/cosaci/enrollment.txt \
    --runner-id <N>
```

The on-disk file format (whitespace-separated, comments with `#`,
one record per line) is documented; you can hand-edit it if
needed:

```
# /etc/cosaci/enrollment.txt
# CosaCI enrollment — one record per non-comment line
# Fields: runner_id signing_fp_hex vrf_fp_hex enrolled_at_unix_ns initial_reputation
1  <signing_fp_hex>  <vrf_fp_hex>  1700000000000000000  1.0
2  <signing_fp_hex>  <vrf_fp_hex>  1700000000000000000  1.0
```

> **PARTIAL — runtime reload deferred (#45 follow-on).** The
> coordinator reads the enrollment file at startup. To reload after
> editing, restart: `sudo systemctl restart cosaci-coordinator`.
> The job loop drains gracefully on `SIGTERM` (exit code 0) — see
> the SIGTERM handling notes in `bins/cosaci-coordinator/src/main.rs`.

### 2d. Start the agent

```bash
sudo install -Dm0755 target/release/agent /usr/local/bin/cosaci-agent
sudo install -Dm0644 contrib/systemd/cosaci-agent@.service \
    /etc/systemd/system/cosaci-agent@.service
sudo install -Dm0644 -o cosaci -g cosaci agent-N.pem        /etc/cosaci/agent-N.pem
sudo install -Dm0600 -o cosaci -g cosaci agent-N.key.pem    /etc/cosaci/agent-N.key.pem
sudo install -Dm0644 -o cosaci -g cosaci /etc/cosaci/ca.pem /etc/cosaci/ca.pem

sudo systemctl daemon-reload
sudo systemctl enable --now cosaci-agent@N  # N is the runner_id
sudo journalctl -u cosaci-agent@N -f
```

Expected output:

```
[agent N] connecting to coordinator.local:7878 (mTLS)
[agent N] registered (mTLS ✓, VRF ✓)
```

If the coordinator rejects with `rejecting unenrolled agent`, your
fingerprints in the enrollment file don't match what the agent
sent. Double-check Step 2b.

---

## 3. Cert rotation

End-state: the coordinator serves a new server cert without
restarting; in-flight TLS connections survive; new handshakes pick
up the new cert.

This procedure relies on **SIGHUP-triggered cert reload** (issue #8,
shipped in v0.2.0).

### 3a. Generate the new cert

Whatever your CA process is — `step-ca`, Vault, manual `openssl`,
your corporate PKI — produce:

- `/etc/cosaci/server.pem.new`  (the new cert)
- `/etc/cosaci/server.key.pem.new`  (the new key)

### 3b. Atomic swap + reload

```bash
sudo mv /etc/cosaci/server.pem     /etc/cosaci/server.pem.bak
sudo mv /etc/cosaci/server.key.pem /etc/cosaci/server.key.pem.bak
sudo mv /etc/cosaci/server.pem.new     /etc/cosaci/server.pem
sudo mv /etc/cosaci/server.key.pem.new /etc/cosaci/server.key.pem
sudo systemctl kill -s HUP cosaci-coordinator
```

### 3c. Verify

In the coordinator log:

```
[coordinator] SIGHUP: server config reloaded (cert=/etc/cosaci/server.pem, crl=<none>)
```

Existing agent connections are unaffected (rustls captured the old
verifier at handshake time). New connections pick up the new cert.

To test the live cert from another host:

```bash
echo | openssl s_client \
    -connect coordinator.local:7878 \
    -CAfile /etc/cosaci/ca.pem \
    -showcerts 2>/dev/null \
    | openssl x509 -noout -dates -subject
```

The `notBefore` / `notAfter` should match the new cert.

### 3d. Failure modes

| Symptom | Cause | Recovery |
|---|---|---|
| `SIGHUP: reload failed (...); keeping previous config` | New cert/key files missing or malformed | Fix the files; SIGHUP again. The coordinator keeps serving the old cert. |
| New cert installed but handshake still uses old | Cached `ServerConnection` for that peer | Reconnect from the client side. |
| Agent connections drop after rotation | Agent's `--ca` doesn't trust the new chain | Update agents' CA bundle if you rotated the CA, not just the server cert. |

---

## 4. CRL update / runner revocation

End-state: a previously-trusted agent cert is revoked; subsequent
TLS handshakes from that agent are rejected.

This procedure relies on **CRL hot-reload** (issue #8, shipped in
v0.2.0).

### 4a. Add the cert serial to the CRL

```bash
# Use your CA's CRL workflow. Output goes to /etc/cosaci/agents.crl
# (or wherever your --crl points). The bundle CosaCI uses is a
# DER-encoded X.509 CRL — same shape OpenSSL emits.
sudo cp /path/to/your/updated.crl /etc/cosaci/agents.crl
```

### 4b. Reload

```bash
sudo systemctl kill -s HUP cosaci-coordinator
```

In the log:

```
[coordinator] SIGHUP: server config reloaded (cert=/etc/cosaci/server.pem, crl=/etc/cosaci/agents.crl)
```

### 4c. Verify

The revoked agent's next reconnect attempt should fail at TLS
handshake. From the coordinator log you should see:

```
[coordinator] handshake/read failed for <peer>: <tls error>
```

> **Note — existing connections.** SIGHUP swaps the config
> atomically; rustls connections already in progress retain the
> old verifier. To kick a revoked agent off mid-job, also restart
> the coordinator. The job loop drains gracefully (SIGTERM) but
> revocation acceleration trades graceful shutdown for security.

---

## 5. Disaster recovery

End-state: the coordinator was killed (crash, OOM, host reboot)
mid-job. The audit trail is intact; in-flight work is replayable
from the runner side.

### 5a. What survives, what doesn't (v0.3)

| State | Survives? | Where |
|---|---|---|
| Anchored attestations | **Yes** | Persistent Merkle log at `--log <path>` (issue #33) |
| Job registry (for read API) | **No (v0.3)** | In-memory `HashMap` (#44); rebuild from log + agent re-registration |
| Agent registrations | **No** | mTLS connections are torn down; agents reconnect on coord restart |
| In-flight job (committee assigned, attestations pending) | **No** | Lost — no journal, no replay |
| Submission queue | **N/A (v0.3)** | Job submission via stdin/socket lands in #32 |

### 5b. v0.3 recovery procedure

```bash
# 1. Diagnose
sudo journalctl -u cosaci-coordinator --since "10 min ago"

# 2. Verify the persistent log is intact
ls -la /var/lib/cosaci/attest.log
# Size must be a multiple of 32. If not, the log is corrupt
# (truncated mid-append) — see 5c below.

# 3. Restart
sudo systemctl restart cosaci-coordinator

# 4. Re-trigger pending jobs from the upstream submission system
# (whoever was submitting work — PR comment hook, cron, etc.).
# The submitted-but-unanchored work is lost; resubmit.
```

### 5c. Corrupt log recovery

The log is fixed-32-byte-record append-only. A power loss
mid-append can leave a non-multiple-of-32 file. The coordinator
refuses to open it (issue #33's safety check).

```bash
# Diagnose
sudo wc -c /var/lib/cosaci/attest.log   # must be a multiple of 32

# If not: truncate to the last whole record.
sudo cosaci truncate-log /var/lib/cosaci/attest.log   # PARTIAL — tool not shipped
# Manual workaround for v0.3:
# size=$(sudo wc -c < /var/lib/cosaci/attest.log)
# good=$(( size - size % 32 ))
# sudo truncate -s "$good" /var/lib/cosaci/attest.log
```

> **DEFERRED — full DR shipping in #51.** Job-queue durability +
> mid-job journal recovery lands with issue #51. For v0.3,
> resubmit lost jobs from upstream.

---

## 6. Debugging a stuck job

End-state: you've identified why a committee selected for `job_N`
didn't reach quorum, and you've decided whether to wait, abort, or
expel a runner.

### 6a. Symptoms

```
[coordinator] job 7 committee: [2, 4, 5] module=[ab, cd, ef, ...]… (...)
[coordinator] job 7 runner 2 attestation sig=ok artifact=[aa, bb, cc, dd]…
[coordinator] job 7 runner 4 attestation sig=ok artifact=[aa, bb, cc, dd]…
# (no output for runner 5; no `outcome` line)
```

### 6b. Diagnose

> **PARTIAL — observability shipping in #47.** v0.3 only has
> stdout logs; v0.4 adds Prometheus metrics + OTLP traces.
> Until then:

```bash
# Coordinator side
sudo journalctl -u cosaci-coordinator | grep "job 7"

# Runner side
sudo journalctl -u "cosaci-agent@5" | grep "job 7"
```

Likely causes (most → least common):

1. **Network partition between coord and one runner.** Runner sent
   `VrfClaim` but never receives `Assign`, or vice versa. Recover
   by restarting the affected agent.
2. **Runner OOM / panic.** Runner is gone; the timeout fires and
   the committee aborts (or carries on with N-1 if quorum still
   reachable). Check the runner's journal.
3. **Resource limit exceeded.** v0.3 reports
   `LimitExceeded { which: Cpu | Memory | Wall }` in the runner's
   `StepOutput`; the runner submits a valid attestation with that
   status. Quorum can still pass if a majority hit the same limit.
4. **Genuine non-determinism in the pipeline.** Different runners
   produce different `artifact_hash` values; quorum fails. The
   pipeline-determinism property (issue #39) is your first
   suspect — check the runner-side log for the diverging step's
   output hash.

### 6c. Mitigate

For now (v0.3), the only mitigation is:

- Wait for the deadline to fire and the committee to abort.
- Restart the affected runner if it's wedged.
- For repeated failures of the same job: submit again with
  different committee selection (the VRF round randomizes
  committee membership per job; the new round avoids the
  problematic runner with high probability).

> **DEFERRED — observability dashboard shipping in #47.** A
> Grafana dashboard / OTLP trace view for stuck jobs lands with
> #47.

---

## 7. Slashing review

End-state: you've reviewed the disagreeing attestations for a
flagged runner and decided whether to expel (revoke + remove from
enrollment) or reinstate.

> **DEFERRED — full procedure shipping in #35.** v0.3 has the
> reputation-monotonicity primitive but no production slashing
> ledger. Treat this section as a placeholder until the slashing
> infrastructure lands.

The v0.3 manual workflow:

```bash
# 1. Pull the disagreeing attestations from the read API (issue #44)
#    for each job where the runner produced a minority artifact_hash.
# 2. Sanity-check the pipeline determinism on the disagreeing input.
#    If multiple runners produce different hashes for the same
#    pipeline + module, the issue is in the pipeline, not the runner.
# 3. If the runner is actually misbehaving:
#    a. Add their cert serial to the CRL (Section 4).
#    b. Remove their line from /etc/cosaci/enrollment.txt.
#    c. SIGHUP the coordinator (CRL takes effect; enrollment
#       takes effect on next coord restart).
```

---

## 8. Capacity planning

### 8a. Knobs

| Knob | Coord flag | Default | Sets |
|---|---|---|---|
| Committee size | `--committee N` | 3 | Number of runners that attest each job. Higher = more safety, more cost. Quorum threshold is `ceil(2/3 × committee_stake)`. |
| Fleet size | `--fleet N` | 5 | How many agent registrations to wait for before starting the job loop. |
| Per-job deadline | (hardcoded 60s) | 60s | Wall-clock budget for the runner to return an attestation. |
| Max jobs | `--max-jobs N` | unlimited | For demo/test runs. Production sets this implicitly via SIGTERM. |

### 8b. Throughput model

For a steady job rate of `R` jobs/sec, a committee size of `K`,
and a runner pool of `P`:

- **Each job consumes `K` runner-slots for its execution wall-time
  plus `K + 1` runner-slots for VRF claim collection.**
- Sustainable rate: `R ≤ P / (K × T_exec)`, where `T_exec` is the
  per-job WASM execution time.

For the demo workload (`add(i32,i32)`, ~microseconds): one
coordinator can handle thousands of jobs/sec at K=3, P=5. For a
real CI workload (`T_exec` measured in minutes): expect 1-10
jobs/min per coordinator.

### 8c. When to scale

- **Add runners** when the committee selection consistently picks
  the same agents (high VRF-output collisions imply a tight pool).
- **Add coordinators** when no single coordinator can handle the
  per-job VRF collection round-trip latency. This requires #50
  (concurrent jobs) at minimum, plus the sharded-Raft + gossip
  primitive in `memory/project_scale_primitives.md` to
  cross-partition the pool.
- **Don't shrink the committee below 3.** The 2/3 stake-weighted
  threshold collapses to "any single runner decides" at K=2, which
  defeats the trust model.

---

## Cross-references

- README.md → "Try it" → this runbook's [Bootstrap](#1-bootstrap-a-fresh-deployment).
- `contrib/README.md` → deployment-artifact details (Dockerfiles,
  Compose, systemd units).
- `hypotheses/index.md` → which falsifiable claims the operator
  can rely on at v0.3 (the audit-trail SSOT).

## Issues that will fill the gaps in this runbook

| Section | What's missing | Tracking issue |
|---|---|---|
| 2 | `cosaci-admin` wire-protocol form (talks to running coord) | #53 (file-only landed) |
| 2 | Runtime enrollment reload (no restart) | #45 follow-on |
| 5 | Job-queue durability + mid-job replay | #51 |
| 6 | Prometheus metrics + OTLP traces | #47 |
| 7 | Slashing ledger + automatic revocation | #35 |
