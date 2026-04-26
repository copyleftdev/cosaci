# Changelog

All notable changes to CosaCI are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until v1.0.0, all crates in the (eventual) workspace bump together;
breaking changes are minor bumps; non-breaking changes are patch
bumps. v1.0 onward, each crate versions independently.

## [Unreleased]

In-progress v0.3.0 work, accumulating since the v0.2.0 tag.

### Added — job submission CLI (#32, partial)

- Coordinator gains `--submit-stdin` (read NDJSON job submissions
  from stdin) and `--queue-cap N` (bounded submission queue,
  default 64). Empty / absent stdin flag preserves the legacy
  canned-`add`/`mul` rotation, so existing demos and integration
  tests keep working unchanged.
- Wire shape (v0.3 MVP): one JSON object per line —
  `{"kind":"add"|"mul","a":<i32>,"b":<i32>,"deadline_secs":<u32>?}`.
  Blank lines and `#`-prefixed comments are skipped; malformed
  records are logged and dropped without aborting the stream.
  `kind` dispatches to a canned WASM module — the format is
  forward-compatible for arbitrary module bytes once #40
  (deterministic source-fetching) lands.
- Bounded `sync_channel` between a stdin-reader daemon thread and
  the main job loop. **Backpressure policy: reject on full**
  (documented in RUNBOOK §1e). The reader uses `try_send`; on
  overflow it logs `submission queue full, dropping record …` and
  continues. Producers retry or back off; the coordinator never
  blocks on its stdin.
- Clean shutdown semantics: closing stdin (EOF) drops the sender,
  `recv_timeout` returns `Disconnected` once the queue drains,
  and the loop exits 0. SIGTERM still drains unconditionally
  regardless of stdin state — the two paths are independent.
- `demo_networked` gains a third pass `RoundKind::SubmitStdin`:
  spawns coord with `--submit-stdin`, pipes
  `{"kind":"add","a":1,"b":2}` and `{"kind":"mul","a":3,"b":5}`,
  closes stdin, asserts coord exits 0. The CI smoke step
  greps for `kind=Add a=1 b=2`, `kind=Mul a=3 b=5`, and
  `stdin closed and queue drained` so a regression that
  silently ignored the submission can't pass.
- New deps in `bins/cosaci-coordinator`: `serde` (workspace),
  `serde_json` (workspace).
- RUNBOOK §1e (Submitting jobs) added: wire shape, backpressure
  semantics, shutdown semantics, and an explicit Out-of-scope
  block listing the Unix-socket/REST alternative (also follow-on),
  per-tenant signed tokens (#46), and arbitrary module bytes
  (#40).
- **Out of scope (follow-on):** Unix-socket and REST alternatives
  to stdin so an external producer can submit without owning
  coord's stdin handle; arbitrary module bytes (depends on #40);
  per-submission priority ordering; per-tenant signed submission
  tokens (depends on #46).

### Changed — docs / audit-trail follow-ups

- `hypotheses/index.md` re-synced with disk: Tier 0 row count
  bumped 20 → 21 and Tier 1 8 → 9 in the section headers (the
  rows themselves were already there); `merkle-log-persistence`
  status `encoded` → `**passing**` (its 4-test file has been
  passing for several PRs); totals line corrected to
  `30 A + 6 B-stat + 4 C + 3 D = 43 cards · 41 passing` and the
  follow-on summary line bumped to `36/36 passing` for the
  combined A + B-stat tier.
- `docs/RUNBOOK.md` §6 (Debugging a stuck job) rewritten now
  that tracing + `RUST_LOG` landed in #47: the section now shows
  a real `journalctl -f | grep "job_id=N"` workflow plus a `jq`
  recipe for slicing the NDJSON journal by job id, instead of
  the prior `PARTIAL — observability shipping in #47` stub. The
  Prometheus + OTLP exporter callout is preserved as an explicit
  follow-on.
- §7 (Slashing review) re-marked from `DEFERRED` to
  `PARTIAL — slashing-faithfulness primitive landed (#35); the
  production ledger + automatic revocation is follow-on`.
- §"Issues that will fill the gaps" table updated to reflect
  what's actually shipped vs. still pending for #47, #51, and
  #35.

### Changed — structured logging via tracing (#47, partial)

- Coordinator and agent binaries now emit logs via `tracing` +
  `tracing-subscriber::fmt` instead of bare `println!` /
  `eprintln!`. Output goes to stderr; format includes
  ISO-8601 timestamp, level, target, and message:
  `2024-01-01T12:00:00.000Z  INFO coordinator: ...`.
- `RUST_LOG` controls per-target verbosity
  (`RUST_LOG=coordinator=debug`); default level is `info`.
- New `init_tracing()` function in each binary calls
  `tracing_subscriber::fmt().with_env_filter(...).try_init()`
  early in `main`; the `try_init` swallows duplicate-init errors
  so a child process or test harness can re-init without
  panicking.
- New workspace deps: `tracing` 0.1.41,
  `tracing-subscriber` 0.3.19 (with `fmt` + `env-filter`
  features only — no JSON output, no spans yet).
- Smoke-test grep patterns are unchanged: tracing prepends a
  level + target prefix but the message body is preserved, so
  `grep -q "outcome Pass"` and friends still match.
- **Out of scope (follow-on PR):** Prometheus metrics endpoint,
  OTLP traces, span instrumentation around `run_one_job`, and
  scrub-the-redundant-`[coordinator]`-prefix-from-messages now
  that the target field provides it. Demo binaries (`demo`,
  `demo_networked`, `verify`, `cosaci-admin`) keep `println!` —
  those are user-facing CLIs, not daemons.

### Changed — journal integrated into coordinator (#51 follow-on)

- Coordinator gains `--journal <path>` flag. Empty (default) =
  no journaling, current behavior. Non-empty: replay at startup,
  append per state transition with fsync.
- Per-transition appends in `run_one_job`: `JobSubmitted` →
  `CommitteeSelected` → `AttestationReceived` (per signature-valid
  attestation) → `Aggregated` (with consensus artifact hash) →
  `Anchored` (with log position).
- Startup replay logs a recovery summary:
  `[coordinator] journal replayed from <path>: N entries, X
  previously-anchored job(s), Y pending re-run, Z pending
  re-anchor`. Pending lists are logged with explicit "NOT
  auto-rerun in v0.3" notes — the auto-recovery loop lands once
  #32 carries job source into the journal.
- `demo_networked` bounded round now passes `--journal
  <temp_dir>/journal.ndjson` so the smoke test exercises the
  full journal lifecycle end-to-end.
- RUNBOOK §5 (Disaster recovery) gets a new §5d describing the
  journal-driven recovery procedure.
- **Out of scope (still follow-on):** auto-rerun of pending jobs
  on startup (depends on #32's job-source-in-journal),
  `cosaci-admin anchor` for manual re-anchor of pending-aggregated
  jobs, checkpoint+truncation (the unbounded-growth mitigation).

### Added — crash-recovery journal (#51, partial)

- New `cosaci-state::journal` module: `JournalEntry` enum
  (JobSubmitted / CommitteeSelected / AttestationReceived /
  Aggregated / Anchored), `JournalOutcome`, `JobState`,
  `JournalState`, `Journal::open` + `append` (NDJSON, fsync per
  record), `replay(path) -> Vec<JournalEntry>`,
  `reconstruct_state(&[entries]) -> JournalState`.
- File format: newline-delimited JSON. One entry per line; lines
  are `\n`-terminated; an unterminated trailing line (torn
  mid-write) is silently skipped on replay — the `kill -9`
  semantics. `sync_data` after every record before `append`
  returns Ok.
- `JournalState` exposes `pending_re_run()` (Submitted / InFlight)
  and `pending_re_anchor()` (AggregatedNotAnchored) so a
  recovering coordinator can decide which jobs to re-run vs
  re-anchor. Anchored jobs surface in `anchored_jobs()` for
  double-anchor rejection.
- New hypothesis card `hypotheses/crash-recovery-soundness.md`
  (class A, Tier 0). Seven Hegel properties + 1 smoke:
  - Replay round-trips appended entries.
  - Pure `reconstruct_state` agrees with disk-replay
    `reconstruct_state(&replay(path))`.
  - Lifecycle progression is monotone (Submitted → InFlight →
    AggregatedNotAnchored → Anchored).
  - Submitted/InFlight jobs surface in `pending_re_run`.
  - AggregatedNotAnchored jobs surface in `pending_re_anchor`.
  - Anchored jobs surface in `anchored_jobs`.
  - Torn final write is skipped (valid prefix preserved).
- `cosaci-state` now depends on `serde_json` directly (was a
  workspace dep added by #38).
- **Out of scope (follow-on PR):** Coordinator integration —
  wiring `journal.append()` into `run_one_job` at every
  transition + replay on startup. Touches the coord's main
  loop, lands separately. Also: checkpoint+truncation (the
  unbounded-growth mitigation), `--journal <path>` flag, and
  the RUNBOOK §5 update with the concrete replay procedure.

### Added — GitHub Checks API contract via fixture replay (#38, partial)

- New `cosaci-state::github_checks` module:
  `CheckRunPayload`, `CheckStatus`, `CheckConclusion`,
  `CheckOutput`, `JobContext`.
- `status_to_check_status(Status)` — pure mapping from
  `cosaci-core::status::Status` (Pending / Running /
  QuorumVerifying / Success / Failure) to GitHub's
  `(status, conclusion)` pair.
- `build_payload(Status, &JobContext)` — full payload assembly
  matching GitHub's documented schema for
  `POST /repos/{owner}/{repo}/check-runs`.
- Fixtures under `tests/fixtures/github_checks/{pending,running,
  quorum_verifying,success,failure}.json` capture one canonical
  JSON per lifecycle state. The 14-test fixture-replay suite at
  `tests/github_checks_fixtures.rs` asserts the transformation
  matches each fixture; any change that breaks the schema
  (renamed field, missing required key, wrong serialization tag)
  fails at PR time without a live GitHub API call.
- `hypotheses/github-checks-integration.md` moves from `pending`
  to `passing` (class D, Tier 4 boundary card). Tier 4 is now
  3/3 passing.
- New `serde_json` workspace dep (1.0.128) for the fixture
  comparison; `cosaci-state` depends on `serde` directly.
- **Out of scope (follow-on):** the actual coordinator-side
  HTTP publishing path (POST to api.github.com on every status
  transition). That's class C live-API; it lands as a
  `/schedule`-able weekly routine against a real test GitHub
  org once an App token is provisioned. Webhook ingestion is
  tracked under #52.

### Added — `cosaci-admin` CLI (#53, partial)

- New `bins/cosaci-admin/` workspace member with binary
  `cosaci-admin`. Filesystem-only for v0.3 — operates directly
  against the enrollment file and the persistent Merkle log;
  does NOT yet talk to a running coordinator over TLS.
- Subcommands:
  - `agents list --enrollment <path>` — print the enrollment
    file as a sorted table.
  - `agents enroll --enrollment <path> --runner-id N
    --signing-fp <hex> --vrf-fp <hex> [--reputation 0..1]
    [--at <unix_ns>]` — append a record. Refuses if `runner_id`
    is already enrolled (use `revoke` first to replace).
  - `agents revoke --enrollment <path> --runner-id N` — remove
    a record.
  - `log root --log <path>` — open the file-backed Merkle log
    (issue #33) and print its current root + length.
- All file mutations are atomic: write tempfile + rename. An
  interrupted run leaves either the original or the new file,
  never half-written.
- `cosaci-state::enrollment::EnrollmentSet::iter()` (new) so the
  CLI can produce sorted-by-runner_id output deterministically.
- RUNBOOK §2 (Adding a runner) updated to use the CLI; the
  "manual file edits" gap is closed for the v0.3 deployment path.
- **Out of scope (follow-on):** wire-protocol Admin* envelopes
  + AuthN gate (depends on #46), `tenants {add,list,revoke}`,
  `jobs {list,inspect}`, `system status`. Those need the wire
  path and the AuthN token format.

### Added — network egress policy evaluation (#54, partial)

- `cosaci-jobs::network` (new module): `NetworkPolicy { allow,
  default }`, `EgressTarget { Host, Cidr }`, `EgressDefault {
  Deny, Audit }`, `Scheme { Http, Https, Tcp }`,
  `EgressAttempt`, `Decision { Allow, Deny, Audit }`.
- `evaluate(policy, attempt) -> Decision` — pure. Walks the
  allowlist; first match wins; falls through to the default.
  Hostname matches require exact equality (no wildcards in v0.3);
  port `0` means "any port"; `Scheme::Tcp` matches any scheme.
  Invalid CIDR strings match nothing — operator typos can't
  silently widen the policy.
- IPv4 `0.0.0.0/0` and IPv6 `::/0` match within their family
  only; an "allow everything" policy adds both. Helper
  `allow_all()` does this; `deny_all()` is `NetworkPolicy::default()`.
- **Wire shape change.** `Limits.network` was previously
  `enum NetworkPolicy { Deny, Allow }`; it's now the struct form.
  `Limits` drops `Copy` (because `Vec<EgressTarget>` isn't Copy);
  it remains `Clone`. The cosaci crates are `publish = false` so
  this is a clean break, not a compatibility shim.
- New hypothesis card `hypotheses/egress-policy-evaluation.md`
  (class A, Tier 0). Eight Hegel properties + 2 deterministic
  smoke tests, all green on first try: empty + Deny → Deny;
  empty + Audit → Audit; Host match → Allow; Cidr match → Allow
  (with non-match counter-test); direct-IP skips Host entries
  (catches the "DNS-bypass" attack); invalid CIDRs don't widen
  the policy; `/0` matches family-only; first match wins
  regardless of position; realistic `cargo fetch` policy.
- **Out of scope (follow-on PR):** Linux netns enforcement
  (class C, gated on `HEGEL_LINUX_HARNESS=1`) — spawning the
  step inside a network namespace and routing TCP through an
  in-process proxy that calls `evaluate(...)` per connection.
  Also deferred: `StepOutput::network_violations` field
  (requires a wire shape change + canonical-encoding update;
  populates only once enforcement lands).

### Added — partial committee tolerance (#61)

- New `cosaci-state::partial_quorum` module: `PartialOutcome`,
  `resolve_with_dropouts(committee, votes_subset, stake_map,
  threshold_fn) -> PartialOutcome`. Pure: returns
  `(outcome, responding, missing, responding_stake, threshold)`.
  Threshold is computed against responding-subset stake (NOT
  full-committee stake), so a 2/3-weighted majority of who actually
  showed up is the right bar.
- Convenience helpers: `two_thirds_threshold(s) = ceil(s × 2 / 3)`
  and `stake_map_from_pairs(...)`.
- Coordinator integration: per-runner read deadline via
  `set_read_timeout` in the attestation collection loop. A runner
  that doesn't return `SubmitAttestation` within the deadline is
  recorded as missing (logged at `[coordinator] job N runner R
  attestation timeout after Ts — recorded as missing`); the
  responding subset still aggregates to a deterministic outcome.
  Replaces the historical `?`-bail-on-IO-error behavior that
  turned every dropped TCP connection into a job failure.
- New `--runner-timeout-secs <s>` flag (default 30) controls the
  per-runner deadline.
- New hypothesis card `hypotheses/partial-committee-tolerance.md`
  (class A, Tier 0). Five Hegel properties + 1 smoke test:
  responding/missing partition the committee, outcome equals
  subset aggregate, single-failure tolerance for k=3, threshold
  uses responding-subset stake (catches the silent-fail bug),
  empty response doesn't panic.
- **Out of scope (follow-on):** the `MissingAttestation`
  reputation decrement (`δ_miss = δ_disagree / 4` per the issue)
  lands when reputation/stake separation lands.

### Added — slashing on detected dishonest attestation (#35)

- New `cosaci-state::stake_ledger` module: `StakeLedger`,
  `SlashEvent`, `slash_minority(consensus, attestations, fraction)`.
  In-memory; persistence (file-backed Store) is a follow-on.
- `slash_minority` is pure: minority disagreers (those whose
  `attestation.artifact_hash != consensus_artifact`) lose
  `floor(stake × fraction_clamped)` weight; majority untouched;
  unenrolled runners produce no event. Saturates at zero.
  `fraction` is clamped to `[0.0, 1.0]`.
- Coordinator integration: `--slash-fraction <f>` flag (default
  `0.25` per the issue spec, == stake / 4). After every job with
  a definitive outcome (Pass or Fail), `run_one_job` calls
  `ledger.slash_minority(...)` and logs each event:
  `[coordinator] job N slashed runner R by D (B → A)`.
- Quorum threshold + `aggregate(...)` now read from
  `ledger.as_stake_map()` rather than the registration-time
  snapshot, so a slashed runner's voting weight shrinks
  immediately. Repeated dishonesty drops the runner toward zero;
  a future selection layer can drop them out of the committee
  pool entirely (issue #61 follow-on).
- New hypothesis card `hypotheses/slashing-faithfulness.md`
  (class A, Tier 0). Six Hegel properties + 1 smoke test:
  disagreement → slash; agreement → no slash; saturation at zero;
  fraction clamping above and below the legal range; unregistered
  runner produces no event; ledger state matches events.
- **Out of scope (follow-on):** disk-backed ledger persistence
  across coord restarts; reputation-vs-stake separation
  (currently slashing tracks raw stake; a soft-signal reputation
  decay lands separately).

### Added — operator runbook (#48)

- New `docs/RUNBOOK.md` with eight sections: bootstrap, adding a
  runner, cert rotation, CRL update, disaster recovery, debugging
  a stuck job, slashing review, capacity planning.
- Each section is a numbered procedure with concrete commands +
  expected output. Sections that depend on un-shipped features
  (`cosaci-admin` CLI #53, observability #47, slashing #35,
  job-queue durability #51) are explicitly marked **PARTIAL** or
  **DEFERRED** with the tracking issue cited inline; what's
  shippable today (Docker/systemd from #49, enrollment from #45,
  cert + CRL hot-reload from #8, persistent log from #33, read
  API from #44) is fully covered.
- README's "Try it" section now cross-refs the runbook for
  operators standing up CosaCI on their own infrastructure.

### Added — deployment artifacts: Docker + Compose + systemd (#49)

- `contrib/docker/Dockerfile.coordinator` and
  `contrib/docker/Dockerfile.agent`: multi-stage builds on
  `rust:1.94-slim-bookworm`, runtime on `debian:bookworm-slim`.
  Both run as non-root `cosaci` user, expect mTLS certs at
  `/etc/cosaci/{ca,server,agent}.pem`, and persist coordinator
  state at `/var/lib/cosaci/`.
- `contrib/docker/Dockerfile.bootstrap` + `bootstrap.sh`: a tiny
  Alpine init image that generates a demo CA + per-fleet certs
  into a shared volume. **Demo only** — the certs live in a Docker
  volume and never leave it; production uses the operator's PKI.
- `contrib/docker-compose.yml`: brings up
  bootstrap → coordinator → 5 agents in one `docker compose up`.
  The non-Rust equivalent of `cargo run -p cosaci-demo --bin
  demo_networked` for hands-on smoke testing.
- `contrib/systemd/cosaci-coordinator.service` and
  `cosaci-agent@.service` (templated by runner_id). Hardening
  defaults: `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `PrivateUsers`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
  `RestrictNamespaces`, `LockPersonality`. `MemoryDenyWriteExecute=no`
  is the documented exception (wasmtime JIT requires write-then-execute
  on the same mapping).
- `contrib/README.md`: install + usage guide for all three tracks.
- CI gate: `Docker images build` job verifies both production
  Dockerfiles + the bootstrap image build on every PR. Caches via
  GHA buildx cache. Smoke-checks each image's entrypoint with
  intentionally-missing cert paths; expects `NotFound` rather than
  a broken binary.
- **Out of scope (follow-on PR):** GHCR push on tagged release;
  multi-arch build verification (`linux/arm64`) — release-tag job.

### Added — agent enrollment gate (#45, partial)

- New `cosaci-state::enrollment` module: `EnrolledRecord`,
  `EnrollmentSet`, `is_enrolled(runner_id, signing_fp, vrf_fp)`.
  Lookup is by `runner_id` AND exact fingerprint match — a matching
  `runner_id` with divergent fingerprints is rejected, so an
  attacker who learns an enrolled id can't claim that slot with
  their own keys.
- File format (v0.3 MVP): one record per line,
  whitespace-separated:
  `<runner_id> <signing_fp_hex> <vrf_fp_hex> <enrolled_at_unix_ns> <initial_reputation>`.
  Lines starting with `#` are comments. Strict parser rejects
  malformed records with `InvalidData`.
- New `fingerprint(pubkey) = SHA-256(pubkey)` and `fingerprint_hex`
  helpers. The fingerprint is the on-disk shape; raw pubkeys never
  appear in the enrollment file.
- Coordinator `--enrollment <path>` flag: load the file at startup
  and consult it during `accept_fleet`. After mTLS + VRF-of-possession
  succeed, the gate is the final say on admission. Empty (default)
  preserves legacy behavior. Rejected agents are logged at
  `[coordinator] rejecting unenrolled agent runner_id=…`.
- `demo_networked` derives the FLEET demo agents' deterministic
  signing + VRF pubkeys, writes their fingerprints to a temp
  enrollment file, and passes `--enrollment <path>` to coord. The
  smoke test now exercises the gate end-to-end.
- New hypothesis card `hypotheses/enrollment-gate-enforcement.md`
  (class A, Tier 0). Six Hegel properties + 2 smoke tests:
  enrolled passes; unenrolled rejected; impersonation (matching
  runner_id, wrong signing_fp / wrong vrf_fp) rejected — both
  fingerprints; empty set rejects everyone; record round-trips
  through the v0.3 file format.
- **Out of scope (follow-on PR):** `cosaci-admin` CLI for
  enroll/revoke (gated on issue #53), SIGHUP-triggered enrollment
  reload, persistent runtime revocation. Operators edit the file
  by hand and restart coord for now.

### Added — read API for attestations + Merkle proofs (#44)

- `cosaci-core::retrieval` (new): pure `JobRecord`, `JobBundle`, and
  `build_bundle(&records, &log, job_id) -> Option<JobBundle>`. The
  bundle is wire-shippable (CBOR) and freezes the
  `(log_position, log_length_at_anchor)` pair so retrievals are
  deterministic across concurrent appends.
- `cosaci-core::merkle_log::InclusionProof` is now `Serialize +
  Deserialize` — the wire-shippable form for external auditors.
- New protocol envelope variants in `cosaci-protocol::proto`:
  `GetJob { job_id }` / `JobBundleResponse(JobBundle)` /
  `JobNotFound { job_id }` / `GetLogRoot` /
  `LogRoot { root, length }`.
- Coordinator `--read-addr <addr>` flag binds a second mTLS listener
  that serves the read API on a daemon thread. Each accepted
  connection handles one request envelope, then closes. The job
  loop's `(records, log)` state is shared via `Arc<Mutex<…>>`.
- New `bins/cosaci-demo/src/bin/verify.rs` binary speaks the read
  protocol: connect, `GetJob`, retry with backoff until anchored,
  cross-check `GetLogRoot`, run `verify_inclusion`. Exit 0 on a
  verifying bundle, 1 on a tampered/missing one.
- `demo_networked` runs `verify` alongside the bounded round and
  asserts exit 0, so the smoke test now exercises the full
  end-to-end retrieval round-trip.
- New hypothesis card `hypotheses/retrieval-soundness.md` (class A,
  Tier 0). Five Hegel properties: proof verifies for every recorded
  job, tamper in entry rejected, tamper in root rejected, bundle is
  byte-stable across calls, unknown job returns None.

### Added — resource-limit enforcement on WASM steps (#43)

- New `cosaci-wasm::execute_with_limits(wasm, args, ExecLimits)` —
  fuel + memory + wall enforcement on the existing `add(i32, i32)`
  ABI. `ExecLimits { fuel, memory_bytes, wall: Duration }` (zero
  means unlimited per axis).
- Wasmtime mechanics: `Config::consume_fuel` + `Store::set_fuel`
  for cpu, custom `ResourceLimiter` returning `Err` from
  `memory_growing` for memory (so `memory.grow` past the cap traps
  rather than silently returning -1), `Config::epoch_interruption`
  + a 10ms-granularity timer thread for wall.
- `cosaci-jobs::execute_wasm_step` translates `Limits` →
  `ExecLimits` (cpu_seconds × `FUEL_PER_CPU_SECOND` (= 10⁹), MiB
  → bytes, secs → `Duration`). On `LimitExceeded`, the step's
  `output_hash` is the SHA-256 of canonical CBOR
  `(step, LimitKind)` — two runners that hit the same kind agree;
  flipping the kind diverges.
- `execute()` is now a thin wrapper around
  `execute_with_limits(..., ExecLimits::unlimited())`; the v0.2
  `execute()` API is unchanged for callers.
- New hypothesis card `hypotheses/resource-limit-enforcement.md`
  (class A, Tier 0). Six Hegel properties: unlimited compliance,
  cpu enforcement (spinning module), memory enforcement (grow
  module), wall enforcement (spinning module, fuel disabled),
  compliant within budget, output-hash distinguishes limit kind.
  Plus an end-to-end `execute_pipeline` smoke test.
- Native (cgroups v2 / setrlimit) enforcement is class C, gated on
  a Linux harness, and lands in a follow-on PR.

### Added — persistent attestation log on disk (#33)

- `cosaci-core::merkle_log` gains a `Store` trait + two impls:
  - `MemStore` (default) — `Vec<Hash>` in RAM. Identical v0.2 behavior.
  - `FileStore` — append-only file, one fixed 32-byte record per entry,
    `sync_data` after every append. Reopening from the same path
    recovers byte-identical state.
- `MerkleLog<S = MemStore>` is generic; the v0.2 `MerkleLog::new()`
  surface is unchanged (returns `MerkleLog<MemStore>` with infallible
  `append`). The new file-backed surface is
  `MerkleLog::<FileStore>::open(path)?` with `append(...) -> Result`.
- Coordinator `--log <path>` flag selects the file-backed log; default
  empty = in-memory (current demo behavior).
- New hypothesis card `hypotheses/merkle-log-persistence.md` (class A,
  Tier 1). Four Hegel properties: append-drop-reopen preserves entries
  + root + length; mid-stream reopen matches uninterrupted-append
  sequence; empty-log persistence; corrupt-file detection rejects
  non-multiple-of-32 file sizes.
- Adds `tempfile` as a dev-dep for filesystem-aware property tests.

### Added — capability-aware committee selection (#34)

- `cosaci-core::capabilities` gains a wire-stable representation:
  `Runtime` and `Platform` derive `Ord` + `Serialize`/`Deserialize`,
  the `runtimes` field in `Capabilities` / `JobRequirements` switched
  from `HashSet<Runtime>` to `BTreeSet<Runtime>` for canonical CBOR.
- New `Candidate<Id>` type + `select_capability_aware_committee(...)`
  pure function. Filter-then-rank: only runners whose `Capabilities`
  satisfy `JobRequirements` participate in the VRF top-k, and
  underprovisioned committees abort honestly (`None` return) rather
  than silently undercutting quorum.
- `Envelope::Register` carries `capabilities: Capabilities`;
  `Envelope::Assign` carries `requirements: JobRequirements`.
  Coordinator stores capabilities at registration, builds a
  `Vec<Candidate>` from per-job VRF claims + capability records, and
  delegates committee selection to the pure function.
- New hypothesis card `hypotheses/capability-aware-committee.md`
  (class A, Tier 0). Four Hegel properties: soundness (no incapable
  runner is selected), completeness (exactly k when ≥ k match),
  underprovisioning honesty (`None` when < k match),
  filter-then-rank (top-k VRF among matching, not rank-then-filter).

### Added — typed pipeline DSL (#39)

- New crate `cosaci-jobs` with `Pipeline`, `Step`, `Limits`,
  `StepOutput`, `PipelineResult`, `PipelineError` types. CBOR-encoded
  on the wire; `execute_pipeline(&Pipeline) -> PipelineResult`
  delegates per-step execution to the per-kind executor.
- `Envelope::Assign` now carries `pipeline: Pipeline` instead of
  `(module, args_cbor)`. **Wire-protocol break vs v0.2** — clean
  break, no compat shim (the cosaci crates are `publish = false`).
- New hypothesis card `hypotheses/pipeline-determinism.md` (class A,
  Tier 0). Five Hegel properties: CBOR round-trip stability,
  repeated-execution stability, output-changing mutation propagation,
  `NotImplemented`-step determinism, empty-pipeline determinism.
- 4th real Hegel shrink resolved during development: the initial
  spec claim "any input mutation changes the artifact hash" was
  falsified by `mul(0, 0) == mul(1, 0) == 0`. The corrected claim
  bounds the property to mutations the executor isn't lossy on; the
  shrink is captured in the card's "Hegel shrink" section.

Step executors implemented today: `ExecWasm` (delegates to
`cosaci-wasm`). `SourceFetch`, `ExecNative`, `CaptureLog`, and
`CaptureArtifact` types are defined and CBOR-roundtrip; their
executors land in #40, #43, #54.

## [0.2.0] — 2026-04-24

The workspace + hardening release. v0.1's monolithic crate is now a
5-library + 3-binary workspace; the coordinator runs a persistent job
loop; agents prove ownership of their VRF keys at registration and
re-prove on every job; modules ship as binary `.wasm` over the wire;
mTLS supports CRLs and SIGHUP-driven cert rotation; every public item
is doc-checked and clippy-pedantic-clean; cargo deny is a hard CI gate.

### Added — workspace + crate boundaries (#1, #2, #3, #4)

- 5-library + 3-binary Cargo workspace. `cosaci-core` (algebra +
  crypto primitives), `cosaci-state` (lifecycle: leases, registry,
  aggregator, partition, replicated cluster, replay, rate limit,
  sharding, sharding-handoff), `cosaci-protocol` (CBOR envelope +
  rustls mTLS + rcgen test CA + CRL helpers), `cosaci-vrf`
  (schnorrkel sr25519), `cosaci-wasm` (wasmtime).
- Bins live under `bins/cosaci-{coordinator,agent,demo}` with
  short `[[bin]]` names (`coordinator`, `agent`, `demo`,
  `demo_networked`).
- Heavy deps (`wasmtime`, `schnorrkel`, `rustls`, `rcgen`) only
  pulled by the crates that actually need them — verified via
  `cargo tree -p cosaci-core`.
- Meta-crate is a thin re-export shim that keeps the existing 32
  integration tests + benches compiling against `cosaci::*` paths.

### Added — persistent coordinator + SIGTERM drain (#5)

- Coordinator is no longer one-shot: after the fleet registers,
  it enters a job loop, reuses agent connections across jobs,
  and only exits on `--max-jobs` or SIGINT/SIGTERM.
- `signal-hook`-driven drain flag checked at every iteration
  boundary: in-flight job finishes, loop exits, agents get a
  Shutdown envelope, exit code 0. Verified end-to-end in
  `demo_networked`'s two-pass run.

### Added — real WASM payloads in Assign (#6)

- `Envelope::Assign` carries `module: Vec<u8>` (binary `.wasm`)
  and `args_cbor: Vec<u8>` instead of `(a, b)`. Wire ABI v0.2
  documented in `cosaci-wasm`: modules export
  `add(i32, i32) -> i32`; args decode from CBOR `(i32, i32)`.
- `output_hash(module_hash, result)` binds the output to the
  module that produced it, so two committee members executing
  different modules can never quorum on the same artifact.
- `MAX_ENVELOPE_BYTES` raised 1 MiB → 16 MiB to fit real modules.
- New Hegel property: `different_modules_disambiguate_outputs`
  encodes the module-hash binding as a falsifiable claim.

### Added — VRF-proof committee verification (#7)

- Replaces the SHA-256(vrf_pk || seed) pseudo-VRF committee
  selection with real verifiable VRFs. `Register` now carries a
  proof of possession over a fixed challenge string; the
  coordinator runs a per-job VRF round (`JobSeed` → `VrfClaim`)
  and verifies every proof before picking the committee as
  top-k by lexicographically smallest VRF output.
- New `Envelope::JobSeed` and `Envelope::VrfClaim` variants.

### Added — cert rotation + CRL hooks (#8)

- `cosaci-protocol::tls`: `read_crls`,
  `server_config_from_paths_with_crl`, `server_config_with_crls`,
  `TestCa::issue_crl`. CRL plumbing is verified by two new
  Hegel properties: `revoked_client_cert_is_rejected` and
  `non_revoked_client_cert_succeeds_with_crl`.
- Coordinator `--crl <path>` flag + SIGHUP-triggered hot reload
  of the cert/key/CRL bundle. Existing TLS connections survive
  the swap by design; only new handshakes pick up the new config.

### Changed — code quality + audit gates (#9, #10, #11, #12, #13)

- Workspace-wide `clippy::pedantic` gate via
  `[workspace.lints.clippy]`. Each blanket allow has a
  justification comment in `Cargo.toml`.
- `deny.toml` curated with allow-listed licenses (MIT,
  Apache-2.0, BSD-2/3-Clause, ISC, Zlib, 0BSD, MPL-2.0,
  Unicode-3.0/DFS-2016, CDLA-Permissive-2.0); two RUSTSEC IDs
  ignored with rationale (paste, rustls-pemfile unmaintained).
  CI's `cargo deny check` flipped from advisory
  (`continue-on-error: true`) to a real gate.
- `.rustfmt.toml` makes the implicit fmt policy explicit
  (edition 2024, max_width 100, stable-only options).
- Every public item across the five lib crates carries a
  docstring; `#![deny(missing_docs)]` enforces this at build
  time, not just CI.
- `rust-toolchain.toml` pins Rust 1.94.0 + rustfmt + clippy.
  Local builds and CI run against identical compiler versions;
  no MSRV creep when a new stable lands.

### Changed — protocol envelope shapes

The wire protocol is **not** stable across v0.1 → v0.2.
`Envelope::Assign` and `Envelope::Register` both gained fields
this cycle (module bytes / VRF proofs); this is a clean break,
no compatibility shim. The cosaci crates are `publish = false`
so this only matters to in-tree callers.

## [0.1.0] — 2026-04-24

The initial release. Library of property-tested distributed
primitives + a working mTLS-secured coordinator/agent demo.

### Added — falsifiable spec + audit trail

- `SPEC.md` — 17-section spec at public-infrastructure scale.
- `hypotheses/` — 33 hypothesis cards + index.md audit trail.
  Every spec claim is mapped to a card, tagged class A / B-stat / C / D,
  and either has a passing Hegel test or a documented `blocked_on:` note.

### Added — primitives (`src/`)

- **Cryptography:** Ed25519 signing wrapper with strict verification
  (`signing`); ChaCha20-Poly1305 envelope encryption (`confidentiality`);
  schnorrkel sr25519 VRF with merlin transcript binding (`vrf`);
  rustls + rcgen + PEM I/O mTLS harness (`tls`).
- **Attestation:** canonical CBOR + SHA-256 (`attestation`); Merkle
  verifier with inclusion-proof soundness (`verifier`); append-only
  Merkle log with MMR peak decomposition (`merkle_log`); bloom
  filter for scale variant of the replay window (`bloom`).
- **Lifecycle:** stake-weighted quorum aggregator (`quorum`);
  Pending/Pass/Fail/Escalate result lifecycle with max-retries
  (`aggregator`); per-(job, runner) lease manager with TTL
  (`lease`); SCM status DAG (`status`); replay protection by
  nonce + Clock window (`replay`); per-tenant token-bucket rate
  limiter (`rate_limit`).
- **Distribution:** runner registry (`registry`); capability
  matching (`capabilities`); single-state-with-gate cluster
  (`partition`); two-replica cluster with split-brain +
  reset-to-majority reconciliation (`replicated_cluster`); LWW
  CRDT for gossip (`gossip`); atomic sharded store (`sharding`);
  phased-handoff sharded store (`sharding_handoff`).
- **Scoring:** flake confidence (`flake`); reputation
  monotonicity (`reputation`).
- **Time + execution:** injectable `Clock` trait + `SystemClock`
  (`clock`); WASM execution via wasmtime (`wasm_runtime`).
- **Wire:** CBOR `Envelope` + length-prefixed framing (`proto`).

### Added — binaries

- `cargo run --bin demo` — single-process end-to-end pipeline.
- `cargo run --bin coordinator` — mTLS-listening coordinator.
- `cargo run --bin agent` — mTLS-connecting agent.
- `cargo run --bin demo_networked` — spawns coordinator + 5 agents
  as separate processes with a fresh CA + per-process certs.

### Added — testing + benchmarks

- 32 integration test files under `tests/`; ~100 Hegel properties
  total. All green at HEAD.
- `benches/hot_paths.rs` — criterion baselines on quorum aggregate,
  attestation canonicalize + hash, Ed25519 sign + verify, VRF
  evaluate + verify, Merkle verifier, gossip merge.
- 3 Hegel shrinks caught and resolved during development:
  `vrf-assignment-uniformity` (distinctness precondition),
  `sybil-resistance` (honest-noise vs. adversary-coordination
  modeling), `bloom-fp-rate` (saturation regime outside formula's
  domain of validity).

### Added — design + repo bootstrap docs

- `README.md` — quickstart + how-to-read-this-repo guide.
- `CHANGELOG.md` — this file.
- `docs/ARCHITECTURE.md` — layered model, trust chain, dep graph.
- `docs/WORKSPACE_LAYOUT.md` — target 5-lib/3-bin Cargo workspace
  + 4-PR migration plan.
- `docs/ROADMAP.md` — v0.2 / v0.3 / v1.0 milestones, 22 initial
  issues across the first two milestones.
- `docs/REPO_BOOTSTRAP.md` — `gh` commands to bootstrap a private
  repo at `copyleftdev/cosaci` with labels, milestones, and the
  initial v0.2 issue set.
- `.github/labels.yml` — 30 labels (kind / priority / area /
  status / conventional) in `github-label-sync` format.
- `.github/ISSUE_TEMPLATE/{bug,feature,refactor,config}.yml` —
  GitHub issue forms; bug template asks for the shrunk Hegel
  counterexample, feature template asks for SPEC.md sections
  affected, refactor template asks for blast radius +
  verification plan.
- `.github/PULL_REQUEST_TEMPLATE.md` — checklist enforces
  test/lint/fmt/deny gates and asks about hypothesis cards
  affected.
- `.github/workflows/ci.yml` — GitHub Actions CI workflow.

### Architecture decisions captured in this release

- **Per-(job, runner) lease keying** — the architectural finding
  surfaced by integration testing: a quorum-based CI assigns
  K-runner committees per job; each `(job, runner)` pair gets its
  own lease. The single-job-keyed model from earlier was wrong.
- **Six locked primitives** for public-infrastructure scale:
  sharded small-Raft groups + gossip; pubkey + stake-weighted
  quorum; VRF assignment; local append-only log + periodic
  Merkle-root anchoring; WASM-primary sandbox with Firecracker
  escalation; stake + slashing economics (payment deferred to v2).

### Known limitations of v0.1

- The coordinator is **one-shot** — it serves a single job and
  exits. Persistent loop is `v0.2.0` issue #5.
- The `Assign` envelope carries `(a, b)` for a canned WAT module.
  Real WASM payloads are `v0.2.0` issue #6.
- Committee selection uses `SHA-256(vrf_pk || seed)` lex-min
  rather than full VRF-proof verification by the coordinator.
  v0.2 issue #7.
- mTLS does not yet support cert rotation or CRL/OCSP revocation.
  v0.2 issue #8.

[Unreleased]: https://github.com/copyleftdev/cosaci/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/copyleftdev/cosaci/releases/tag/v0.2.0
[0.1.0]: https://github.com/copyleftdev/cosaci/releases/tag/v0.1.0
