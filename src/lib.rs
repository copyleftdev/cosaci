#![forbid(unsafe_code)]

//! CosaCI — distributed attested CI mesh.
//!
//! Public-infrastructure-scale CI execution fabric. Spec lives in `SPEC.md` at
//! the crate root; every falsifiable claim is encoded as a Hegel property test
//! under `tests/`, paired with a card under `hypotheses/`.
//!
//! As of v0.2 (issues #2/#3/#4), this meta-crate re-exports the modules that
//! have moved to dedicated workspace crates. New code should depend on the
//! per-crate paths directly (e.g. `cosaci_core::clock`); the re-exports below
//! exist to keep the test suite + binaries compiling during the split.

// Re-exports from cosaci-core (issue #2).
pub use cosaci_core::{
    attestation, bloom, capabilities, clock, confidentiality, flake, gossip, merkle_log, quorum,
    reputation, retrieval, signing, status, verifier,
};
// Re-exports from cosaci-state (issue #2).
pub use cosaci_state::{
    aggregator, enrollment, lease, partition, rate_limit, registry, replay, replicated_cluster,
    sharding, sharding_handoff, stake_ledger,
};
// Re-exports from cosaci-protocol (issue #3).
pub use cosaci_protocol::{proto, tls};
// Re-export from cosaci-vrf (issue #3).
pub use cosaci_vrf::vrf;
// Re-export from cosaci-wasm (issue #3).
/// Re-export of the typed pipeline DSL crate (issue #39).
pub use cosaci_jobs as jobs;
pub use cosaci_wasm::wasm_runtime;
