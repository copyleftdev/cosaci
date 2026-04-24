#![forbid(unsafe_code)]

//! CosaCI — distributed attested CI mesh.
//!
//! Public-infrastructure-scale CI execution fabric. Spec lives in `SPEC.md` at
//! the crate root; every falsifiable claim is encoded as a Hegel property test
//! under `tests/`, paired with a card under `hypotheses/`.

pub mod aggregator;
pub mod attestation;
pub mod bloom;
pub mod capabilities;
pub mod clock;
pub mod confidentiality;
pub mod flake;
pub mod gossip;
pub mod lease;
pub mod merkle_log;
pub mod partition;
pub mod proto;
pub mod quorum;
pub mod rate_limit;
pub mod registry;
pub mod replay;
pub mod replicated_cluster;
pub mod reputation;
pub mod sharding;
pub mod sharding_handoff;
pub mod signing;
pub mod status;
pub mod tls;
pub mod verifier;
pub mod vrf;
pub mod wasm_runtime;
