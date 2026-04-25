#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! `cosaci-state` — stateful subsystems for CosaCI.
//!
//! Modules with mutable state (leases, registries, aggregators, partitions,
//! sharding/handoff, replay windows, rate limiters, replicated cluster).
//! Depends on `cosaci-core` for shared primitives (clock, quorum, bloom).

pub mod aggregator;
pub mod enrollment;
pub mod lease;
pub mod partition;
pub mod rate_limit;
pub mod registry;
pub mod replay;
pub mod replicated_cluster;
pub mod sharding;
pub mod sharding_handoff;
pub mod stake_ledger;
