#![forbid(unsafe_code)]

//! `cosaci-core` — pure algebra + crypto primitives for CosaCI.
//!
//! No I/O, no network, no heavy deps. The bar for inclusion is "could
//! plausibly be reused by a different distributed system." Each module
//! is a stand-alone primitive backed by a Hegel property test under the
//! root workspace's `tests/`.

pub mod attestation;
pub mod bloom;
pub mod capabilities;
pub mod clock;
pub mod confidentiality;
pub mod flake;
pub mod gossip;
pub mod merkle_log;
pub mod quorum;
pub mod reputation;
pub mod signing;
pub mod status;
pub mod verifier;
