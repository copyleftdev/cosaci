#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! `cosaci-vrf` — VRF subsystem (schnorrkel sr25519).
//!
//! Heavy crypto deps (`schnorrkel`, `merlin`) are isolated to this crate
//! so consumers that don't need a VRF (e.g. `cosaci-core`-only users)
//! don't pay their compile cost.

pub mod vrf;
