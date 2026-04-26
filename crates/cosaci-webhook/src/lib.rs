#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! `cosaci-webhook` — pure layer below the SCM webhook listener.
//!
//! Verifies GitHub / GitLab webhook signatures, enforces a
//! freshness window on event timestamps, and parses
//! `.cosaci.toml` (the per-repo pipeline manifest). The HTTP
//! listener that wires these primitives into a real network
//! endpoint lives in a follow-on PR — keeping the algebra in
//! its own crate means the property tests don't drag in `tokio`
//! / `axum` and the falsifiable claims of
//! `hypotheses/webhook-auth-gate.md` are testable offline.

pub mod manifest;
pub mod signature;

pub use manifest::{CosaciToml, ManifestError, parse_manifest};
pub use signature::{
    GITHUB_SIGNATURE_HEADER, GITLAB_TOKEN_HEADER, SignatureError, is_fresh,
    verify_github_signature, verify_gitlab_token,
};
