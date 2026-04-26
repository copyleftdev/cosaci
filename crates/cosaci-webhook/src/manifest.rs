//! `.cosaci.toml` manifest parser (issue #52).
//!
//! Per-repo pipeline manifest the webhook listener loads from
//! the head ref of an incoming event. The file declares which
//! tenant the submission is signed under and which pipelines
//! to run for which event types.
//!
//! v0.3 ships the parser only — the webhook listener that
//! takes a `(GithubEvent, CosaciToml)` pair and produces a
//! signed `JobSubmission` lands as a follow-on PR. Keeping
//! the parser in `cosaci-webhook` (not the listener bin) means
//! its property tests don't depend on `tokio` / `axum`.
//!
//! Schema (issue #52 proposal):
//!
//! ```text
//! [tenant]
//! id = 42
//!
//! [[pipeline]]
//! name = "ci"
//! on   = ["pull_request.synchronize", "push"]
//!
//!   [[pipeline.step]]
//!   type      = "source-fetch"
//!   url       = "{{ event.repository.clone_url }}"
//!   reference = "{{ event.pull_request.head.sha }}"
//! ```
//!
//! v0.3 keeps the schema *narrow*: only `source-fetch` and
//! `exec-wasm` step types parse, matching the executor coverage
//! shipped in #40 + #39. Unknown `type` values are
//! `ManifestError::UnknownStepType` — the parser refuses to
//! silently drop a step the executor wouldn't run.

use serde::{Deserialize, Serialize};

/// Top-level manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CosaciToml {
    /// Tenant section — which signing identity to submit
    /// under.
    pub tenant: TenantSection,
    /// Pipelines defined by this manifest. Each pipeline lists
    /// the events it triggers on plus its step list.
    #[serde(default, rename = "pipeline")]
    pub pipelines: Vec<PipelineSection>,
}

/// `[tenant]` section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantSection {
    /// Tenant id this repo's submissions are signed under.
    /// Must match an entry in the coord's tenant registry
    /// (`tenants.txt`).
    pub id: u64,
}

/// One `[[pipeline]]` array entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineSection {
    /// Operator-chosen name. Free-form; used for log lines
    /// and the read-API record.
    pub name: String,
    /// Event types this pipeline triggers on. Strings match
    /// the SCM provider's webhook event-type taxonomy
    /// (`pull_request.synchronize`, `push`, …). v0.3 doesn't
    /// validate that the names are real — an unknown name
    /// just means the pipeline never fires.
    #[serde(default, rename = "on")]
    pub on_events: Vec<String>,
    /// Steps in pipeline order.
    #[serde(default, rename = "step")]
    pub steps: Vec<StepSection>,
}

/// One `[[pipeline.step]]` entry. Variants are
/// `serde(tag = "type")`-tagged so the wire shape is
/// `type = "source-fetch"` etc.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum StepSection {
    /// `Step::SourceFetch` (issue #40).
    SourceFetch {
        /// Git URL — may carry `{{ event.* }}` placeholders
        /// the listener resolves at submission time.
        url: String,
        /// Git reference (commit SHA, tag, or branch).
        reference: String,
    },
    /// `Step::ExecWasm` (issue #39). Module bytes live
    /// outside the manifest (loaded from the artifact bundle
    /// produced by an earlier `source-fetch` step); the
    /// manifest carries only the args.
    ExecWasm {
        /// Path inside the source tree to the WASM module.
        /// Listener resolves it at submission time after the
        /// `source-fetch` step lands the working tree.
        module_path: String,
        /// Lower-case-hex-encoded CBOR bytes of the
        /// `(i32, i32)` argument tuple. Operators emit the
        /// hex from `cosaci-admin` (when the wire form
        /// lands) or via a small generator script.
        args_cbor_hex: String,
    },
}

/// Errors returned by [`parse_manifest`].
#[derive(Debug, Clone)]
pub enum ManifestError {
    /// TOML lexer / parser rejected the document.
    Toml(String),
    /// TOML parsed, but the structure didn't match the
    /// expected schema (missing required field, wrong type,
    /// unknown step `type` discriminator, …).
    Schema(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Toml(s) => write!(f, "toml parse: {s}"),
            Self::Schema(s) => write!(f, "manifest schema: {s}"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// Parse a `.cosaci.toml` document.
///
/// # Errors
///
/// Returns `ManifestError::Toml` for lexer / TOML-parser
/// failures and `ManifestError::Schema` for cases where the
/// document parsed but fields were missing or had the wrong
/// type — most notably an unknown `type` discriminator on a
/// `[[pipeline.step]]` entry.
pub fn parse_manifest(input: &str) -> Result<CosaciToml, ManifestError> {
    toml::from_str::<CosaciToml>(input).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("unknown variant") {
            ManifestError::Schema(msg)
        } else {
            ManifestError::Toml(msg)
        }
    })
}

/// Re-emit a `CosaciToml` as TOML. Used by property tests to
/// confirm round-trip stability.
///
/// # Errors
///
/// Returns `ManifestError::Toml` if `toml`'s serializer fails
/// (unreachable for well-formed types but the error path is
/// preserved so the caller doesn't have to assume infallibility).
pub fn emit_manifest(manifest: &CosaciToml) -> Result<String, ManifestError> {
    toml::to_string(manifest).map_err(|e| ManifestError::Toml(e.to_string()))
}
