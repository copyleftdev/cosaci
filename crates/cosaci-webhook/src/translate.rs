//! Webhook event → signed `JobSubmission` translation
//! (issue #52 follow-on).
//!
//! Pure layer between an SCM webhook event JSON body + a
//! `.cosaci.toml` manifest and the NDJSON submission lines the
//! coordinator's stdin reader (`--submit-stdin`, issue #32)
//! consumes. Three responsibilities:
//!
//! 1. **Event-kind matching.** Each `[[pipeline]]` declares an
//!    `on = […]` list. We match the inbound event's
//!    `<event_kind>.<action>` (or just `<event_kind>` when no
//!    action is present) against that list.
//! 2. **Placeholder resolution.** Manifest fields like
//!    `url = "{{ event.repository.clone_url }}"` walk the
//!    event JSON via dot-path lookup. v0.3 supports the
//!    `{{ event.* }}` namespace only — no scripting, no
//!    arithmetic, no `{{ env.* }}`.
//! 3. **Signing.** The resolved pipeline, paired with the
//!    tenant id from `[tenant]` and a fresh nonce, is wrapped
//!    in a `JobSubmissionPayload`-shaped record (the wire
//!    shape from #46) and signed under the listener's
//!    configured ed25519 key.
//!
//! The output is a `Vec<String>` of NDJSON lines, one per
//! triggered pipeline. The HTTP listener writes them to
//! stdout, where an operator pipes them to
//! `coordinator --submit-stdin --tenants tenants.txt`.

use crate::manifest::{CosaciToml, PipelineSection, StepSection};

/// Errors returned by [`translate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranslateError {
    /// A `{{ event.<path> }}` placeholder didn't resolve to a
    /// JSON string at that path. Path and the offending
    /// template are included so the operator can fix the
    /// manifest or the webhook config.
    PlaceholderUnresolved {
        /// The full template (e.g. `{{ event.foo.bar }}`).
        template: String,
        /// The dot-path that failed to resolve.
        path: String,
    },
    /// A placeholder referenced a non-`event` namespace
    /// (`{{ env.X }}` etc.). v0.3 only supports `event.*`.
    UnsupportedNamespace(String),
    /// A v0.3 step variant uses `{{ event.* }}` in a field
    /// where placeholder resolution isn't supported. (Today
    /// only `Step::SourceFetch.url` and `.reference` resolve
    /// placeholders; ExecWasm fields are literal.)
    PlaceholderInLiteralField {
        /// Which step variant the literal-only field belongs to.
        step_kind: &'static str,
        /// Which field the placeholder was found in.
        field: &'static str,
    },
}

impl std::fmt::Display for TranslateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PlaceholderUnresolved { template, path } => {
                write!(f, "placeholder {template} unresolved (path={path})")
            }
            Self::UnsupportedNamespace(ns) => {
                write!(f, "unsupported template namespace: {ns}")
            }
            Self::PlaceholderInLiteralField { step_kind, field } => {
                write!(f, "placeholder in literal-only field {step_kind}.{field}")
            }
        }
    }
}

impl std::error::Error for TranslateError {}

/// One pipeline matched against the inbound event, with all
/// placeholders resolved. The translator returns these so the
/// caller (the listener bin) can wrap them in
/// `JobSubmissionPayload` records and sign them under whichever
/// tenant key it holds. Keeping signing out of this module
/// means the property tests don't need a keypair to verify
/// resolution behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPipeline {
    /// Pipeline name from the manifest.
    pub name: String,
    /// Resolved steps (placeholder-substituted).
    pub steps: Vec<ResolvedStep>,
}

/// A `StepSection` after placeholder resolution. The variant
/// shape mirrors `StepSection` but every string field is
/// guaranteed not to contain `{{ … }}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedStep {
    /// `Step::SourceFetch` with concrete `url` and `reference`.
    SourceFetch {
        /// Resolved git URL.
        url: String,
        /// Resolved git reference (commit SHA, branch, or tag).
        reference: String,
    },
    /// `Step::ExecWasm` with the literal manifest fields.
    ExecWasm {
        /// Path inside the source tree to the WASM module.
        module_path: String,
        /// Hex-encoded CBOR args.
        args_cbor_hex: String,
    },
}

/// Match the inbound event against `manifest`'s pipelines and
/// resolve `{{ event.* }}` placeholders for each match.
///
/// `event_name` is the composed event identifier
/// (`<kind>.<action>` for events with an action, just
/// `<kind>` otherwise). For GitHub the kind comes from the
/// `X-GitHub-Event` header and the action (if any) from the
/// JSON body's `action` field; the listener bin composes them.
///
/// `event_body` is the raw event JSON (already deserialized
/// into a `serde_json::Value` so the dot-path lookup is
/// type-safe).
///
/// # Errors
///
/// Returns `TranslateError` for unresolved placeholders,
/// unsupported namespaces, or placeholders in literal-only
/// fields. A placeholder failure on **any** step of any matching
/// pipeline aborts the whole translation — partial output of a
/// pipeline whose later step couldn't resolve is worse than no
/// output (the operator gets a clear error rather than a
/// stuck-half-way job).
pub fn translate(
    manifest: &CosaciToml,
    event_name: &str,
    event_body: &serde_json::Value,
) -> Result<Vec<ResolvedPipeline>, TranslateError> {
    let mut out = Vec::new();
    for p in &manifest.pipelines {
        if pipeline_matches(p, event_name) {
            let resolved = resolve_pipeline(p, event_body)?;
            out.push(resolved);
        }
    }
    Ok(out)
}

fn pipeline_matches(p: &PipelineSection, event_name: &str) -> bool {
    p.on_events.iter().any(|e| e == event_name)
}

fn resolve_pipeline(
    p: &PipelineSection,
    event: &serde_json::Value,
) -> Result<ResolvedPipeline, TranslateError> {
    let mut resolved_steps = Vec::with_capacity(p.steps.len());
    for step in &p.steps {
        resolved_steps.push(resolve_step(step, event)?);
    }
    Ok(ResolvedPipeline {
        name: p.name.clone(),
        steps: resolved_steps,
    })
}

fn resolve_step(
    step: &StepSection,
    event: &serde_json::Value,
) -> Result<ResolvedStep, TranslateError> {
    match step {
        StepSection::SourceFetch { url, reference } => Ok(ResolvedStep::SourceFetch {
            url: resolve_template(url, event)?,
            reference: resolve_template(reference, event)?,
        }),
        StepSection::ExecWasm {
            module_path,
            args_cbor_hex,
        } => {
            // ExecWasm fields are literal in v0.3 — reject any
            // placeholder use loudly so the operator doesn't
            // think the substitution is happening silently.
            if has_placeholder(module_path) {
                return Err(TranslateError::PlaceholderInLiteralField {
                    step_kind: "exec-wasm",
                    field: "module_path",
                });
            }
            if has_placeholder(args_cbor_hex) {
                return Err(TranslateError::PlaceholderInLiteralField {
                    step_kind: "exec-wasm",
                    field: "args_cbor_hex",
                });
            }
            Ok(ResolvedStep::ExecWasm {
                module_path: module_path.clone(),
                args_cbor_hex: args_cbor_hex.clone(),
            })
        }
    }
}

fn has_placeholder(s: &str) -> bool {
    s.contains("{{")
}

/// Resolve every `{{ event.<dot.path> }}` placeholder in `template`
/// against `event`. Whitespace inside the braces is trimmed —
/// `{{event.x}}`, `{{ event.x }}`, and `{{  event.x  }}` all
/// resolve to the same value.
fn resolve_template(template: &str, event: &serde_json::Value) -> Result<String, TranslateError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after_open = &rest[open + 2..];
        let close = after_open
            .find("}}")
            .ok_or_else(|| TranslateError::PlaceholderUnresolved {
                template: template.to_string(),
                path: "(unterminated `{{`)".to_string(),
            })?;
        let inner = after_open[..close].trim();
        let resolved = resolve_inner(inner, template, event)?;
        out.push_str(&resolved);
        rest = &after_open[close + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn resolve_inner(
    inner: &str,
    template: &str,
    event: &serde_json::Value,
) -> Result<String, TranslateError> {
    let path = inner
        .strip_prefix("event.")
        .ok_or_else(|| TranslateError::UnsupportedNamespace(inner.to_string()))?;
    let value = walk_path(event, path).ok_or_else(|| TranslateError::PlaceholderUnresolved {
        template: template.to_string(),
        path: path.to_string(),
    })?;
    // Only string + integer scalars resolve; objects + arrays
    // would be ambiguous (do we JSON-encode? prettify?). v0.3
    // refuses them — the manifest must reference a leaf.
    match value {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        _ => Err(TranslateError::PlaceholderUnresolved {
            template: template.to_string(),
            path: format!("{path} (non-scalar)"),
        }),
    }
}

fn walk_path<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}
