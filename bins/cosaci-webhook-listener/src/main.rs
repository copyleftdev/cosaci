//! CosaCI webhook listener (issue #52 follow-on).
//!
//! HTTP/1.1 listener that translates GitHub / GitLab webhook
//! deliveries into signed `JobSubmission` NDJSON lines on
//! stdout. The intended deployment is a Unix-pipe stack:
//!
//! ```text
//!   webhook-listener --addr 0.0.0.0:8080 \
//!                    --github-secret /etc/cosaci/github.secret \
//!                    --tenant-id 1 \
//!                    --tenant-key /etc/cosaci/tenant.seed \
//!                    --manifest   /etc/cosaci/.cosaci.toml \
//!     | coordinator --submit-stdin --tenants /etc/cosaci/tenants.txt …
//! ```
//!
//! Three gates apply per request, in order:
//!
//! 1. `verify_github_signature` / `verify_gitlab_token` — reject
//!    on bad signature or missing header.
//! 2. `cosaci_webhook::translate` — match the inbound event
//!    against the manifest's pipelines and resolve
//!    `{{ event.* }}` placeholders.
//! 3. Sign the resulting `JobSubmissionPayload` records under
//!    the configured tenant key (loaded once at startup) and
//!    write each as one NDJSON line to stdout.
//!
//! v0.3 ships only what's needed to wire one repo's
//! `.cosaci.toml` to the coord — no per-tenant manifest
//! routing, no per-repo tenant keys (one tenant per listener
//! process), no TLS termination (operators front it with
//! nginx / Caddy / a load balancer).

use std::env;
use std::fs;
use std::io::{self, Write};
use std::process::ExitCode;

use cosaci_core::signing::Keypair;
use cosaci_state::submission_auth::{JobSubmissionPayload, canonical_bytes};
use cosaci_webhook::{
    CosaciToml, ResolvedStep, SignatureError, parse_manifest, translate, verify_github_signature,
    verify_gitlab_token,
};

const ROUTE_GITHUB: &str = "/webhook/github";
const ROUTE_GITLAB: &str = "/webhook/gitlab";

fn main() -> ExitCode {
    init_tracing();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("[webhook-listener] fatal: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let addr = arg_or(&args, "--addr", "127.0.0.1:8080");
    let github_secret_path = arg_or(&args, "--github-secret", "");
    let gitlab_token_path = arg_or(&args, "--gitlab-token", "");
    let tenant_id: u64 = arg_or(&args, "--tenant-id", "0")
        .parse()
        .map_err(|_| io::Error::other("--tenant-id must be a u64"))?;
    let tenant_key_path = arg_or(&args, "--tenant-key", "");
    let manifest_path = arg_or(&args, "--manifest", "");

    if tenant_id == 0 {
        return Err(io::Error::other(
            "--tenant-id is required (must match an entry in coord's --tenants file)",
        ));
    }
    if tenant_key_path.is_empty() {
        return Err(io::Error::other("--tenant-key path is required"));
    }
    if manifest_path.is_empty() {
        return Err(io::Error::other("--manifest path is required"));
    }
    if github_secret_path.is_empty() && gitlab_token_path.is_empty() {
        return Err(io::Error::other(
            "at least one of --github-secret / --gitlab-token must be configured",
        ));
    }

    let tenant_seed_bytes = fs::read(&tenant_key_path)?;
    if tenant_seed_bytes.len() < 32 {
        return Err(io::Error::other(
            "--tenant-key file must be at least 32 bytes (raw ed25519 seed)",
        ));
    }
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&tenant_seed_bytes[..32]);
    let tenant_kp = Keypair::from_seed(seed);

    let manifest_text = fs::read_to_string(&manifest_path)?;
    let manifest = parse_manifest(&manifest_text)
        .map_err(|e| io::Error::other(format!("manifest parse: {e}")))?;
    if manifest.tenant.id != tenant_id {
        return Err(io::Error::other(format!(
            "manifest tenant id {} != --tenant-id {tenant_id}",
            manifest.tenant.id
        )));
    }

    let github_secret = if github_secret_path.is_empty() {
        Vec::new()
    } else {
        let s = fs::read(&github_secret_path)?;
        // GitHub allows newlines + trailing whitespace in the
        // file but strips them from the configured secret.
        let trimmed = trim_end_inplace(s);
        if trimmed.is_empty() {
            return Err(io::Error::other("--github-secret file is empty"));
        }
        trimmed
    };
    let gitlab_token = if gitlab_token_path.is_empty() {
        String::new()
    } else {
        let s = fs::read_to_string(&gitlab_token_path)?;
        let trimmed = s.trim().to_string();
        if trimmed.is_empty() {
            return Err(io::Error::other("--gitlab-token file is empty"));
        }
        trimmed
    };

    let server = tiny_http::Server::http(&addr)
        .map_err(|e| io::Error::other(format!("bind {addr}: {e}")))?;
    tracing::info!("[webhook-listener] listening on {addr} (tenant_id={tenant_id})");

    let stdout = io::stdout();
    for mut req in server.incoming_requests() {
        let url = req.url().to_string();
        let method = req.method().to_string();
        if method != "POST" {
            respond(req, 405, "method not allowed");
            continue;
        }
        let route = url.split('?').next().unwrap_or(&url).to_string();

        let mut body = Vec::new();
        if let Err(e) = req.as_reader().read_to_end(&mut body) {
            tracing::warn!("[webhook-listener] body read error: {e}");
            respond(req, 400, "bad request");
            continue;
        }

        let lines = match route.as_str() {
            ROUTE_GITHUB => handle_github(&body, headers_of(&req), &github_secret, &manifest),
            ROUTE_GITLAB => handle_gitlab(&body, headers_of(&req), &gitlab_token, &manifest),
            _ => {
                respond(req, 404, "no such route");
                continue;
            }
        };

        match lines {
            Ok(submissions) => {
                let count = submissions.len();
                let mut writer = stdout.lock();
                for payload in submissions {
                    let line = sign_and_serialize(&payload, &tenant_kp);
                    if let Err(e) = writeln!(writer, "{line}") {
                        tracing::error!("[webhook-listener] stdout write failed: {e}");
                        return Err(e);
                    }
                }
                drop(writer);
                respond(req, 202, &format!("accepted ({count} submission(s))"));
            }
            Err(HandleError::BadSignature) => respond(req, 401, "unauthorized"),
            Err(HandleError::BadRequest(s)) => respond(req, 400, &s),
            Err(HandleError::Internal(s)) => {
                tracing::error!("[webhook-listener] internal: {s}");
                respond(req, 500, "internal error");
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
enum HandleError {
    BadSignature,
    BadRequest(String),
    Internal(String),
}

impl From<SignatureError> for HandleError {
    fn from(_: SignatureError) -> Self {
        Self::BadSignature
    }
}

fn handle_github(
    body: &[u8],
    headers: Vec<(String, String)>,
    secret: &[u8],
    manifest: &CosaciToml,
) -> Result<Vec<JobSubmissionPayload>, HandleError> {
    if secret.is_empty() {
        return Err(HandleError::BadRequest(
            "github webhook delivered but --github-secret not configured".into(),
        ));
    }
    let sig = header(&headers, "x-hub-signature-256").ok_or(HandleError::BadSignature)?;
    verify_github_signature(body, &sig, secret)?;

    let event_kind = header(&headers, "x-github-event")
        .ok_or_else(|| HandleError::BadRequest("missing X-GitHub-Event".into()))?;

    let event: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| HandleError::BadRequest(format!("invalid JSON body: {e}")))?;
    let event_name = compose_event_name(&event_kind, &event);
    build_payloads(manifest, &event_name, &event)
}

fn handle_gitlab(
    body: &[u8],
    headers: Vec<(String, String)>,
    token: &str,
    manifest: &CosaciToml,
) -> Result<Vec<JobSubmissionPayload>, HandleError> {
    if token.is_empty() {
        return Err(HandleError::BadRequest(
            "gitlab webhook delivered but --gitlab-token not configured".into(),
        ));
    }
    let provided = header(&headers, "x-gitlab-token").ok_or(HandleError::BadSignature)?;
    verify_gitlab_token(&provided, token)?;

    let event_kind = header(&headers, "x-gitlab-event")
        .ok_or_else(|| HandleError::BadRequest("missing X-Gitlab-Event".into()))?;

    let event: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| HandleError::BadRequest(format!("invalid JSON body: {e}")))?;
    let event_name = compose_event_name(&event_kind, &event);
    build_payloads(manifest, &event_name, &event)
}

fn build_payloads(
    manifest: &CosaciToml,
    event_name: &str,
    event: &serde_json::Value,
) -> Result<Vec<JobSubmissionPayload>, HandleError> {
    let resolved = translate(manifest, event_name, event)
        .map_err(|e| HandleError::Internal(format!("translate: {e}")))?;
    let nonce_base = nonce_seed(event);
    let mut out = Vec::with_capacity(resolved.len());
    for (idx, pipeline) in resolved.into_iter().enumerate() {
        // v0.3 listener-emitted submissions reduce to the
        // first ExecWasm step's args (kind/a/b shape) — the
        // executor side hasn't had a chance to lift the
        // submission DSL to arbitrary pipelines yet (#40
        // landed source-fetch but the coord still dispatches
        // canned modules per-job). We surface the first
        // ExecWasm step (or canned add(0,0) if there isn't
        // one) so the listener integration is testable end-
        // to-end today; the wider pipeline shape lands when
        // the coord switches to arbitrary submitted modules.
        let (kind, a, b) = first_canned_args(&pipeline).unwrap_or(("add".to_string(), 0, 0));
        let payload = JobSubmissionPayload {
            tenant_id: manifest.tenant.id,
            kind,
            a,
            b,
            deadline_secs: 60,
            nonce: nonce_base.wrapping_add(idx as u128),
        };
        out.push(payload);
    }
    Ok(out)
}

/// Pull the first ExecWasm step's (kind-equivalent, a, b) tuple
/// out of the resolved pipeline, if any. SourceFetch / others
/// don't carry the canned-module shape, so they don't
/// participate in the v0.3 listener path.
fn first_canned_args(pipeline: &cosaci_webhook::ResolvedPipeline) -> Option<(String, i32, i32)> {
    for step in &pipeline.steps {
        if let ResolvedStep::ExecWasm {
            module_path,
            args_cbor_hex,
        } = step
        {
            // Heuristic: module path's basename without `.wasm`
            // — `mul` if it contains "mul", else "add". Keeps
            // the listener forward-compatible with the
            // canned-module dispatch the coord still does.
            let kind = if module_path.contains("mul") {
                "mul".to_string()
            } else {
                "add".to_string()
            };
            // args_cbor_hex is the pre-CBOR-encoded `(i32, i32)`
            // tuple. v0.3 strips it down to (a, b) by parsing
            // the hex back to bytes and decoding via ciborium.
            let (a, b) = decode_args_cbor_hex(args_cbor_hex).unwrap_or((0, 0));
            return Some((kind, a, b));
        }
    }
    None
}

fn decode_args_cbor_hex(hex: &str) -> Option<(i32, i32)> {
    let bytes = hex_to_bytes(hex)?;
    let (a, b): (i32, i32) = ciborium::from_reader(&bytes[..]).ok()?;
    Some((a, b))
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

fn sign_and_serialize(payload: &JobSubmissionPayload, kp: &Keypair) -> String {
    let bytes = canonical_bytes(payload).expect("encode payload");
    let sig = kp.sign(&bytes).to_bytes();
    let pk = kp.verifying_key().to_bytes();
    format!(
        "{{\"kind\":\"{kind}\",\"a\":{a},\"b\":{b},\"deadline_secs\":{ds},\"tenant_id\":{tid},\"nonce\":{nonce},\"pubkey_hex\":\"{pk_hex}\",\"signature_hex\":\"{sig_hex}\"}}",
        kind = payload.kind,
        a = payload.a,
        b = payload.b,
        ds = payload.deadline_secs,
        tid = payload.tenant_id,
        nonce = payload.nonce,
        pk_hex = lower_hex(&pk),
        sig_hex = lower_hex(&sig),
    )
}

/// Compose `<kind>.<action>` for events that have an action,
/// `<kind>` otherwise. Mirrors the manifest's `on = […]` shape.
fn compose_event_name(kind: &str, body: &serde_json::Value) -> String {
    if let Some(action) = body.get("action").and_then(serde_json::Value::as_str) {
        format!("{kind}.{action}")
    } else if let Some(object_kind) = body.get("object_kind").and_then(serde_json::Value::as_str) {
        // GitLab uses `object_kind` instead of an event header
        // for some payload shapes; defer to that when it's
        // present and disagrees with `kind`.
        if object_kind != kind {
            format!("{kind}.{object_kind}")
        } else {
            kind.to_string()
        }
    } else {
        kind.to_string()
    }
}

/// Derive a nonce seed from the event body. Uses any of the
/// `head_commit.id` / `pull_request.head.sha` / `id` fields if
/// present (in that priority order), folded into a u128. If
/// none is present, falls back to wall-clock nanoseconds.
fn nonce_seed(event: &serde_json::Value) -> u128 {
    let field_paths = [
        "head_commit.id",
        "pull_request.head.sha",
        "checkout_sha",
        "id",
    ];
    for path in field_paths {
        let mut current = event;
        let mut found = true;
        for seg in path.split('.') {
            match current.get(seg) {
                Some(v) => current = v,
                None => {
                    found = false;
                    break;
                }
            }
        }
        if found && let Some(s) = current.as_str() {
            // Fold the bytes into a u128 — first 16 bytes,
            // padded with zeros if shorter.
            let mut buf = [0_u8; 16];
            let bytes = s.as_bytes();
            let n = bytes.len().min(16);
            buf[..n].copy_from_slice(&bytes[..n]);
            return u128::from_le_bytes(buf);
        }
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn headers_of(req: &tiny_http::Request) -> Vec<(String, String)> {
    req.headers()
        .iter()
        .map(|h| (h.field.as_str().to_string(), h.value.as_str().to_string()))
        .collect()
}

fn respond(req: tiny_http::Request, code: u16, body: &str) {
    let resp = tiny_http::Response::from_string(body.to_string()).with_status_code(code);
    if let Err(e) = req.respond(resp) {
        tracing::warn!("[webhook-listener] response write failed: {e}");
    }
}

fn arg_or(args: &[String], flag: &str, default: &str) -> String {
    if let Some(pos) = args.iter().position(|a| a == flag)
        && let Some(v) = args.get(pos + 1)
    {
        return v.clone();
    }
    default.to_string()
}

fn trim_end_inplace(mut v: Vec<u8>) -> Vec<u8> {
    while matches!(v.last(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        v.pop();
    }
    v
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let _ = fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
}
