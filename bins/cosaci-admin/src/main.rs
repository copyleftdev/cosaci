//! CosaCI admin CLI (issue #53 + follow-on).
//!
//! Two modes per subcommand: **filesystem-only** (the v0.3 default)
//! and **wire-protocol** (read-only in v0.3). The CLI picks the
//! mode by which flag is set:
//!
//! - `agents list --enrollment <path>`        → filesystem
//! - `agents list --coord <addr> ...`         → wire
//! - `log root --log <path>`                  → filesystem
//! - `log root --coord <addr> ...`            → wire
//!
//! Wire-mode auth: mTLS handshake using the standard
//! `--ca / --cert / --key` triple, then `AdminHello` signed by the
//! `--admin-key` ed25519 seed. The matching pubkey fingerprint
//! must be in the coord's `--admin-keys` allowlist.
//!
//! # Subcommands
//!
//! - `agents list --enrollment <path>` — print the enrollment file
//!   as a table of `(runner_id, signing_fp_short, vrf_fp_short,
//!   enrolled_at, reputation)`.
//! - `agents enroll --enrollment <path> --runner-id N
//!   --signing-fp <hex> --vrf-fp <hex> [--reputation 0..1]`
//!   — append a record. Refuses if `runner_id` is already in the
//!   file (use `revoke` first if you mean to replace).
//! - `agents revoke --enrollment <path> --runner-id N` — remove a
//!   record by `runner_id`.
//! - `log root --log <path>` — open the file-backed Merkle log
//!   (issue #33) and print its current root + length.
//!
//! # Out of scope (follow-on)
//!
//! - Wire-protocol Admin* envelopes (talks to running coord).
//! - AuthN token gate (depends on issue #46).
//! - `tenants {add,list,revoke}`, `jobs {list,inspect}`,
//!   `system status` — these need the wire path.
//! - Reload-without-restart (the coord re-reads the enrollment
//!   file at startup; SIGHUP-driven reload lands separately).
//!
//! # Determinism
//!
//! All file mutations are **append + atomic-rename**: the CLI
//! writes the new content to a tempfile next to the original and
//! renames over it. An interrupted run leaves either the original
//! or the new file, never a half-written one.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use cosaci_core::merkle_log::{FileStore, MerkleLog};
use cosaci_core::signing::Keypair;
use cosaci_protocol::proto::{
    ADMIN_HELLO_CHALLENGE, AdminAgentRecord, Envelope, read_envelope, write_envelope,
};
use cosaci_protocol::tls::{client_config_from_paths, install_crypto_provider};
use cosaci_state::enrollment::{EnrolledRecord, EnrollmentSet, fingerprint_hex};

const USAGE: &str = "\
cosaci-admin — administrative CLI for a CosaCI deployment

USAGE:
    cosaci-admin <subcommand> [args]

FILESYSTEM-MODE SUBCOMMANDS (operate on local files):
    agents list     --enrollment <path>
    agents enroll   --enrollment <path> --runner-id <u64>
                    --signing-fp <hex64> --vrf-fp <hex64>
                    [--reputation <0.0..=1.0>] [--at <unix_ns>]
    agents revoke   --enrollment <path> --runner-id <u64>
    log root        --log <path>

WIRE-MODE SUBCOMMANDS (talk to a running coord; mutations take
effect on next coord restart):
    agents list     --coord <addr> --ca <ca.pem> --cert <admin.pem>
                    --key <admin.key.pem> --admin-key <seed-file>
                    [--server-name <name>]
    agents enroll   --coord <addr> ... (same auth flags)
                    --runner-id <u64>
                    --signing-fp <hex64> --vrf-fp <hex64>
                    [--reputation <0.0..=1.0>] [--at <unix_ns>]
    agents revoke   --coord <addr> ... (same auth flags)
                    --runner-id <u64>
    log root        --coord <addr> ...   (same auth flags)
    tenants list    --coord <addr> ...
    tenants add     --coord <addr> ... --tenant-id <u64>
                    --signing-fp <hex64>
                    --rate-capacity <u64> --rate-refill-per-sec <u64>
                    [--at <unix_ns>]
    tenants revoke  --coord <addr> ... --tenant-id <u64>

EXAMPLES:
    # filesystem
    cosaci-admin agents list --enrollment /etc/cosaci/enrollment.txt
    cosaci-admin agents enroll \\
        --enrollment /etc/cosaci/enrollment.txt \\
        --runner-id 7 \\
        --signing-fp $(sha256sum agent-7.signing.pub | cut -d' ' -f1) \\
        --vrf-fp     $(sha256sum agent-7.vrf.pub     | cut -d' ' -f1) \\
        --reputation 1.0
    cosaci-admin log root --log /var/lib/cosaci/attest.log
    # wire (read-only in v0.3)
    cosaci-admin agents list \\
        --coord 10.0.0.1:7880 \\
        --ca /etc/cosaci/ca.pem \\
        --cert /etc/cosaci/admin.pem \\
        --key  /etc/cosaci/admin.key.pem \\
        --admin-key /etc/cosaci/admin.seed
    cosaci-admin log root --coord 10.0.0.1:7880 --ca ... --cert ... --key ... --admin-key ...
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("agents") => agents_cmd(&args[1..]),
        Some("tenants") => tenants_cmd(&args[1..]),
        Some("log") => log_cmd(&args[1..]),
        Some("--help" | "-h" | "help") | None => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some(other) => Err(format!("unknown subcommand `{other}`\n\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// agents <verb>
// ────────────────────────────────────────────────────────────────────────

fn agents_cmd(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("list") => agents_list(&args[1..]),
        Some("enroll") => agents_enroll(&args[1..]),
        Some("revoke") => agents_revoke(&args[1..]),
        Some(other) => Err(format!(
            "unknown agents verb `{other}` (expected: list, enroll, revoke)"
        )),
        None => Err("agents: missing verb (list, enroll, revoke)".to_string()),
    }
}

fn agents_list(args: &[String]) -> Result<(), String> {
    if let Some(addr) = optional_flag(args, "--coord") {
        return agents_list_wire(args, &addr);
    }
    let path = required_flag(args, "--enrollment")?;
    let set = EnrollmentSet::load_from_path(&path).map_err(|e| format!("load {path}: {e}"))?;
    if set.is_empty() {
        println!("(no runners enrolled in {path})");
        return Ok(());
    }
    print_agents_header();
    // Sort by runner_id for deterministic output.
    let mut records: Vec<&EnrolledRecord> = set.iter().collect();
    records.sort_by_key(|r| r.runner_id);
    for r in records {
        let s_short = &fingerprint_hex(&r.signing_fp)[..16];
        let v_short = &fingerprint_hex(&r.vrf_fp)[..16];
        println!(
            "{:<10}  {:<16}  {:<16}  {:>22}  {:>10.3}",
            r.runner_id,
            s_short,
            v_short,
            r.enrolled_at_unix_ns,
            r.initial_reputation()
        );
    }
    Ok(())
}

fn print_agents_header() {
    println!(
        "{:<10}  {:<16}  {:<16}  {:>22}  {:>10}",
        "runner_id", "signing_fp", "vrf_fp", "enrolled_at", "reputation"
    );
}

fn agents_list_wire(args: &[String], addr: &str) -> Result<(), String> {
    let conn = AdminWireConn::connect(args, addr)?;
    match conn.request(Envelope::AdminListAgents)? {
        Envelope::AdminAgentList { entries } => {
            if entries.is_empty() {
                println!("(no runners enrolled per coord at {addr})");
                return Ok(());
            }
            print_agents_header();
            // The coord already returns sorted-by-runner_id, but
            // re-sort defensively in case a future change relaxes
            // that — the CLI's contract is "deterministic output".
            let mut entries: Vec<AdminAgentRecord> = entries;
            entries.sort_by_key(|e| e.runner_id);
            for r in entries {
                let s_short = &fingerprint_hex(&r.signing_fp)[..16];
                let v_short = &fingerprint_hex(&r.vrf_fp)[..16];
                let rep = (r.initial_reputation_thousandths.min(1000) as f32) / 1000.0;
                println!(
                    "{:<10}  {:<16}  {:<16}  {:>22}  {:>10.3}",
                    r.runner_id, s_short, v_short, r.enrolled_at_unix_ns, rep
                );
            }
            Ok(())
        }
        Envelope::AdminError { reason } => Err(format!("coord rejected: {reason}")),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

fn agents_enroll(args: &[String]) -> Result<(), String> {
    let runner_id: u64 = required_flag(args, "--runner-id")?
        .parse()
        .map_err(|e| format!("--runner-id: {e}"))?;
    let signing_fp_hex = required_flag(args, "--signing-fp")?;
    let vrf_fp_hex = required_flag(args, "--vrf-fp")?;
    let reputation: f32 = optional_flag(args, "--reputation")
        .as_deref()
        .unwrap_or("1.0")
        .parse()
        .map_err(|e| format!("--reputation: {e}"))?;
    if !(0.0..=1.0).contains(&reputation) {
        return Err(format!("--reputation {reputation} not in [0.0, 1.0]"));
    }
    let signing_fp = parse_hex32(&signing_fp_hex).map_err(|e| format!("--signing-fp: {e}"))?;
    let vrf_fp = parse_hex32(&vrf_fp_hex).map_err(|e| format!("--vrf-fp: {e}"))?;
    let enrolled_at_unix_ns: i64 = optional_flag(args, "--at")
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|e| format!("--at: {e}"))?
        .unwrap_or_else(now_unix_ns);

    if let Some(addr) = optional_flag(args, "--coord") {
        return agents_enroll_wire(
            args,
            &addr,
            runner_id,
            signing_fp,
            vrf_fp,
            enrolled_at_unix_ns,
            reputation,
        );
    }

    let path = required_flag(args, "--enrollment")?;
    // Refuse if the runner_id is already enrolled. Operators who
    // mean to replace must `revoke` first; this catches typos.
    let existing = if Path::new(&path).exists() {
        EnrollmentSet::load_from_path(&path).map_err(|e| format!("load {path}: {e}"))?
    } else {
        EnrollmentSet::new()
    };
    if existing.get(runner_id).is_some() {
        return Err(format!(
            "runner_id {runner_id} is already enrolled in {path}; \
             revoke first if you mean to replace"
        ));
    }

    let line = format!(
        "{runner_id} {} {} {enrolled_at_unix_ns} {reputation}",
        fingerprint_hex(&signing_fp),
        fingerprint_hex(&vrf_fp),
    );

    append_atomic(&path, &line).map_err(|e| format!("append to {path}: {e}"))?;
    println!(
        "enrolled runner {runner_id} (signing_fp[..8]={}, vrf_fp[..8]={})",
        &fingerprint_hex(&signing_fp)[..16],
        &fingerprint_hex(&vrf_fp)[..16],
    );
    Ok(())
}

fn agents_enroll_wire(
    args: &[String],
    addr: &str,
    runner_id: u64,
    signing_fp: [u8; 32],
    vrf_fp: [u8; 32],
    enrolled_at_unix_ns: i64,
    reputation: f32,
) -> Result<(), String> {
    let conn = AdminWireConn::connect(args, addr)?;
    let initial_reputation_thousandths = (reputation * 1000.0).round().clamp(0.0, 1000.0) as u32;
    match conn.request(Envelope::AdminEnrollAgent {
        runner_id,
        signing_fp,
        vrf_fp,
        enrolled_at_unix_ns,
        initial_reputation_thousandths,
    })? {
        Envelope::AdminEnrollAck => {
            println!(
                "enrolled runner {runner_id} on coord at {addr} (signing_fp[..8]={}, vrf_fp[..8]={})",
                &fingerprint_hex(&signing_fp)[..16],
                &fingerprint_hex(&vrf_fp)[..16],
            );
            println!("note: takes effect on next coord restart");
            Ok(())
        }
        Envelope::AdminError { reason } => Err(format!("coord rejected: {reason}")),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

fn agents_revoke(args: &[String]) -> Result<(), String> {
    let runner_id: u64 = required_flag(args, "--runner-id")?
        .parse()
        .map_err(|e| format!("--runner-id: {e}"))?;
    if let Some(addr) = optional_flag(args, "--coord") {
        return agents_revoke_wire(args, &addr, runner_id);
    }
    let path = required_flag(args, "--enrollment")?;
    if !Path::new(&path).exists() {
        return Err(format!("{path} does not exist; nothing to revoke"));
    }
    let original = fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
    let mut found = false;
    let mut out = String::with_capacity(original.len());
    for line in original.lines() {
        let trimmed = line.trim_start();
        // Comment / blank: pass through.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        // First whitespace-separated token is the runner_id.
        let id_str = trimmed.split_whitespace().next().unwrap_or("");
        match id_str.parse::<u64>() {
            Ok(id) if id == runner_id => {
                found = true;
                // Drop the line.
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    if !found {
        return Err(format!("runner_id {runner_id} not found in {path}"));
    }
    write_atomic(&path, &out).map_err(|e| format!("write {path}: {e}"))?;
    println!("revoked runner {runner_id} from {path}");
    Ok(())
}

fn agents_revoke_wire(args: &[String], addr: &str, runner_id: u64) -> Result<(), String> {
    let conn = AdminWireConn::connect(args, addr)?;
    match conn.request(Envelope::AdminRevokeAgent { runner_id })? {
        Envelope::AdminRevokeAck => {
            println!("revoked runner {runner_id} on coord at {addr}");
            println!(
                "note: takes effect on next coord restart; use the CRL path (RUNBOOK §4) for immediate revocation"
            );
            Ok(())
        }
        Envelope::AdminError { reason } => Err(format!("coord rejected: {reason}")),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

// ────────────────────────────────────────────────────────────────────────
// tenants <verb>  (issue #46 + #53 follow-on; wire mode only — file-only
// tenants management isn't shipped because the operator-facing CLI
// path for tenants didn't exist before this PR).
// ────────────────────────────────────────────────────────────────────────

fn tenants_cmd(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("list") => tenants_list(&args[1..]),
        Some("add") => tenants_add(&args[1..]),
        Some("revoke") => tenants_revoke(&args[1..]),
        Some(other) => Err(format!(
            "unknown tenants verb `{other}` (expected: list, add, revoke)"
        )),
        None => Err("tenants: missing verb (list, add, revoke)".to_string()),
    }
}

fn tenants_list(args: &[String]) -> Result<(), String> {
    let addr = required_flag(args, "--coord")?;
    let conn = AdminWireConn::connect(args, &addr)?;
    match conn.request(Envelope::AdminListTenants)? {
        Envelope::AdminTenantList { mut entries } => {
            if entries.is_empty() {
                println!("(no tenants registered per coord at {addr})");
                return Ok(());
            }
            println!(
                "{:<10}  {:<16}  {:>10}  {:>14}  {:>22}",
                "tenant_id", "signing_fp", "capacity", "refill_per_s", "registered_at"
            );
            entries.sort_by_key(|r| r.tenant_id);
            for r in entries {
                let s_short = &fingerprint_hex(&r.signing_fp)[..16];
                println!(
                    "{:<10}  {:<16}  {:>10}  {:>14}  {:>22}",
                    r.tenant_id,
                    s_short,
                    r.rate_capacity,
                    r.rate_refill_per_sec,
                    r.registered_at_unix_ns
                );
            }
            Ok(())
        }
        Envelope::AdminError { reason } => Err(format!("coord rejected: {reason}")),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

fn tenants_add(args: &[String]) -> Result<(), String> {
    let addr = required_flag(args, "--coord")?;
    let tenant_id: u64 = required_flag(args, "--tenant-id")?
        .parse()
        .map_err(|e| format!("--tenant-id: {e}"))?;
    let signing_fp_hex = required_flag(args, "--signing-fp")?;
    let signing_fp = parse_hex32(&signing_fp_hex).map_err(|e| format!("--signing-fp: {e}"))?;
    let rate_capacity: u64 = required_flag(args, "--rate-capacity")?
        .parse()
        .map_err(|e| format!("--rate-capacity: {e}"))?;
    let rate_refill_per_sec: u64 = required_flag(args, "--rate-refill-per-sec")?
        .parse()
        .map_err(|e| format!("--rate-refill-per-sec: {e}"))?;
    let registered_at_unix_ns: u64 = optional_flag(args, "--at")
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|e| format!("--at: {e}"))?
        .unwrap_or_else(|| now_unix_ns().max(0) as u64);

    let conn = AdminWireConn::connect(args, &addr)?;
    match conn.request(Envelope::AdminAddTenant {
        tenant_id,
        signing_fp,
        rate_capacity,
        rate_refill_per_sec,
        registered_at_unix_ns,
    })? {
        Envelope::AdminAddTenantAck => {
            println!(
                "added tenant {tenant_id} on coord at {addr} (signing_fp[..8]={}, capacity={rate_capacity}, refill={rate_refill_per_sec}/s)",
                &fingerprint_hex(&signing_fp)[..16],
            );
            println!("note: in effect immediately (coord auto-reloaded auth state)");
            Ok(())
        }
        Envelope::AdminError { reason } => Err(format!("coord rejected: {reason}")),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

fn tenants_revoke(args: &[String]) -> Result<(), String> {
    let addr = required_flag(args, "--coord")?;
    let tenant_id: u64 = required_flag(args, "--tenant-id")?
        .parse()
        .map_err(|e| format!("--tenant-id: {e}"))?;
    let conn = AdminWireConn::connect(args, &addr)?;
    match conn.request(Envelope::AdminRevokeTenant { tenant_id })? {
        Envelope::AdminRevokeTenantAck => {
            println!("revoked tenant {tenant_id} on coord at {addr}");
            println!("note: in effect immediately (coord auto-reloaded auth state)");
            Ok(())
        }
        Envelope::AdminError { reason } => Err(format!("coord rejected: {reason}")),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

// ────────────────────────────────────────────────────────────────────────
// log <verb>
// ────────────────────────────────────────────────────────────────────────

fn log_cmd(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("root") => log_root(&args[1..]),
        Some(other) => Err(format!("unknown log verb `{other}` (expected: root)")),
        None => Err("log: missing verb (root)".to_string()),
    }
}

fn log_root(args: &[String]) -> Result<(), String> {
    if let Some(addr) = optional_flag(args, "--coord") {
        return log_root_wire(args, &addr);
    }
    let path = required_flag(args, "--log")?;
    let log = MerkleLog::<FileStore>::open(&path).map_err(|e| format!("open {path}: {e}"))?;
    let len = log.len();
    match log.root() {
        Some(root) => {
            println!("length: {len}");
            println!("root:   {}", hex_lower(&root));
        }
        None => {
            println!("length: 0 (log is empty; no root)");
        }
    }
    Ok(())
}

fn log_root_wire(args: &[String], addr: &str) -> Result<(), String> {
    let conn = AdminWireConn::connect(args, addr)?;
    match conn.request(Envelope::AdminGetLogRoot)? {
        Envelope::AdminLogRoot { root, length } => {
            match root {
                Some(r) => {
                    println!("length: {length}");
                    println!("root:   {}", hex_lower(&r));
                }
                None => println!("length: 0 (log is empty; no root)"),
            }
            Ok(())
        }
        Envelope::AdminError { reason } => Err(format!("coord rejected: {reason}")),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

// ────────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────────

fn required_flag(args: &[String], flag: &str) -> Result<String, String> {
    optional_flag(args, flag).ok_or_else(|| format!("missing required flag {flag}"))
}

fn optional_flag(args: &[String], flag: &str) -> Option<String> {
    let pos = args.iter().position(|a| a == flag)?;
    args.get(pos + 1).cloned()
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0_u8; 32];
    for (i, byte_out) in out.iter_mut().enumerate() {
        let hi = hex_digit(s.as_bytes()[i * 2])?;
        let lo = hex_digit(s.as_bytes()[i * 2 + 1])?;
        *byte_out = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(format!("non-hex byte 0x{other:02x}")),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn now_unix_ns() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Append `line` (with a trailing newline) to `path` atomically:
/// write the new content (existing bytes + new line) to a tempfile
/// next to the original, then rename over. An interrupted run
/// leaves either the original or the new file, never partial.
fn append_atomic(path: &str, line: &str) -> io::Result<()> {
    let existing = if Path::new(path).exists() {
        fs::read_to_string(path)?
    } else {
        String::new()
    };
    let mut new_content = existing;
    if !new_content.is_empty() && !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    new_content.push_str(line);
    new_content.push('\n');
    write_atomic(path, &new_content)
}

fn write_atomic(path: &str, content: &str) -> io::Result<()> {
    let tmp = format!("{path}.tmp.{}", std::process::id());
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

// ────────────────────────────────────────────────────────────────────────
// Admin wire-protocol client (issue #53 follow-on)
// ────────────────────────────────────────────────────────────────────────

type ClientStream = StreamOwned<ClientConnection, TcpStream>;

struct AdminWireConn {
    stream: ClientStream,
}

impl AdminWireConn {
    /// Open an mTLS connection to coord's `--admin-addr`, send an
    /// `AdminHello` signed under the operator's admin signing key,
    /// and wait for the coord's `AdminWelcome`. Returns a handle
    /// whose `.request(env)` writes one envelope and reads one
    /// envelope back.
    fn connect(args: &[String], addr: &str) -> Result<Self, String> {
        install_crypto_provider();
        let ca_path = required_flag(args, "--ca")?;
        let cert_path = required_flag(args, "--cert")?;
        let key_path = required_flag(args, "--key")?;
        let server_name_str = optional_flag(args, "--server-name").unwrap_or_else(|| {
            // Match the SUBJECT_SERVER constant cosaci-protocol's
            // TestCa stamps onto demo certs. Real operator deploys
            // pass --server-name explicitly; this keeps the demo
            // path single-arg.
            "cosaci.local".to_string()
        });
        let admin_key_path = required_flag(args, "--admin-key")?;

        let admin_seed_bytes =
            fs::read(&admin_key_path).map_err(|e| format!("read {admin_key_path}: {e}"))?;
        if admin_seed_bytes.len() < 32 {
            return Err(format!(
                "{admin_key_path}: admin key must be at least 32 bytes (raw ed25519 seed)"
            ));
        }
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&admin_seed_bytes[..32]);
        let admin_kp = Keypair::from_seed(seed);

        let client_cfg: Arc<ClientConfig> =
            client_config_from_paths(&ca_path, &cert_path, &key_path)
                .map_err(|e| format!("client config: {e}"))?;

        let tcp = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
        tcp.set_nodelay(true)
            .map_err(|e| format!("set_nodelay: {e}"))?;
        let server_name: ServerName<'static> = ServerName::try_from(server_name_str.clone())
            .map_err(|e| format!("server name {server_name_str}: {e}"))?;
        let conn =
            ClientConnection::new(client_cfg, server_name).map_err(|e| format!("rustls: {e}"))?;
        let mut stream = ClientStream::new(conn, tcp);

        // Send AdminHello.
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("clock: {e}"))?
            .as_nanos() as u64;
        let admin_pubkey = admin_kp.verifying_key().to_bytes();
        let mut signed = Vec::with_capacity(ADMIN_HELLO_CHALLENGE.len() + 8);
        signed.extend_from_slice(ADMIN_HELLO_CHALLENGE);
        signed.extend_from_slice(&now_ns.to_le_bytes());
        let signature = admin_kp.sign(&signed).to_bytes();

        write_envelope(
            &mut stream,
            &Envelope::AdminHello {
                admin_pubkey,
                ts_unix_ns: now_ns,
                signature,
            },
        )
        .map_err(|e| format!("write AdminHello: {e}"))?;
        match read_envelope(&mut stream).map_err(|e| format!("read welcome: {e}"))? {
            Envelope::AdminWelcome => Ok(Self { stream }),
            Envelope::AdminError { reason } => Err(format!("coord rejected hello: {reason}")),
            other => Err(format!("unexpected hello response: {other:?}")),
        }
    }

    fn request(mut self, env: Envelope) -> Result<Envelope, String> {
        write_envelope(&mut self.stream, &env).map_err(|e| format!("write request: {e}"))?;
        read_envelope(&mut self.stream).map_err(|e| format!("read response: {e}"))
    }
}
