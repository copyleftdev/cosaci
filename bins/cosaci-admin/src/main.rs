//! CosaCI admin CLI (issue #53).
//!
//! v0.3 scope: filesystem-only operations. The CLI reads/writes the
//! enrollment file directly and reads the persistent Merkle log
//! directly; it does NOT yet talk to the coordinator over the wire
//! protocol. The wire-side (Admin* envelope variants + AuthN gate)
//! lands in a follow-on once #46 ships.
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
use std::path::Path;
use std::process::ExitCode;

use cosaci_core::merkle_log::{FileStore, MerkleLog};
use cosaci_state::enrollment::{EnrolledRecord, EnrollmentSet, fingerprint_hex};

const USAGE: &str = "\
cosaci-admin — administrative CLI for a CosaCI deployment

USAGE:
    cosaci-admin <subcommand> [args]

SUBCOMMANDS:
    agents list     --enrollment <path>
    agents enroll   --enrollment <path> --runner-id <u64>
                    --signing-fp <hex64> --vrf-fp <hex64>
                    [--reputation <0.0..=1.0>] [--at <unix_ns>]
    agents revoke   --enrollment <path> --runner-id <u64>
    log root        --log <path>

EXAMPLES:
    cosaci-admin agents list --enrollment /etc/cosaci/enrollment.txt
    cosaci-admin agents enroll \\
        --enrollment /etc/cosaci/enrollment.txt \\
        --runner-id 7 \\
        --signing-fp $(sha256sum agent-7.signing.pub | cut -d' ' -f1) \\
        --vrf-fp     $(sha256sum agent-7.vrf.pub     | cut -d' ' -f1) \\
        --reputation 1.0
    cosaci-admin log root --log /var/lib/cosaci/attest.log
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("agents") => agents_cmd(&args[1..]),
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
    let path = required_flag(args, "--enrollment")?;
    let set = EnrollmentSet::load_from_path(&path).map_err(|e| format!("load {path}: {e}"))?;
    if set.is_empty() {
        println!("(no runners enrolled in {path})");
        return Ok(());
    }
    println!(
        "{:<10}  {:<16}  {:<16}  {:>22}  {:>10}",
        "runner_id", "signing_fp", "vrf_fp", "enrolled_at", "reputation"
    );
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

fn agents_enroll(args: &[String]) -> Result<(), String> {
    let path = required_flag(args, "--enrollment")?;
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

fn agents_revoke(args: &[String]) -> Result<(), String> {
    let path = required_flag(args, "--enrollment")?;
    let runner_id: u64 = required_flag(args, "--runner-id")?
        .parse()
        .map_err(|e| format!("--runner-id: {e}"))?;
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
