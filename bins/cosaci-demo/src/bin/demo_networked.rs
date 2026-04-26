//! Networked demo runner — generates a temp CA + per-process certs at
//! startup, then spawns `coordinator` and N `agent` subprocesses with
//! their cert paths. Pipes their stdout/stderr to this process.
//!
//! Two passes per run:
//!   1. **Bounded** — coordinator runs `MAX_JOBS` jobs and exits cleanly.
//!      Verifies the persistent loop + connection reuse.
//!   2. **SIGTERM** — coordinator runs unbounded; the launcher sends
//!      SIGTERM after `SIGTERM_AFTER`. Verifies graceful drain.
//!
//! Pre-build: `cargo build --bin coordinator --bin agent`.
//! Run: `cargo run --bin demo_networked`.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cosaci_core::signing::Keypair;
use cosaci_protocol::tls::{SUBJECT_SERVER, TestCa, install_crypto_provider};
use cosaci_state::enrollment::{fingerprint, fingerprint_hex};
use cosaci_state::submission_auth::{JobSubmissionPayload, canonical_bytes};
use cosaci_vrf::vrf::VrfKeypair;

/// Lowercase-hex-encode a byte slice. Used for pubkey + signature
/// fields in the pass-3 NDJSON submission lines.
fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

const ADDR_BOUNDED: &str = "127.0.0.1:7879";
const ADDR_SIGTERM: &str = "127.0.0.1:7880";
const READ_ADDR_BOUNDED: &str = "127.0.0.1:7881";
const ADDR_SUBMIT_STDIN: &str = "127.0.0.1:7882";
const FLEET: u64 = 5;
const COMMITTEE: usize = 3;
const MAX_JOBS_BOUNDED: u64 = 3;
const SIGTERM_AFTER: Duration = Duration::from_millis(1500);

struct Certs {
    temp_dir: PathBuf,
    ca: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    agents: Vec<(PathBuf, PathBuf)>,
    /// Path to the enrollment file (issue #45) listing the FLEET demo
    /// agents — coord rejects any registration not on this list.
    enrollment: PathBuf,
    /// Path to the tenant registry file (issue #46). Contains a
    /// single demo tenant whose signing key is derived from the
    /// fixed seed in `demo_tenant_seed()`.
    tenants: PathBuf,
}

/// Deterministic seed for the demo tenant's ed25519 signing key.
/// The launcher signs pass-3 submissions with this key; the coord
/// loads the matching pubkey fingerprint from the tenants file.
fn demo_tenant_seed() -> [u8; 32] {
    let mut seed = [0_u8; 32];
    seed[0] = 0xde;
    seed[1] = 0xad;
    seed[2] = 0xbe;
    seed[3] = 0xef;
    seed
}

const DEMO_TENANT_ID: u64 = 1;

fn main() {
    install_crypto_provider();

    println!("═══════════════════════════════════════════════════════════");
    println!(" CosaCI networked demo — coordinator + {FLEET} agents (mTLS)");
    println!("═══════════════════════════════════════════════════════════\n");

    let certs = generate_certs();
    println!("[launcher] CA + certs in {}\n", certs.temp_dir.display());

    let bin_dir = std::env::current_exe()
        .expect("current_exe")
        .parent()
        .expect("bin dir")
        .to_path_buf();
    let coord_bin = bin_dir.join("coordinator");
    let agent_bin = bin_dir.join("agent");
    if !coord_bin.exists() || !agent_bin.exists() {
        eprintln!(
            "error: {} or {} not found.\n\nPre-build with:\n    cargo build --bin coordinator --bin agent\n",
            coord_bin.display(),
            agent_bin.display()
        );
        std::process::exit(1);
    }

    // ── Pass 1: bounded run, --max-jobs 3 ──────────────────────────────────
    println!("───── pass 1: bounded ({MAX_JOBS_BOUNDED} jobs) ─────");
    let exit1 = run_round(
        &coord_bin,
        &agent_bin,
        &certs,
        ADDR_BOUNDED,
        RoundKind::Bounded {
            read_addr: Some(READ_ADDR_BOUNDED),
        },
    );
    println!("\n[launcher] pass 1 coord exit: {exit1:?}");
    assert_eq!(exit1, Some(0), "bounded coord should exit 0");

    // ── Pass 2: unbounded, SIGTERM after a short delay ────────────────────
    println!("\n───── pass 2: SIGTERM drain ─────");
    let exit2 = run_round(
        &coord_bin,
        &agent_bin,
        &certs,
        ADDR_SIGTERM,
        RoundKind::Sigterm,
    );
    println!("\n[launcher] pass 2 coord exit: {exit2:?}");
    assert_eq!(exit2, Some(0), "SIGTERMed coord should drain and exit 0");

    // ── Pass 3: stdin submission (issue #32) ──────────────────────────────
    println!("\n───── pass 3: stdin NDJSON submission ─────");
    let exit3 = run_round(
        &coord_bin,
        &agent_bin,
        &certs,
        ADDR_SUBMIT_STDIN,
        RoundKind::SubmitStdin,
    );
    println!("\n[launcher] pass 3 coord exit: {exit3:?}");
    assert_eq!(
        exit3,
        Some(0),
        "stdin-submission coord should drain and exit 0"
    );

    println!("\n═══════════════════════════════════════════════════════════");
    println!(" Done. All three rounds completed cleanly.");
    println!("═══════════════════════════════════════════════════════════");

    let _ = std::fs::remove_dir_all(&certs.temp_dir);
}

#[derive(Clone, Copy)]
enum RoundKind {
    /// Bounded run; if `Some(read_addr)`, also spawns a `verify`
    /// subprocess against the coord's read API and asserts the
    /// retrieved bundle verifies.
    Bounded {
        read_addr: Option<&'static str>,
    },
    Sigterm,
    /// Stdin NDJSON submission (issue #32): the launcher pipes a
    /// short script of `JobSubmission` records to coord's stdin,
    /// then closes stdin. Coord drains the queue and exits.
    SubmitStdin,
}

fn run_round(
    coord_bin: &Path,
    agent_bin: &Path,
    certs: &Certs,
    addr: &str,
    kind: RoundKind,
) -> Option<i32> {
    let mut coord_args: Vec<String> = vec![
        "--addr".into(),
        addr.into(),
        "--ca".into(),
        certs.ca.to_string_lossy().into(),
        "--cert".into(),
        certs.server_cert.to_string_lossy().into(),
        "--key".into(),
        certs.server_key.to_string_lossy().into(),
        "--fleet".into(),
        FLEET.to_string(),
        "--committee".into(),
        COMMITTEE.to_string(),
        "--enrollment".into(),
        certs.enrollment.to_string_lossy().into(),
    ];
    if let RoundKind::Bounded { read_addr } = kind {
        coord_args.push("--max-jobs".into());
        coord_args.push(MAX_JOBS_BOUNDED.to_string());
        if let Some(read_addr) = read_addr {
            coord_args.push("--read-addr".into());
            coord_args.push(read_addr.to_string());
        }
        // Issue #51 follow-on: exercise the journal end-to-end in
        // the bounded round. The path lives in the per-process temp
        // dir alongside the demo's certs; demo_networked deletes the
        // dir on exit.
        let journal_path = certs.temp_dir.join("journal.ndjson");
        coord_args.push("--journal".into());
        coord_args.push(journal_path.to_string_lossy().into_owned());
    }
    if matches!(kind, RoundKind::SubmitStdin) {
        coord_args.push("--submit-stdin".into());
        coord_args.push("--queue-cap".into());
        coord_args.push("8".into());
        // Issue #46: enable the auth gate — submissions must be
        // signed by the demo tenant key registered in
        // `certs.tenants`.
        coord_args.push("--tenants".into());
        coord_args.push(certs.tenants.to_string_lossy().into());
    }

    let stdin_setting = if matches!(kind, RoundKind::SubmitStdin) {
        Stdio::piped()
    } else {
        Stdio::null()
    };
    let mut coord = Command::new(coord_bin)
        .args(&coord_args)
        .stdin(stdin_setting)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn coordinator");
    let coord_pid = coord.id();
    let coord_out = coord.stdout.take().expect("stdout");
    let coord_err = coord.stderr.take().expect("stderr");
    let t_out = thread::spawn(move || forward(coord_out, "coord"));
    let t_err = thread::spawn(move || forward(coord_err, "coord!"));

    thread::sleep(Duration::from_millis(250));

    let mut agents: Vec<Child> = Vec::with_capacity(FLEET as usize);
    let mut agent_threads: Vec<thread::JoinHandle<()>> = Vec::new();
    for (id, (cert, key)) in certs.agents.iter().enumerate() {
        let mut child = Command::new(agent_bin)
            .args([
                "--id",
                &id.to_string(),
                "--addr",
                addr,
                "--ca",
                &certs.ca.to_string_lossy(),
                "--cert",
                &cert.to_string_lossy(),
                "--key",
                &key.to_string_lossy(),
                "--server-name",
                SUBJECT_SERVER,
                "--stake",
                "100",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn agent");
        let out = child.stdout.take().expect("stdout");
        let err = child.stderr.take().expect("stderr");
        let label_out = format!("agent{id}");
        let label_err = format!("agent{id}!");
        agent_threads.push(thread::spawn(move || forward(out, &label_out)));
        agent_threads.push(thread::spawn(move || forward(err, &label_err)));
        agents.push(child);
    }

    // ── Verifier: run alongside the bounded round ─────────────────────────
    // Once the agent fleet is up and the coord starts processing jobs,
    // the verifier polls the read API for job_id 1, fetches the bundle,
    // and runs `verify_inclusion` against the simultaneously-retrieved
    // log root. This is the end-to-end round-trip for issue #44.
    let verify_handle: Option<thread::JoinHandle<Option<i32>>> = if let RoundKind::Bounded {
        read_addr: Some(read_addr),
    } = kind
    {
        let bin_dir = coord_bin.parent().expect("bin dir").to_path_buf();
        let verify_bin = bin_dir.join("verify");
        let ca = certs.ca.clone();
        // Reuse agent-0's cert as the auditor identity. The CA
        // trusts it; the read API doesn't differentiate.
        let (cert, key) = certs.agents[0].clone();
        let read_addr = read_addr.to_string();
        Some(thread::spawn(move || -> Option<i32> {
            let mut child = Command::new(&verify_bin)
                .args([
                    "--addr",
                    &read_addr,
                    "--ca",
                    &ca.to_string_lossy(),
                    "--cert",
                    &cert.to_string_lossy(),
                    "--key",
                    &key.to_string_lossy(),
                    "--server-name",
                    SUBJECT_SERVER,
                    "--job-id",
                    "1",
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn verify");
            let out = child.stdout.take().expect("stdout");
            let err = child.stderr.take().expect("stderr");
            let t_o = thread::spawn(move || forward(out, "verify"));
            let t_e = thread::spawn(move || forward(err, "verify!"));
            let status = child.wait().expect("verify wait");
            let _ = t_o.join();
            let _ = t_e.join();
            status.code()
        }))
    } else {
        None
    };

    if matches!(kind, RoundKind::Sigterm) {
        // Schedule a SIGTERM to coord while jobs are running.
        thread::spawn(move || {
            thread::sleep(SIGTERM_AFTER);
            // `kill -TERM <pid>` — coord's signal_hook flag flips and the
            // job loop drains at its next iteration boundary.
            let status = Command::new("kill")
                .args(["-TERM", &coord_pid.to_string()])
                .status();
            eprintln!("[launcher] sent SIGTERM to coord pid {coord_pid}: {status:?}");
        });
    }

    if matches!(kind, RoundKind::SubmitStdin) {
        // Pipe two NDJSON job submissions to coord's stdin. The
        // first is `add(1, 2)`, the second `mul(3, 5)` — distinct
        // (kind, a, b) tuples so a regression that ignored the
        // submission and re-used the canned --a/--b would produce
        // wrong artifact_hashes and the quorum lines would mismatch.
        //
        // Issue #46: each submission is signed under the demo
        // tenant's ed25519 key. The coord's `--tenants` registry
        // holds the matching pubkey fingerprint, so unsigned or
        // wrongly-signed submissions are rejected at the auth gate.
        // Closing stdin (drop the handle) is the shutdown signal
        // — coord's main loop notices `Disconnected` after the
        // queue drains.
        let mut stdin = coord.stdin.take().expect("coord stdin piped");
        thread::spawn(move || {
            let kp = Keypair::from_seed(demo_tenant_seed());
            let pk = kp.verifying_key().to_bytes();
            // Wait briefly so coord's tracing line for the fleet
            // assembly comes out before our submissions — keeps
            // the smoke output readable.
            thread::sleep(Duration::from_millis(500));
            let payloads = [
                ("add", 1_i32, 2_i32, 60_u32, 0xa1_u128),
                ("mul", 3_i32, 5_i32, 60_u32, 0xb2_u128),
            ];
            for (kind, a, b, deadline_secs, nonce) in payloads {
                let payload = JobSubmissionPayload {
                    tenant_id: DEMO_TENANT_ID,
                    kind: kind.to_string(),
                    a,
                    b,
                    deadline_secs,
                    nonce,
                };
                let bytes = canonical_bytes(&payload).expect("encode payload");
                let sig = kp.sign(&bytes).to_bytes();
                let line = format!(
                    r#"{{"kind":"{kind}","a":{a},"b":{b},"deadline_secs":{deadline_secs},"tenant_id":{tenant_id},"nonce":{nonce},"pubkey_hex":"{pk_hex}","signature_hex":"{sig_hex}"}}"#,
                    tenant_id = DEMO_TENANT_ID,
                    pk_hex = lower_hex(&pk),
                    sig_hex = lower_hex(&sig),
                );
                if let Err(e) = writeln!(stdin, "{line}") {
                    eprintln!("[launcher] stdin write error: {e}");
                    return;
                }
            }
            // Drop closes coord stdin → reader thread EOFs →
            // sender drops → main loop's recv returns Disconnected.
            drop(stdin);
            eprintln!("[launcher] stdin closed; coord should drain");
        });
    }

    let coord_status = coord.wait().expect("coordinator wait");
    let _ = t_out.join();
    let _ = t_err.join();
    for mut a in agents {
        let _ = a.wait();
    }
    for t in agent_threads {
        let _ = t.join();
    }
    if let Some(h) = verify_handle {
        let v = h.join().expect("verify thread");
        eprintln!("[launcher] verify exit: {v:?}");
        assert_eq!(v, Some(0), "verify should exit 0 on a verifying bundle");
    }
    coord_status.code()
}

fn generate_certs() -> Certs {
    let temp_dir = std::env::temp_dir().join(format!("cosaci-demo-{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");

    let ca = TestCa::generate("cosaci-demo-ca").expect("generate CA");
    let ca_path = temp_dir.join("ca.pem");
    ca.write_pem(&ca_path).expect("write CA pem");

    let server_cert = ca.issue(SUBJECT_SERVER).expect("issue server cert");
    let server_cert_path = temp_dir.join("server.pem");
    let server_key_path = temp_dir.join("server.key.pem");
    server_cert
        .write_pem(&server_cert_path, &server_key_path)
        .expect("write server cert");

    let mut agents: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(FLEET as usize);
    for i in 0..FLEET {
        let agent_cert = ca.issue(&format!("agent-{i}")).expect("issue agent cert");
        let cert_path = temp_dir.join(format!("agent-{i}.pem"));
        let key_path = temp_dir.join(format!("agent-{i}.key.pem"));
        agent_cert
            .write_pem(&cert_path, &key_path)
            .expect("write agent cert");
        agents.push((cert_path, key_path));
    }

    // Enrollment file (issue #45). Pre-enroll the FLEET demo agents
    // by deriving the same deterministic seeds the agent binary uses
    // and writing their pubkey fingerprints. Coord rejects any
    // registration not on this list.
    let enrollment_path = temp_dir.join("enrollment.txt");
    let now_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let mut enrollment_text = String::from("# CosaCI demo enrollment file\n");
    for i in 0..FLEET {
        let mut signing_seed = [0_u8; 32];
        let mut vrf_seed = [0_u8; 32];
        signing_seed[..8].copy_from_slice(&i.to_le_bytes());
        vrf_seed[..8].copy_from_slice(&i.to_le_bytes());
        vrf_seed[8] = 0xff;
        let signing_pk = Keypair::from_seed(signing_seed).verifying_key().to_bytes();
        let vrf_pk = VrfKeypair::from_seed(vrf_seed).public_key_bytes();
        enrollment_text.push_str(&format!(
            "{} {} {} {} 1.0\n",
            i,
            fingerprint_hex(&fingerprint(&signing_pk)),
            fingerprint_hex(&fingerprint(&vrf_pk)),
            now_unix_ns
        ));
    }
    fs::write(&enrollment_path, enrollment_text).expect("write enrollment file");

    // Tenants file (issue #46). One demo tenant, capacity 100,
    // refill 10/sec — generous enough that pass 3's two
    // submissions never tip the bucket past empty.
    let tenants_path = temp_dir.join("tenants.txt");
    let demo_tenant_pk = Keypair::from_seed(demo_tenant_seed())
        .verifying_key()
        .to_bytes();
    let demo_tenant_fp_hex = fingerprint_hex(&fingerprint(&demo_tenant_pk));
    let tenants_text = format!(
        "# CosaCI demo tenant registry\n{} {} 100 10 {}\n",
        DEMO_TENANT_ID, demo_tenant_fp_hex, now_unix_ns
    );
    fs::write(&tenants_path, tenants_text).expect("write tenants file");

    Certs {
        temp_dir,
        ca: ca_path,
        server_cert: server_cert_path,
        server_key: server_key_path,
        agents,
        enrollment: enrollment_path,
        tenants: tenants_path,
    }
}

fn forward<R: std::io::Read + Send + 'static>(r: R, label: &str) {
    let reader = BufReader::new(r);
    for line in reader.lines() {
        match line {
            Ok(l) => println!("[{label}] {l}"),
            Err(_) => break,
        }
    }
}
