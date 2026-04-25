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

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use cosaci_protocol::tls::{SUBJECT_SERVER, TestCa, install_crypto_provider};

const ADDR_BOUNDED: &str = "127.0.0.1:7879";
const ADDR_SIGTERM: &str = "127.0.0.1:7880";
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
}

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
        RoundKind::Bounded,
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

    println!("\n═══════════════════════════════════════════════════════════");
    println!(" Done. Both rounds completed cleanly.");
    println!("═══════════════════════════════════════════════════════════");

    let _ = std::fs::remove_dir_all(&certs.temp_dir);
}

#[derive(Clone, Copy)]
enum RoundKind {
    Bounded,
    Sigterm,
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
    ];
    if matches!(kind, RoundKind::Bounded) {
        coord_args.push("--max-jobs".into());
        coord_args.push(MAX_JOBS_BOUNDED.to_string());
    }

    let mut coord = Command::new(coord_bin)
        .args(&coord_args)
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

    let coord_status = coord.wait().expect("coordinator wait");
    let _ = t_out.join();
    let _ = t_err.join();
    for mut a in agents {
        let _ = a.wait();
    }
    for t in agent_threads {
        let _ = t.join();
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

    Certs {
        temp_dir,
        ca: ca_path,
        server_cert: server_cert_path,
        server_key: server_key_path,
        agents,
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
