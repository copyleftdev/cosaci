//! Networked demo runner — generates a temp CA + per-process certs at
//! startup, then spawns `coordinator` and N `agent` subprocesses with
//! their cert paths. Pipes their stdout/stderr to this process.
//!
//! Pre-build: `cargo build --bin coordinator --bin agent`.
//! Run: `cargo run --bin demo_networked`.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use cosaci_protocol::tls::{SUBJECT_SERVER, TestCa, install_crypto_provider};

const ADDR: &str = "127.0.0.1:7879";
const FLEET: u64 = 5;
const COMMITTEE: usize = 3;

fn main() {
    install_crypto_provider();

    println!("═══════════════════════════════════════════════════════════");
    println!(" CosaCI networked demo — coordinator + {FLEET} agents (mTLS)");
    println!("═══════════════════════════════════════════════════════════\n");

    // ── Generate a temp CA + certs in /tmp/cosaci-demo-<pid> ────────────
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

    let mut agent_paths: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(FLEET as usize);
    for i in 0..FLEET {
        let agent_cert = ca.issue(&format!("agent-{i}")).expect("issue agent cert");
        let cert_path = temp_dir.join(format!("agent-{i}.pem"));
        let key_path = temp_dir.join(format!("agent-{i}.key.pem"));
        agent_cert
            .write_pem(&cert_path, &key_path)
            .expect("write agent cert");
        agent_paths.push((cert_path, key_path));
    }

    println!("[launcher] CA + certs in {}\n", temp_dir.display());

    // Locate the binaries.
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

    // ── Spawn coordinator ───────────────────────────────────────────────
    let mut coord = Command::new(&coord_bin)
        .args([
            "--addr",
            ADDR,
            "--ca",
            ca_path.to_str().unwrap(),
            "--cert",
            server_cert_path.to_str().unwrap(),
            "--key",
            server_key_path.to_str().unwrap(),
            "--fleet",
            &FLEET.to_string(),
            "--committee",
            &COMMITTEE.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn coordinator");

    let coord_stdout = coord.stdout.take().expect("stdout");
    let coord_stderr = coord.stderr.take().expect("stderr");
    let t_coord_out = thread::spawn(move || forward(coord_stdout, "coord"));
    let t_coord_err = thread::spawn(move || forward(coord_stderr, "coord!"));

    // Brief settle so the coordinator has bind()'d.
    thread::sleep(Duration::from_millis(250));

    // ── Spawn agents ────────────────────────────────────────────────────
    let mut agents: Vec<std::process::Child> = Vec::with_capacity(FLEET as usize);
    let mut agent_threads: Vec<thread::JoinHandle<()>> = Vec::new();
    for (id, (cert_path, key_path)) in agent_paths.iter().enumerate() {
        let mut child = Command::new(&agent_bin)
            .args([
                "--id",
                &id.to_string(),
                "--addr",
                ADDR,
                "--ca",
                ca_path.to_str().unwrap(),
                "--cert",
                cert_path.to_str().unwrap(),
                "--key",
                key_path.to_str().unwrap(),
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

    // Wait for everyone.
    let coord_status = coord.wait().expect("coordinator wait");
    let _ = t_coord_out.join();
    let _ = t_coord_err.join();
    for mut a in agents {
        let _ = a.wait();
    }
    for t in agent_threads {
        let _ = t.join();
    }

    println!("\n═══════════════════════════════════════════════════════════");
    println!(
        " Done. Coordinator exit: {}.",
        coord_status
            .code()
            .map_or_else(|| "signal".to_string(), |c| c.to_string())
    );
    println!("═══════════════════════════════════════════════════════════");

    // Clean up the temp dir.
    let _ = std::fs::remove_dir_all(&temp_dir);
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
