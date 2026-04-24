//! Networked demo runner — spawns `coordinator` and N `agent`
//! subprocesses, pipes their stdout into this process, and waits for
//! everyone to finish.
//!
//! Pre-build both binaries: `cargo build --bin coordinator --bin agent`.
//! Then run `cargo run --bin demo_networked`.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

const ADDR: &str = "127.0.0.1:7879";
const FLEET: u64 = 5;
const COMMITTEE: usize = 3;

fn main() {
    println!("═══════════════════════════════════════════════════════════");
    println!(" CosaCI networked demo — coordinator + {FLEET} agents");
    println!("═══════════════════════════════════════════════════════════\n");

    // Look for the binaries next to this one.
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

    // Spawn coordinator first.
    let mut coord = Command::new(&coord_bin)
        .args([
            "--addr",
            ADDR,
            "--fleet",
            &FLEET.to_string(),
            "--committee",
            &COMMITTEE.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn coordinator");

    // Forward coordinator's output to our stdout.
    let coord_stdout = coord.stdout.take().expect("stdout");
    let coord_stderr = coord.stderr.take().expect("stderr");
    let t_coord_out = thread::spawn(move || forward(coord_stdout, "coord"));
    let t_coord_err = thread::spawn(move || forward(coord_stderr, "coord!"));

    // Give the coordinator a moment to bind. Probing with TcpStream::connect
    // would count as an accept and eat one of the fleet slots, so we just
    // sleep a bit. 250ms is plenty for bind() on localhost.
    thread::sleep(Duration::from_millis(250));

    // Spawn agents.
    let mut agents: Vec<std::process::Child> = Vec::with_capacity(FLEET as usize);
    let mut agent_threads: Vec<thread::JoinHandle<()>> = Vec::new();
    for id in 0..FLEET {
        let mut child = Command::new(&agent_bin)
            .args([
                "--id",
                &id.to_string(),
                "--addr",
                ADDR,
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

    // Wait for coordinator to finish.
    let coord_status = coord.wait().expect("coordinator wait");
    let _ = t_coord_out.join();
    let _ = t_coord_err.join();

    // Wait for agents.
    for mut a in agents {
        let _ = a.wait();
    }
    for t in agent_threads {
        let _ = t.join();
    }

    println!("\n═══════════════════════════════════════════════════════════");
    println!(
        " Done. Coordinator exit: {}.",
        coord_status.code().map_or_else(|| "signal".to_string(), |c| c.to_string())
    );
    println!("═══════════════════════════════════════════════════════════");
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

