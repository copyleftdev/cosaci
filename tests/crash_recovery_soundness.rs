//! Property tests for `cosaci-state::journal`.
//!
//! Encodes the falsifiable claims of
//! `hypotheses/crash-recovery-soundness.md` (issue #51, class A).

use std::fmt::Write as _;
use std::fs;

use cosaci::journal::{JobState, Journal, JournalEntry, JournalOutcome, reconstruct_state, replay};
use hegel::{TestCase, generators};
use tempfile::tempdir;

// ────────────────────────────────────────────────────────────────────────
// Hegel generators
// ────────────────────────────────────────────────────────────────────────

fn draw_outcome(tc: &TestCase) -> JournalOutcome {
    let i = tc.draw(generators::integers::<u8>().min_value(0).max_value(3));
    match i {
        0 => JournalOutcome::Pass,
        1 => JournalOutcome::Fail,
        2 => JournalOutcome::Escalate,
        _ => JournalOutcome::Retry,
    }
}

fn draw_artifact(tc: &TestCase) -> String {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut s = String::with_capacity(64);
    for b in v {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

/// Draw a lifecycle for a single job_id: Submitted → CommitteeSelected →
/// (some attestations) → Aggregated → Anchored. The Hegel-drawn
/// integer determines how far the lifecycle progresses (mid-flight
/// vs full completion).
fn draw_lifecycle(tc: &TestCase, job_id: u64) -> Vec<JournalEntry> {
    let progress = tc.draw(generators::integers::<u8>().min_value(0).max_value(4));
    let mut entries = vec![JournalEntry::JobSubmitted { job_id }];
    if progress >= 1 {
        let k = tc.draw(generators::integers::<usize>().min_value(1).max_value(5));
        let committee: Vec<u64> = (0..k as u64).collect();
        entries.push(JournalEntry::CommitteeSelected { job_id, committee });
    }
    if progress >= 2 {
        let n = tc.draw(generators::integers::<usize>().min_value(0).max_value(3));
        for runner_id in 0..n as u64 {
            entries.push(JournalEntry::AttestationReceived { job_id, runner_id });
        }
    }
    if progress >= 3 {
        entries.push(JournalEntry::Aggregated {
            job_id,
            outcome: draw_outcome(tc),
            artifact_hex: draw_artifact(tc),
        });
    }
    if progress >= 4 {
        let position = tc.draw(generators::integers::<u64>().min_value(0).max_value(1000));
        entries.push(JournalEntry::Anchored { job_id, position });
    }
    entries
}

fn draw_entries(tc: &TestCase) -> Vec<JournalEntry> {
    let n_jobs = tc.draw(generators::integers::<u64>().min_value(1).max_value(8));
    let mut all = Vec::new();
    for job_id in 1..=n_jobs {
        all.extend(draw_lifecycle(tc, job_id));
    }
    all
}

// ────────────────────────────────────────────────────────────────────────
// Property 1 — replay round-trips appended entries.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn replay_round_trips_appended_entries(tc: TestCase) {
    let entries = draw_entries(&tc);
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("journal.ndjson");

    {
        let mut j = Journal::open(&path).expect("open");
        for e in &entries {
            j.append(e).expect("append");
        }
    } // drop = simulated process exit (fsync already happened per record)

    let replayed = replay(&path).expect("replay");
    assert_eq!(
        replayed, entries,
        "replay must return appended entries in order"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 2 — pure reconstruction agrees with disk replay.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn pure_reconstruct_matches_disk_replay(tc: TestCase) {
    let entries = draw_entries(&tc);
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("journal.ndjson");

    let mut j = Journal::open(&path).expect("open");
    for e in &entries {
        j.append(e).expect("append");
    }
    drop(j);

    let from_disk = replay(&path).expect("replay");
    let pure = reconstruct_state(&entries);
    let from_disk_state = reconstruct_state(&from_disk);
    assert_eq!(pure, from_disk_state);
}

// ────────────────────────────────────────────────────────────────────────
// Property 3 — lifecycle progression is monotone.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn submitted_to_inflight_to_aggregated_to_anchored(tc: TestCase) {
    let job_id: u64 = tc.draw(generators::integers::<u64>().min_value(1));
    let entries = [
        JournalEntry::JobSubmitted { job_id },
        JournalEntry::CommitteeSelected {
            job_id,
            committee: vec![0, 1, 2],
        },
        JournalEntry::AttestationReceived {
            job_id,
            runner_id: 0,
        },
        JournalEntry::Aggregated {
            job_id,
            outcome: JournalOutcome::Pass,
            artifact_hex: draw_artifact(&tc),
        },
        JournalEntry::Anchored {
            job_id,
            position: 42,
        },
    ];
    // Walk the prefix; assert the state is correct at each point.
    for k in 1..=entries.len() {
        let state = reconstruct_state(&entries[..k]);
        let job_state = state.jobs.get(&job_id).expect("present");
        match k {
            1 => assert!(matches!(job_state, JobState::Submitted)),
            2 | 3 => assert!(matches!(job_state, JobState::InFlight)),
            4 => assert!(matches!(job_state, JobState::AggregatedNotAnchored { .. })),
            5 => assert!(matches!(job_state, JobState::Anchored { position: 42 })),
            _ => unreachable!(),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Property 4 — pending_re_run contains submitted+inflight.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn pending_re_run_contains_submitted_and_inflight(tc: TestCase) {
    let id_a: u64 = tc.draw(generators::integers::<u64>().min_value(1).max_value(100));
    let id_b: u64 = id_a + 1;
    let id_c: u64 = id_a + 2;
    let entries = vec![
        JournalEntry::JobSubmitted { job_id: id_a }, // Submitted
        JournalEntry::JobSubmitted { job_id: id_b },
        JournalEntry::CommitteeSelected {
            job_id: id_b,
            committee: vec![0, 1, 2],
        }, // InFlight
        JournalEntry::JobSubmitted { job_id: id_c },
        JournalEntry::CommitteeSelected {
            job_id: id_c,
            committee: vec![0, 1, 2],
        },
        JournalEntry::Aggregated {
            job_id: id_c,
            outcome: JournalOutcome::Pass,
            artifact_hex: draw_artifact(&tc),
        },
        JournalEntry::Anchored {
            job_id: id_c,
            position: 0,
        }, // Anchored
    ];
    let state = reconstruct_state(&entries);
    let pending: std::collections::HashSet<u64> = state.pending_re_run().into_iter().collect();
    assert!(
        pending.contains(&id_a),
        "id_a (Submitted) must be pending re-run"
    );
    assert!(
        pending.contains(&id_b),
        "id_b (InFlight) must be pending re-run"
    );
    assert!(
        !pending.contains(&id_c),
        "id_c (Anchored) must NOT be in re-run"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 5 — pending_re_anchor contains aggregated-not-anchored.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn pending_re_anchor_contains_aggregated_not_anchored(tc: TestCase) {
    let id_pending: u64 = tc.draw(generators::integers::<u64>().min_value(1).max_value(100));
    let id_anchored: u64 = id_pending + 1;
    let entries = vec![
        JournalEntry::JobSubmitted { job_id: id_pending },
        JournalEntry::CommitteeSelected {
            job_id: id_pending,
            committee: vec![0, 1, 2],
        },
        JournalEntry::Aggregated {
            job_id: id_pending,
            outcome: JournalOutcome::Pass,
            artifact_hex: draw_artifact(&tc),
        }, // AggregatedNotAnchored
        JournalEntry::JobSubmitted {
            job_id: id_anchored,
        },
        JournalEntry::CommitteeSelected {
            job_id: id_anchored,
            committee: vec![0, 1, 2],
        },
        JournalEntry::Aggregated {
            job_id: id_anchored,
            outcome: JournalOutcome::Pass,
            artifact_hex: draw_artifact(&tc),
        },
        JournalEntry::Anchored {
            job_id: id_anchored,
            position: 7,
        }, // Anchored
    ];
    let state = reconstruct_state(&entries);
    let pending: std::collections::HashSet<u64> = state.pending_re_anchor().into_iter().collect();
    assert!(pending.contains(&id_pending));
    assert!(!pending.contains(&id_anchored));
}

// ────────────────────────────────────────────────────────────────────────
// Property 6 — anchored_jobs contains anchored.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn anchored_jobs_contains_anchored(tc: TestCase) {
    let entries = draw_entries(&tc);
    let state = reconstruct_state(&entries);
    let anchored = state.anchored_jobs();
    // Every key with state Anchored should be in the set.
    for (id, st) in &state.jobs {
        if matches!(st, JobState::Anchored { .. }) {
            assert!(anchored.contains(id), "job {id} should be in anchored_jobs");
        } else {
            assert!(
                !anchored.contains(id),
                "job {id} (state {st:?}) should NOT be in anchored_jobs"
            );
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Property 7 — torn final write is skipped.
// ────────────────────────────────────────────────────────────────────────
#[test]
fn torn_final_write_is_skipped() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("torn.ndjson");

    // Write two valid lines, then a torn (truncated) third line.
    let entries = vec![
        JournalEntry::JobSubmitted { job_id: 1 },
        JournalEntry::JobSubmitted { job_id: 2 },
    ];
    {
        let mut j = Journal::open(&path).expect("open");
        for e in &entries {
            j.append(e).expect("append");
        }
    }
    // Append a truncated JSON object (no closing brace, no newline).
    {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("reopen");
        f.write_all(br#"{"k":"JobSubmitted","job_id":3"#)
            .expect("torn write");
    }

    let replayed = replay(&path).expect("replay");
    assert_eq!(
        replayed, entries,
        "torn final line must be skipped; valid prefix preserved"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Smoke — full lifecycle through journal.
// ────────────────────────────────────────────────────────────────────────
#[test]
fn smoke_full_lifecycle_through_journal() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("smoke.ndjson");

    {
        let mut j = Journal::open(&path).expect("open");
        j.append(&JournalEntry::JobSubmitted { job_id: 42 })
            .unwrap();
        j.append(&JournalEntry::CommitteeSelected {
            job_id: 42,
            committee: vec![1, 3, 5],
        })
        .unwrap();
        j.append(&JournalEntry::AttestationReceived {
            job_id: 42,
            runner_id: 1,
        })
        .unwrap();
        j.append(&JournalEntry::AttestationReceived {
            job_id: 42,
            runner_id: 3,
        })
        .unwrap();
        j.append(&JournalEntry::Aggregated {
            job_id: 42,
            outcome: JournalOutcome::Pass,
            artifact_hex: "ab".repeat(32),
        })
        .unwrap();
        j.append(&JournalEntry::Anchored {
            job_id: 42,
            position: 137,
        })
        .unwrap();
    }

    let entries = replay(&path).expect("replay");
    assert_eq!(entries.len(), 6);
    let state = reconstruct_state(&entries);
    let job = state.jobs.get(&42).expect("present");
    assert!(matches!(job, JobState::Anchored { position: 137 }));
    assert!(state.anchored_jobs().contains(&42));
    assert!(state.pending_re_anchor().is_empty());
    assert!(state.pending_re_run().is_empty());
}
