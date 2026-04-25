//! Append-only job journal for crash recovery (issue #51).
//!
//! Source: `SPEC.md` §10.5 / `hypotheses/crash-recovery-soundness.md`
//! (class A). Every externally-visible job-state transition gets one
//! line in the journal; on restart, the coordinator replays the
//! journal to reconstruct in-flight state.
//!
//! # File format
//!
//! Newline-delimited JSON. One [`JournalEntry`] per line. Lines are
//! `\n`-terminated; an unterminated trailing line is treated as a
//! crash mid-write and skipped on replay. fsync after every record
//! before the writer returns `Ok`.
//!
//! ```text
//! {"v":1,"k":"JobSubmitted","job_id":42}
//! {"v":1,"k":"CommitteeSelected","job_id":42,"committee":[2,4,5]}
//! {"v":1,"k":"AttestationReceived","job_id":42,"runner_id":2}
//! {"v":1,"k":"Aggregated","job_id":42,"outcome":"Pass","artifact":"…"}
//! {"v":1,"k":"Anchored","job_id":42,"position":137}
//! ```
//!
//! # Replay semantics
//!
//! - Jobs in `Submitted` or `CommitteeSelected` at the crash point
//!   are re-run from scratch (the work they did before the crash
//!   is discarded; the committee selection happens fresh because
//!   the VRF round is fast and the runners may have changed).
//! - Jobs in `Aggregated` but not `Anchored` are re-anchored on
//!   recovery. Re-anchor is idempotent at the Merkle-log level
//!   (issue #33's `merkle-log-persistence` covers that property).
//! - Jobs in `Anchored` are complete; replay only needs to know
//!   they're done.
//!
//! The pure-function shape: `reconstruct_state(&[entries]) ->
//! JournalState` returns a snapshot of (in-flight, anchored,
//! highest-anchor-position) deterministically.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Outcome of a job's quorum aggregation. Mirrors
/// `cosaci_core::quorum::Outcome` but is local to the journal so
/// the `cosaci-state` crate doesn't acquire a wire-shape dependency
/// on `cosaci-core::quorum::Outcome`'s serde derives (which it
/// doesn't have today).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalOutcome {
    /// Quorum agreed Pass.
    Pass,
    /// Quorum agreed Fail.
    Fail,
    /// Quorum couldn't reach a definitive outcome; needs review.
    Escalate,
    /// Job should be retried from scratch.
    Retry,
}

/// One state transition in a job's lifecycle. Tagged on the wire
/// via serde's external tag (`{"k":"JobSubmitted",...}`) so the
/// format is human-readable and forward-compatible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "k")]
pub enum JournalEntry {
    /// Operator (or webhook) submitted a job. The earliest event for
    /// a given `job_id`.
    JobSubmitted {
        /// Job identifier.
        job_id: u64,
    },
    /// VRF round picked the committee.
    CommitteeSelected {
        /// Job identifier.
        job_id: u64,
        /// Runner IDs in the committee, in selection order.
        committee: Vec<u64>,
    },
    /// One committee member returned a (signature-valid) attestation.
    /// The attestation bytes are NOT in the journal — they live
    /// on the runner's stream / in the per-job records map; the
    /// journal records only that one was received.
    AttestationReceived {
        /// Job identifier.
        job_id: u64,
        /// Runner who submitted.
        runner_id: u64,
    },
    /// Quorum aggregator produced a definitive outcome.
    Aggregated {
        /// Job identifier.
        job_id: u64,
        /// Outcome reached.
        outcome: JournalOutcome,
        /// Consensus artifact hash, lowercase hex.
        artifact_hex: String,
    },
    /// Consensus artifact appended to the Merkle log.
    Anchored {
        /// Job identifier.
        job_id: u64,
        /// 0-indexed log position.
        position: u64,
    },
}

/// Per-job state derived from the journal up to some replay point.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobState {
    /// Submitted but no committee yet — re-run from scratch.
    Submitted,
    /// Committee picked; some attestations may have been received
    /// but not yet aggregated. Re-run from scratch.
    InFlight,
    /// Aggregated but not anchored — re-anchor on recovery.
    AggregatedNotAnchored {
        /// Outcome the aggregator reached.
        outcome: JournalOutcome,
        /// Hex-encoded consensus artifact (per `Aggregated.artifact_hex`).
        artifact_hex: String,
    },
    /// Fully anchored. Done.
    Anchored {
        /// Log position the artifact was anchored at.
        position: u64,
    },
}

/// Snapshot of journal-derived state.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct JournalState {
    /// Job → its current state. A job stops appearing here once the
    /// caller decides to stop tracking it, but the journal keeps
    /// its history forever (until checkpoint-truncation, a
    /// follow-on).
    pub jobs: HashMap<u64, JobState>,
}

impl JournalState {
    /// Empty state. Equivalent to `JournalState::default()`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set of job_ids that need to be re-anchored on coordinator
    /// startup. Order is unspecified.
    #[must_use]
    pub fn pending_re_anchor(&self) -> Vec<u64> {
        self.jobs
            .iter()
            .filter_map(|(id, st)| match st {
                JobState::AggregatedNotAnchored { .. } => Some(*id),
                _ => None,
            })
            .collect()
    }

    /// Set of job_ids that need to be re-run from scratch.
    #[must_use]
    pub fn pending_re_run(&self) -> Vec<u64> {
        self.jobs
            .iter()
            .filter_map(|(id, st)| match st {
                JobState::Submitted | JobState::InFlight => Some(*id),
                _ => None,
            })
            .collect()
    }

    /// Set of fully-anchored job_ids. Used to reject double-anchor
    /// attempts post-recovery.
    #[must_use]
    pub fn anchored_jobs(&self) -> HashSet<u64> {
        self.jobs
            .iter()
            .filter_map(|(id, st)| match st {
                JobState::Anchored { .. } => Some(*id),
                _ => None,
            })
            .collect()
    }
}

/// Reconstruct journal state from a sequence of entries. Pure: no
/// I/O, no clock; same input always produces the same output.
///
/// Entries are processed in order. State transitions follow the
/// normal lifecycle (Submitted → InFlight → AggregatedNotAnchored →
/// Anchored); out-of-order entries (e.g. `Anchored` for a job that
/// never appeared as `Submitted`) are still applied, since the
/// journal is append-only and trusted.
#[must_use]
pub fn reconstruct_state(entries: &[JournalEntry]) -> JournalState {
    let mut state = JournalState::new();
    for entry in entries {
        match entry {
            JournalEntry::JobSubmitted { job_id } => {
                state.jobs.insert(*job_id, JobState::Submitted);
            }
            JournalEntry::CommitteeSelected { job_id, .. } => {
                state.jobs.insert(*job_id, JobState::InFlight);
            }
            JournalEntry::AttestationReceived { job_id, .. } => {
                // Stays in InFlight — receiving an attestation
                // doesn't move the public state forward; only
                // Aggregated does.
                state.jobs.entry(*job_id).or_insert(JobState::InFlight);
            }
            JournalEntry::Aggregated {
                job_id,
                outcome,
                artifact_hex,
            } => {
                state.jobs.insert(
                    *job_id,
                    JobState::AggregatedNotAnchored {
                        outcome: *outcome,
                        artifact_hex: artifact_hex.clone(),
                    },
                );
            }
            JournalEntry::Anchored { job_id, position } => {
                state.jobs.insert(
                    *job_id,
                    JobState::Anchored {
                        position: *position,
                    },
                );
            }
        }
    }
    state
}

/// Append-only journal writer. fsync per record; survives `kill -9`
/// up to the last fully-flushed line.
pub struct Journal {
    path: PathBuf,
    file: File,
}

impl Journal {
    /// Open or create the journal at `path`. Pre-existing content
    /// is preserved; new entries append to the end.
    ///
    /// # Errors
    ///
    /// I/O error from `OpenOptions::open`.
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        Ok(Self { path, file })
    }

    /// Append one entry. Returns when the entry is durable on disk.
    ///
    /// # Errors
    ///
    /// I/O errors from serialize, write, or fsync.
    pub fn append(&mut self, entry: &JournalEntry) -> std::io::Result<()> {
        let mut bytes = serde_json::to_vec(entry).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        self.file.write_all(&bytes)?;
        self.file.sync_data()?;
        Ok(())
    }

    /// Path the journal is bound to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Replay a journal file, returning every entry in append order.
/// Lines that fail to parse (e.g. a final unterminated line from a
/// crashed write) are skipped silently — that's the recover-from-
/// `kill -9` semantics.
///
/// # Errors
///
/// I/O error opening the file. A non-existent path is treated as
/// "no journal yet" and yields an empty vector.
pub fn replay<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<JournalEntry>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Best-effort parse: a torn final write produces a
        // truncated JSON line which we skip.
        if let Ok(entry) = serde_json::from_str::<JournalEntry>(trimmed) {
            entries.push(entry);
        }
    }
    Ok(entries)
}
