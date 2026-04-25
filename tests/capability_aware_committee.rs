//! Property-based tests for `cosaci_core::capabilities::select_capability_aware_committee`.
//!
//! Encodes the falsifiable claims of `hypotheses/capability-aware-committee.md`
//! (issue #34, class A). The four properties:
//!
//!   1. Soundness — every selected runner satisfies the requirements.
//!   2. Completeness — when ≥ k match, exactly k are returned.
//!   3. Underprovisioning honesty — when < k match, return None.
//!   4. Filter-then-rank — selection is top-k VRF among matching, not
//!      top-k VRF clamped to matching.

use std::collections::BTreeSet;

use cosaci::capabilities::{
    Candidate, Capabilities, JobRequirements, Platform, Runtime, matches,
    select_capability_aware_committee,
};
use hegel::{TestCase, generators};

// ----------------------------------------------------------------------------
// Draw helpers
// ----------------------------------------------------------------------------

fn draw_platform(tc: &TestCase) -> Platform {
    let i = tc.draw(generators::integers::<usize>().min_value(0).max_value(3));
    match i {
        0 => Platform::LinuxX86_64,
        1 => Platform::LinuxAarch64,
        2 => Platform::DarwinX86_64,
        _ => Platform::DarwinAarch64,
    }
}

fn draw_runtimes(tc: &TestCase) -> BTreeSet<Runtime> {
    let mut s = BTreeSet::new();
    if tc.draw(generators::booleans()) {
        s.insert(Runtime::Wasm);
    }
    if tc.draw(generators::booleans()) {
        s.insert(Runtime::Firecracker);
    }
    if tc.draw(generators::booleans()) {
        s.insert(Runtime::Docker);
    }
    s
}

fn draw_capabilities(tc: &TestCase) -> Capabilities {
    Capabilities {
        cpu: tc.draw(generators::integers::<u32>().min_value(0).max_value(64)),
        memory_mb: tc.draw(generators::integers::<u32>().min_value(0).max_value(65536)),
        platform: draw_platform(tc),
        runtimes: draw_runtimes(tc),
    }
}

fn draw_requirements(tc: &TestCase) -> JobRequirements {
    JobRequirements {
        cpu: tc.draw(generators::integers::<u32>().min_value(0).max_value(64)),
        memory_mb: tc.draw(generators::integers::<u32>().min_value(0).max_value(65536)),
        platform: draw_platform(tc),
        runtimes: draw_runtimes(tc),
    }
}

fn draw_vrf_output(tc: &TestCase) -> [u8; 32] {
    let bytes: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn draw_fleet(tc: &TestCase, max_size: usize) -> Vec<Candidate<u64>> {
    let n = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(max_size),
    );
    (0..n)
        .map(|i| Candidate {
            id: i as u64,
            capabilities: draw_capabilities(tc),
            vrf_output: draw_vrf_output(tc),
        })
        .collect()
}

// ----------------------------------------------------------------------------
// Property 1 — soundness: every selected runner satisfies requirements.
// ----------------------------------------------------------------------------
#[hegel::test]
fn selected_runners_always_satisfy_requirements(tc: TestCase) {
    let fleet = draw_fleet(&tc, 16);
    let req = draw_requirements(&tc);
    let k = tc.draw(generators::integers::<usize>().min_value(1).max_value(16));

    if let Some(committee) = select_capability_aware_committee(&fleet, &req, k) {
        for picked_id in &committee {
            let picked = fleet
                .iter()
                .find(|c| c.id == *picked_id)
                .expect("selected id must be in the fleet");
            assert!(
                matches(&picked.capabilities, &req),
                "runner {} was selected but doesn't match requirements (caps {:?}, req {:?})",
                picked_id,
                picked.capabilities,
                req
            );
        }
    }
}

// ----------------------------------------------------------------------------
// Property 2 — completeness: when ≥ k match, exactly k are returned.
// ----------------------------------------------------------------------------
#[hegel::test]
fn returns_exactly_k_when_enough_match(tc: TestCase) {
    let fleet = draw_fleet(&tc, 16);
    let req = draw_requirements(&tc);
    let k = tc.draw(generators::integers::<usize>().min_value(1).max_value(16));

    let n_matching = fleet
        .iter()
        .filter(|c| matches(&c.capabilities, &req))
        .count();

    let result = select_capability_aware_committee(&fleet, &req, k);
    if n_matching >= k {
        let committee = result.expect("≥ k match → committee should be Some");
        assert_eq!(
            committee.len(),
            k,
            "committee size should be exactly k when ≥ k match"
        );
    } else {
        assert!(
            result.is_none(),
            "< k match → committee should be None, got {result:?}"
        );
    }
}

// ----------------------------------------------------------------------------
// Property 3 — underprovisioning honesty: < k match → None.
// (Subsumed by property 2's else branch but kept as a focused check
// since it's the security-critical half of the contract.)
// ----------------------------------------------------------------------------
#[hegel::test]
fn under_k_matches_returns_none(tc: TestCase) {
    // Synthesize a fleet where we know exactly how many match.
    let n_matching = tc.draw(generators::integers::<usize>().min_value(0).max_value(8));
    let n_nonmatching = tc.draw(generators::integers::<usize>().min_value(0).max_value(8));
    let k = tc.draw(generators::integers::<usize>().min_value(1).max_value(16));

    // A "match-anything" requirement.
    let req = JobRequirements {
        cpu: 0,
        memory_mb: 0,
        platform: Platform::LinuxX86_64,
        runtimes: BTreeSet::new(),
    };

    let mut fleet = Vec::new();
    // Matching runners: LinuxX86_64 (matches the req's platform).
    for i in 0..n_matching {
        fleet.push(Candidate {
            id: i as u64,
            capabilities: Capabilities {
                cpu: 1,
                memory_mb: 256,
                platform: Platform::LinuxX86_64,
                runtimes: BTreeSet::new(),
            },
            vrf_output: draw_vrf_output(&tc),
        });
    }
    // Non-matching: DarwinAarch64 — wrong platform, so matches() = false.
    for i in 0..n_nonmatching {
        fleet.push(Candidate {
            id: (1000 + i) as u64,
            capabilities: Capabilities {
                cpu: 1,
                memory_mb: 256,
                platform: Platform::DarwinAarch64,
                runtimes: BTreeSet::new(),
            },
            vrf_output: draw_vrf_output(&tc),
        });
    }

    let result = select_capability_aware_committee(&fleet, &req, k);
    if n_matching < k {
        assert!(
            result.is_none(),
            "expected None for n_matching={n_matching} < k={k}, got {result:?}"
        );
    } else {
        assert!(
            result.is_some(),
            "expected Some for n_matching={n_matching} >= k={k}, got None"
        );
    }
}

// ----------------------------------------------------------------------------
// Property 4 — filter-then-rank: selection is top-k VRF among matching,
// not top-k VRF of the whole fleet trimmed to matching.
//
// This catches a common bug where a coder ranks first then filters,
// silently dropping a low-VRF non-matching runner that should have been
// excluded entirely (and replaced by a higher-VRF matching runner).
// ----------------------------------------------------------------------------
#[hegel::test]
fn filter_then_rank_not_rank_then_filter(tc: TestCase) {
    let fleet = draw_fleet(&tc, 16);
    let req = draw_requirements(&tc);
    let k = tc.draw(generators::integers::<usize>().min_value(1).max_value(16));

    if let Some(committee) = select_capability_aware_committee(&fleet, &req, k) {
        let matching: Vec<&Candidate<u64>> = fleet
            .iter()
            .filter(|c| matches(&c.capabilities, &req))
            .collect();
        let mut by_vrf = matching.clone();
        by_vrf.sort_by(|a, b| a.vrf_output.cmp(&b.vrf_output));
        let expected_top_k: Vec<u64> = by_vrf.into_iter().take(k).map(|c| c.id).collect();

        assert_eq!(
            committee, expected_top_k,
            "committee should be top-k VRF *among matching*, not rank-then-filter"
        );
    }
}
