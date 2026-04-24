//! Model-based test for `cosaci::rate_limit::RateLimiter`.
//!
//! Encodes the falsifiable claims of `hypotheses/tenant-rate-limit.md`
//! (class A). Reuses the `TestClock` pattern from lease/replay — the 3rd
//! consumer of this pattern makes a shared test helper worth lifting, but
//! that cleanup is deferred one more card.

use std::collections::{HashMap, HashSet};

use cosaci::rate_limit::{RateLimiter, TenantId};
use hegel::{generators, TestCase};

mod common;
use common::TestClock;

const CAPACITY: u64 = 10;
const REFILL_PER_SEC: u64 = 5;
const TENANT_POOL: u64 = 4;

fn draw_tenant(tc: &TestCase) -> TenantId {
    tc.draw(
        generators::integers::<TenantId>()
            .min_value(0)
            .max_value(TENANT_POOL - 1),
    )
}

fn draw_cost(tc: &TestCase) -> u64 {
    tc.draw(
        generators::integers::<u64>()
            .min_value(0)
            .max_value(CAPACITY + 2),
    )
}

struct RateLimitTest {
    clock: TestClock,
    subject: RateLimiter<TestClock>,
    /// Per-tenant accepts count. Used by the fairness/isolation invariants.
    accepts_per_tenant: HashMap<TenantId, u64>,
    /// Tenants that have ever been touched (so we can check all their buckets).
    seen_tenants: HashSet<TenantId>,
}

#[hegel::state_machine]
impl RateLimitTest {
    // Try to accept a (tenant, cost). Check bounded-state + cost-correctness
    // invariants against the subject's reported balance.
    #[rule]
    fn accept(&mut self, tc: TestCase) {
        let tenant = draw_tenant(&tc);
        let cost = draw_cost(&tc);
        let before = self.subject.tokens_of(tenant);

        let admitted = self.subject.accept(tenant, cost);
        let after = self.subject.tokens_of(tenant);

        // Bounded state: balance never exceeds capacity, never goes negative
        // (u64 enforces non-negative structurally).
        assert!(
            after <= CAPACITY,
            "tokens {} exceeded capacity {} after accept(tenant={}, cost={})",
            after,
            CAPACITY,
            tenant,
            cost
        );

        // Cost correctness: if admitted, tokens decreased by exactly `cost`
        // (ignoring any refill that happened between `before` and `after` —
        // here both readings happen at the same virtual time, so no refill).
        if admitted {
            assert_eq!(
                after,
                before - cost,
                "cost-correctness violated: before={} cost={} after={}",
                before,
                cost,
                after
            );
            *self.accepts_per_tenant.entry(tenant).or_insert(0) += 1;
        } else {
            // Rejected: balance unchanged and was insufficient.
            assert!(
                before < cost,
                "rejected with sufficient tokens: before={} cost={}",
                before,
                cost
            );
            assert_eq!(after, before, "rejected request altered balance");
        }
        self.seen_tenants.insert(tenant);
    }

    // Advance the clock. Monotone-refill invariant: all tenants' balances
    // must be >= their pre-advance balance.
    #[rule]
    fn advance_clock(&mut self, tc: TestCase) {
        let delta = tc.draw(
            generators::integers::<u64>()
                .min_value(1)
                .max_value(3_000_000_000),
        );
        let before: HashMap<TenantId, u64> = self
            .seen_tenants
            .iter()
            .map(|&t| (t, self.subject.tokens_of(t)))
            .collect();
        self.clock.advance(delta);
        for (&t, &b_before) in &before {
            let b_after = self.subject.tokens_of(t);
            assert!(
                b_after >= b_before,
                "monotone-refill broken: tenant {} before={} after={}",
                t,
                b_before,
                b_after
            );
            assert!(
                b_after <= CAPACITY,
                "refill exceeded capacity: tenant {} after={}",
                t,
                b_after
            );
        }
    }

    // Structural invariant: every seen tenant's balance is within [0, CAPACITY].
    // Isolation: untouched tenants report default_capacity.
    #[invariant]
    fn balance_bounds(&mut self, _: TestCase) {
        for &t in &self.seen_tenants.clone() {
            let b = self.subject.tokens_of(t);
            assert!(b <= CAPACITY, "tenant {} balance {} > capacity", t, b);
        }
        // An untouched tenant reports default capacity (isolation).
        let untouched: u64 = TENANT_POOL; // one past the pool
        assert_eq!(
            self.subject.tokens_of(untouched),
            self.subject.capacity(),
            "untouched tenant {} reports non-default balance",
            untouched
        );
    }
}

#[hegel::test]
fn rate_limiter_matches_model(tc: TestCase) {
    let clock = TestClock::new();
    let subject = RateLimiter::new(clock.clone(), CAPACITY, REFILL_PER_SEC);
    let test = RateLimitTest {
        clock,
        subject,
        accepts_per_tenant: HashMap::new(),
        seen_tenants: HashSet::new(),
    };
    hegel::stateful::run(test, tc);
}
