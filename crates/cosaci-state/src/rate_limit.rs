//! Per-tenant token-bucket rate limiter.
//!
//! Source: new card (public-scale infra); `hypotheses/tenant-rate-limit.md`
//! (class A). Uses the `cosaci::clock::Clock` trait for time injection —
//! no `std::time` inside the module, so the whole subsystem is
//! deterministic-simulation friendly.
//!
//! v0.1 uses a classic per-tenant token bucket: capacity `C`, refill rate
//! `r` tokens/sec. Distributed rate limiting (across coordinator shards) is
//! a separate future concern and would be its own card.

use std::collections::HashMap;

use cosaci_core::clock::Clock;

pub type TenantId = u64;

/// Per-tenant bucket. Not exposed; `RateLimiter` is the public surface.
#[derive(Clone, Copy, Debug)]
struct TokenBucket {
    capacity: u64,
    refill_per_sec: u64,
    tokens: u64,
    last_refill_ns: u64,
}

impl TokenBucket {
    fn new(capacity: u64, refill_per_sec: u64, now_ns: u64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            tokens: capacity,
            last_refill_ns: now_ns,
        }
    }

    /// Bring the bucket's token count up to date with `now_ns`. Capped at
    /// capacity.
    fn refill(&mut self, now_ns: u64) {
        let elapsed_ns = now_ns.saturating_sub(self.last_refill_ns);
        // u128 intermediate to avoid overflow on large elapsed * rate.
        let new_tokens =
            (u128::from(elapsed_ns) * u128::from(self.refill_per_sec) / 1_000_000_000_u128) as u64;
        self.tokens = self.tokens.saturating_add(new_tokens).min(self.capacity);
        self.last_refill_ns = now_ns;
    }

    /// Try to consume `cost` tokens. Returns true on success (and deducts),
    /// false if insufficient tokens (no-op on balance).
    fn try_consume(&mut self, cost: u64, now_ns: u64) -> bool {
        self.refill(now_ns);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Per-tenant rate limiter.
pub struct RateLimiter<C: Clock> {
    clock: C,
    buckets: HashMap<TenantId, TokenBucket>,
    default_capacity: u64,
    default_refill_per_sec: u64,
}

impl<C: Clock> RateLimiter<C> {
    #[must_use]
    pub fn new(clock: C, capacity: u64, refill_per_sec: u64) -> Self {
        Self {
            clock,
            buckets: HashMap::new(),
            default_capacity: capacity,
            default_refill_per_sec: refill_per_sec,
        }
    }

    /// Attempt to admit a request of `cost` tokens for `tenant`. Returns
    /// true iff the bucket had sufficient tokens after refill.
    pub fn accept(&mut self, tenant: TenantId, cost: u64) -> bool {
        let now = self.clock.now_ns();
        let (cap, refill) = (self.default_capacity, self.default_refill_per_sec);
        let bucket = self
            .buckets
            .entry(tenant)
            .or_insert_with(|| TokenBucket::new(cap, refill, now));
        bucket.try_consume(cost, now)
    }

    /// Current token balance for `tenant` (after refill). A never-seen
    /// tenant returns `default_capacity` (its bucket would be fresh).
    pub fn tokens_of(&mut self, tenant: TenantId) -> u64 {
        let now = self.clock.now_ns();
        match self.buckets.get_mut(&tenant) {
            Some(b) => {
                b.refill(now);
                b.tokens
            }
            None => self.default_capacity,
        }
    }

    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.default_capacity
    }
}
