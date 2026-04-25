//! Network egress policy primitives (issue #54).
//!
//! Source: `SPEC.md` §6.4 / `hypotheses/egress-policy-evaluation.md`
//! (class A — pure policy evaluation; the netns enforcement half is
//! class C, gated, lands in a follow-on PR).
//!
//! A pipeline step that needs network egress (`cargo fetch`,
//! `npm install`, `pip download`) declares a `NetworkPolicy`
//! describing which targets the runner is permitted to contact.
//! The runner's enforcement layer consults this policy on each
//! outbound connection; non-matching attempts are refused with
//! `ECONNREFUSED` (or, under [`EgressDefault::Audit`], allowed but
//! recorded in `StepOutput::network_violations`).
//!
//! This module ships only the **pure evaluation** half: given a
//! policy and a target, what's the decision? The actual netns
//! interception is class C and lands separately, gated on
//! `HEGEL_LINUX_HARNESS=1`.

use serde::{Deserialize, Serialize};

/// Per-step network egress policy. The default is "deny everything"
/// — a step that doesn't explicitly opt into egress gets none.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Allowlisted egress targets. A target matches if any entry
    /// here matches; iteration order doesn't affect the decision.
    pub allow: Vec<EgressTarget>,
    /// What to do when no allowlist entry matches.
    pub default: EgressDefault,
}

/// What happens to an outbound connection that didn't match any
/// allowlist entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressDefault {
    /// Refuse the connection with `ECONNREFUSED`. Default.
    #[default]
    Deny,
    /// Allow the connection but record the attempt in
    /// `StepOutput::network_violations`. Operators use this during
    /// migration to discover what the step actually needs before
    /// switching to `Deny`.
    Audit,
}

/// One allowlist entry. Match semantics:
///
/// - [`Host`](Self::Host) matches a hostname-port-scheme triple
///   exactly. Wildcards are NOT supported in v0.3 — use multiple
///   entries.
/// - [`Cidr`](Self::Cidr) matches an IP within the CIDR range and
///   a port within the closed `[start, end]` range. The CIDR is
///   stored as a string (e.g. `"10.0.0.0/8"`) and parsed at
///   evaluation time; invalid CIDRs match nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressTarget {
    /// DNS-name-based allow.
    Host {
        /// Exact hostname; no wildcards.
        hostname: String,
        /// Port number. `0` means "any port"; otherwise exact match.
        port: u16,
        /// URL scheme. Match is on the protocol class; the runner's
        /// enforcement layer translates HTTP/HTTPS into the right
        /// connection check.
        scheme: Scheme,
    },
    /// IP/port-range allow.
    Cidr {
        /// CIDR notation, e.g. `"10.0.0.0/8"` or `"::/0"`.
        cidr: String,
        /// Port range, inclusive on both ends. `(0, 0)` means
        /// "any port".
        port_range_start: u16,
        /// See `port_range_start`.
        port_range_end: u16,
    },
}

/// URL scheme class. Matches the protocol the step intends to
/// speak; the enforcement layer maps this to the actual
/// connection-time check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scheme {
    /// HTTP (port 80 by default).
    Http,
    /// HTTPS / TLS (port 443 by default).
    Https,
    /// Any TCP — the runner doesn't inspect the L7 protocol.
    Tcp,
}

/// What to do with an attempted egress. The enforcement layer
/// consumes this and either allows the connection, refuses it
/// with `ECONNREFUSED`, or records a violation while allowing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Connection allowed.
    Allow,
    /// Connection refused with `ECONNREFUSED`.
    Deny,
    /// Connection allowed but recorded in
    /// `StepOutput::network_violations`.
    Audit,
}

/// What an outbound connection is trying to reach. The enforcement
/// layer fills this in from the resolved address; the policy
/// evaluator is pure data over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressAttempt<'a> {
    /// Hostname the step asked for, if any. None for direct-IP
    /// connections.
    pub hostname: Option<&'a str>,
    /// Resolved (or directly-supplied) destination IP.
    pub addr: std::net::IpAddr,
    /// Destination port.
    pub port: u16,
    /// Protocol the step intends to speak. The enforcement layer
    /// derives this from URL prefix or socket type.
    pub scheme: Scheme,
}

/// Evaluate a `NetworkPolicy` against a single outbound attempt.
/// Pure: returns the decision without performing any I/O.
///
/// Algorithm:
/// 1. Walk `policy.allow` in order. The first matching entry
///    yields `Decision::Allow`.
/// 2. If no entry matches, return `policy.default` translated to
///    a `Decision`.
#[must_use]
pub fn evaluate(policy: &NetworkPolicy, attempt: &EgressAttempt<'_>) -> Decision {
    for target in &policy.allow {
        if matches_target(target, attempt) {
            return Decision::Allow;
        }
    }
    match policy.default {
        EgressDefault::Deny => Decision::Deny,
        EgressDefault::Audit => Decision::Audit,
    }
}

fn matches_target(target: &EgressTarget, attempt: &EgressAttempt<'_>) -> bool {
    match target {
        EgressTarget::Host {
            hostname,
            port,
            scheme,
        } => {
            // Hostname must match exactly; if the attempt has no
            // hostname (direct-IP connect), Host entries don't match.
            let hostname_match = matches!(attempt.hostname, Some(h) if h == hostname);
            let port_match = *port == 0 || *port == attempt.port;
            let scheme_match = scheme_matches(*scheme, attempt.scheme);
            hostname_match && port_match && scheme_match
        }
        EgressTarget::Cidr {
            cidr,
            port_range_start,
            port_range_end,
        } => {
            let port_match = (*port_range_start == 0 && *port_range_end == 0)
                || (attempt.port >= *port_range_start && attempt.port <= *port_range_end);
            port_match && cidr_contains(cidr, attempt.addr)
        }
    }
}

/// `Scheme::Tcp` matches anything; otherwise exact match.
fn scheme_matches(allowed: Scheme, attempted: Scheme) -> bool {
    matches!(allowed, Scheme::Tcp) || allowed == attempted
}

/// Parse `cidr` as `<addr>/<prefix>` and check whether `addr` falls
/// inside the range. Invalid CIDR strings match nothing — operator
/// errors don't accidentally widen the policy.
fn cidr_contains(cidr: &str, addr: std::net::IpAddr) -> bool {
    let Some((base_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u8>() else {
        return false;
    };
    match (base_str.parse::<std::net::IpAddr>(), addr) {
        (Ok(std::net::IpAddr::V4(base)), std::net::IpAddr::V4(target)) => {
            if prefix > 32 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask: u32 = u32::MAX << (32 - prefix);
            (u32::from(base) & mask) == (u32::from(target) & mask)
        }
        (Ok(std::net::IpAddr::V6(base)), std::net::IpAddr::V6(target)) => {
            if prefix > 128 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask: u128 = u128::MAX << (128 - prefix);
            (u128::from(base) & mask) == (u128::from(target) & mask)
        }
        // Mixed v4/v6 never match. (An operator who wants IPv6
        // coverage adds an explicit `::/0` entry.)
        _ => false,
    }
}

/// Convenience: a policy that denies everything. Equivalent to
/// `NetworkPolicy::default()`.
#[must_use]
pub fn deny_all() -> NetworkPolicy {
    NetworkPolicy::default()
}

/// Convenience: a policy that allows everything by hosting a
/// single `Cidr { ::/0 }` entry that matches every IPv6 address,
/// plus a `Cidr { 0.0.0.0/0 }` for IPv4. Operators who want
/// "audit-only" set `default = EgressDefault::Audit` instead;
/// this helper is for tests + the demo path.
#[must_use]
pub fn allow_all() -> NetworkPolicy {
    NetworkPolicy {
        allow: vec![
            EgressTarget::Cidr {
                cidr: "0.0.0.0/0".to_string(),
                port_range_start: 0,
                port_range_end: 0,
            },
            EgressTarget::Cidr {
                cidr: "::/0".to_string(),
                port_range_start: 0,
                port_range_end: 0,
            },
        ],
        default: EgressDefault::Deny,
    }
}
