//! Property tests for `cosaci_jobs::network::evaluate`.
//!
//! Encodes the falsifiable claims of
//! `hypotheses/egress-policy-evaluation.md` (issue #54, class A).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use cosaci::jobs::network::{
    Decision, EgressAttempt, EgressDefault, EgressTarget, NetworkPolicy, Scheme, allow_all,
    deny_all, evaluate,
};
use hegel::{TestCase, generators};

// ────────────────────────────────────────────────────────────────────────
// Hegel generators
// ────────────────────────────────────────────────────────────────────────

fn draw_ipv4(tc: &TestCase) -> Ipv4Addr {
    let bytes: Vec<u8> = tc.draw(generators::binary().min_size(4).max_size(4));
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

fn draw_ipv6(tc: &TestCase) -> Ipv6Addr {
    let bytes: Vec<u8> = tc.draw(generators::binary().min_size(16).max_size(16));
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&bytes);
    Ipv6Addr::from(octets)
}

fn draw_port(tc: &TestCase) -> u16 {
    tc.draw(generators::integers::<u16>().min_value(1).max_value(65535))
}

// ────────────────────────────────────────────────────────────────────────
// Property 1 — empty allowlist + Deny default ⇒ Deny.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn empty_allowlist_with_deny_default_yields_deny(tc: TestCase) {
    let policy = NetworkPolicy {
        allow: Vec::new(),
        default: EgressDefault::Deny,
    };
    let attempt = EgressAttempt {
        hostname: None,
        addr: IpAddr::V4(draw_ipv4(&tc)),
        port: draw_port(&tc),
        scheme: Scheme::Tcp,
    };
    assert_eq!(evaluate(&policy, &attempt), Decision::Deny);
}

// ────────────────────────────────────────────────────────────────────────
// Property 2 — empty allowlist + Audit default ⇒ Audit.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn empty_allowlist_with_audit_default_yields_audit(tc: TestCase) {
    let policy = NetworkPolicy {
        allow: Vec::new(),
        default: EgressDefault::Audit,
    };
    let attempt = EgressAttempt {
        hostname: None,
        addr: IpAddr::V4(draw_ipv4(&tc)),
        port: draw_port(&tc),
        scheme: Scheme::Tcp,
    };
    assert_eq!(evaluate(&policy, &attempt), Decision::Audit);
}

// ────────────────────────────────────────────────────────────────────────
// Property 3 — matching Host entry ⇒ Allow.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn matching_host_entry_yields_allow(tc: TestCase) {
    let port = draw_port(&tc);
    let policy = NetworkPolicy {
        allow: vec![EgressTarget::Host {
            hostname: "registry.npmjs.org".to_string(),
            port,
            scheme: Scheme::Https,
        }],
        default: EgressDefault::Deny,
    };
    let attempt = EgressAttempt {
        hostname: Some("registry.npmjs.org"),
        addr: IpAddr::V4(draw_ipv4(&tc)),
        port,
        scheme: Scheme::Https,
    };
    assert_eq!(evaluate(&policy, &attempt), Decision::Allow);
}

// ────────────────────────────────────────────────────────────────────────
// Property 4 — matching Cidr entry ⇒ Allow.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn matching_cidr_entry_yields_allow(tc: TestCase) {
    // Allowlist 10.0.0.0/8; attempts to 10.x.y.z must allow.
    let policy = NetworkPolicy {
        allow: vec![EgressTarget::Cidr {
            cidr: "10.0.0.0/8".to_string(),
            port_range_start: 1,
            port_range_end: 65535,
        }],
        default: EgressDefault::Deny,
    };
    let octets: Vec<u8> = tc.draw(generators::binary().min_size(3).max_size(3));
    let addr = Ipv4Addr::new(10, octets[0], octets[1], octets[2]);
    let attempt = EgressAttempt {
        hostname: None,
        addr: IpAddr::V4(addr),
        port: draw_port(&tc),
        scheme: Scheme::Tcp,
    };
    assert_eq!(evaluate(&policy, &attempt), Decision::Allow);

    // An attempt to 11.x.y.z must NOT match.
    let outside_octets: Vec<u8> = tc.draw(generators::binary().min_size(3).max_size(3));
    let outside_addr = Ipv4Addr::new(11, outside_octets[0], outside_octets[1], outside_octets[2]);
    let outside_attempt = EgressAttempt {
        hostname: None,
        addr: IpAddr::V4(outside_addr),
        port: draw_port(&tc),
        scheme: Scheme::Tcp,
    };
    assert_eq!(evaluate(&policy, &outside_attempt), Decision::Deny);
}

// ────────────────────────────────────────────────────────────────────────
// Property 5 — direct-IP attempts skip Host entries.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn direct_ip_attempt_skips_host_entry(tc: TestCase) {
    // Even though we allowlist registry.npmjs.org:443, a direct-IP
    // attempt without a hostname must NOT match.
    let policy = NetworkPolicy {
        allow: vec![EgressTarget::Host {
            hostname: "registry.npmjs.org".to_string(),
            port: 443,
            scheme: Scheme::Https,
        }],
        default: EgressDefault::Deny,
    };
    let attempt = EgressAttempt {
        hostname: None,
        addr: IpAddr::V4(draw_ipv4(&tc)),
        port: 443,
        scheme: Scheme::Https,
    };
    assert_eq!(evaluate(&policy, &attempt), Decision::Deny);
}

// ────────────────────────────────────────────────────────────────────────
// Property 6 — invalid CIDR strings match nothing.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn invalid_cidr_does_not_match(tc: TestCase) {
    let bogus_cidrs = [
        "not-a-cidr",
        "10.0.0.0",          // missing prefix
        "10.0.0.0/abc",      // non-numeric prefix
        "10.0.0.0/33",       // prefix > 32 for v4
        "::/129",            // prefix > 128 for v6
        "999.999.999.999/8", // invalid base addr
    ];
    let cidr = bogus_cidrs[tc.draw(generators::integers::<usize>().min_value(0).max_value(5))];
    let policy = NetworkPolicy {
        allow: vec![EgressTarget::Cidr {
            cidr: cidr.to_string(),
            port_range_start: 0,
            port_range_end: 0,
        }],
        default: EgressDefault::Deny,
    };
    let attempt = EgressAttempt {
        hostname: None,
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        port: 443,
        scheme: Scheme::Tcp,
    };
    assert_eq!(
        evaluate(&policy, &attempt),
        Decision::Deny,
        "invalid CIDR `{cidr}` must not widen the policy"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 7 — /0 matches everything within its family.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn slash_zero_matches_within_family_only(tc: TestCase) {
    // 0.0.0.0/0 matches any IPv4 but not any IPv6.
    let v4_policy = NetworkPolicy {
        allow: vec![EgressTarget::Cidr {
            cidr: "0.0.0.0/0".to_string(),
            port_range_start: 0,
            port_range_end: 0,
        }],
        default: EgressDefault::Deny,
    };
    let v4_attempt = EgressAttempt {
        hostname: None,
        addr: IpAddr::V4(draw_ipv4(&tc)),
        port: draw_port(&tc),
        scheme: Scheme::Tcp,
    };
    assert_eq!(evaluate(&v4_policy, &v4_attempt), Decision::Allow);

    let v6_attempt = EgressAttempt {
        hostname: None,
        addr: IpAddr::V6(draw_ipv6(&tc)),
        port: draw_port(&tc),
        scheme: Scheme::Tcp,
    };
    assert_eq!(
        evaluate(&v4_policy, &v6_attempt),
        Decision::Deny,
        "0.0.0.0/0 must NOT match IPv6 — operators add ::/0 explicitly"
    );

    // ::/0 matches any IPv6 but not any IPv4.
    let v6_policy = NetworkPolicy {
        allow: vec![EgressTarget::Cidr {
            cidr: "::/0".to_string(),
            port_range_start: 0,
            port_range_end: 0,
        }],
        default: EgressDefault::Deny,
    };
    assert_eq!(evaluate(&v6_policy, &v6_attempt), Decision::Allow);
    assert_eq!(evaluate(&v6_policy, &v4_attempt), Decision::Deny);
}

// ────────────────────────────────────────────────────────────────────────
// Property 8 — first match wins regardless of position.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn first_match_wins_regardless_of_position(tc: TestCase) {
    // Build N junk entries that don't match, then put a matching
    // entry at a Hegel-drawn position. Result must be Allow.
    let n_junk = tc.draw(generators::integers::<usize>().min_value(0).max_value(10));
    let mut allow: Vec<EgressTarget> = (0..n_junk)
        .map(|_| EgressTarget::Host {
            hostname: "nonmatching.invalid".to_string(),
            port: 443,
            scheme: Scheme::Https,
        })
        .collect();
    let position = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(allow.len()),
    );
    let port = draw_port(&tc);
    allow.insert(
        position,
        EgressTarget::Host {
            hostname: "match.example".to_string(),
            port,
            scheme: Scheme::Https,
        },
    );
    let policy = NetworkPolicy {
        allow,
        default: EgressDefault::Deny,
    };
    let attempt = EgressAttempt {
        hostname: Some("match.example"),
        addr: IpAddr::V4(draw_ipv4(&tc)),
        port,
        scheme: Scheme::Https,
    };
    assert_eq!(evaluate(&policy, &attempt), Decision::Allow);
}

// ────────────────────────────────────────────────────────────────────────
// Smoke — realistic policy for `cargo fetch`.
// ────────────────────────────────────────────────────────────────────────
#[test]
fn smoke_realistic_cargo_fetch_policy() {
    // A realistic build step that wants `cargo fetch` against
    // crates.io plus its CDN, and nothing else.
    let policy = NetworkPolicy {
        allow: vec![
            EgressTarget::Host {
                hostname: "crates.io".to_string(),
                port: 443,
                scheme: Scheme::Https,
            },
            EgressTarget::Host {
                hostname: "static.crates.io".to_string(),
                port: 443,
                scheme: Scheme::Https,
            },
            EgressTarget::Host {
                hostname: "index.crates.io".to_string(),
                port: 443,
                scheme: Scheme::Https,
            },
        ],
        default: EgressDefault::Deny,
    };

    // Allowed
    for host in ["crates.io", "static.crates.io", "index.crates.io"] {
        let attempt = EgressAttempt {
            hostname: Some(host),
            addr: IpAddr::V4(Ipv4Addr::new(140, 82, 121, 1)),
            port: 443,
            scheme: Scheme::Https,
        };
        assert_eq!(evaluate(&policy, &attempt), Decision::Allow, "{host}");
    }

    // Denied — different host
    let attempt = EgressAttempt {
        hostname: Some("evil.example"),
        addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        port: 443,
        scheme: Scheme::Https,
    };
    assert_eq!(evaluate(&policy, &attempt), Decision::Deny);

    // Denied — right host, wrong port
    let attempt = EgressAttempt {
        hostname: Some("crates.io"),
        addr: IpAddr::V4(Ipv4Addr::new(140, 82, 121, 1)),
        port: 80,
        scheme: Scheme::Http,
    };
    assert_eq!(evaluate(&policy, &attempt), Decision::Deny);
}

#[test]
fn helpers_deny_all_and_allow_all() {
    let attempt = EgressAttempt {
        hostname: None,
        addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        port: 443,
        scheme: Scheme::Tcp,
    };
    assert_eq!(evaluate(&deny_all(), &attempt), Decision::Deny);
    assert_eq!(evaluate(&allow_all(), &attempt), Decision::Allow);

    let v6_attempt = EgressAttempt {
        hostname: None,
        addr: IpAddr::V6("2606:4700::1".parse().unwrap()),
        port: 443,
        scheme: Scheme::Tcp,
    };
    assert_eq!(evaluate(&allow_all(), &v6_attempt), Decision::Allow);
}
