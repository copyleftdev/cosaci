---
id: mtls-enforcement
source: SPEC.md §5.2c + §5.1
class: C
status: passing
test: tests/mtls_enforcement.rs
depends_on: "rustls 0.23 (ring provider) + rcgen 0.14"
primitive_pick: "In-process rustls handshake over in-memory byte buffers; rcgen generates a test CA + end-entity certs; no network or system trust store needed. harness in src/tls.rs."
first_passing: 2026-04-24
note: "First Tier 3 card closed. Three properties green: valid client cert accepted, no cert rejected, wrong-CA cert rejected. Cert rotation mid-session and CRL/OCSP revocation remain v0.2 hardening items."
sub_claim_deferred: "Cert rotation mid-session and CRL/OCSP revocation. The spec's rotation + revocation clauses require stateful session handling and a real revocation channel — left for when CosaCI has real long-lived TLS sessions to rotate."
---

# mtls-enforcement

**Claim:** Mutual TLS is enforced on all coordinator ↔ agent connections. Clients without valid certs are rejected. Revoked certs are rejected. Cert rotation succeeds without dropping in-flight leases.

**Why class C:** mTLS is a real-network property. Rustls has its own property tests; what this card must verify is our *integration* (cert store, revocation check, rotation hook). That requires real TLS handshakes against test CAs with controlled cert state.

**How to unblock:**
1. Stand up a test CA (minica / step-ca).
2. Generate client/server certs with short TTLs.
3. Test harness: agent + coordinator over localhost TLS, assert:
   - Connection with no cert → rejected.
   - Connection with untrusted cert → rejected.
   - Connection with valid cert → accepted.
   - Rotate server cert mid-session → reconnection succeeds; in-flight leases preserved.
   - Revoke client cert (CRL or OCSP) → subsequent connections rejected; active connection treatment documented.
4. Gate behind `HEGEL_TLS_HARNESS=1`.

**What survives the filter now:** identity-authenticity is not testable here. The `registry-algebra` card assumes an authenticated registration event exists; this card would close that gap once unblocked.

**Notes:** If we later adopt SPIFFE / workload identity, this card evolves (or splits).
