---
id: mtls-enforcement
source: SPEC.md §5.2c + §5.1
class: C
status: pending
blocked_on: "real TLS harness (rustls + client cert infra)"
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
