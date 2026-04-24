---
id: tee-attestation
source: SPEC.md §15 (Future Work)
class: C
status: pending
blocked_on: "real TEE hardware or emulator (TPM 2.0 / SGX / SEV-SNP / TDX)"
---

# tee-attestation

**Claim:** Hardware TEE attestation (TPM 2.0 PCR quotes, SGX EREPORT, SEV-SNP attestation, Intel TDX attestation) verifies correctly against vendor roots, and the resulting measurement uniquely identifies the loaded agent binary + configuration.

**Why class C:** TEE attestation is a hardware property. It cannot be made pure; even emulators (e.g., swtpm, SGX simulator) test *against a simulator's behavior*, not real silicon.

**How to unblock (per TEE type):**
- **TPM 2.0:** `swtpm` emulator is acceptable for development; real hardware required for production acceptance.
- **SGX:** Intel DCAP attestation tooling; requires SGX-capable CPU.
- **SEV-SNP:** AMD attestation tooling; requires EPYC with SNP firmware.
- **TDX:** Intel attestation service; requires Sapphire Rapids or later.

**What survives the filter now:** nothing. TEE is listed as Future Work in §15 and remains class C. The card exists to ensure it doesn't silently disappear.

**Notes:** TEE measurement canonicalization matters for reproducibility across TEE versions — a small firmware change can alter the quote. Pin TEE versions in the primitive commitment when we enter this phase.
