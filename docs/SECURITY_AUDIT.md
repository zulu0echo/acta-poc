# ACTA Security Audit — Findings & Remediation Tracker

**Audit date:** 2026-05-27  
**Scope:** ACTA PoC — Groth16 anonymous credentials for AI agents (issuer / holder / verifier / on-chain GP verifier)  
**Status:** Remediation applied in-repo; production deployment still requires ceremony + external WUP audit.

---

## Summary

| Severity | Total | Fixed | Open |
|----------|-------|-------|------|
| Critical | 3 | 3 | 0* |
| High | 9 | 9 | 0† |
| Medium | 5 | 5 | 0 |
| Low / Informational | 3 | 2 | 1 |

\* Critical fixes are in code; **production Groth16 verifier must still be deployed from ceremony output** (see ACTA-001).  
† **wallet-unit-poc circuit equivalence** (ACTA-004) is documented; full verification requires the external library audit.

---

## Findings

### ACTA-001 — Sentinel on-chain SNARK verifier (Critical)

| Field | Value |
|-------|-------|
| **Category** | Soundness / Setup |
| **Location** | `packages/contracts/contracts/verifiers/OpenACSnarkVerifier.sol` |
| **Issue** | `verifyProof()` accepted `keccak256("OPENAC_TEST_PROOF_V1")` on any network. |
| **Status** | **Fixed** |
| **Remediation** | Split into `OpenACSnarkVerifier` (production placeholder — reverts `VerifierNotConfigured`) and `TestOpenACSnarkVerifier` (sentinel, local/Hardhat only). Deploy script uses `TestOpenACSnarkVerifier`. Run `packages/contracts/scripts/setup-circuits.sh` and deploy generated verifier for production. |

---

### ACTA-002 — Anchored commitment not verified at presentation (Critical)

| Field | Value |
|-------|-------|
| **Category** | Soundness |
| **Location** | `GeneralizedPredicateVerifier.sol`, `OpenACGPPresentation.circom` |
| **Issue** | On-chain Step 5 checked Merkle root only; prover could use different randomness / commitment than anchor. |
| **Status** | **Fixed** |
| **Remediation** | Added 7th public signal `credentialCommitmentOut`; GP verifier Step 5b compares `pubSignals[5]` to `credentialAnchor.getCommitment()`. |

**Public signal order (v0.2):**

| Index | Signal |
|-------|--------|
| 0 | nullifier |
| 1 | contextHash |
| 2 | predicateProgramHash |
| 3 | issuerPubKeyCommitment |
| 4 | credentialMerkleRoot |
| 5 | credentialCommitment |
| 6 | expiryBlock |

---

### ACTA-003 — `predicateProgramHash` not bound to circuit witnesses (Critical)

| Field | Value |
|-------|-------|
| **Category** | Soundness |
| **Location** | `OpenACGPPresentation.circom:78-81` (prior) |
| **Issue** | Hash was passthrough private input; prover could set policy hash while disabling predicates (`min=0`). |
| **Status** | **Fixed** |
| **Remediation** | In-circuit `predHasher = Poseidon(10)` over `(auditScoreMin, capMask, sanctions[8])`. `hashPredicateProgram()` in `@acta/shared` now uses matching Poseidon hash via `predicateCircuit.ts` (production requires circomlibjs; local dev may fall back to a deterministic placeholder). |

---

### ACTA-004 — No auditable predicate → witness bridge (High)

| Field | Value |
|-------|-------|
| **Category** | Soundness |
| **Location** | `packages/shared/src/predicateCircuit.ts` (new) |
| **Status** | **Fixed (in-repo)** |
| **Remediation** | Added `predicateToCircuitInputs()`, `hashPredicateProgramCircuit()`, `validatePredicateProgramSupported()`. **Open:** Confirm `wallet-unit-poc` uses same mapping when installed. |

---

### ACTA-005 — PredicateBuilder wider than circuit (High)

| Field | Value |
|-------|-------|
| **Category** | Soundness |
| **Location** | `packages/verifier/src/predicateBuilder.ts` |
| **Status** | **Fixed** |
| **Remediation** | `build()` calls `validatePredicateProgramSupported()`. Unsupported `AgentPredicateOperator` variants throw. Only flat AND of auditScore/capabilities/jurisdiction enforced. |

---

### ACTA-006 — Holder accepts any OID4VP challenge (High)

| Field | Value |
|-------|-------|
| **Category** | Role-separation |
| **Location** | `packages/holder/src/presentationValidation.ts` |
| **Status** | **Fixed** |
| **Remediation** | Optional allowlists `TRUSTED_VERIFIER_DIDS`, `TRUSTED_ONCHAIN_VERIFIERS`. Production should set both. |

---

### ACTA-007 — Verifier API client-controlled predicate (High)

| Field | Value |
|-------|-------|
| **Category** | Role-separation |
| **Location** | `packages/verifier/src/verifierRoutes.ts` |
| **Status** | **Fixed** |
| **Remediation** | `POST /presentation-request` loads predicate from `PolicyRegistry` by `policyId` only; client cannot supply arbitrary hash. |

---

### ACTA-008 — Off-chain verifier skipped policy hash (High)

| Field | Value |
|-------|-------|
| **Category** | Role-separation |
| **Location** | `packages/verifier/src/offchainVerifier.ts` |
| **Status** | **Fixed** |
| **Remediation** | `verifyOffchain()` checks `presentation.publicSignals.predicateProgramHash` against registered policy. |

---

### ACTA-009 — Step 7 / contextHasher optional (High)

| Field | Value |
|-------|-------|
| **Category** | Setup |
| **Location** | `GeneralizedPredicateVerifier.sol` |
| **Status** | **Fixed** |
| **Remediation** | `verifyAndRegister` reverts `ContextHasherNotConfigured()` when `contextHasher == address(0)` and `block.chainid != 31337` (Hardhat). |

---

### ACTA-010 — Stub prover misconfiguration (High)

| Field | Value |
|-------|-------|
| **Category** | Hygiene |
| **Location** | `packages/holder/src/openacAdapter.ts`, `packages/holder/src/server.ts` |
| **Status** | **Fixed** |
| **Remediation** | Stub uses Poseidon helpers matching Circom. Holder exits in production if `wallet-unit-poc` missing. |

---

### ACTA-011 — Trusted setup not production-ready (High)

| Field | Value |
|-------|-------|
| **Category** | Setup |
| **Location** | `setup-circuits.sh`, `OpenACSnarkVerifier.sol` |
| **Status** | **Partially fixed** |
| **Remediation** | Production verifier rejects all proofs until ceremony output deployed. **Open:** Run multi-party ceremony before mainnet. |

---

### ACTA-012 — Weak issuance gate (High)

| Field | Value |
|-------|-------|
| **Category** | Role-separation |
| **Location** | `packages/issuer/src/issuanceRoutes.ts` |
| **Status** | **Fixed** |
| **Remediation** | `STRICT_ISSUANCE=true` ignores client `credential_subject`. `ALLOW_OPEN_CREDENTIAL_OFFER=false` blocks open offers in production. PoP JWT `aud` checked. |

---

### ACTA-013 — Anchor without ZK proof (Medium)

| Field | Value |
|-------|-------|
| **Category** | Soundness |
| **Status** | **Accepted risk (documented)** |
| **Note** | Anchoring remains trust-on-first-use by holder; presentation now binds commitment. Optional future: require anchor proof from `OpenACCredentialAnchor.circom`. |

---

### ACTA-014 — On-chain `agentId` linkability (Medium)

| Field | Value |
|-------|-------|
| **Category** | Anonymity |
| **Status** | **Mitigated (operational); cryptographic fix planned in v0.5** |
| **Remediation (v0.3)** | Two layers shipped: (1) stealth-address derivation per `(verifier, policyId, sessionIndex)` in `packages/holder/src/stealth.ts` — ADR-0002; (2) ADR-0003 for anchor-by-holder-commitment, removing the on-chain address↔commitment map. Holder + anchor wiring lands in v0.5 — see `docs/ROADMAP.md` Phase 2. Until then, the operational mitigation (ephemeral `did:ethr` identities) remains in force. |

---

### ACTA-015 — JWT verification non-canonical (Medium)

| Field | Value |
|-------|-------|
| **Category** | Hygiene |
| **Location** | `openacAdapter.ts` `verifyJwtSignature` |
| **Status** | **Fixed** |
| **Remediation** | Enforce ES256K `low-s` (ECDSA malleability hardening) and bind VP JWT `aud` + `exp` in `OffchainVerifier.verifyVPJwtStructure()`. |

---

### ACTA-016 — PoP JWT missing `aud` (Medium)

| Field | Value |
|-------|-------|
| **Status** | **Fixed** |
| **Remediation** | `verifyAndExtractPopJwt` validates `aud` against `ISSUER_BASE_URL`. |

---

### ACTA-017 — Issuer commitment not in-circuit (Medium)

| Field | Value |
|-------|-------|
| **Status** | **Mitigated (off-chain checks)** |
| **Remediation** | Holder verifies JWT-VC signature during `importCredential()` and the verifier checks issuer commitment vs resolved issuer DID in `OpenACAdapter.verifyPresentation()`. Full cryptographic binding via in-circuit signature verification remains out of scope for this PoC. |

---

### ACTA-018 — Stale NullifierRegistry comment (Low)

| Field | Value |
|-------|-------|
| **Status** | **Fixed** |
| **Remediation** | Comment updated to Poseidon contextHash. |

---

### ACTA-019 — Integration tests without real SNARK (Informational)

| Field | Value |
|-------|-------|
| **Status** | **Documented** |
| **Note** | Tests use `TestOpenACSnarkVerifier`. Add Circom + snarkjs negative tests in CI when `.zkey` is committed. |

---

### ACTA-020 — Unused MerkleProof / anchor circuits (Informational)

| Field | Value |
|-------|-------|
| **Status** | **Documented** |
| **Note** | `MerkleProof.circom` and `OpenACCredentialAnchor.circom` reserved for future selective-disclosure / anchor proofs. |

---

## Production checklist

Before any public network deployment:

- [ ] Run `setup-circuits.sh` with ≥3 independent ceremony contributors
- [ ] Deploy `OpenACSnarkVerifier_generated.sol` (not `TestOpenACSnarkVerifier`)
- [ ] Deploy `IPoseidonT4` and call `setContextHasher()`
- [ ] Install and audit `wallet-unit-poc`; confirm R1CS matches `OpenACGPPresentation.circom`
- [ ] Set `STRICT_ISSUANCE=true`, `ALLOW_OPEN_CREDENTIAL_OFFER=false`
- [ ] Set `TRUSTED_VERIFIER_DIDS` and `TRUSTED_ONCHAIN_VERIFIERS` on holder
- [ ] Replace in-memory `preAuthCodes` / sessions with Redis
- [ ] Professional Solidity + Circom audit

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-27 | Initial audit (Passes 1–3) |
| 2026-05-27 | Remediation: circuit v0.2 (7 pub signals), GP verifier Step 5b, predicate Poseidon hash, test/production verifier split, holder/verifier/issuer hardening |
| 2026-05-27 | v0.3: zkID GP IR + canonical hash shipped in `@acta/shared/gp` (ADR-0001); stealth-address derivation shipped in `@acta/holder/stealth` (ADR-0002); Circom V2 draft (`OpenACGPPresentationV2.circom`); `@acta/sdk` skeleton (ADR-0004); roadmap published. |

---

## Open architectural improvements (v0.3 → v0.5)

The audit findings are remediated in code (v0.2) and operationally (ACTA-013/014/017).
The cryptographic improvements that *fully* close those mitigations are tracked in
[`docs/ROADMAP.md`](./ROADMAP.md):

- Phase 1 (v0.4): zkID generalized-predicate circuit V2 ships → ACTA-004/005 superseded by parity tests.
- Phase 2 (v0.5): anchor-by-holder-commitment + stealth-address presentation flow → ACTA-013/014 closed cryptographically.
- Phase 3 (v0.6): `@acta/sdk` clients + CLI + conformance suite → integration audit surface stabilised.

---

## References

- Architecture: [ARCHITECTURE.md](./ARCHITECTURE.md)
- Protocol spec: [SPEC.md](./SPEC.md)
- Circuit: [circuits/presentation/OpenACGPPresentation.circom](../circuits/presentation/OpenACGPPresentation.circom)
- Predicate encoding: [packages/shared/src/predicateCircuit.ts](../packages/shared/src/predicateCircuit.ts)
