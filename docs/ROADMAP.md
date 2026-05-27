# ACTA Roadmap — zkID parity, unlinkability, and devex

> Living document. Maintained alongside `docs/SECURITY_AUDIT.md`.
> Source of truth for the "what's next" after the May 2026 security audit closed Critical and High findings.

This roadmap captures the **post-audit gap list**:

1. zkID `generalized-predicates` parity (currently ACTA enforces 3 hard-coded predicate families).
2. Unlinkability between verifiers and across sessions (currently `agentId = holder address` leaks correlation).
3. Developer experience (no SDK, no CLI, no conformance suite).

It is organised into versioned phases. Each phase has acceptance criteria, ADR pointers, and a documentation surface impacted (per the always-on `documentation-sync.mdc` PM rule).

---

## Versioning

| Tag | Scope |
|-----|-------|
| `v0.2` | Audit remediation — Critical/High/Medium findings, ceremony-required production verifier (shipped). |
| `v0.3` | zkID GP IR shipped off-chain (TypeScript), stealth-address derivation, ADRs published, draft Circom V2. |
| `v0.4` | JS witness builder, `PredicateBuilderV2`, `OpenACAdapterV2`, off-chain V2 path, ceremony script. Live ceremony still pending toolchain. |
| `v0.5` | Anchor-by-commitment + stealth-address end-to-end; legacy `agentId` removed from public surface. |
| `v0.6` | `@acta/sdk` (issuer + holder + verifier API), CLI (`acta`), conformance suite, OpenAPI. |
| `v1.0` | Audited Solidity + audited Circom + cross-team interop test against zkID `wallet-unit-poc`. |

---

## Phase 1 — zkID generalized predicates (v0.3 → v0.4)

**Reference**: [`privacy-ethereum/zkID/generalized-predicates`](https://github.com/privacy-ethereum/zkID/tree/main/generalized-predicates) (design spec; no Circom published as of 2026-05).

**ADR**: [`docs/adr/0001-zkid-generalized-predicates.md`](./adr/0001-zkid-generalized-predicates.md)

**Goals**:
- Reach byte-for-byte parity with zkID GP encoding (`(claim_index, op, operand, isClaimRef)`, postfix-tokenised expressions, supported ops `≤`, `≥`, `==`, `AND`, `OR`, `NOT`).
- Replace the hard-coded `auditScore≥N ∧ caps⊇M ∧ jurisdiction∉S` predicates in `OpenACGPPresentation.circom` with the generic GP evaluator.

| Task | Status | Path |
|------|--------|------|
| TypeScript IR (`GPProgram`, `GPPredicate`, `GPToken`) | **Shipped (v0.3)** | `packages/shared/src/gp/types.ts` |
| Infix → postfix compiler (shunting-yard) | **Shipped (v0.3)** | `packages/shared/src/gp/compiler.ts` |
| Witness encoder (program → fixed-size circuit inputs) | **Shipped (v0.3)** | `packages/shared/src/gp/encoder.ts` |
| Canonical Poseidon hash (`predicateProgramHash`) over GP IR | **Shipped (v0.3)** | `packages/shared/src/gp/encoder.ts` |
| Unit tests for IR + compiler + encoder | **Shipped (v0.3)** | `packages/shared/test/gp/` |
| Circom V2 circuit (`OpenACGPPresentationV2.circom`) | **Draft (v0.3)** — needs ZK-engineer review and re-ceremony | `circuits/presentation/OpenACGPPresentationV2.circom` |
| JS witness builder (`buildCircuitWitness`) + snarkjs input adapter | **Shipped (v0.4)** | `packages/shared/src/gp/witness.ts` |
| Encoder hash padded to power-of-2 leaves (matches circuit) | **Shipped (v0.4)** | `packages/shared/src/gp/encoder.ts` |
| V1→V2 program translator (`v1ToGP`) | **Shipped (v0.4)** | `packages/shared/src/gp/v1Compat.ts` |
| `PredicateBuilderV2` (GP-native fluent API) | **Shipped (v0.4)** | `packages/verifier/src/predicateBuilderV2.ts` |
| `OpenACAdapterV2` + `StubWalletUnitV2` (V2 holder path) | **Shipped (v0.4)** | `packages/holder/src/openacAdapterV2.ts` |
| `OffchainVerifier.verifyOffchainV2()` | **Shipped (v0.4)** | `packages/verifier/src/offchainVerifier.ts` |
| `@acta/sdk` exposes `holder.*` + `verifier.*` (V2) | **Shipped (v0.4)** | `packages/sdk/src/{holder,verifier,predicate}.ts` |
| Trusted-setup ceremony script for V2 | **Shipped (v0.4)** — pending toolchain to execute | `packages/contracts/scripts/setup-circuits-v2.sh` |
| Live Groth16 ceremony + generated Solidity verifier | **Open (v0.4 → v0.5)** — blocked on circom 2.1.x + snarkjs 0.7 install | `circuits/build/`, `contracts/verifiers/OpenACGPV2SnarkVerifier_generated.sol` |
| Parity vector against zkID `wallet-unit-poc` | **Open (v0.5)** — blocked on zkID publishing its prover | `packages/shared/test/gp-zkid-parity.test.ts` |
| `GeneralizedPredicateVerifier` re-pointed at V2 Groth16 verifier | **Open (v0.4)** — comments updated; awaits live ceremony | `packages/contracts/contracts/core/GeneralizedPredicateVerifier.sol` |
| Capability bitmask containment in GP (claim-per-bit schema) | **Open (v0.5)** | `packages/shared/src/types.ts` (schema), `packages/shared/src/gp/types.ts` |

**Acceptance criteria for v0.4**:
- A GP program `(age_unix ≤ X) AND (jurisdiction == Y OR jurisdiction == Z)` round-trips: TS encoder → witness → snarkjs Groth16 → on-chain Solidity verifier → emits `PresentationAccepted`.
- The same predicate string compiled by ACTA produces the same `predicateProgramHash` as zkID `wallet-unit-poc` (validated by parity vector test).

**v0.4 status (2026-05-27)**: every piece of the off-chain V2 stack is implemented and tested under `StubWalletUnitV2` — the holder, verifier, and SDK fully exercise the new IR, encoder, witness builder, and canonical hash end-to-end. The two outstanding items are the live Groth16 ceremony (blocked on local `circom`/`snarkjs` install) and the cross-team parity vector (blocked on zkID publishing its prover). The on-chain `GeneralizedPredicateVerifier` already uses the V1/V2-compatible 7-public-signal layout, so the only contract change required at ceremony time is re-pointing `proofVerifier`.

---

## Phase 2 — Unlinkability (v0.5)

**ADRs**:
- [`docs/adr/0002-stealth-addresses-for-unlinkability.md`](./adr/0002-stealth-addresses-for-unlinkability.md)
- [`docs/adr/0003-anchor-by-holder-commitment.md`](./adr/0003-anchor-by-holder-commitment.md)

**Goals**:
- A holder presenting the same credential to verifier A and verifier B is **unlinkable on-chain**: no observer can correlate `(tx_A.msg.sender, tx_B.msg.sender, tx_A.agentId, tx_B.agentId)`.
- Two presentations to the **same** verifier under different `policyId` values are also unlinkable.

**Strategy** (chosen 2026-05-27):
- **Stealth addresses per `(verifier, policyId, sessionIndex)`**: holder derives a fresh keypair from a master secret. The stealth address pays gas, signs the transaction, and is the `msg.sender` for `verifyAndRegister`. The verifier never sees the master.
- **Anchor by holder-commitment**: `OpenACCredentialAnchor` keys anchors by `Poseidon(holderMasterSecret, salt)` instead of by raw `uint160(address)`. Presentation proves Merkle membership in the anchor set without revealing the commitment-to-address binding.

| Task | Status | Path |
|------|--------|------|
| Stealth keypair derivation (HD-style) | **Shipped (v0.3)** | `packages/holder/src/stealth.ts` |
| Stealth address unit tests (determinism + uniqueness) | **Shipped (v0.3)** | `packages/holder/test/stealth.test.ts` |
| Stealth-address funding helper (faucet integration / relay-on-demand) | **Open (v0.5)** | `packages/holder/src/stealthFunding.ts` |
| Holder presentation flow uses stealth address for VP JWT `iss` + on-chain `msg.sender` | **Open (v0.5)** | `packages/holder/src/openacAdapter.ts`, `packages/holder/src/presentationHandler.ts` |
| `OpenACCredentialAnchor` v2: anchor by commitment, not by address | **Open (v0.5)** | `packages/contracts/contracts/core/OpenACCredentialAnchorV2.sol` |
| Anchor-set inclusion proof in circuit (Merkle root over commitments) | **Open (v0.5)** | `circuits/presentation/OpenACGPPresentationV2.circom` (extends Phase 1) |
| Verifier accepts anchor-by-commitment proofs | **Open (v0.5)** | `GeneralizedPredicateVerifier.sol` |
| Holder UX docs explaining stealth-address funding | **Open (v0.5)** | `docs/PM_GUIDE.md`, `docs/FLOW.md` |

**Acceptance criteria for v0.5**:
- Two presentations from the same `holderMasterSecret` to the same verifier yield two distinct `msg.sender` addresses and two unlinkable transactions; both verify against the same anchor-set root.
- `agentId` is no longer a public input or event field anywhere downstream.
- `docs/SECURITY_AUDIT.md` finding **ACTA-014** can be moved from *Mitigated (operational)* to **Fixed**.

---

## Phase 3 — Developer experience (v0.6)

**ADR**: [`docs/adr/0004-acta-sdk-package.md`](./adr/0004-acta-sdk-package.md)

**Goals**:
- `npm install @acta/sdk` is enough to issue, hold, and verify ACTA presentations from a backend or browser.
- A single CLI (`acta`) covers the entire local-dev loop.
- OpenAPI specs for the issuer, holder, and verifier services.
- Conformance suite that any third-party implementation can run.

| Task | Status | Path |
|------|--------|------|
| `@acta/sdk` package skeleton (public API surface) | **Shipped (v0.3)** | `packages/sdk/` |
| `@acta/sdk` issuer client (issue VC, anchor, rotate) | **Open (v0.6)** | `packages/sdk/src/issuer.ts` |
| `@acta/sdk` holder client (import VC, derive stealth, present) | **Open (v0.6)** | `packages/sdk/src/holder.ts` |
| `@acta/sdk` verifier client (register policy, request, verify off+on-chain) | **Open (v0.6)** | `packages/sdk/src/verifier.ts` |
| `acta` CLI (`acta issue`, `acta present`, `acta verify`, `acta ceremony`) | **Open (v0.6)** | `packages/cli/` |
| OpenAPI specs for the three Express services | **Open (v0.6)** | `docs/openapi/*.yaml` |
| Conformance suite (`@acta/conformance`) — black-box tests against any implementation | **Open (v0.6)** | `packages/conformance/` |
| End-to-end browser example (vite + `@acta/sdk` in browser) | **Open (v0.6)** | `examples/browser-presentation/` |

**Acceptance criteria for v0.6**:
- A developer with no prior ACTA exposure can run `npx @acta/sdk init && npx acta demo` and see a successful presentation in under 5 minutes.
- The conformance suite passes against zkID's `wallet-unit-poc` and against `StubWalletUnit` with the same test vectors.

---

## Cross-cutting items

| Item | Owner | Notes |
|------|-------|-------|
| Trusted-setup ceremony (multi-party) for V2 circuit | Cryptography lead | Required for `OpenACSnarkVerifier_generated.sol` deployment. |
| Audit of GP encoder ↔ Circom V2 parity | ZK engineer | Each GP IR field must map to exactly one Circom witness; encoder unit tests cover this. |
| Audit of stealth-address derivation function | Cryptography lead | Must be IND-CCA against the master secret given a sampled subset of stealth addresses. |
| Sync demo app to GP IR | Frontend | `packages/demo-app/src/components/steps/Step5Predicate.tsx` + `SimulationEngine.ts`. |
| Update `docs/diagrams/*.mermaid` for stealth flow | PM / engineer | New `docs/diagrams/stealth-presentation.mermaid`. |
| `docs/SPEC.md` normative update for GP IR + stealth | PM / spec author | Must precede any external integration commitment. |

---

## Linked findings (`docs/SECURITY_AUDIT.md`)

- **ACTA-004 / ACTA-005**: Phase 1 supersedes the v1 predicate→circuit bridge.
- **ACTA-013**: Phase 2 (anchor-set inclusion proof) directly addresses this.
- **ACTA-014**: Phase 2 closes operational mitigation with a cryptographic fix.
- **ACTA-017**: Tracked separately; full in-circuit signature verification remains out of scope for v0.6.

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-27 | Initial roadmap published alongside ADRs 0001–0004; v0.3 deliverables shipped. |
| 2026-05-27 | v0.4 shipped: JS witness builder + V1→V2 translator + `PredicateBuilderV2` + `OpenACAdapterV2` + V2 off-chain verifier path + ceremony script + encoder hash now matches in-circuit Merkle fold (power-of-2 padding). 92 tests pass across `@acta/shared`, `@acta/verifier`, `@acta/holder`, `@acta/sdk`. Live ceremony + zkID cross-parity remain open (tooling/upstream blocked). |
