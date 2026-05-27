# ADR-0001 — Adopt zkID generalized-predicates as ACTA's predicate model

* **Status**: Accepted
* **Date**: 2026-05-27
* **Deciders**: Product / Cryptography / Engineering
* **Supersedes**: The hard-coded `auditScore ≥ N ∧ caps ⊇ M ∧ jurisdiction ∉ S` model embedded in `OpenACGPPresentation.circom` (v1).

## Context

ACTA v0.2's circuit only enforces three predicate families:

```
auditScore           ≥ predicateAuditScoreMin
capabilitiesBitmask  ⊇ predicateCapabilityMask
jurisdictionNumeric  ∉ predicateJurisdictionSanctions
```

This is enough for the audit-grading use case but **too narrow** for general agent-capability policies (e.g., "operator is in EU AND audit was less than 12 months ago AND model_class ∈ {A, B}").

zkID's [`generalized-predicates`](https://github.com/privacy-ethereum/zkID/tree/main/generalized-predicates) project specifies a general predicate model that ACTA explicitly identified as the target ([ethresearch ACTA post, section "Predicate Built"](https://ethresear.ch/t/anonymous-credentials-for-trustless-agents-acta/24797)).

## Decision

ACTA adopts the zkID generalized-predicates **design as its source of truth** for predicate semantics, encoding, and on-chain hashing.

Concretely:

1. ACTA's predicate IR matches zkID 1:1 — claims, predicates `(claim_idx, op, operand, isClaimRef)`, postfix logical expression with `AND`, `OR`, `NOT`.
2. Operators supported in circuit: `≤`, `≥`, `==`. Derived operators (`<`, `>`, `≠`, range, membership, non-membership) are expressed via logical composition off-circuit (per zkID spec §"Derived Predicate Patterns").
3. `predicateProgramHash` is computed as **Poseidon over the canonical encoding of the predicate list and postfix expression**. The canonical encoding is defined in `packages/shared/src/gp/encoder.ts`.
4. ACTA continues to publish `predicateProgramHash` as a public output of the circuit; the on-chain `PolicyRegistry` stores it as the canonical policy identifier.
5. ACTA does **not** vendor zkID's `wallet-unit-poc` as a binary dependency. Instead, ACTA reimplements the design with byte-for-byte hashing parity, validated by a parity-vector test suite that runs against `wallet-unit-poc` when available.

## Why not vendor `wallet-unit-poc` directly?

zkID's `wallet-unit-poc` is an end-to-end prover wallet; ACTA only needs the predicate IR and circuit logic. Vendoring would:
- Pull in a large surface area that ACTA does not use (storage layer, key management, UI bindings).
- Make ACTA versions lock-step with `wallet-unit-poc` releases.
- Increase the audit surface.

The chosen approach (reimplement design, prove parity) keeps ACTA's PoC scope tight and the integration audit-friendly. If `wallet-unit-poc` matures into a published npm package with a stable surface, this ADR should be revisited (see "Open questions" below).

## Consequences

### Positive

- ACTA can express any policy that zkID can.
- Verifiers can author policies in familiar zkID syntax and copy them to other zkID-aligned systems.
- `predicateProgramHash` becomes a cross-system identifier (same hash → same predicate, regardless of implementation).

### Negative / cost

- The Circom circuit grows from ~3 specialised templates to a generic GP evaluator (`PostfixEval` + per-predicate comparator dispatcher). Initial constraint count estimate: 25k–40k constraints for `(N_CLAIMS=16, M_PREDS=8, T_TOKENS=16)`. To be confirmed by snarkjs `r1cs info` once the V2 circuit compiles.
- A new trusted-setup ceremony is required (V2's R1CS is incompatible with V1's `.zkey`).
- Off-chain encoder must be kept in lockstep with the circuit — covered by parity unit tests.

### Neutral

- The on-chain `GeneralizedPredicateVerifier.sol` does not change conceptually; only the number of public signals and the `predicateProgramHash` derivation change.

## Implementation status (v0.4 snapshot)

| Component | Shipped | Path |
|-----------|---------|------|
| GP IR types | v0.3 | `packages/shared/src/gp/types.ts` |
| Infix → postfix compiler (shunting-yard) | v0.3 | `packages/shared/src/gp/compiler.ts` |
| Canonical encoder + Poseidon hash | v0.3 | `packages/shared/src/gp/encoder.ts` |
| Hash leaves zero-padded to next power of 2 (matches circuit) | v0.4 | `packages/shared/src/gp/encoder.ts` |
| Witness builder (`buildCircuitWitness` + `buildSnarkjsInput`) | v0.4 | `packages/shared/src/gp/witness.ts` |
| V1 → V2 program translator | v0.4 | `packages/shared/src/gp/v1Compat.ts` |
| `PredicateBuilderV2` (GP-native fluent API) | v0.4 | `packages/verifier/src/predicateBuilderV2.ts` |
| `OpenACAdapterV2` + `StubWalletUnitV2` | v0.4 | `packages/holder/src/openacAdapterV2.ts` |
| `OffchainVerifier.verifyOffchainV2` | v0.4 | `packages/verifier/src/offchainVerifier.ts` |
| `@acta/sdk` predicate/witness/holder/verifier surfaces | v0.4 | `packages/sdk/src/{predicate,holder,verifier}.ts` |
| Circom V2 circuit | **draft** | `circuits/presentation/OpenACGPPresentationV2.circom` |
| V2 ceremony script | v0.4 — script ships, execution pending toolchain | `packages/contracts/scripts/setup-circuits-v2.sh` |
| Live Groth16 ceremony + generated Solidity verifier | open | tracked in `docs/ROADMAP.md` Phase 1 |
| Cross-team parity vector vs zkID `wallet-unit-poc` | open | blocked on upstream publishing prover |

## Open questions

1. Should ACTA publish the GP IR under a stable JSON Schema in `docs/SPEC.md`? **Recommended**: yes, before v0.5.
2. Should ACTA add `IN` as a primitive operator (zkID lists it under "Custom Operators")? **Recommended**: defer to v0.5 once usage data shows membership is a common pattern.
3. Should `predicateProgramHash` include a version tag to allow IR evolution? **Resolved (v0.4)**: yes — leaf 0 of the canonical hash vector is the encoder version (currently `1`). Verified by `buildHashLeaves` + the circuit's `hashLeaves[0] <== 1` constraint.
4. Capability bitmask containment requires a credential-schema change (one claim per bit) before it can be expressed in GP IR. **Tracked**: `docs/ROADMAP.md` Phase 1 open work item.

## References

- zkID generalized-predicates spec: <https://github.com/privacy-ethereum/zkID/tree/main/generalized-predicates/README.md>
- ACTA Ethereum Research post: <https://ethresear.ch/t/anonymous-credentials-for-trustless-agents-acta/24797>
- `docs/SPEC.md` (ACTA normative spec — to be updated for GP IR before v0.4).
