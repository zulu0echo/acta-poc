# `@acta/sdk` — ACTA integration SDK

> **Status (v0.4): predicate + stealth + holder + verifier surfaces shipped.**
> Top-level `ActaClient` orchestrator + CLI land in v0.6
> (see [`docs/ROADMAP.md`](../../docs/ROADMAP.md) Phase 3).

This package is the **only** integration surface for ACTA.

| Namespace | Status | Notes |
|-----------|--------|-------|
| `acta.predicate.*` | shipped (v0.3 + v0.4) | zkID GP IR, builder, encoder, witness builder, canonical hash, V1 → V2 translator. |
| `acta.stealth.*`   | shipped (v0.3) | Stealth-address derivation for unlinkability (ADR-0002). |
| `acta.holder.*`    | shipped (v0.4) | `OpenACAdapterV2` + `StubWalletUnitV2` (replace stub with snarkjs prover post-ceremony). |
| `acta.verifier.*`  | shipped (v0.4) | `PredicateBuilderV2` (GP-native fluent API) + `fromV1Program` migration. |
| `ActaClient`       | placeholder    | Throws `NotImplementedError`; concrete top-level client lands in v0.6 per ADR-0004. |

## Install

```bash
npm install @acta/sdk
```

## Example — predicates

```typescript
import { predicate } from '@acta/sdk'

// Build a zkID GP program programmatically.
const program = predicate.builder()
  .add({ claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 80n } })   // P0: auditScore >= 80
  .add({ claimIndex: 2, op: 'eq', operand: { kind: 'const', value: 840n } }) // P1: jurisdiction == US
  .add({ claimIndex: 2, op: 'eq', operand: { kind: 'const', value: 826n } }) // P2: jurisdiction == GB
  .expression([
    { kind: 'pred', predicateIndex: 0 },
    { kind: 'pred', predicateIndex: 1 },
    { kind: 'pred', predicateIndex: 2 },
    { kind: 'op', op: 'OR' },          // P1 OR P2
    { kind: 'op', op: 'AND' },         // P0 AND (P1 OR P2)
  ])
  .build()

const hash = predicate.hash(program)
console.log('predicateProgramHash:', hash)
```

## Example — stealth addresses

```typescript
import { stealth } from '@acta/sdk'
import { randomBytes } from 'crypto'

const holderMaster = randomBytes(32) // persist this in a wallet

const id = stealth.derive(holderMaster, {
  verifierAddress: '0x...',
  policyId: '0x...',
  sessionIndex: 0,
})

console.log('Stealth DID :', id.did)
console.log('Stealth addr:', id.address)
```

## Example — V0.4 holder + verifier round trip (stub prover)

```typescript
import { predicate, holder, verifier } from '@acta/sdk'

// 1. Verifier authors a GP-native policy.
const policy = verifier.builder()
  .require('auditScore').greaterThanOrEqual(80)
  .and().not()
  .require('operatorJurisdiction').inJurisdictions(['IR', 'KP', 'RU'])
  .build()

// 2. Holder imports a credential into the V2 stub prover.
const claims = /* 16-element bigint array — see ATTRIBUTE_INDEX */
const adapter = holder.createAdapter()
const handle = await adapter.importExistingCredential({
  attributeValues: claims,
  issuerPubKeyCommitment,
  randomness,
})

// 3. Holder generates a V2 presentation bound to the verifier + policy.
const presentation = await adapter.generatePresentationProof({
  credentialHandle: handle,
  predicateProgram: policy.program,
  verifierAddress: '0x...',
  policyId: '0x...',
  nonce: 42n,
  expiryBlock: 9_999_999,
})

console.log('predicateProgramHash:', policy.hash)
// presentation.publicSignals.predicateProgramHash === policy.hash
```

## Roadmap

| Surface | Status | Roadmap |
|---------|--------|---------|
| `acta.predicate` | shipped (v0.3 + v0.4) | stable; witness builder + V1→V2 translator added in v0.4 |
| `acta.stealth` | shipped (v0.3) | stable |
| `acta.holder` | shipped (v0.4) | stable surface; swap stub prover post-ceremony |
| `acta.verifier` | shipped (v0.4) | stable; off-chain V2 verification path exposed |
| `acta.issuer` | open | v0.6 |
| `acta.ceremony` | open | v0.6 |
| Browser bundle | open | v0.6 |
| CLI (`acta`) | open | v0.6 |

See [`docs/adr/0004-acta-sdk-package.md`](../../docs/adr/0004-acta-sdk-package.md) for the design contract.
