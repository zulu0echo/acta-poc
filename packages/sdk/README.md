# `@acta/sdk` — ACTA integration SDK

> **Status (v0.3): skeleton only.**
> Public API surface is frozen; client implementations land in v0.6
> (see [`docs/ROADMAP.md`](../../docs/ROADMAP.md) Phase 3).

This package will become the **only** integration surface for ACTA.
Until v0.6 it exposes:

- `acta.predicate.*` — zkID generalized-predicate IR, infix DSL parser, canonical hash.
- `acta.stealth.*` — stealth-address derivation for unlinkability (ADR-0002).

The `acta.issuer`, `acta.holder`, and `acta.verifier` namespaces are
declared but throw `NotImplementedError` from `ActaClient.create`. They
are tracked in `docs/ROADMAP.md` and ADR-0004.

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

## Roadmap

| Surface | Status | Roadmap |
|---------|--------|---------|
| `acta.predicate` | shipped (v0.3) | stable |
| `acta.stealth` | shipped (v0.3) | stable |
| `acta.issuer` | open | v0.6 |
| `acta.holder` | open | v0.6 |
| `acta.verifier` | open | v0.6 |
| `acta.ceremony` | open | v0.6 |
| Browser bundle | open | v0.6 |
| CLI (`acta`) | open | v0.6 |

See [`docs/adr/0004-acta-sdk-package.md`](../../docs/adr/0004-acta-sdk-package.md) for the design contract.
