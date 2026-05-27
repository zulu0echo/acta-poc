# ADR-0004 — Ship `@acta/sdk` as the public integration surface

* **Status**: Accepted
* **Date**: 2026-05-27
* **Related**: `docs/ROADMAP.md` Phase 3.
* **Supersedes**: The v0.2 expectation that integrators import from `@acta/holder`, `@acta/verifier`, `@acta/shared`, `@acta/issuer` directly.

## Context

Today an integrator must:

1. Read `docs/API_REFERENCE.md` to learn about `PredicateBuilder`, `PresentationRequestBuilder`, `OffchainVerifier`, `OnchainSubmitter`, `PolicyRegistry`, `OpenACAdapter`, `WalletUnit`.
2. Wire up Express services for issuer, holder, verifier.
3. Manage circuit setup, ceremony output, and stealth-address funding manually.

The surface area is too wide for a 5-minute onboarding. Per Phase 3 of the roadmap, this ADR records the decision to consolidate the integration surface into a single SDK package.

## Decision

Ship a new workspace `packages/sdk/` exporting `@acta/sdk` as the **only** integration surface. Internal packages (`@acta/holder`, `@acta/verifier`, etc.) remain as service implementations but are not part of the public API.

### Public API shape

```typescript
import { ActaClient } from '@acta/sdk'

const acta = ActaClient.create({
  network: 'base-sepolia',
  contracts: { /* … addresses or autoload */ },
  prover:   'wallet-unit-poc',   // or 'stub' in dev
  unlinkability: 'stealth',      // or 'none' for backwards-compat
})

// Issuer side
const credential = await acta.issuer.issue({
  subject: holderDid,
  schema: 'AgentCapabilityCredential',
  fields: { auditScore: 87, jurisdiction: 'US', /* … */ },
})

// Holder side
await acta.holder.importCredential(credential)
const presentation = await acta.holder.present({ verifier, policyId, request })

// Verifier side
const policyId = await acta.verifier.registerPolicy({
  predicate: acta.predicate.from(`auditScore >= 80 AND jurisdiction == "US"`),
  issuerDid,
})
const { valid, nullifier } = await acta.verifier.verify(presentation)
```

### Sub-packages

| Surface | Description |
|---------|-------------|
| `acta.predicate` | GP DSL: parse predicate strings, build GP IR programmatically, compute canonical hash. |
| `acta.issuer` | Issue VCs, anchor commitments, rotate credentials. |
| `acta.holder` | Import VCs, derive stealth addresses, generate presentations. |
| `acta.verifier` | Register policies, build presentation requests, verify off-chain + on-chain. |
| `acta.ceremony` | Helpers around `setup-circuits.sh` and verifier deployment. |

### Distribution

- Published as `@acta/sdk` on npm.
- Bundled in three flavours: Node (CJS+ESM), browser (ESM only), Deno (npm: import).
- Includes TypeScript declarations.
- Peer-depends on `ethers` and `snarkjs`.

## Consequences

### Positive

- One package to install. One README to read.
- Internal package boundaries can refactor freely without breaking integrators.
- The CLI (`acta`) and conformance suite both consume `@acta/sdk` rather than duplicating logic.

### Negative

- A new package to maintain.
- API surface stability becomes a contract — breaking changes require a major version bump.
- Some service-specific helpers (Credo.ts plumbing, Express routes) can't be exposed in a server-agnostic SDK.

### Neutral

- The existing `docs/API_REFERENCE.md` will pivot to documenting `@acta/sdk` rather than the per-package APIs.

## Implementation status (v0.3 snapshot)

| Component | Shipped | Path |
|-----------|---------|------|
| Package skeleton + types | yes | `packages/sdk/` |
| `acta.predicate` (GP DSL re-exports + factory) | yes (re-exports `@acta/shared/gp`) | `packages/sdk/src/predicate.ts` |
| `acta.holder.stealth` (re-export of derivation) | yes | `packages/sdk/src/stealth.ts` |
| `acta.issuer.*`, `acta.holder.*`, `acta.verifier.*` clients | open (v0.6) | `packages/sdk/src/{issuer,holder,verifier}.ts` |
| CLI (`acta`) | open (v0.6) | `packages/cli/` |
| Browser bundle | open (v0.6) | `packages/sdk/dist/browser/` |

## Open questions

1. Should `@acta/sdk` ship its own contract ABI types, or re-export from `@acta/contracts`? **Recommended**: re-export with a `contracts.abi.NullifierRegistry` namespace.
2. Should the SDK auto-discover deployed contract addresses by network? **Recommended**: yes — ship a `networks.json` lookup like `@account-abstraction/contracts`.
3. Should the SDK include the simulation/mock layer used by `packages/demo-app/`? **Recommended**: yes, gated under `@acta/sdk/mock` for documentation and testing.

## References

- `docs/ROADMAP.md` Phase 3.
- `docs/API_REFERENCE.md` (current, will be rewritten when v0.6 ships).
