# Anonymous Credentials for Trustless Agents (ACTA)

> Reference implementation of ACTA — a privacy-preserving protocol for anonymous credential verification for AI agents on EVM chains. Production-grade Solidity contracts, Credo.ts issuer/holder/verifier, OpenAC ZK proofs, and a no-code interactive demo app.

## Quick Start — Interactive Demo

The demo app runs entirely in the browser. No backend, no wallet, no network required.

```bash
cd packages/demo-app
npm install
npm run dev
# → Open http://localhost:5173
```

See [Interactive Demo](#interactive-demo) section for details.

---

## Architecture Overview

```
acta-poc/
├── packages/
│   ├── shared/         # Shared types, constants, predicate hashing, zkID GP IR
│   ├── sdk/            # @acta/sdk — public integration surface (predicate + stealth in v0.3)
│   ├── issuer/         # Credo.ts + OID4VCI issuer node (Express, port 3001)
│   ├── holder/         # Credo.ts + OpenAC wallet-unit-poc adapter (Express, port 3002)
│   ├── verifier/       # Credo.ts + OID4VP + Predicate SDK (Express, port 3003)
│   ├── contracts/      # Hardhat + Solidity (NullifierRegistry, GPVerifier, etc.)
│   └── demo-app/       # React 18 + Vite + Tailwind interactive demo (port 5173)
├── circuits/           # Circom 2.x ZK circuits (V1 production, V2 draft for zkID GP)
├── docs/               # ARCHITECTURE.md, FLOW.md, PM_GUIDE.md, API_REFERENCE.md,
│                       # ROADMAP.md, SECURITY_AUDIT.md, adr/0001-0004
└── docker-compose.yml  # Full local stack
```

The four protocol layers:

| Layer | Technology | Files |
|-------|-----------|-------|
| DID Identity | `did:ethr` (ERC-1056) on Base Sepolia | `*/src/didEthrSetup.ts` |
| W3C Credentials | Credo.ts + OID4VCI/OID4VP | `issuer/`, `holder/`, `verifier/` |
| ZK Privacy | OpenAC `wallet-unit-poc` + Circom 2.x Groth16 | `circuits/`, `holder/src/openacAdapter.ts` |
| On-Chain Execution | Hardhat + Solidity `^0.8.24` + OpenZeppelin 5.x | `contracts/` |

---

## Interactive Demo

### What it does

A self-contained React webapp that simulates the complete ACTA flow in 10 steps. Product managers and non-engineers can walk through every step without writing any code or running any backend.

### Layout

```
┌──────────────────────────────────────────────────────────────────┐
│  HEADER: ACTA Interactive Demo  [Step X of 10]  [Reset]      │
├──────────────────────┬───────────────────────┬───────────────────┤
│  LEFT: Architecture  │  CENTRE: Active Step  │  RIGHT: Docs      │
│  Diagram (react-flow)│  Panel (controls,     │  Panel (what is   │
│  Animated per step.  │  outputs, plain-lang  │  this? / how it   │
│                      │  explanation)         │  works / code)    │
└──────────────────────┴───────────────────────┴───────────────────┘
│  BOTTOM: Live Event Log — scrolling log of all simulated events   │
└──────────────────────────────────────────────────────────────────┘
```

### The 10 Steps

| Step | Title | Key Interaction |
|------|-------|----------------|
| 1 | Actors Created | See three did:ethr identities generated |
| 2 | Schema Configured | Edit credential values (audit score, jurisdiction, capabilities) |
| 3 | Credential Issued | See JWT-VC decoded — header/payload/signature/raw tabs |
| 4 | On-Chain Anchor | See commitment bytes and simulated transaction |
| 5 | Predicate Built | **Interactive predicate editor** — drag/drop conditions |
| 6 | Policy Registered | See PolicyDescriptor and generated policyId |
| 7 | Presentation Request | See OID4VP authorization request with custom extensions |
| 8 | ZK Proof Generated | **Privacy split-panel** — what agent knows vs what proof reveals |
| 9 | Verified | **10-step checklist** animates ✅ in sequence |
| 10 | Access Granted | Lock animation + **replay attack demo** showing `NullifierAlreadyActive` |

### What is simulated vs. real

| Component | Status |
|-----------|--------|
| did:ethr DIDs | ✅ Deterministically generated, real format |
| JWT-VC structure | ✅ Real format, fields match spec |
| ZK proof bytes | ⚡ Fake bytes (look real, not cryptographically valid) |
| Smart contract calls | ⚡ Simulated (no real network) |
| OID4VCI/OID4VP messages | ✅ Real protocol structure |
| Predicate hashing | ✅ Real keccak256 computation |

The demo is designed to be indistinguishable from real outputs to a non-technical viewer, while being clearly documented as simulated for technical reviewers.

---

## Full Local Development

### Prerequisites

- Node.js 20+
- npm 10+

### Setup

```bash
# Clone and install all packages
git clone <repo>
cd acta-poc
cp .env.example .env
npm install   # installs all workspace packages

# Compile Solidity contracts
cd packages/contracts && npm run compile

# Run contract tests
npm test

# Start all services with Docker
docker-compose up --build
```

### Individual Services

```bash
# Demo app (no other services needed)
cd packages/demo-app && npm run dev

# Contracts (local Hardhat node + deploy)
cd packages/contracts && npm run node   # terminal 1
cd packages/contracts && npm run deploy  # terminal 2

# Issuer (requires Hardhat node)
cd packages/issuer && npm run dev

# Holder
cd packages/holder && npm run dev

# Verifier
cd packages/verifier && npm run dev
```

### Running Tests

```bash
# All packages
npm test

# Contracts only
cd packages/contracts && npm test

# Integration test
cd packages/contracts && npx hardhat test test/integration/FullFlow.test.ts
```

---

## ZK Circuit Setup

Before deploying to a public network, run the trusted setup ceremony:

```bash
# Requires: circom 2.x, snarkjs (npm install -g snarkjs)
bash packages/contracts/scripts/setup-circuits.sh

# This generates:
# circuits/build/OpenACGPPresentation.zkey    (proving key)
# circuits/build/OpenACGPPresentation_vk.json (verification key)
# packages/contracts/contracts/verifiers/OpenACSnarkVerifier_generated.sol
```

Replace `OpenACSnarkVerifier.sol` with the generated verifier before production deployment.

---

## Smart Contracts

### Deployed Addresses (Base Sepolia)

Addresses are populated in `packages/contracts/deployments/base-sepolia.json` after running the deploy script.

### Key Contracts

| Contract | Description |
|----------|-------------|
| `NullifierRegistry` | Context-scoped nullifier store. Replay prevention. |
| `OpenACCredentialAnchor` | Links `did:ethr` → credential commitment. `anchorCredential()` reverts `ActiveAnchorExists` if a live anchor exists — use `rotateCredential()` to update. |
| `GeneralizedPredicateVerifier` | 10-step ZK verifier. `ReentrancyGuard` + `Pausable`. Requires `setContextHasher(poseidonT4)` before production (Step 7 front-running protection). |
| `ZKReputationAccumulator` | Anonymous reputation. Policy-scoped (`isAcceptedForPolicy`) to prevent cross-policy inflation. |
| `AgentAccessGate` | Example consumer. Policy-scoped gate + permanent revocation via `_permanentlyRevoked`. |
| `OpenACSnarkVerifier` | Groth16 verifier. Replace with ceremony-generated verifier before production. |
| `IPoseidonT4` | On-chain Poseidon-T4 interface. Required for Step 7 context hash. |

### Gas Costs (Base Sepolia)

| Operation | Gas | USD (approx) |
|-----------|-----|-------------|
| `anchorCredential()` | ~65,000 | ~$0.001 |
| `registerPolicy()` | ~80,000 | ~$0.001 |
| `verifyAndRegister()` (with Poseidon + Groth16) | ~205,000 | ~$0.002 |
| `grantAccess()` | ~48,000 | ~$0.001 |
| `setContextHasher()` (one-time setup) | ~25,000 | ~$0.001 |

---

## Verifier SDK — Quick Reference

```typescript
import { PredicateBuilder } from '@acta/verifier/src/predicateBuilder'
import { PresentationRequestBuilder } from '@acta/verifier/src/presentationRequest'
import { OffchainVerifier } from '@acta/verifier/src/offchainVerifier'
import { OnchainSubmitter } from '@acta/verifier/src/onchainSubmitter'
import { PolicyRegistry } from '@acta/verifier/src/policyRegistry'

// 1. Define your compliance requirement
const predicate = new PredicateBuilder('AgentCapabilityCredential')
  .require('auditScore').greaterThanOrEqual(80)
  .and()
  .require('capabilities').includes('evm-execution')
  .and()
  .require('operatorJurisdiction').notIn(['IR', 'KP', 'RU', 'BY'])
  .build()

// 2. Register policy on-chain
const policyId = await policyRegistry.registerPolicy(predicate, issuerCommitment)

// 3. Create a presentation request for an agent
const { requestUri } = requestBuilder.createPresentationRequest({
  policyId, predicate, verifierCallbackUrl: '...', sessionNonce: nonce, onchainVerifierAddress: '...'
})

// 4. When VP arrives in your callback:
const { valid } = await offchainVerifier.verifyOffchain({ presentation, policyId, issuerDid, vpJwt, holderDid })
const { txHash, nullifier } = await onchainSubmitter.submit({ policyId, presentation, agentDid, nonce })
```

See [docs/API_REFERENCE.md](./docs/API_REFERENCE.md) for the full API.

---

## Documentation

| Document | Audience | Contents |
|----------|----------|---------|
| [docs/PM_GUIDE.md](./docs/PM_GUIDE.md) | Product managers | Plain-language explanation, integration checklist, FAQ |
| [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) | Engineers, auditors | Technical design, trust assumptions, audit surface |
| [docs/FLOW.md](./docs/FLOW.md) | Engineers | Step-by-step flow with exact function calls |
| [docs/API_REFERENCE.md](./docs/API_REFERENCE.md) | Integrators | Complete Verifier SDK API reference |
| [docs/PM_AGENT_PROMPT.md](./docs/PM_AGENT_PROMPT.md) | PMs, AI agents | Copy-paste prompt: keep all docs and demo in sync on every change |
| [docs/SECURITY_AUDIT.md](./docs/SECURITY_AUDIT.md) | Engineers, auditors | Security findings and remediation tracker |
| [docs/ROADMAP.md](./docs/ROADMAP.md) | Everyone | Phase-ordered execution plan for zkID parity, unlinkability, and devex |
| [docs/adr/0001-zkid-generalized-predicates.md](./docs/adr/0001-zkid-generalized-predicates.md) | Engineers | Adopt zkID generalized-predicates as ACTA's predicate model |
| [docs/adr/0002-stealth-addresses-for-unlinkability.md](./docs/adr/0002-stealth-addresses-for-unlinkability.md) | Engineers | Stealth addresses per (verifier, policyId, sessionIndex) |
| [docs/adr/0003-anchor-by-holder-commitment.md](./docs/adr/0003-anchor-by-holder-commitment.md) | Engineers | Anchor credentials by holder-commitment, not by raw agentId |
| [docs/adr/0004-acta-sdk-package.md](./docs/adr/0004-acta-sdk-package.md) | Engineers, PMs | Ship `@acta/sdk` as the public integration surface |

---

## wallet-unit-poc Dependency

The `wallet-unit-poc` from [github.com/privacy-ethereum/zkID](https://github.com/privacy-ethereum/zkID/tree/main/wallet-unit-poc) is referenced as a local workspace dependency:

```json
"@privacy-ethereum/zkid-wallet-unit-poc": "file:../../wallet-unit-poc"
```

**Setup:**
```bash
# Clone zkID next to this repo
git clone https://github.com/privacy-ethereum/zkID ../zkID
# The adapter will automatically find it at ../../wallet-unit-poc
```

If `wallet-unit-poc` is not installed, the `OpenACAdapter` automatically falls back to `StubWalletUnit`, which generates deterministic fake proofs accepted by `OpenACSnarkVerifier` in test mode. All tests pass without the real library.

**The demo app does NOT depend on `wallet-unit-poc`** — it uses `SimulationEngine.ts` exclusively.

---

## Security Notice

This is a proof-of-concept implementation. The items below must be resolved before production use.

### Must-fix before deployment

1. **Real wallet-unit-poc required**: The `StubWalletUnit` is for local dev only; holder refuses to start in production without WUP. See [docs/SECURITY_AUDIT.md](./docs/SECURITY_AUDIT.md).
2. **Deploy ceremony-generated verifier**: `OpenACSnarkVerifier` rejects all proofs until replaced with `OpenACSnarkVerifier_generated.sol` from `setup-circuits.sh`. Local tests use `TestOpenACSnarkVerifier` only.
3. **Deploy IPoseidonT4**: Call `setContextHasher(poseidonT4Address)` on `GeneralizedPredicateVerifier` — **required on live networks** (Step 7 reverts if unset outside Hardhat).
4. **Trusted setup**: Run the Groth16 ceremony with ≥3 independent parties; replace placeholder verifier.
5. **Persist credential randomness**: Call `credentialStore.setAnchorData(id, commitment, merkleRoot, randomnessHex)` after anchoring. A server restart will fail to re-import if `randomnessHex` is not stored.
6. **Replace in-memory stores**: `preAuthCodes` and `sessions` are module-level Maps — lost on restart and not safe for multi-instance deployments. Replace with Redis or a database.
7. **Production env**: Set `STRICT_ISSUANCE=true`, `ALLOW_OPEN_CREDENTIAL_OFFER=false`, `TRUSTED_VERIFIER_DIDS`, `TRUSTED_ONCHAIN_VERIFIERS` on holder.

### Should-fix soon

6. **Contract audit**: All Solidity contracts must be professionally audited (6 core contracts + `IPoseidonT4` implementation)
7. **Poseidon consistency**: Run `test/PoseidonConsistency.test.ts` to confirm on-chain `IPoseidonT4.hash()` matches snarkjs circuit witness
8. **Key management**: Replace `WALLET_KEY=insecure-dev-key` with production HSM-backed keys
9. **RPC security**: Use authenticated RPC endpoints (Alchemy/Infura API key), not public ones
10. **wallet-unit-poc stability**: The OpenAC library must reach production stability
11. **Credential rotation**: Test `rotateCredential()` flow — `anchorCredential()` reverts `ActiveAnchorExists` if a live anchor already exists

---

## What's next (v0.3 → v1.0)

Concrete roadmap lives in [`docs/ROADMAP.md`](./docs/ROADMAP.md). Highlights shipped in v0.3:

| Capability | Status | Path |
|------------|--------|------|
| zkID generalized-predicate IR + canonical hash | shipped | `packages/shared/src/gp/` |
| Off-circuit predicate compiler + encoder + unit tests | shipped | `packages/shared/src/gp/`, `packages/shared/test/gp.test.ts` |
| Stealth-address derivation (HKDF-SHA256 + secp256k1) | shipped | `packages/holder/src/stealth.ts` |
| `@acta/sdk` skeleton with `predicate` + `stealth` surfaces | shipped | `packages/sdk/` |
| Circom V2 circuit implementing zkID GP | **draft** — pending ZK-engineer review + ceremony | `circuits/presentation/OpenACGPPresentationV2.circom` |
| Anchor V2 (by holder-commitment) | planned (v0.5) | tracked in ROADMAP Phase 2 |
| End-to-end holder + verifier on V2 + stealth | planned (v0.5) | tracked in ROADMAP Phase 2 |
| `@acta/sdk` issuer/holder/verifier clients + CLI | planned (v0.6) | tracked in ROADMAP Phase 3 |

ADR index: [0001 (zkID GP)](./docs/adr/0001-zkid-generalized-predicates.md) ·
[0002 (stealth addresses)](./docs/adr/0002-stealth-addresses-for-unlinkability.md) ·
[0003 (anchor-by-commitment)](./docs/adr/0003-anchor-by-holder-commitment.md) ·
[0004 (`@acta/sdk`)](./docs/adr/0004-acta-sdk-package.md).

---

## References

- [ERC-1056 — Ethereum DID Registry](https://github.com/uport-project/ethr-did-registry)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
- [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [Credo.ts Documentation](https://credo.js.org/)
- [OpenID Foundation: Identity Management for Agentic AI (October 2025)](https://openid.net/wp-content/uploads/2025/10/Identity-Management-for-Agentic-AI.pdf) — OBO delegation model, scope attenuation analysis, and CIBA patterns
