# ACTA Architecture — Technical Reference

> For ZK auditors, engineers, and protocol integrators.

## System Overview

ACTA is a four-layer protocol for anonymous credential verification for AI agents on EVM chains. The layers are strictly separated: a failure in any layer does not compromise the security of adjacent layers.

```
Layer 4: On-Chain Execution     ← Smart contracts enforce verification and gate access
Layer 3: ZK Privacy             ← Groth16 SNARK proves predicate satisfaction privately
Layer 2: W3C Credential         ← JWT-VC signed by did:ethr issuer
Layer 1: DID Identity           ← did:ethr backed by ERC-1056 (EthereumDIDRegistry)
```

See `docs/diagrams/system-overview.mermaid` for a visual overview.

---

## Layer 1: DID Identity (did:ethr)

### Why did:ethr

`did:ethr` was chosen because:
1. **No registration cost**: The DID is implicit from the Ethereum address. No on-chain transaction is needed to create a DID.
2. **Native on-chain linkage**: Every `did:ethr` DID resolves through `EthereumDIDRegistry` (ERC-1056), which is already deployed on Base Sepolia.
3. **Unified identity**: The same Ethereum address is used for both the W3C DID and on-chain contract interactions. The `agentId` in `OpenACCredentialAnchor` equals `uint256(uint160(ethAddress))`.
4. **Key rotation**: Issuers can rotate keys via `DIDOwnerChanged` events without breaking existing credentials — resolvers see the new key transparently.

### DID Format

```
did:ethr:0x14f69:0x<checksummedEthereumAddress>
         │       │
         │       └── 40-hex-char Ethereum address
         └── Base Sepolia chainId (84532 = 0x14f69)
```

### ERC-1056 Registry

**Deployed at:** `0xdca7ef03e98e0dc2b855be647c39abe984fcf21b` (Base Sepolia, canonical)

The registry stores:
- `owners`: maps `address → owner` (controller of the DID document)
- `attributes`: maps `(address, name, value) → validity` (e.g., public key attributes)
- `nonce`: for meta-transactions

A DID document is **implicit** until a transaction modifies it — the default controller is the address itself, and the default verification method is the secp256k1 key corresponding to that address.

### Key Format

All actors use **secp256k1** (Ethereum native). This maps to:
- JWT algorithm: `ES256K`
- JWK curve: `secp256k1`
- Verification method type: `EcdsaSecp256k1VerificationKey2019`

The same key is used for:
1. Signing JWT-VCs (as the Issuer)
2. Signing VP JWTs (as the Holder)
3. Signing Ethereum transactions (on-chain anchoring)

---

## Layer 2: W3C Credential Layer

### Credo.ts Modules

Each actor (Issuer, Holder, Verifier) runs a Credo.ts agent configured with:
- `@credo-ts/core` — agent runtime, DID management, wallet
- `@credo-ts/openid4vc` — OID4VCI (issuance) and OID4VP (presentation) protocol handlers
- `@credo-ts/node` — Node.js file system, crypto dependencies
- `ethr-did-resolver` — Registered as a DID resolver so Credo can resolve `did:ethr` DIDs

### AgentCapabilityCredential

The credential type for ACTA agent compliance verification.

**JWT-VC Structure:**
```json
{
  "header": { "alg": "ES256K", "typ": "JWT", "kid": "did:ethr:0x14f69:0xISSUER#controller" },
  "payload": {
    "iss": "did:ethr:0x14f69:0xISSUER",
    "sub": "did:ethr:0x14f69:0xHOLDER",
    "vc": {
      "@context": ["https://www.w3.org/2018/credentials/v1", "https://acta.ethereum.org/contexts/AgentCapability/v1"],
      "type": ["VerifiableCredential", "AgentCapabilityCredential"],
      "credentialSubject": {
        "id": "did:ethr:0x14f69:0xHOLDER",
        "auditScore": 87,
        "modelHash": "0x…",
        "operatorJurisdiction": "US",
        "capabilities": ["evm-execution"],
        "auditedBy": "did:ethr:0x14f69:0xISSUER",
        "auditDate": "2026-03-01"
      }
    }
  }
}
```

### OID4VCI Issuance Protocol

See `docs/diagrams/issuance-flow.mermaid`.

Key security properties:
- Pre-authorized code is single-use (tracked in `preAuthCodes` map)
- Proof-of-possession JWT must have `iss` = holder's `did:ethr`
- Issued credential `iss` must equal issuer's `did:ethr`
- Issuer resolves holder's `did:ethr` to verify PoP signature

### OID4VP Presentation Protocol

See `docs/diagrams/verification-flow.mermaid`.

The `x-openac-predicate` and `x-openac-policy-id` extensions are custom fields that carry ACTA-specific data through the standard OID4VP envelope.

---

## Layer 3: ZK Privacy Layer

### Attribute Index Mapping

The circuit expects a fixed 16-element `attributeValues[]` array. The mapping from credential fields to array indices is defined in `packages/shared/src/constants.ts`:

| Index | Field | Encoding |
|-------|-------|----------|
| 0 | `auditScore` | integer 0–100 |
| 1 | `modelHash` | uint256 (keccak256 of model string, truncated to field size) |
| 2 | `operatorJurisdiction` | ISO 3166-1 numeric (US=840, GB=826, …) |
| 3 | `capabilities` | bitmask (bit 0 = evm-execution, bit 1 = risk-assessment, …) |
| 4 | `auditedBy` | keccak256 of auditor DID string, truncated to 248 bits |
| 5 | `auditDate` | Unix timestamp (midnight UTC of YYYY-MM-DD) |
| 6–15 | Reserved | MUST be 0n |

**Critical:** Mismatch between this mapping and the circuit constants would cause all proofs to fail silently or produce incorrect results. The canonical mapping lives in `packages/shared/src/constants.ts` and is imported by both the OpenAC adapter and the circuit.

### Circuit: OpenACGPPresentation

**File:** `circuits/presentation/OpenACGPPresentation.circom`

**Proving system:** Groth16 (BN254 curve)

**Constraints:** ~50,000 (estimated; run `snarkjs r1cs info` after compilation)

**What the circuit proves:**
1. Knowledge of `attributeValues[]` and `randomness` that hash (via Poseidon) to the on-chain `credentialCommitment`
2. `credentialMerkleRoot` is correctly computed from `attributeValues[]`
3. The predicate is satisfied:
   - `auditScore >= predicateAuditScoreMin` (if enabled)
   - `capabilitiesBitmask & predicateCapabilityMask == predicateCapabilityMask` (if enabled)
   - `jurisdiction NOT IN predicateJurisdictionSanctions[]` (if enabled)
4. `nullifier = Poseidon(Poseidon(commitment, randomness), Poseidon(verifierAddress, policyId, nonce))`
5. `contextHash = Poseidon(verifierAddress, policyId, nonce)` (in-circuit; keccak256 check on-chain)

**Public signals (6):**
```
pubSignals[0] = nullifier
pubSignals[1] = contextHash
pubSignals[2] = predicateProgramHash
pubSignals[3] = issuerPubKeyCommitment
pubSignals[4] = credentialMerkleRoot
pubSignals[5] = expiryBlock
```

### OpenAC wallet-unit-poc

The `wallet-unit-poc` from `https://github.com/privacy-ethereum/zkID/tree/main/wallet-unit-poc` is used as a black box. The `OpenACAdapter` class in `packages/holder/src/openacAdapter.ts` bridges the W3C credential layer to the wallet-unit-poc API.

**Key format translation:**
The issuer's secp256k1 public key is converted to an `issuerPubKeyCommitment` via:
```
issuerPubKeyCommitment = keccak256(compressedPubKeyBytes) & ((1n << 248n) - 1n)
```
This fits within the BN254 scalar field modulus.

When `wallet-unit-poc` is not installed, the adapter falls back to `StubWalletUnit` which generates deterministic fake proofs accepted by `OpenACSnarkVerifier` in test mode (via the sentinel `OPENAC_TEST_PROOF_V1` hash).

---

## Layer 4: On-Chain Execution

### Contract Architecture

```
GeneralizedPredicateVerifier
    ↓ reads from
OpenACCredentialAnchor ← holds commitment + merkleRoot per (agentId, credentialType)
    ↓ writes to
NullifierRegistry ← context-scoped nullifier store

GeneralizedPredicateVerifier
    ↓ uses
ICircuitVerifier (interface) ← OpenACSnarkVerifier (implementation)

Consumer Contracts:
AgentAccessGate ← calls gpVerifier.isAccepted(nullifier)
ZKReputationAccumulator ← calls gpVerifier.isAccepted(nullifier)
AnonymousReputationPool ← calls reputationAccumulator.increment(nullifier)
```

### 10-Step Verification Sequence

See `docs/diagrams/onchain-execution-flow.mermaid` and `GeneralizedPredicateVerifier.sol`.

All 10 steps execute atomically in `verifyAndRegister()`. A failure at any step reverts the entire transaction with a descriptive custom error.

### Security Boundaries

| Boundary | Enforcer | Attack Mitigated |
|----------|----------|------------------|
| Only DID controller can anchor | `msg.sender == address(uint160(agentId))` | Credential squatting |
| Replay protection | `NullifierRegistry.isActive()` check in Step 9 | Double-spend of proof |
| Front-running protection | `contextHash = keccak256(caller \|\| policyId \|\| nonce)` (Step 7) | Front-running proof submission |
| Cross-policy linkability | Nullifier = Poseidon(credSecret, contextHash) | Cross-policy identity linkage |
| Issuer substitution | `issuerCommitment` checked in Step 6 | Using proof from different issuer |
| Stale credential | `isMerkleRootCurrent()` in Step 5 | Using revoked/expired credential |
| Circuit substitution | `circuitId` bound to `ICircuitVerifier` implementation | Substituting weak proof system |

### Audit Surface

For ZK auditors:
1. `OpenACGPPresentation.circom` — primary circuit; verify predicate constraint soundness
2. `OpenACSnarkVerifier.sol` — Groth16 verifier; verify verification key matches ceremony output
3. `NullifierRegistry.sol` — verify nullifier uniqueness invariants
4. `GeneralizedPredicateVerifier.sol` — verify 10-step ordering and atomicity
5. `OpenACCredentialAnchor.sol` — verify `msg.sender` enforcement

---

## Trust Assumptions

1. **Issuer honesty**: The Issuer issues credentials only to agents it has verified. ACTA does not enforce credential validity — it enforces that the agent has a credential from a trusted issuer that satisfies the predicate.
2. **Circom soundness**: The Groth16 proof is sound under the discrete log assumption on BN254.
3. **Poseidon collision resistance**: The circuit's commitments and nullifier derivation rely on Poseidon hash collision resistance.
4. **Powers of Tau ceremony**: The Groth16 verification key must be produced from a trusted setup ceremony with at least one honest participant.
5. **ERC-1056 integrity**: The `EthereumDIDRegistry` contract is trusted to correctly record DID controller changes.
