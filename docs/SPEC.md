---
slug: acta
title: ACTA/ANONYMOUS-AGENT-CREDENTIALS
name: Anonymous Credentials for Trustless Agents (ACTA)
status: raw
category: Standards Track
tags: zero-knowledge, anonymous-credentials, ai-agents, evm, nullifiers, did-ethr, groth16, poseidon, privacy
editor: ACTA Working Group
contributors:
  - ACTA Working Group
---

# Change Process

This document is governed by the [1/COSS](https://github.com/privacy-ethereum/zkspecs/tree/main/specs/1) (COSS).

# Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

---

# Abstract

This specification defines a four-layer protocol that allows an AI agent to prove compliance with a verifier-defined predicate policy — without disclosing the underlying credential attributes — and receive on-chain access rights whose scope is permanently bounded to a single (verifier, policy, nonce) context.

The agent holds a W3C Verifiable Credential issued by a trusted `did:ethr` issuer. A Groth16 SNARK (`OpenACGPPresentation`) proves that the credential satisfies the verifier's predicate (e.g., `auditScore ≥ 80 AND jurisdiction NOT IN [IR, KP]`) while exposing only six public signals: a context-scoped nullifier, a context hash, a predicate program hash, an issuer public key commitment, a credential Merkle root, and an expiry block.

On-chain verification (`GeneralizedPredicateVerifier.verifyAndRegister`) executes a 10-step atomic sequence that validates all six signals, verifies the Groth16 proof, registers the nullifier, and emits `PresentationAccepted`. Replay attacks are cryptographically prevented: the nullifier is deterministic for a given `(credentialSecret, verifierAddress, policyId, nonce)` tuple and is stored permanently on registration.

---

# Motivation

AI agents operating in DeFi, on-chain governance, and regulated protocol contexts require compliance verification before accessing sensitive operations. Classical approaches — KYC databases, allow-lists, on-chain identity registries — either break agent privacy or create centralised chokepoints.

ACTA separates *eligibility proof* from *identity disclosure*. A protocol can enforce "only audit-certified agents with no sanctioned-jurisdiction exposure may execute trades" without learning which specific agent passed, what their exact audit score is, or linking two distinct protocol interactions to the same agent.

The core primitive is a **context-scoped nullifier**: a single credential produces a different nullifier for every `(verifier, policy, nonce)` context, so cross-protocol identity linkage is computationally infeasible even if an adversary observes every nullifier on every chain.

---

# Specification

## System Architecture

Four layers are strictly separated. A compromise at one layer MUST NOT propagate to adjacent layers.

```
Layer 4: On-Chain Execution     — smart contracts enforce verification and gate access
Layer 3: ZK Privacy             — Groth16 SNARK proves predicate satisfaction in private
Layer 2: W3C Credential         — JWT-VC signed by a did:ethr issuer
Layer 1: DID Identity           — did:ethr backed by ERC-1056 (EthereumDIDRegistry)
```

Three roles participate in every protocol run:

| Role | Description | Key Material |
|------|-------------|-------------|
| **Issuer** | Certifies agent attributes; issues `AgentCapabilityCredential` | `did:ethr` secp256k1 key |
| **Holder (Agent)** | Carries credential; generates ZK proof on request | `did:ethr` secp256k1 key |
| **Verifier (Protocol)** | Defines predicate policy; submits proof on-chain | `did:ethr` secp256k1 key |

---

## Layer 1: DID Identity

### 1.1 DID Method

Implementations MUST use `did:ethr` (ERC-1056) as the DID method for all three roles.

DID format:

```
did:ethr:<chainId>:<checksummedEthereumAddress>
```

For Base Sepolia (chainId `0x14f69 = 84532`):

```
did:ethr:0x14f69:0x<40-hex-char address>
```

### 1.2 Key Format

All actors MUST use **secp256k1** keys. The same key is used for:

- Signing JWT-VCs (`alg: ES256K`)
- Signing VP JWTs (`alg: ES256K`)
- Signing Ethereum transactions

Verification method type: `EcdsaSecp256k1VerificationKey2019`.

### 1.3 ERC-1056 Registry

The `EthereumDIDRegistry` contract MUST be deployed at the canonical address for the target chain. On Base Sepolia:

```
0xdca7ef03e98e0dc2b855be647c39abe984fcf21b
```

DID documents are implicit until modified. Default controller equals the Ethereum address; default verification method equals the secp256k1 key that controls the address.

### 1.4 On-Chain Identity Linkage

The `agentId` used in `OpenACCredentialAnchor` MUST be computed as:

```solidity
agentId = uint256(uint160(holderAddress))
```

The contract MUST enforce `msg.sender == address(uint160(agentId))` on every `anchorCredential` call, ensuring only the DID controller can register a commitment for that agent identity.

---

## Layer 2: W3C Credential

### 2.1 Credential Type

The credential type is `AgentCapabilityCredential` with JSON-LD context:

```
https://acta.ethereum.org/contexts/AgentCapability/v1
```

### 2.2 JWT-VC Structure

```json
{
  "header": {
    "alg": "ES256K",
    "typ": "JWT",
    "kid": "did:ethr:0x14f69:0xISSUER#controller"
  },
  "payload": {
    "iss": "did:ethr:0x14f69:0xISSUER",
    "sub": "did:ethr:0x14f69:0xHOLDER",
    "iat": 1741824000,
    "nbf": 1741824000,
    "exp": 1749600000,
    "vc": {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://acta.ethereum.org/contexts/AgentCapability/v1"
      ],
      "type": ["VerifiableCredential", "AgentCapabilityCredential"],
      "credentialSubject": {
        "id": "did:ethr:0x14f69:0xHOLDER",
        "auditScore": 87,
        "modelHash": "0x…",
        "operatorJurisdiction": "US",
        "capabilities": ["evm-execution", "risk-assessment"],
        "auditedBy": "did:ethr:0x14f69:0xISSUER",
        "auditDate": "2026-03-01"
      }
    }
  }
}
```

### 2.3 Credential Attributes and Circuit Encoding

Credential subject fields MUST be encoded into a 16-element `attributeValues[]` array at fixed indices before circuit input construction. Indices 6–15 are reserved and MUST be zero.

| Index | Field | Encoding |
|-------|-------|----------|
| 0 | `auditScore` | integer 0–100 |
| 1 | `modelHash` | uint256 (keccak256 of model hash string, truncated to BN254 field) |
| 2 | `operatorJurisdiction` | ISO 3166-1 numeric (US=840, GB=826, DE=276, FR=250, …) |
| 3 | `capabilities` | 8-bit bitmask (bit 0=evm-execution, bit 1=risk-assessment, …) |
| 4 | `auditedBy` | keccak256 of auditor DID string, truncated to 248 bits |
| 5 | `auditDate` | Unix timestamp (midnight UTC of YYYY-MM-DD) |
| 6–15 | Reserved | MUST be 0 |

Implementations MUST use the canonical bitmask encoding for capabilities:

| Capability | Bit |
|------------|-----|
| `evm-execution` | `0x01` |
| `risk-assessment` | `0x02` |
| `medical-analysis` | `0x04` |
| `kyc-verification` | `0x08` |
| `data-oracle` | `0x10` |

### 2.4 Issuance Protocol (OID4VCI)

Credential issuance MUST follow the OpenID for Verifiable Credential Issuance (OID4VCI) draft specification using the pre-authorized code grant.

Required steps:

1. Issuer publishes credential offer at `GET /.well-known/openid-credential-issuer`
2. Holder exchanges pre-authorized code for an access token at `POST /token`
3. Holder submits proof-of-possession JWT (`iss` = holder's `did:ethr`) with credential request at `POST /credentials`
4. Issuer verifies PoP JWT signature by resolving holder's `did:ethr` document
5. Issuer returns signed JWT-VC

Pre-authorized codes MUST be single-use. Implementations MUST reject replay of a code.

### 2.5 Presentation Protocol (OID4VP)

Presentation requests MUST follow the OpenID for Verifiable Presentations (OID4VP) draft specification. ACTA extends the base request with two custom fields:

| Field | Type | Description |
|-------|------|-------------|
| `x-openac-predicate` | JSON string | Serialised `PredicateProgram` including `schemaId`, `version`, `root` tree, and `hash` |
| `x-openac-policy-id` | `bytes32` hex | On-chain `policyId` the proof must satisfy |
| `x-onchain-verifier` | address | `GeneralizedPredicateVerifier` contract address |

The request `client_id` MUST equal the verifier's `did:ethr`. The request MUST include a `nonce` that is cryptographically unpredictable and single-use.

---

## Layer 3: ZK Privacy Layer

### 3.1 Circuit: OpenACGPPresentation

**File:** `circuits/presentation/OpenACGPPresentation.circom`
**Proving system:** Groth16 (BN254 curve)
**Dependency:** `circomlib` Poseidon hash

#### 3.1.1 Private Inputs

| Signal | Description |
|--------|-------------|
| `attributeValues[16]` | Credential subject fields at fixed indices (see §2.3) |
| `randomness` | Blinding factor for the credential commitment |
| `credentialCommitment` | On-chain commitment = `Poseidon(attributeValues[], randomness)` |
| `issuerPubKeyCommitmentPrivate` | `keccak256(compressedPubKey) & ((1 << 248) - 1)` |
| `verifierAddress` | Ethereum address of the verifier (field element) |
| `policyId` | `bytes32` policy identifier (field element) |
| `nonce` | `uint64` session nonce from OID4VP request |
| `expiryBlockPrivate` | Block number after which the presentation is invalid |
| `predicateAuditScoreMin` | Minimum audit score (0 = disabled) |
| `predicateCapabilityMask` | Required capability bitmask (0 = disabled) |
| `predicateJurisdictionSanctions[8]` | Banned jurisdiction numerics (0 = unused slot) |
| `predicateProgramHashPrivate` | Hash of the predicate program |

#### 3.1.2 Public Outputs

| Index | Signal | Description |
|-------|--------|-------------|
| 0 | `nullifier` | Context-scoped anonymous agent identifier |
| 1 | `contextHash` | `Poseidon(verifierAddress, policyId, nonce)` — on-chain Step 7 recomputes via `IPoseidonT4` |
| 2 | `predicateProgramHash` | Binds proof to specific policy |
| 3 | `issuerPubKeyCommitment` | Binds proof to specific trusted issuer |
| 4 | `credentialMerkleRoot` | Proves credential is current on-chain |
| 5 | `expiryBlock` | Enforces proof time-bounding |

#### 3.1.3 Circuit Constraints

The circuit MUST enforce all of the following:

**Constraint C1 — Credential commitment integrity:**
```
Poseidon(attributeValues[0..15], randomness) == credentialCommitment
```
Proves the prover knows the exact credential attributes corresponding to the on-chain commitment.

**Constraint C2 — Merkle root derivation:**

The circuit computes a 4-level binary Merkle tree over `attributeValues[]` using Poseidon pairwise hashing. Leaf pairs: `(attrs[0],attrs[1]), …, (attrs[14],attrs[15])`. The computed root is exposed as `credentialMerkleRoot`.

**Constraint C3a — Audit score predicate:**
```
(1 - GreaterEqThan(auditScore, predicateAuditScoreMin)) * predicateAuditScoreMin === 0
```
If `predicateAuditScoreMin > 0`, enforces `auditScore >= predicateAuditScoreMin`.

**Constraint C3b — Capabilities predicate:**
```
for each bit i in [0,7]:
  maskBit[i] * (1 - bitmaskBit[i]) === 0
```
For every bit set in `predicateCapabilityMask`, the corresponding bit in `attributeValues[3]` (capabilities bitmask) MUST be set.

**Constraint C3c — Sanctions jurisdiction predicate:**
```
for each slot j in [0,7]:
  IsEqual(attributeValues[2], predicateJurisdictionSanctions[j]) * predicateJurisdictionSanctions[j] === 0
```
If slot `j` is non-zero, the jurisdiction MUST NOT equal `predicateJurisdictionSanctions[j]`.

**Constraint C4 — Nullifier derivation:**
```
credentialSecret = Poseidon(credentialCommitment, randomness)
contextHashInner  = Poseidon(verifierAddress, policyId, nonce)
nullifier         = Poseidon(credentialSecret, contextHashInner)
```
The nullifier is deterministic for a given `(credential, verifier, policy, nonce)` tuple. It is computationally unlinkable across different contexts because `contextHashInner` varies by `(verifierAddress, policyId, nonce)`.

**Constraint C5 — Reserved attributes:**
```
for i in [6, 15]: attributeValues[i] === 0
```

#### 3.1.4 Context Hash — On-Chain Poseidon Verification

The circuit outputs `contextHash = Poseidon(verifierAddress, policyId, nonce)` as a public signal. In Step 7, `GeneralizedPredicateVerifier` recomputes the same value on-chain using a deployed `IPoseidonT4` contract and asserts equality with `pubSignals[1]`. This binds the proof to the exact `(caller, policyId, nonce)` triple and prevents front-running attacks where a different Ethereum address attempts to replay a captured proof.

Implementations MUST deploy an `IPoseidonT4` implementation whose `hash(a, b, c)` output matches circomlib's `Poseidon(3)` template over BN254 at the exact commit used during the trusted setup. The `GeneralizedPredicateVerifier` owner MUST call `setContextHasher(poseidonT4Address)` before any production use. If `contextHasher` is `address(0)`, Step 7 is skipped — this mode is permissible only for local Hardhat testing.

**SECURITY NOTE:** Running `verifyAndRegister()` with `contextHasher == address(0)` disables front-running protection. Any party who observes a pending transaction can replay it from a different address with full success. This MUST NOT occur on any public network.

### 3.2 Issuer Public Key Commitment

The issuer's secp256k1 compressed public key (33 bytes) MUST be committed as:

```
issuerPubKeyCommitment = keccak256(compressedPubKeyBytes) & ((1 << 248) - 1)
```

Truncation to 248 bits ensures the value fits within the BN254 scalar field.

---

## Layer 4: On-Chain Execution

### 4.1 Contract Registry

```
OpenACCredentialAnchor      — stores (commitment, merkleRoot) per (agentId, credentialType)
GeneralizedPredicateVerifier — 10-step atomic verifier; emits PresentationAccepted
NullifierRegistry            — context-scoped nullifier store with replay prevention
OpenACSnarkVerifier          — Groth16 verifier (generated from trusted setup)
AgentAccessGate              — example consumer; gates actions on isAccepted(nullifier)
```

### 4.2 Policy Registration

A verifier registers a policy once per compliance requirement:

```solidity
struct PolicyDescriptor {
    address  verifier;
    bytes32  predicateProgramHash;
    bytes32  credentialType;
    bytes32  circuitId;
    uint256  expiryBlock;      // 0 = no expiry
    bytes32  issuerCommitment;
    bool     active;
}

function registerPolicy(PolicyDescriptor calldata desc) external returns (bytes32 policyId);
```

`policyId` is deterministic:

```solidity
policyId = keccak256(abi.encode(
    desc.verifier, desc.predicateProgramHash, desc.credentialType,
    desc.circuitId, desc.expiryBlock, desc.issuerCommitment
));
```

Registered policies MUST NOT be modified. They MAY be deactivated by the original registrant.

### 4.3 10-Step Verification Sequence

`verifyAndRegister(policyId, proof, pubSignals, agentId, nonce)` MUST execute all 10 steps atomically. Any step that fails MUST revert the entire transaction.

| Step | Check | Reverts With |
|------|-------|--------------|
| 1 | Policy exists, is active, not expired | `PolicyNotFound`, `PolicyInactive`, `PolicyExpired` |
| 2 | `pubSignals.length == 6` | `InvalidPublicSignalCount` |
| 3 | `pubSignals[2] == policy.predicateProgramHash` | `PredicateHashMismatch` |
| 4 | `pubSignals[5] > block.number` | `ExpiryBlockPassed` |
| 5 | `credentialAnchor.isMerkleRootCurrent(agentId, credentialType, pubSignals[4])` | `MerkleRootNotCurrent` |
| 6 | `pubSignals[3] == policy.issuerCommitment` | `IssuerCommitmentMismatch` |
| 7 | `IPoseidonT4.hash(msg.sender, policyId, nonce) == pubSignals[1]` (requires `contextHasher != address(0)`) | `ContextHashMismatch` |
| 8 | `circuitVerifier.verifyProof(proof, pubSignals) == true` | `ProofInvalid` |
| 9 | `nullifierRegistry.register(nullifier, contextHash, expiryBlock)` | `NullifierAlreadyActive` |
| 10 | Emit `PresentationAccepted(policyId, nullifier, contextHash, caller, block.number)` | — |

### 4.4 Nullifier Registry

```solidity
function register(bytes32 nullifier, bytes32 contextHash, uint256 expiryBlock) external;
function isActive(bytes32 nullifier) external view returns (bool);
function revoke(bytes32 nullifier) external;
```

A nullifier is **active** if: it has been registered, has not been revoked, and `block.number <= expiryBlock`.

Nullifiers MUST be registered by authorised callers only (`lockAuthorization(address)` called by the owner). This prevents governance from silently revoking verifier access after credential issuance.

### 4.5 Consumer Contract Pattern

Consumer protocols SHOULD inherit `AgentAccessGate` and use the `onlyVerifiedAgent(nullifier)` modifier:

```solidity
function protectedAction(bytes32 nullifier, ...) external onlyVerifiedAgent(nullifier) {
    // Agent is verified — execute action
}
```

`onlyVerifiedAgent` MUST call `gpVerifier.isAcceptedForPolicy(nullifier, policyId)` using the gate's bound `policyId`. Calling the policy-agnostic `isAccepted(nullifier)` instead is a security error: a nullifier accepted under a weaker policy (lower audit score threshold) would be accepted by a gate configured for a stricter policy.

The `GeneralizedPredicateVerifier` exposes both methods:
- `isAccepted(nullifier)` — policy-agnostic, for informational queries
- `isAcceptedForPolicy(nullifier, policyId)` — REQUIRED for access gating

---

## Cryptographic Primitives

| Primitive | Usage | Parameters |
|-----------|-------|------------|
| Poseidon | Commitment, nullifier, Merkle tree, context hash | BN254 scalar field; circomlib parameters |
| Groth16 | SNARK proving and verification | BN254 curve; trusted setup required |
| secp256k1 / ES256K | DID keys, JWT signing, Ethereum transactions | Standard Ethereum parameters |
| keccak256 | On-chain context hash, issuer commitment, policyId | EVM native |
| SHA-256 | Reserved (not used in current circuit) | — |

Implementations MUST use the [circomlib Poseidon](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom) implementation with BN254 scalar field parameters. Different Poseidon configurations across prover and verifier WILL produce proof failures.

---

## Protocol Flow

A conforming implementation MUST execute the following steps in order:

### Phase 0 — Setup (One-time per deployment)

1. Deploy `NullifierRegistry`, `OpenACCredentialAnchor`, `GeneralizedPredicateVerifier`, `OpenACSnarkVerifier`
2. Deploy `IPoseidonT4` implementation (see `contracts/lib/PoseidonT4.sol` for interface and deployment instructions)
3. Call `setContextHasher(poseidonT4Address)` on `GeneralizedPredicateVerifier` — REQUIRED for Step 7 front-running protection
4. Call `registerCircuitVerifier(circuitId, snarkVerifierAddress)` on `GeneralizedPredicateVerifier`
5. Call `lockAuthorization(gpVerifierAddress)` on `NullifierRegistry`
6. Run Groth16 trusted setup ceremony; publish `.zkey` and verification key
7. Run Poseidon consistency test confirming on-chain `IPoseidonT4.hash()` output matches `snarkjs` Poseidon witness

### Phase 1 — Credential Issuance (Issuer → Holder)

1. Issuer creates `AgentCapabilityCredential` with subject attributes
2. Holder requests credential via OID4VCI pre-authorized code flow
3. Issuer verifies holder's proof-of-possession JWT; issues JWT-VC (`alg: ES256K`)
4. Holder stores JWT-VC

### Phase 2 — On-Chain Anchoring (Holder → Contract)

1. Holder computes `commitment = Poseidon(attributeValues[], randomness)`
2. Holder computes `merkleRoot` from `attributeValues[]`
3. Holder calls `credentialAnchor.anchorCredential(agentId, credentialType, commitment, merkleRoot)`

### Phase 3 — Policy Registration (Verifier → Contract, once per policy)

1. Verifier constructs `PredicateProgram` specifying audit score, capabilities, and jurisdiction constraints
2. Verifier computes `predicateProgramHash` (deterministic bytes32 of canonical program encoding)
3. Verifier calls `gpVerifier.registerPolicy(desc)` to obtain `policyId`

### Phase 4 — Presentation Request (Verifier → Holder)

1. Verifier generates session `nonce` (cryptographically unpredictable, single-use)
2. Verifier sends OID4VP authorization request with `x-openac-policy-id`, `x-openac-predicate`, `x-onchain-verifier`
3. Request `client_id` MUST equal verifier's `did:ethr`

### Phase 5 — Proof Generation (Holder, on-device)

1. Holder retrieves credential and verifies presentation request signature
2. Holder constructs circuit private inputs from credential attributes, randomness, and request parameters
3. Holder generates Groth16 proof using `OpenACGPPresentation` circuit
4. Holder assembles VP JWT (`iss` = holder's `did:ethr`) containing proof bytes and public signals

### Phase 6 — Verification (Verifier, two-phase)

**Off-chain pre-flight:**
1. Verifier verifies VP JWT signature (holder's `did:ethr`)
2. Verifier calls `snarkVerifier.verifyProof(proof, pubSignals)` locally
3. Verifier checks `pubSignals[3] == expectedIssuerCommitment`
4. Verifier checks `pubSignals[5] > currentBlock`

**On-chain commitment:**
1. Verifier calls `gpVerifier.verifyAndRegister(policyId, proof, pubSignals, agentId, nonce)`
2. All 10 steps execute atomically (§4.3)
3. `PresentationAccepted` event is emitted; nullifier is registered

### Phase 7 — Access Grant (Consumer Contract)

1. Consumer contract calls `gpVerifier.isAcceptedForPolicy(nullifier, policyId)` — returns `true`
2. Access is granted via `AgentAccessGate.grantAccess(nullifier)`; action executes
3. Replay attempt: `nullifierRegistry.register` reverts with `NullifierAlreadyActive`
4. If access is later revoked via `AgentAccessGate.revokeAccess(nullifier)`, the nullifier is permanently blocked and `grantAccess()` will always revert with `AccessPermanentlyRevoked`

---

## Proof Output Format

A conforming presentation MUST serialize its VP as a signed JWT with the following structure:

```json
{
  "header": { "alg": "ES256K", "typ": "JWT", "kid": "<holderDid>#controller" },
  "payload": {
    "iss": "<holderDid>",
    "aud": "<verifierDid>",
    "vp": {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "type": ["VerifiablePresentation"],
      "verifiableCredential": ["<JWT-VC>"]
    },
    "zkProof": {
      "proofBytes": "0x<256-byte Groth16 proof>",
      "publicSignals": {
        "nullifier": "0x<bytes32>",
        "contextHash": "0x<bytes32>",
        "predicateProgramHash": "0x<bytes32>",
        "issuerPubKeyCommitment": "0x<bytes32>",
        "credentialMerkleRoot": "0x<bytes32>",
        "expiryBlock": "<uint256>"
      }
    }
  }
}
```

---

## Error Handling

Implementations MUST handle the following error conditions:

| Error | Layer | Cause |
|-------|-------|-------|
| `NullifierAlreadyActive(bytes32)` | Contract | Replay: same proof submitted twice |
| `PredicateHashMismatch(bytes32, bytes32)` | Contract | Proof generated for different predicate |
| `MerkleRootNotCurrent(bytes32)` | Contract | Credential revoked, expired, or not yet anchored |
| `IssuerCommitmentMismatch(bytes32, bytes32)` | Contract | Credential issued by untrusted issuer |
| `ContextHashMismatch(bytes32, bytes32)` | Contract | Proof bound to different verifier or nonce |
| `ProofInvalid()` | Contract | Groth16 verification failed |
| `ExpiryBlockPassed(uint256, uint256)` | Contract | Presentation expired |
| `PolicyNotFound(bytes32)` | Contract | Unknown or never-registered policyId |
| `PolicyInactive(bytes32)` | Contract | Policy deactivated by registrant |

Off-chain error responses MUST include an error code, message, and available context.

---

## Interoperability Constraints

- Implementations MUST use the attribute index mapping defined in §2.3 for all circuit inputs. Deviation will produce proofs that fail on-chain with `ProofInvalid`.
- Implementations MUST use `circomlib` Poseidon with BN254 scalar field for all hash operations within the circuit.
- Implementations MUST use `IPoseidonT4.hash(uint256(msg.sender), uint256(policyId), nonce)` for the on-chain context hash (Step 7). Using `keccak256` for the on-chain check will always produce `ContextHashMismatch` because the circuit outputs Poseidon.
- The `policyId` computation MUST use `keccak256(abi.encode(...))` with the six-field canonical encoding defined in §4.2. Pre-computed `policyId` values shared between integrators MUST use this encoding.
- Capability bitmask encoding MUST use the bit positions defined in §2.3. Out-of-spec bitmask encodings will silently produce incorrect predicate results.

---

# Security Considerations

## Trust Model

The ACTA security model partitions trust into four independent assumptions. Each can be audited and replaced independently.

### T1 — Issuer Honesty

**Assumption:** The Issuer issues `AgentCapabilityCredential` only to agents it has independently verified against the claimed attributes.

**Scope:** ACTA enforces that the holder possesses a valid credential from the registered issuer that satisfies the predicate. It does NOT enforce that the issuer's certification process is sound. A dishonest issuer can issue high-score credentials to non-compliant agents.

**Mitigation:** The `issuerCommitment` field in each `PolicyDescriptor` binds a policy to a specific issuer key. Verifiers SHOULD maintain an allow-list of issuer commitments they trust. Credential issuers SHOULD be publicly identified and subject to external audit.

**Residual risk:** A compromised issuer key allows issuance of fraudulent credentials until the verifier updates `issuerCommitment`. Key rotation requires a new policy registration.

### T2 — ZK Proof Soundness

**Assumption:** Groth16 over BN254 is computationally sound under the algebraic group model and the hardness of the discrete logarithm on BN254.

**Scope:** A forged proof — asserting predicate satisfaction without a valid credential — would break Groth16 soundness.

**Known limitation:** Groth16 is not zero-knowledge for the verifier who can observe public signals. It provides *witness-indistinguishability* (the verifier cannot distinguish which credential was used among valid ones) but not full ZK with respect to the verification key.

### T3 — Poseidon Collision Resistance

**Assumption:** The Poseidon hash function (circomlib, BN254) is collision-resistant and second-preimage-resistant for the commitment and nullifier derivation.

**Scope:** If Poseidon is broken, an adversary could:
- Forge a credential commitment without knowing the attributes (breaks C1)
- Derive a nullifier collision, enabling double-spend in a single context (breaks C4)
- Find two different attribute sets with the same Merkle root (breaks C2)

**Note:** Poseidon is newer than SHA-256 and has had less cryptanalytic scrutiny. Production deployments SHOULD monitor the cryptographic literature.

### T4 — Trusted Setup Integrity

**Assumption:** The Groth16 proving key (`.zkey`) was generated by a Powers of Tau ceremony with at least one honest participant.

**Scope:** A ceremony participant who retains their toxic waste can construct a fake proof for any statement without a valid witness.

**Mitigation:** The trusted setup ceremony MUST be performed by multiple independent parties. The ceremony transcript MUST be published for public verification. The verification key MUST be derived from the published ceremony output.

**Residual risk:** A single-party setup is equivalent to a trusted oracle and MUST NOT be used in production.

### T5 — ERC-1056 Registry Integrity

**Assumption:** The `EthereumDIDRegistry` contract correctly records DID controller changes and has not been compromised.

**Scope:** A compromised registry could allow an attacker to rotate a DID's verification method to a key they control, allowing them to forge VP JWT signatures.

### T6 — IPoseidonT4 Implementation Correctness

**Assumption:** The deployed `IPoseidonT4` contract computes `Poseidon(a, b, c)` with the exact same constants as `circomlib`'s `Poseidon(3)` template on BN254.

**Scope:** If the implementation uses different constants or a different permutation structure, Step 7 will always fail (`ContextHashMismatch`) for valid proofs, or — more dangerously — always pass for an incorrect hash if the deviation is systematic.

**Mitigation:** Run the Poseidon consistency integration test (`test/PoseidonConsistency.test.ts`) before production deployment. This test computes a known witness via `snarkjs` and asserts that the Solidity contract returns the identical output.

**Residual risk:** A bug in the Poseidon implementation that produces correct output only for zero inputs would pass a na‌ïve unit test but fail for real proofs. Use differential testing with randomised inputs.

---

## Security Properties

### Replay Prevention

The nullifier `Poseidon(credentialSecret, Poseidon(verifierAddress, policyId, nonce))` is deterministic for a given credential and context. Once registered in `NullifierRegistry`, any second `register` call for the same nullifier reverts with `NullifierAlreadyActive`. This is enforced atomically in Step 9 of `verifyAndRegister`.

A verifier MUST use a fresh, unpredictable `nonce` for each presentation session. A nonce collision allows an existing valid proof to be reused in a new session.

### Cross-Context Unlinkability

Two presentations by the same agent to different verifiers, or to the same verifier under different policies or nonces, produce **computationally unlinkable nullifiers**. This holds under Poseidon collision resistance (T3).

Formally: given `nullifier_1 = Poseidon(s, ctx_1)` and `nullifier_2 = Poseidon(s, ctx_2)` where `ctx_1 ≠ ctx_2`, determining that both are derived from the same `s` requires computing a Poseidon preimage.

### Front-Running Protection

The context hash binds the proof to the **caller's address** (`msg.sender`) in Step 7. `GeneralizedPredicateVerifier` recomputes:

```solidity
expectedContextHash = contextHasher.hash(uint256(msg.sender), uint256(policyId), nonce)
```

where `contextHasher` is a deployed `IPoseidonT4` implementation. The result is compared to `pubSignals[1]`, which was computed in-circuit as `Poseidon(verifierAddress, policyId, nonce)`.

A front-runner who copies a pending `verifyAndRegister` transaction cannot substitute their own address: the on-chain recomputed hash uses `msg.sender`, so any address substitution produces a mismatch and the transaction reverts with `ContextHashMismatch`.

**REQUIREMENT:** `setContextHasher(address)` MUST be called with a valid `IPoseidonT4` contract before production deployment. See §4.3 Step 7.

### Credential Authenticity

Implementations MUST verify the ES256K signature of JWT-VCs before importing attributes into the ZK layer. `OpenACAdapter.importCredential()` resolves the issuer's `did:ethr`, extracts the secp256k1 public key, reconstructs the signature digest as `keccak256(header + '.' + payload)`, and verifies via `ecrecover`. A credential whose signature does not match the resolved issuer DID is rejected before any circuit computation.

Implementations MUST verify the ES256K signature of VP JWTs before off-chain pre-flight acceptance. `OffchainVerifier.verifyOffchain()` performs this check using the holder's resolved `did:ethr`.

### Policy-Scoped Access Gating

Consumer contracts using `AgentAccessGate` MUST call `gpVerifier.isAcceptedForPolicy(nullifier, policyId)` rather than the policy-agnostic `gpVerifier.isAccepted(nullifier)`. A nullifier accepted under a weaker policy (lower audit score threshold) MUST NOT grant access to a gate configured for a stricter policy. This is enforced in `AgentAccessGate.grantAccess()` and `ZKReputationAccumulator.increment()`.

### Reentrancy Safety

`GeneralizedPredicateVerifier.verifyAndRegister()` carries the `nonReentrant` modifier (OpenZeppelin `ReentrancyGuard`). All three external calls made during verification (`credentialAnchor`, `circuitVerifier`, `nullifierRegistry`) are to addresses fixed at construction time and cannot be reassigned without owner action.

### Emergency Pause

The owner MAY call `pause()` on `GeneralizedPredicateVerifier` to halt `verifyAndRegister()` and `registerPolicy()` in response to a discovered vulnerability. `unpause()` resumes normal operation. Pausing does not affect previously accepted nullifiers or granted access.

### Credential Binding

Step 5 calls `credentialAnchor.isMerkleRootCurrent(agentId, credentialType, merkleRoot)`. This ensures the agent's credential is still anchored and has not been revoked or superseded. A credential that has been re-anchored with a new `merkleRoot` (e.g., after attribute update) invalidates all proofs based on the old Merkle root.

### Issuer Binding

Step 6 checks `pubSignals[3] == policy.issuerCommitment`. This prevents accepting a proof generated from a credential issued by a different (potentially attacker-controlled) issuer.

### Circuit Binding

The `circuitId` field in `PolicyDescriptor` maps to a specific `ICircuitVerifier` implementation. A verifier CANNOT accept proofs from a weaker or substituted proving system unless they register a new policy pointing to a different circuit ID.

---

## Linkability Analysis

### On-Chain Metadata

When `verifyAndRegister` is called, the following data is publicly observable on-chain:

- `msg.sender` (the verifier's address)
- `policyId` (reveals which policy was verified)
- `nullifier` (anonymous but permanent; logs one verification event per context)
- `block.number` and transaction timestamp
- Gas fee and transaction sender (may link to verifier's operational wallet)

Nullifiers themselves do not reveal agent identity. However, patterns in the set of nullifiers emitted for a given `policyId` over time may provide statistical inference about deployment activity.

### Off-Chain Metadata

The VP JWT is transmitted between holder and verifier off-chain. The verifier learns:

- The holder's `did:ethr` (from VP JWT `iss`)
- The VP timing and IP address (if not relayed)
- The six public signals (non-attributable to a real-world identity)

Implementations SHOULD route VP submissions through a privacy-preserving relay to prevent IP address linkage between the holder and the on-chain transaction.

### Agent Self-Identification Risk

The holder's `did:ethr` is included in the VP JWT as `iss`. If the verifier logs VP JWTs, they hold a mapping from `did:ethr` to `nullifier`. Cross-context linkage is possible if the same `did:ethr` is observed across multiple verifiers.

**Mitigation:** Holders MAY use a fresh `did:ethr` per verifier relationship. This requires a separate credential issuance flow per DID.

---

## Known Limitations

### L1 — Single Predicate Structure (v0.1)

The circuit supports exactly three predicate types: minimum audit score, capability bitmask inclusion, and jurisdiction exclusion list. It does not support arbitrary boolean combinations, range proofs over multiple attributes, or attribute equality checks.

### L2 — Static Attribute Set (v0.1)

The `AgentCapabilityCredential` schema is fixed at 16 attribute slots. Adding new credential attributes requires a circuit upgrade, a new trusted setup, and re-anchoring of all credentials.

### L3 — No Device Binding (v0.1)

The credential and proving key are portable across devices. Credential theft (exfiltration of the private key and credential) allows an attacker to generate valid proofs indefinitely until the issuer revokes the credential.

### L4 — Revocation Latency

Credential revocation requires the issuer to trigger re-anchoring with a new `merkleRoot` (or zero out the anchor). There is no push-revocation mechanism. A revoked agent can continue to generate valid proofs until their old `merkleRoot` is superseded on-chain.

### L5 — Trusted Setup Required

Groth16 requires a per-circuit trusted setup ceremony. Unlike transparent proof systems (e.g., STARKs, Spartan2), a compromised ceremony cannot be detected post-hoc. This creates a one-time supply-chain risk at deployment.

---

# Implementation Notes

A reference implementation is available at [github.com/privacy-ethereum/acta-poc](https://github.com/privacy-ethereum/acta-poc).

The reference implementation provides:

- `packages/issuer` — Credo.ts + OID4VCI issuance server (Express, port 3001)
- `packages/holder` — Credo.ts + OpenAC wallet-unit-poc adapter (Express, port 3002)
- `packages/verifier` — Credo.ts + OID4VP + policy SDK (Express, port 3003)
- `packages/contracts` — Hardhat + Solidity (`^0.8.24`) + OpenZeppelin 5.x
- `circuits/` — Circom 2.x ZK circuit (`OpenACGPPresentation`)
- `packages/demo-app` — Interactive 10-step React demo (no backend required)

Implementations SHOULD provide test vectors for:

- Attribute index encoding (§2.3)
- Commitment computation: `Poseidon(attributeValues[], randomness)`
- Nullifier derivation: `Poseidon(Poseidon(commitment, randomness), Poseidon(verifier, policy, nonce))`
- `policyId` derivation: `keccak256(abi.encode(verifier, predicateHash, credType, circuitId, expiry, issuerCommitment))`
- On-chain context hash: `keccak256(abi.encodePacked(callerAddress, policyId, nonce))`

The `wallet-unit-poc` library from [github.com/privacy-ethereum/zkID](https://github.com/privacy-ethereum/zkID) provides the Groth16 proof generation backend. If unavailable, the `StubWalletUnit` fallback generates deterministic test proofs accepted by `OpenACSnarkVerifier` in test mode via the `OPENAC_TEST_PROOF_V1` sentinel value.

---

# References

- [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt) — Key Words for Use in RFCs
- [W3C Verifiable Credentials Data Model 1.1](https://www.w3.org/TR/vc-data-model/)
- [OpenID for Verifiable Credential Issuance (OID4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID for Verifiable Presentations (OID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [EIP-1056 — Ethereum DID Registry](https://eips.ethereum.org/EIPS/eip-1056)
- [Groth16 — On the Size of Pairing-based Non-interactive Arguments](https://eprint.iacr.org/2016/260)
- [Poseidon Hash Function](https://eprint.iacr.org/2019/458)
- [circomlib Poseidon](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom)
- [OpenAC (paper)](https://github.com/privacy-ethereum/zkID/blob/main/paper/zkID.pdf)
- [BN254 Elliptic Curve Parameters](https://eips.ethereum.org/EIPS/eip-196)
- [OpenID Foundation: Identity Management for Agentic AI (Oct 2025)](https://openid.net/wp-content/uploads/2025/10/Identity-Management-for-Agentic-AI.pdf)
- [5/ZK-HUMAN-VERIFICATION](https://github.com/privacy-ethereum/zkspecs/tree/main/specs/5) — Closely related nullifier and certificate verification pattern

---

# Glossary

## AgentCapabilityCredential

A W3C Verifiable Credential (`type: AgentCapabilityCredential`) containing AI agent compliance attributes: audit score, model hash, operator jurisdiction, capability bitmask, auditor DID, and audit date.

## Commitment

`Poseidon(attributeValues[], randomness)` — a hiding and binding commitment to the credential attributes. Stored on-chain in `OpenACCredentialAnchor`.

## Context Hash

`keccak256(abi.encodePacked(verifierAddress, policyId, nonce))` — binds a presentation to a specific verifier session. Prevents front-running and cross-session reuse.

## Credential Merkle Root

A 4-level Poseidon Merkle tree root over `attributeValues[]`. Stored alongside the commitment in `OpenACCredentialAnchor`. Enables attribute membership proofs.

## Groth16

A succinct non-interactive proof system requiring a per-circuit trusted setup. Used in ACTA because it produces constant-size proofs (256 bytes) and supports cheap on-chain verification via a precompile-compatible pairing check.

## Issuer Commitment

`keccak256(compressedPubKeyBytes) & ((1 << 248) - 1)` — a field-element commitment to the issuer's secp256k1 public key. Bound to `PolicyDescriptor.issuerCommitment`; checked in Step 6 of verification.

## Nullifier

`Poseidon(credentialSecret, contextHash)` where `credentialSecret = Poseidon(commitment, randomness)`. A deterministic, context-scoped anonymous identifier. The same credential produces a different nullifier for every `(verifier, policy, nonce)` triple.

## Policy

An on-chain `PolicyDescriptor` that binds a verifier, a predicate program hash, a circuit ID, an issuer commitment, and an optional expiry. Identified by `policyId`.

## Predicate Program

A structured logical formula over credential attributes (e.g., `auditScore ≥ 80 AND capabilities includes 'evm-execution'`). Hashed to `predicateProgramHash` for on-chain binding.

## Trusted Setup

A multi-party computation ceremony that produces the Groth16 proving key (`.zkey`) and verification key from a shared random secret that is subsequently destroyed. At least one participant must be honest for the setup to be secure.

---

# Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
