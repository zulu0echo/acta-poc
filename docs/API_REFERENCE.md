# ACTA Verifier SDK — API Reference

Complete API reference for integrating ACTA credential verification into your protocol.

> **Version note (post-audit, v0.2):** This reference reflects all fixes from the v0.1 and v0.2 security reviews.
> v0.1: `verifyJwtSignature`, `isAcceptedForPolicy`, `setContextHasher`, `buildLogicalTree`, `ActiveAnchorExists`, `AccessPermanentlyRevoked`, nonce `keccak256` derivation.
> v0.2: contextHash input contract changed (raw verifier/policy/nonce, not pre-computed hash); `importCredential` now requires and returns `randomnessHex` for restart-safe re-import; bearer token validated in `/credentials`; PoP JWT signature verified; SSRF guards on `response_uri`; session nonce lookup requires `state` = `sessionId`; `NullifierRegistry.register()` prevents all re-registration; `KeyType.K256` (not P256) in Credo; private key no longer logged.

---

## PredicateBuilder

**Import:** `import { PredicateBuilder } from '@acta/verifier/src/predicateBuilder'`

### `new PredicateBuilder(schemaId: string)`

Creates a new predicate builder for the given credential type.

| Parameter | Type | Description |
|-----------|------|-------------|
| `schemaId` | `string` | Credential type identifier (e.g. `"AgentCapabilityCredential"`) |

### `require(attribute: string): AttributeConstraint`

Starts a condition for the named attribute.

| Parameter | Type | Description |
|-----------|------|-------------|
| `attribute` | `string` | Attribute name from `AgentCapabilityCredentialSubject` |

**Returns:** `AttributeConstraint` — chain an operator method to complete the condition.

### `and(): PredicateBuilder`

Adds an AND connective before the next condition.

### `or(): PredicateBuilder`

Adds an OR connective before the next condition.

> **Note:** Mixed `and()` / `or()` connectives are correctly handled via left-associative binary tree construction. Each condition's connective is honoured independently, producing correct predicate hashes for compound logic. This matches the fix for the `buildLogicalTree()` bug identified in the security review.

### `not(): PredicateBuilder`

Adds a NOT connective before the next condition.

### `build(): BuiltPredicate`

Compiles all conditions into a validated, hashed `BuiltPredicate`.

**Throws:** `Error` if no conditions are added, or if the predicate is structurally invalid.

### `PredicateBuilder.fromAgentOperators(schemaId, operators): BuiltPredicate`

Convenience method. Builds a predicate from an array of `AgentPredicateOperator` objects, all AND-ed together.

---

## AttributeConstraint

Returned by `PredicateBuilder.require()`. Chain one operator method to return the builder.

| Method | Parameters | Description |
|--------|-----------|-------------|
| `greaterThanOrEqual(value)` | `number` | `attribute >= value` |
| `lessThanOrEqual(value)` | `number` | `attribute <= value` |
| `equals(value)` | `string \| number` | `attribute == value` |
| `notEquals(value)` | `string \| number` | `attribute != value` |
| `includes(value)` | `string` | array attribute includes value |
| `notIn(values)` | `string[]` | attribute is not in the given list |
| `between(min, max)` | `number, number` | `min <= attribute <= max` |

---

## BuiltPredicate

Returned by `PredicateBuilder.build()`.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `hash` | `string` | Deterministic bytes32 hash of the predicate (on-chain representation) |
| `raw` | `PredicateProgram` | The raw predicate program object |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `toJSON()` | `string` | JSON string for embedding in OID4VP `x-openac-predicate` |
| `toDescription()` | `string` | Human-readable description for UI display |

---

## PresentationRequestBuilder

**Import:** `import { PresentationRequestBuilder } from '@acta/verifier/src/presentationRequest'`

### `new PresentationRequestBuilder(identity: EthrDIDIdentity)`

Creates a request builder authenticated as the given did:ethr identity.

### `createPresentationRequest(params): PresentationRequestResult`

Creates an OID4VP authorization request.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `params.policyId` | `string` | bytes32 policyId from `PolicyRegistry.registerPolicy()` |
| `params.predicate` | `BuiltPredicate` | The predicate to embed in the request |
| `params.verifierCallbackUrl` | `string` | URL the agent posts the VP to |
| `params.sessionNonce` | `bigint` | Unique session nonce (prevents request replay) |
| `params.onchainVerifierAddress` | `string` | `GeneralizedPredicateVerifier` address |

**Returns:** `PresentationRequestResult`

```typescript
interface PresentationRequestResult {
  requestUri: string           // "openid4vp://?request=…" — send to agent
  authorizationRequest: OID4VPAuthRequest
  sessionId: string            // UUID for tracking this session
}
```

---

## OffchainVerifier

**Import:** `import { OffchainVerifier } from '@acta/verifier/src/offchainVerifier'`

### `new OffchainVerifier(identity: EthrDIDIdentity)`

### `verifyOffchain(params): Promise<{ valid: boolean; reason?: string; timingMs?: number }>`

Runs off-chain pre-flight verification before on-chain submission.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `params.presentation` | `OpenACPresentation` | The ZK presentation from the holder's VP |
| `params.policyId` | `string` | bytes32 policyId |
| `params.issuerDid` | `string` | Issuer's `did:ethr` (for commitment verification) |
| `params.vpJwt` | `string` | The VP JWT from the holder |
| `params.holderDid` | `string` | Holder's `did:ethr` (for VP signature check) |

**Returns:**

| Field | Type | Description |
|-------|------|-------------|
| `valid` | `boolean` | `true` if all checks pass |
| `reason` | `string?` | Failure reason (if `valid = false`) |
| `timingMs` | `number?` | Off-chain verification time in milliseconds |

**Verification steps performed:**

| Step | Check |
|------|-------|
| 1 | VP JWT ES256K signature verified against holder's resolved `did:ethr` key |
| 2 | VP JWT `iss` claim matches `holderDid` |
| 3 | VP JWT contains `verifiableCredential` and `zkProof` fields |
| 4 | Groth16 proof bytes pass local snark verification |
| 5 | `pubSignals[3]` (issuerPubKeyCommitment) matches resolved issuer DID |
| 6 | `pubSignals[5]` (expiryBlock) > current block |

**Errors:**
- `"ZK proof invalid: …"` — proof bytes are invalid
- `"VP JWT invalid: …"` — VP JWT structure is malformed (not 3 parts)
- `"VP JWT signature invalid"` — ES256K signature does not match resolved holder DID key
- `"Presentation expired at block …"` — expiryBlock has passed

---

## OnchainSubmitter

**Import:** `import { OnchainSubmitter } from '@acta/verifier/src/onchainSubmitter'`

### `new OnchainSubmitter(identity: EthrDIDIdentity, gpVerifierAddress: string)`

### `submit(params): Promise<OnchainSubmitResult>`

Submits a ZK presentation to `GeneralizedPredicateVerifier.verifyAndRegister()`.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `params.policyId` | `string` | bytes32 policyId |
| `params.presentation` | `OpenACPresentation` | The ZK presentation |
| `params.agentDid` | `string` | Agent's `did:ethr` (used to extract `agentId`) |
| `params.nonce` | `bigint` | Session nonce (must match the OID4VP request nonce) |

**Returns:** `OnchainSubmitResult`

```typescript
interface OnchainSubmitResult {
  txHash: string
  blockNumber: number
  gasUsed: string
  nullifier: string
  presentationAcceptedEvent: {
    policyId: string
    nullifier: string
    contextHash: string
    blockNumber: number
  }
}
```

**Reverts (from GeneralizedPredicateVerifier):**

| Error | Step | Cause |
|-------|------|-------|
| `PolicyNotFound(bytes32)` | 1 | policyId not registered |
| `PolicyInactive(bytes32)` | 1 | Policy deactivated |
| `PolicyExpired(bytes32, uint256)` | 1 | expiryBlock passed |
| `InvalidPublicSignalCount(uint256, uint256)` | 2 | pubSignals.length ≠ 6 |
| `PredicateHashMismatch(bytes32, bytes32)` | 3 | Wrong predicate |
| `ExpiryBlockPassed(uint256, uint256)` | 4 | Proof expired |
| `MerkleRootNotCurrent(bytes32)` | 5 | Credential not anchored or revoked |
| `IssuerCommitmentMismatch(bytes32, bytes32)` | 6 | Wrong issuer key |
| `ContextHashMismatch(bytes32, bytes32)` | 7 | Poseidon(msg.sender, policyId, nonce) mismatch — also thrown if contextHasher is address(0) and callee is not address(0) |
| `CircuitVerifierNotRegistered(bytes32)` | 8 | No verifier for circuitId |
| `ProofInvalid()` | 8 | Groth16 verification failed |
| `NullifierAlreadyActive(bytes32)` | 9 | Nullifier already seen — replay, or attempt to re-register after revocation/expiry. Once registered, a nullifier is permanently blocked from re-registration. |
| `EnforcedPause()` | — | Contract is paused (verifyAndRegister or registerPolicy) |

---

## GeneralizedPredicateVerifier (owner-only admin)

**Import:** `import { GeneralizedPredicateVerifier__factory } from '@acta/contracts/typechain-types'`

### `setContextHasher(address hasher)`

Sets the `IPoseidonT4` implementation used in Step 7 to recompute `Poseidon(msg.sender, policyId, nonce)`.

**REQUIRED for production.** If not set (`address(0)`), Step 7 is skipped — front-running protection is disabled.

```typescript
await gpVerifier.connect(owner).setContextHasher(poseidonT4Address)
// Emits: ContextHasherSet(address indexed hasher)
```

### `pause() / unpause()`

Halts / resumes `verifyAndRegister()` and `registerPolicy()`. Emergency controls.

```typescript
await gpVerifier.connect(owner).pause()    // halts all state changes
await gpVerifier.connect(owner).unpause()  // resumes
// Emits: Paused(address account) / Unpaused(address account)
```

### `registerCircuitVerifier(bytes32 circuitId, address verifier)`

Registers a Groth16 verifier implementation for a circuit ID. Call once during setup.

---

## PolicyRegistry

**Import:** `import { PolicyRegistry } from '@acta/verifier/src/policyRegistry'`

### `new PolicyRegistry(identity: EthrDIDIdentity, gpVerifierAddress: string)`

### `registerPolicy(predicate, issuerCommitment, expiryBlock?): Promise<string>`

Registers a predicate policy on-chain.

| Parameter | Type | Description |
|-----------|------|-------------|
| `predicate` | `BuiltPredicate` | The compiled predicate |
| `issuerCommitment` | `string` | bytes32 Poseidon commitment of the trusted issuer's public key |
| `expiryBlock` | `number?` | Block number for policy expiry (default: `0` = never) |

**Returns:** `string` — bytes32 `policyId`

**Emits:** `PolicyRegistered(policyId, verifier, predicateProgramHash, circuitId)`

### `getPolicy(policyId: string): PolicyDescriptor | undefined`

Returns the local (in-memory) `PolicyDescriptor` for a registered policy.

### `getAllPolicies(): PolicyDescriptor[]`

Returns all policies registered in this session.

---

## OpenACAdapter

**Import:** `import { OpenACAdapter } from '@acta/holder/src/openacAdapter'`

### `new OpenACAdapter()`

Falls back to `StubWalletUnit` if `wallet-unit-poc` is not installed.

### `importCredential(jwtVc, issuerDid, resolver, randomnessHex?): Promise<CredentialHandle & { randomnessHex }>`

Imports a JWT-VC into OpenAC. Cryptographically verifies the ES256K signature against the resolved issuer DID — **hard failure if DID resolution fails or signature is invalid** (no silent bypass).

| Parameter | Type | Description |
|-----------|------|-------------|
| `jwtVc` | `string` | Compact JWT-VC string (3-part: header.payload.signature) |
| `issuerDid` | `string` | Issuer's `did:ethr` (for DID resolution and signature verification) |
| `resolver` | `Resolver` | DID resolver (from `createEthrDIDIdentity`) |
| `randomnessHex?` | `string?` | Previously persisted BN254 randomness (hex, no 0x). Supply on re-import to reproduce the same on-chain commitment. Omit on first import — fresh randomness is generated. |

**Returns:** `CredentialHandle & { credentialId: string; randomnessHex: string }`

> **IMPORTANT:** Persist `randomnessHex` alongside the credential (e.g., via `CredentialStore.setAnchorData()`). A server restart clears the in-memory handle cache; if `randomnessHex` is not persisted, re-import generates a different commitment and fails with `CommitmentAlreadyAnchored` on the on-chain anchor.

**Throws:**
- `"Cannot import credential: failed to resolve issuer DID …"` — DID resolution failure (hard error, was previously a silent warning)
- `"Cannot verify JWT-VC signature: issuer address not parseable …"` — malformed DID
- `"JWT-VC signature verification failed: credential not signed by issuer …"` — ES256K mismatch
- `"Invalid JWT-VC: expected 3 parts"` — malformed JWT
- `"Invalid JWT-VC: failed to parse payload"` — non-JSON payload

### `verifyJwtSignature(jwt, signerAddress): boolean`

**Export:** `import { verifyJwtSignature } from '@acta/holder/src/openacAdapter'`

Cryptographically verifies an ES256K-signed JWT (JWT-VC or VP JWT) against an Ethereum address.

| Parameter | Type | Description |
|-----------|------|-------------|
| `jwt` | `string` | Compact JWT string (`header.payload.signature`) |
| `signerAddress` | `string` | Expected Ethereum address of the signer |

Reconstructs the digest as `keccak256(header + '.' + payload)` and calls `ethers.recoverAddress` with both `v=27` and `v=28` recovery values. Returns `true` if either matches `signerAddress` (case-insensitive).

**Returns:** `boolean` — `true` if the JWT was signed by `signerAddress`

---

### `generatePresentationProof(params): Promise<OpenACPresentation>`

Generates a Groth16 ZK proof. Passes `verifierAddress`, `policyId`, and `nonce` as **separate raw inputs** to the wallet unit, not as a pre-computed `contextHash`. This allows the real `wallet-unit-poc` to compute `Poseidon(verifier, policy, nonce)` internally, matching the circuit constraint and on-chain `IPoseidonT4` Step 7.

| Parameter | Type | Description |
|-----------|------|-------------|
| `params.credentialHandle` | `CredentialHandle` | From `importCredential()` |
| `params.predicateProgram` | `PredicateProgram` | From `PredicateBuilder.build().raw` |
| `params.policyId` | `string` | bytes32 policyId |
| `params.verifierAddress` | `string` | Ethereum address of the verifier |
| `params.nonce` | `bigint` | Session nonce from OID4VP request (derived as `keccak256(nonceStr) & 0xFFFFFFFFFFFFFFFFn`) |
| `params.expiryBlock` | `number` | Block number for proof expiry |

**Returns:** `OpenACPresentation`

```typescript
interface OpenACPresentation {
  proofBytes: string        // "0x…" — 256-byte hex Groth16 proof
  publicSignals: PublicSignals
  contextHash: string       // bytes32
}
```

### `verifyPresentation(presentation, policyId, issuerDid, resolver): Promise<{ valid: boolean; reason? }>`

Off-chain proof verification.

---

## AgentPredicateOperator

Advanced operator types for the ACTA agent-specific predicate model:

```typescript
type AgentPredicateOperator =
  | { op: 'capability_includes'; capabilityId: string }
    // → capabilities bitmask has the given bit set
  | { op: 'audit_score_gte'; threshold: number }
    // → auditScore >= threshold
  | { op: 'model_hash_in'; trustedSet: string[] }
    // → modelHash is one of the trusted hashes
  | { op: 'jurisdiction_not_in'; sanctionsList: string[] }
    // → operatorJurisdiction is NOT in the sanctions list
  | { op: 'delegation_depth_lte'; maxDepth: number }
    // → delegationDepth <= maxDepth (ACTA §4.8)
    // maxDepth=1 requires direct human delegation
  | { op: 'principal_vc_satisfies'; innerPredicate: ... }
    // → principal's VC satisfies an inner predicate (recursive)
    // Used for delegated agent chains (OBO model)
  | { op: 'delegation_scope_includes'; scopeId: string }
    // → agent's delegated authority covers the given action scope
    // Supports OpenID Foundation (2025) §3.2 offline scope attenuation
```

Use with `PredicateBuilder.fromAgentOperators()` for the most concise API.

---

## Nonce Derivation

Both `PresentationHandler` (holder) and `PresentationRequestBuilder` (verifier) derive a `uint64` nonce from the OID4VP request's `nonce` string using:

```typescript
const nonceHashHex = ethers.keccak256(ethers.toUtf8Bytes(authRequest.nonce))
const nonce = BigInt(nonceHashHex) & 0xFFFFFFFFFFFFFFFFn
```

This ensures a full 64-bit deterministic nonce regardless of the input string's character set or encoding. **Both sides must use this same derivation** for Step 7's `contextHash` comparison to succeed.

## VP Callback Session Matching

The verifier's `/verify-callback/:policyId` endpoint requires the VP response to include `state: sessionId` in the POST body, where `sessionId` was returned by `/presentation-request`. This ensures the correct `nonce` is used for on-chain submission.

```typescript
// Holder submits VP:
await axios.post(authRequest.response_uri, {
  vp_token: vpJwt,
  state: authRequest.nonce,   // ← must be the sessionId from /presentation-request
})
```

Sessions older than 10 minutes are automatically purged. Sessions are deleted after successful on-chain submission to prevent reuse.

---

## OpenACCredentialAnchor Errors

| Error | Cause | Resolution |
|-------|-------|------------|
| `AgentIdMismatch(uint256 agentId, address sender)` | `msg.sender` does not equal `address(uint160(agentId))` | Caller must be the DID controller |
| `ActiveAnchorExists(uint256 agentId, bytes32 credentialType)` | `anchorCredential()` called when a live, non-revoked anchor already exists | Use `rotateCredential()` to update — prevents silent overwrites |
| `CommitmentAlreadyAnchored(bytes32 commitment)` | Same commitment reused | Generate new `randomness` before re-import |
| `NoActiveCredential(uint256 agentId, bytes32 credentialType)` | `rotateCredential()` with no existing anchor | Call `anchorCredential()` first |
| `CredentialRevoked(uint256 agentId, bytes32 credentialType)` | Operation on revoked credential | Re-anchor after revocation |

---

## AgentAccessGate Errors

| Error | Cause | Resolution |
|-------|-------|------------|
| `PresentationNotAccepted(bytes32 nullifier)` | `isAcceptedForPolicy()` returned false | Run `verifyAndRegister()` under the correct `policyId` first |
| `AccessAlreadyGranted(bytes32 nullifier)` | `grantAccess()` called twice | Check `isAccessGranted()` before calling |
| `AccessPermanentlyRevoked(bytes32 nullifier)` | `grantAccess()` called after `revokeAccess()` | Permanent — agent must re-present with a fresh nonce to create a new nullifier |
| `AccessNotGranted(bytes32 nullifier)` | `onlyVerifiedAgent` modifier failed | Call `grantAccess()` after successful `verifyAndRegister()` |
