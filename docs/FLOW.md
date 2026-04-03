# ACTA End-to-End Flow — Step-by-Step with Function Calls

This document covers the complete flow with exact function calls, including did:ethr identity creation.

---

## Step 0: Setup (One-time per deployment)

### 0a. Create did:ethr identities

```typescript
import { createEthrDIDIdentity } from '@acta/issuer/src/didEthrSetup'

const issuerIdentity   = await createEthrDIDIdentity(process.env.ISSUER_PRIVATE_KEY)
const holderIdentity   = await createEthrDIDIdentity(process.env.HOLDER_PRIVATE_KEY)
const verifierIdentity = await createEthrDIDIdentity(process.env.VERIFIER_PRIVATE_KEY)

// Each identity has the form:
// { did: "did:ethr:0x14f69:0x<address>", signer, provider, ethrDid, resolver }
```

### 0b. Deploy contracts

```bash
cd packages/contracts && npx hardhat run scripts/deploy.ts --network localhost
# → deployments/localhost.json with all contract addresses
```

### 0c. Compile ZK circuit

```bash
cd packages/contracts && bash scripts/setup-circuits.sh
# → circuits/build/OpenACGPPresentation.zkey + OpenACGPPresentation_vk.json
```

---

## Step 1: Issuer Setup

### 1a. Start Credo.ts Issuer agent

```typescript
import { createIssuerAgent } from '@acta/issuer/src/agent'
const issuerAgent = await createIssuerAgent(issuerIdentity)
```

### 1b. Start Express server

```typescript
import { createIssuanceRouter } from '@acta/issuer/src/issuanceRoutes'
app.use('/', createIssuanceRouter(issuerIdentity))
// → GET /.well-known/openid-credential-issuer
// → GET /credential-offer
// → POST /token
// → POST /credentials
```

---

## Step 2: Holder Requests Credential (OID4VCI)

### 2a. GET /credential-offer

```
GET http://localhost:3001/credential-offer?holder_did=did:ethr:0x14f69:0xHOLDER
→ { offer_uri: "openid-credential-offer://...", offer: { pre-authorized_code: "pac_abc123" } }
```

### 2b. POST /token

```
POST http://localhost:3001/token
Body: grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=pac_abc123
→ { access_token: "at_xyz", c_nonce: "cn_123" }
```

### 2c. Build proof-of-possession JWT

```typescript
// iss = holderIdentity.did ("did:ethr:0x14f69:0xHOLDER")
// Signed with holder's secp256k1 key
// alg = ES256K
```

### 2d. POST /credentials

```
POST http://localhost:3001/credentials
Authorization: Bearer at_xyz
Body: { format: "jwt_vc_json", types: ["AgentCapabilityCredential"], proof: { jwt: "eyJ..." } }
→ { format: "jwt_vc_json", credential: "eyJ..." }  // JWT-VC
```

### 2e. Store credential

```typescript
import { CredentialStore } from '@acta/holder/src/credentialStore'
const credId = credentialStore.store({ jwt: jwtVc, decoded: vcPayload })
```

---

## Step 3: Holder Anchors Credential On-Chain

### 3a. Import credential into OpenAC

```typescript
import { OpenACAdapter } from '@acta/holder/src/openacAdapter'
const adapter = new OpenACAdapter()
const handle = await adapter.importCredential(jwtVc, issuerIdentity.did, holderIdentity.resolver)
// → { credentialId, commitment: "0x…", merkleRoot: "0x…" }
```

### 3b. Anchor on-chain

```typescript
const CREDENTIAL_TYPE = ethers.keccak256(ethers.toUtf8Bytes('AgentCapabilityCredential'))
const agentId = BigInt(holderIdentity.signer.address)

await credentialAnchor.connect(holderIdentity.signer).anchorCredential(
  agentId,          // uint256(uint160(holderAddress))
  CREDENTIAL_TYPE,
  handle.commitment,
  handle.merkleRoot
)
// → CredentialAnchored(agentId, credentialType, commitment, merkleRoot, anchoredAt)
```

---

## Step 4: Verifier Builds Predicate and Registers Policy

### 4a. Build predicate

```typescript
import { PredicateBuilder } from '@acta/verifier/src/predicateBuilder'
const predicate = new PredicateBuilder('AgentCapabilityCredential')
  .require('auditScore').greaterThanOrEqual(80)
  .and()
  .require('capabilities').includes('evm-execution')
  .and()
  .require('operatorJurisdiction').notIn(['IR', 'KP', 'RU', 'BY'])
  .build()
// predicate.hash → "0x…" (deterministic bytes32)
// predicate.toDescription() → "Audit Score ≥ 80 AND Capabilities includes "evm-execution" AND …"
```

### 4b. Register policy on-chain

```typescript
import { PolicyRegistry } from '@acta/verifier/src/policyRegistry'
const policyRegistry = new PolicyRegistry(verifierIdentity, GP_VERIFIER_ADDRESS)
const policyId = await policyRegistry.registerPolicy(predicate, issuerPubKeyCommitment)
// → "0x…" (bytes32 policyId)
// → PolicyRegistered(policyId, verifier, predicateProgramHash, circuitId)
```

---

## Step 5: Verifier Creates Presentation Request

```typescript
import { PresentationRequestBuilder } from '@acta/verifier/src/presentationRequest'
const requestBuilder = new PresentationRequestBuilder(verifierIdentity)
const { requestUri, authorizationRequest, sessionId } = requestBuilder.createPresentationRequest({
  policyId,
  predicate,
  verifierCallbackUrl: 'https://myprotocol.xyz/verify-callback/' + policyId,
  sessionNonce: crypto.getRandomValues(new BigUint64Array(1))[0],
  onchainVerifierAddress: GP_VERIFIER_ADDRESS,
})
// requestUri: "openid4vp://?request={…}"
// Send this to the agent via any channel
```

---

## Step 6: Holder Generates ZK Proof and Responds

```typescript
import { PresentationHandler } from '@acta/holder/src/presentationHandler'
const handler = new PresentationHandler(holderIdentity, credentialStore)
const response = await handler.handlePresentationRequest(authorizationRequest)
// → { vpJwt, zkProof, nullifier }
// VP JWT posted to authorizationRequest.response_uri
```

Internally:
```typescript
// adapter.generatePresentationProof() calls wallet-unit-poc
// → Groth16 proof with public signals: [nullifier, contextHash, predicateHash, …]
```

---

## Step 7: Verifier Verifies (Off-chain + On-chain)

### 7a. Off-chain verification

```typescript
import { OffchainVerifier } from '@acta/verifier/src/offchainVerifier'
const verifier = new OffchainVerifier(verifierIdentity)
const { valid, timingMs } = await verifier.verifyOffchain({
  presentation, policyId, issuerDid, vpJwt, holderDid
})
// valid: true, timingMs: ~50
```

### 7b. On-chain submission

```typescript
import { OnchainSubmitter } from '@acta/verifier/src/onchainSubmitter'
const submitter = new OnchainSubmitter(verifierIdentity, GP_VERIFIER_ADDRESS)
const { txHash, nullifier, presentationAcceptedEvent } = await submitter.submit({
  policyId, presentation, agentDid: holderIdentity.did, nonce
})
// → PresentationAccepted(policyId, nullifier, contextHash, verifier, blockNumber)
```

---

## Step 8: Smart Contract Acts on Verified Proof

```solidity
// Consumer contract
contract MyProtocol is AgentAccessGate {
    function submitTrade(bytes32 nullifier, TradeParams calldata params)
        external
        onlyVerifiedAgent(nullifier)   // ← Checks gpVerifier.isAccepted(nullifier)
    {
        // Execute trade
    }
}
```

Or manually:

```typescript
// Grant access
await agentAccessGate.connect(anyone).grantAccess(nullifier)
// AccessGranted(nullifier, blockNumber)

// Check access
await agentAccessGate.isAccessGranted(nullifier)  // → true

// Replay attempt
await agentAccessGate.grantAccess(nullifier)
// → revert AccessAlreadyGranted(nullifier)
```

---

## Error Reference

| Error | Step | Cause |
|-------|------|-------|
| `NullifierAlreadyActive` | 9 | Replay attack: same proof submitted twice |
| `PredicateHashMismatch` | 3 | Proof was generated for a different predicate |
| `MerkleRootNotCurrent` | 5 | Credential revoked or not yet anchored |
| `IssuerCommitmentMismatch` | 6 | Credential was issued by an untrusted issuer |
| `ContextHashMismatch` | 7 | Proof was generated for a different verifier/nonce |
| `ProofInvalid` | 8 | ZK proof is invalid (malformed or tampered) |
| `ExpiryBlockPassed` | 4 | Presentation has expired |
| `AgentIdMismatch` | anchor | msg.sender is not the DID controller for the agentId |
