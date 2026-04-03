import { useState, useEffect, useRef } from 'react'

const SECTIONS = [
  { id: 'overview',       label: 'Overview' },
  { id: 'architecture',   label: 'Architecture' },
  { id: 'credential',     label: 'Credential Schema' },
  { id: 'circuit',        label: 'ZK Circuit' },
  { id: 'contracts',      label: 'Smart Contracts' },
  { id: 'verifier-sdk',   label: 'Verifier SDK' },
  { id: 'holder-sdk',     label: 'Holder Integration' },
  { id: 'issuer-sdk',     label: 'Issuer Integration' },
  { id: 'deployment',     label: 'Deployment Guide' },
  { id: 'security',       label: 'Security Model' },
  { id: 'errors',         label: 'Error Reference' },
] as const

export default function DocsPage() {
  const [active, setActive] = useState('overview')
  const contentRef = useRef<HTMLDivElement>(null)
  const sectionRefs = useRef<Record<string, HTMLElement | null>>({})

  useEffect(() => {
    const el = contentRef.current
    if (!el) return
    const handler = () => {
      let current = 'overview'
      for (const { id } of SECTIONS) {
        const ref = sectionRefs.current[id]
        if (ref && ref.getBoundingClientRect().top - 120 < 0) current = id
      }
      setActive(current)
    }
    el.addEventListener('scroll', handler, { passive: true })
    return () => el.removeEventListener('scroll', handler)
  }, [])

  const scrollTo = (id: string) => {
    sectionRefs.current[id]?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  const ref = (id: string) => (el: HTMLElement | null) => { sectionRefs.current[id] = el }

  return (
    <div className="flex h-full overflow-hidden bg-dark-900">
      <nav className="w-52 flex-shrink-0 border-r border-gray-700/60 overflow-y-auto py-6 px-3">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-500 px-3 mb-3">Contents</p>
        {SECTIONS.map(s => (
          <button key={s.id} onClick={() => scrollTo(s.id)}
            className={`w-full text-left text-xs px-3 py-1.5 rounded-md mb-0.5 transition-colors ${
              active === s.id ? 'bg-brand-900/60 text-brand-300 font-medium' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/40'
            }`}>{s.label}</button>
        ))}
      </nav>

      <div ref={contentRef} className="flex-1 overflow-y-auto">
        <div className="max-w-3xl mx-auto px-8 py-10 text-sm text-gray-300 leading-relaxed">

          {/* ── Overview ───────────────────────────────────────────────── */}
          <Section id="overview" label="Overview" ref_={ref('overview')}>
            <div className="mb-6 p-4 rounded-xl bg-gradient-to-r from-brand-950/60 to-teal-950/30 border border-brand-700/30">
              <h2 className="text-xl font-bold text-white mb-1">Anonymous Credentials for Trustless Agents</h2>
              <p className="text-gray-400 text-xs">ACTA · v0.1 · Production Reference Implementation</p>
            </div>
            <P>ACTA is a four-layer protocol that allows AI agents to prove compliance with verifier-defined predicate policies — without disclosing credential attributes — and receive on-chain access rights whose scope is permanently bounded to a single (verifier, policy, nonce) context.</P>
            <P>A Groth16 SNARK proves that a W3C Verifiable Credential satisfies conditions such as <C>auditScore ≥ 80 AND capabilities includes 'evm-execution' AND jurisdiction NOT IN ['IR','KP']</C> while exposing only six public signals. Replay attacks are prevented deterministically: a context-scoped nullifier is stored permanently on first registration and any duplicate submission reverts.</P>
            <H3>Key Properties</H3>
            <ul className="space-y-1.5 ml-4 list-disc text-gray-400">
              <li><span className="text-gray-200 font-medium">Privacy by default.</span> Credential attributes are never revealed on-chain.</li>
              <li><span className="text-gray-200 font-medium">Cross-context unlinkability.</span> The same credential produces a distinct nullifier for every (verifier, policy, nonce) triple.</li>
              <li><span className="text-gray-200 font-medium">Atomic on-chain enforcement.</span> A 10-step verification sequence in <C>GeneralizedPredicateVerifier</C> executes atomically; partial failures revert fully.</li>
              <li><span className="text-gray-200 font-medium">Reentrancy-safe.</span> <C>verifyAndRegister()</C> is protected by <C>ReentrancyGuard</C>.</li>
              <li><span className="text-gray-200 font-medium">Front-running resistant.</span> Context hash binds the proof to caller address via on-chain Poseidon verification.</li>
              <li><span className="text-gray-200 font-medium">Emergency pausable.</span> Owner can halt all state changes instantly via <C>pause()</C>.</li>
              <li><span className="text-gray-200 font-medium">Composable.</span> Consumer contracts inherit <C>AgentAccessGate</C> and use a single modifier.</li>
            </ul>
            <H3>Quick Start</H3>
            <CB>{`# 1. Install
npm install @acta/verifier @acta/shared

# 2. Define your compliance requirement
const predicate = new PredicateBuilder('AgentCapabilityCredential')
  .require('auditScore').greaterThanOrEqual(80)
  .and()
  .require('capabilities').includes('evm-execution')
  .build()

# 3. Register policy once
const policyId = await policyRegistry.registerPolicy(predicate, issuerCommitment)

# 4. When an agent presents, verify and submit
const { nullifier } = await onchainSubmitter.submit({ policyId, presentation, agentDid, nonce })

# 5. Gate your contract
function executeAction(bytes32 nullifier) external onlyVerifiedAgent(nullifier) { ... }`}</CB>
            <H3>Repository Layout</H3>
            <CB>{`acta-poc/
├── packages/
│   ├── shared/       # Types, constants, PredicateHash utilities  (@acta/shared)
│   ├── issuer/       # Credo.ts + OID4VCI issuer server           (@acta/issuer)
│   ├── holder/       # Credo.ts + OpenAC ZK adapter               (@acta/holder)
│   ├── verifier/     # Credo.ts + OID4VP + policy SDK             (@acta/verifier)
│   ├── contracts/    # Hardhat + Solidity ^0.8.24                 (@acta/contracts)
│   └── demo-app/     # React 18 + Vite interactive demo
├── circuits/         # Circom 2.x ZK circuits
└── docs/             # Architecture, flow, API reference, spec`}</CB>
          </Section>

          {/* ── Architecture ───────────────────────────────────────────── */}
          <Section id="architecture" label="Protocol Architecture" ref_={ref('architecture')}>
            <CB>{`Layer 4: On-Chain Execution   — Solidity contracts enforce verification and gate access
Layer 3: ZK Privacy          — Groth16 SNARK proves predicate satisfaction privately
Layer 2: W3C Credential      — JWT-VC signed by a did:ethr issuer (ES256K)
Layer 1: DID Identity        — did:ethr backed by ERC-1056 (EthereumDIDRegistry)`}</CB>
            <H3>Actors</H3>
            <T headers={['Actor', 'Role', 'Key Material']} rows={[
              ['Issuer', 'Certifies agent attributes; issues AgentCapabilityCredential via OID4VCI', 'did:ethr secp256k1 key'],
              ['Holder (Agent)', 'Holds credential; generates Groth16 proof on presentation request', 'did:ethr secp256k1 key'],
              ['Verifier (Protocol)', 'Defines predicate policy; submits proof on-chain', 'did:ethr secp256k1 key'],
            ]} />
            <H3>Protocol Flow (10 Steps)</H3>
            <T headers={['Phase', 'Step', 'Actor', 'Action']} rows={[
              ['Setup', '0', 'Deployer', 'Deploy contracts, run ZK trusted setup, set Poseidon hasher, wire authorizations'],
              ['Issuance', '1–2', 'Issuer → Holder', 'OID4VCI pre-authorized code flow — holder receives JWT-VC (ES256K signed)'],
              ['Anchoring', '3', 'Holder → Chain', 'anchorCredential(agentId, type, commitment, merkleRoot)'],
              ['Policy', '4', 'Verifier → Chain', 'registerPolicy(descriptor) → policyId'],
              ['Request', '5', 'Verifier → Holder', 'OID4VP authorization request with x-openac-policy-id'],
              ['Proof', '6', 'Holder (local)', 'Groth16 witness generation + proof → VP JWT (ES256K signed)'],
              ['Submit', '7', 'Verifier → Chain', 'verifyAndRegister() — 10-step atomic sequence'],
              ['Access', '8', 'Consumer', 'grantAccess(nullifier) → isAcceptedForPolicy(nullifier, policyId) ✓'],
            ]} />
            <H3>DID Identity</H3>
            <CB>{`// DID format
did:ethr:0x14f69:0x<checksummedEthereumAddress>

// agentId (used in contract calls)
agentId = uint256(uint160(holderAddress))

// ERC-1056 registry on Base Sepolia
0xdca7ef03e98e0dc2b855be647c39abe984fcf21b`}</CB>
          </Section>

          {/* ── Credential Schema ──────────────────────────────────────── */}
          <Section id="credential" label="Credential Schema" ref_={ref('credential')}>
            <H3>JWT-VC Structure</H3>
            <CB>{`{
  "header": { "alg": "ES256K", "typ": "JWT", "kid": "did:ethr:0x14f69:0xISSUER#controller" },
  "payload": {
    "iss": "did:ethr:0x14f69:0xISSUER",
    "sub": "did:ethr:0x14f69:0xHOLDER",
    "iat": 1741824000,
    "exp": 1749600000,
    "vc": {
      "@context": ["https://www.w3.org/2018/credentials/v1",
                   "https://acta.ethereum.org/contexts/AgentCapability/v1"],
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
}`}</CB>
            <Note>The JWT-VC ES256K signature is cryptographically verified by <C>openacAdapter.importCredential()</C> before any attribute values are accepted. A forged or tampered JWT-VC will be rejected before reaching the ZK layer.</Note>
            <H3>Circuit Attribute Encoding</H3>
            <T headers={['Index', 'Field', 'Type', 'Encoding']} rows={[
              ['0', 'auditScore', 'integer', '0–100 (circuit enforces range check)'],
              ['1', 'modelHash', 'uint256', 'First 31 bytes of the hex hash string'],
              ['2', 'operatorJurisdiction', 'integer', 'ISO 3166-1 numeric: US=840, GB=826…'],
              ['3', 'capabilities', 'bitmask', 'evm-execution=0x01, risk-assessment=0x02…'],
              ['4', 'auditedBy', 'uint248', 'keccak256(auditorDid) & ((1n << 248n) - 1n)'],
              ['5', 'auditDate', 'uint256', 'Unix timestamp (midnight UTC of YYYY-MM-DD)'],
              ['6–15', 'Reserved', '—', 'Must be 0 — enforced by circuit constraint'],
            ]} />
            <H3>Issuer Public Key Commitment</H3>
            <CB>{`issuerPubKeyCommitment = keccak256(pubKeyHex) & ((1n << 248n) - 1n)

// Verification: both holder (import) and verifier (verifyPresentation)
// MUST resolve the issuer DID and call pubKeyToFieldCommitment() with the
// same raw key bytes to produce matching commitments.`}</CB>
          </Section>

          {/* ── ZK Circuit ─────────────────────────────────────────────── */}
          <Section id="circuit" label="ZK Circuit" ref_={ref('circuit')}>
            <P>The primary circuit is <C>OpenACGPPresentation</C> — a Groth16 SNARK on the BN254 curve implemented in Circom 2.1.6.</P>
            <H3>System Parameters</H3>
            <T headers={['Parameter', 'Value']} rows={[
              ['File', 'circuits/presentation/OpenACGPPresentation.circom'],
              ['Proving system', 'Groth16 (BN254 curve)'],
              ['Hash function', 'Poseidon (circomlib, BN254 scalar field)'],
              ['Public signal count', '6'],
              ['Attribute slots', '16 (indices 0–5 used, 6–15 reserved = 0)'],
              ['Max sanction slots', '8'],
              ['Setup requirement', 'Per-circuit trusted setup ceremony required (multi-party)'],
            ]} />
            <H3>Public Outputs (pubSignals)</H3>
            <T headers={['Index', 'Signal', 'Description']} rows={[
              ['0', 'nullifier', 'Poseidon(credentialSecret, Poseidon(verifier, policyId, nonce))'],
              ['1', 'contextHash', 'Poseidon(verifierAddress, policyId, nonce) — verified on-chain via IPoseidonT4'],
              ['2', 'predicateProgramHash', 'Binds proof to registered policy predicate'],
              ['3', 'issuerPubKeyCommitment', 'Binds proof to specific trusted issuer'],
              ['4', 'credentialMerkleRoot', 'Proves credential attributes are current on-chain'],
              ['5', 'expiryBlock', 'Enforces proof time-bounding'],
            ]} />
            <H3>Context Hash — Poseidon Binding (Step 7)</H3>
            <P>The circuit outputs <C>contextHash = Poseidon(verifierAddress, policyId, nonce)</C>. On-chain, <C>GeneralizedPredicateVerifier</C> recomputes this same Poseidon hash via the <C>IPoseidonT4</C> library and compares it to <C>pubSignals[1]</C>. This binds the proof to the exact caller, policy, and nonce — preventing front-running.</P>
            <P>The <C>contextHasher</C> address must be set via <C>setContextHasher(poseidonT4Address)</C> before production deployment. If <C>address(0)</C>, Step 7 is skipped (local test mode only — front-running protection is not active).</P>
            <Note>Production deployment MUST set contextHasher to a verified IPoseidonT4 implementation whose output matches circomlib's Poseidon(3) template over BN254. See <C>contracts/lib/PoseidonT4.sol</C> for the interface and deployment instructions.</Note>
            <H3>Circuit Constraints</H3>
            <CB>{`// C1 — Credential commitment integrity
Poseidon(attributeValues[0..15], randomness) === credentialCommitment

// C2 — Merkle root (4-level binary Poseidon tree)
rootHasher(l2[0], l2[1]) === credentialMerkleRoot

// C3a — Audit score range (prevents GreaterEqThan overflow)
LessEqThan(8): attributeValues[0] <= 100

// C3a — Audit score predicate
(1 - GreaterEqThan(8)(auditScore, min)) * min === 0

// C3b — Capability bitmask (bit-by-bit)
for each bit i: maskBits[i] * (1 - credBits[i]) === 0

// C3c — Sanctions exclusion
for each slot j: IsEqual(jurisdiction, sanctions[j]) * sanctions[j] === 0

// C4 — Nullifier derivation
credentialSecret = Poseidon(credentialCommitment, randomness)
contextHashInner = Poseidon(verifierAddress, policyId, nonce)
nullifier        = Poseidon(credentialSecret, contextHashInner)

// C5 — Reserved attributes
for i in [6..15]: attributeValues[i] === 0`}</CB>
          </Section>

          {/* ── Smart Contracts ────────────────────────────────────────── */}
          <Section id="contracts" label="Smart Contracts" ref_={ref('contracts')}>
            <P>All contracts use Solidity <C>^0.8.24</C> with OpenZeppelin 5.x. Core contracts use <C>Ownable2Step</C>, <C>ReentrancyGuard</C>, and <C>Pausable</C> where appropriate.</P>
            <H3>Contract Registry</H3>
            <T headers={['Contract', 'Purpose']} rows={[
              ['NullifierRegistry', 'Context-scoped nullifier store; replay prevention'],
              ['OpenACCredentialAnchor', 'Links did:ethr identities to ZK commitment + Merkle root'],
              ['GeneralizedPredicateVerifier', 'Central 10-step verifier; policy registry; circuit registry; pausable; reentrancy-safe'],
              ['OpenACSnarkVerifier', 'Groth16 verifier (generated from trusted setup ceremony)'],
              ['ZKReputationAccumulator', 'Anonymous reputation accumulation — policy-scoped'],
              ['AgentAccessGate', 'Example consumer — permanent revocation; policy-scoped gate'],
              ['IPoseidonT4', 'Interface for on-chain Poseidon-T4 hasher (required for Step 7)'],
            ]} />
            <H3>Deployment Order</H3>
            <CB>{`1. NullifierRegistry(owner)
2. OpenACCredentialAnchor(owner)
3. OpenACSnarkVerifier()
4. GeneralizedPredicateVerifier(owner, nullifierRegistry, credentialAnchor)
5. PoseidonT4 (deploy IPoseidonT4 implementation — see contracts/lib/PoseidonT4.sol)
6. gpVerifier.setContextHasher(poseidonT4Address)    ← required for production
7. nullifierRegistry.lockAuthorization(gpVerifier)   ← authorize GPV to register nullifiers
8. gpVerifier.registerCircuitVerifier(circuitId, snarkV)  ← register proof system
9. ZKReputationAccumulator(owner, gpVerifier)
10. AgentAccessGate(owner, gpVerifier, policyId)      ← one per policy`}</CB>
            <H3>GeneralizedPredicateVerifier</H3>
            <CB>{`// Policy management
function registerPolicy(PolicyDescriptor calldata desc) external whenNotPaused returns (bytes32 policyId)
function deactivatePolicy(bytes32 policyId) external
function getPolicy(bytes32 policyId) external view returns (PolicyDescriptor memory)

// 10-step verification (nonReentrant + whenNotPaused)
function verifyAndRegister(
    bytes32 policyId,
    bytes calldata proof,
    uint256[] calldata pubSignals,  // [nullifier, contextHash, predHash, issuerC, merkleR, expiry]
    uint256 agentId,
    uint256 nonce
) external nonReentrant whenNotPaused

// Access checks
function isAccepted(bytes32 nullifier) external view returns (bool)         // policy-agnostic
function isAcceptedForPolicy(bytes32 nullifier, bytes32 policyId)           // USE THIS in consumers
    external view returns (bool)

// Circuit registry (owner only)
function registerCircuitVerifier(bytes32 circuitId, ICircuitVerifier verifier) external onlyOwner

// Poseidon hasher for Step 7 context hash verification (owner only)
// Must be set to a deployed IPoseidonT4 before production use.
// If address(0), Step 7 is skipped (test mode — no front-running protection).
function setContextHasher(address hasher) external onlyOwner

// Emergency controls (owner only)
function pause() external onlyOwner    // halts verifyAndRegister + registerPolicy
function unpause() external onlyOwner`}</CB>
            <H3>OpenACCredentialAnchor</H3>
            <CB>{`// Anchor a new credential (holder only — msg.sender must equal address(uint160(agentId)))
// Reverts ActiveAnchorExists if a live anchor already exists for this (agentId, credentialType).
// Use rotateCredential() instead to update an existing anchor.
function anchorCredential(uint256 agentId, bytes32 credentialType,
    bytes32 commitment, bytes32 merkleRoot) external

// Rotate to a new credential (requires existing active anchor — emits CredentialRotated)
function rotateCredential(uint256 agentId, bytes32 credentialType,
    bytes32 newCommitment, bytes32 newMerkleRoot) external

// Revoke (by holder, authorised revoker, or owner)
function revokeCredential(uint256 agentId, bytes32 credentialType) external

// Query
function isMerkleRootCurrent(uint256 agentId, bytes32 credentialType, bytes32 root) external view returns (bool)
function getCommitment(uint256 agentId, bytes32 credentialType) external view
    returns (bytes32 commitment, bytes32 merkleRoot, uint256 anchoredAt)`}</CB>
            <H3>AgentAccessGate</H3>
            <CB>{`// Grant access — only succeeds if GPVerifier accepted nullifier for this gate's specific policyId.
// Reverts AccessPermanentlyRevoked if the nullifier was previously revoked.
function grantAccess(bytes32 nullifier) external

// Permanently revoke access (owner only).
// Once revoked, grantAccess() will always revert for this nullifier, even if
// gpVerifier.isAcceptedForPolicy() still returns true. totalAccessesGranted is decremented.
function revokeAccess(bytes32 nullifier) external onlyOwner

function isAccessGranted(bytes32 nullifier) external view returns (bool)

// Modifier for gated protocol functions
modifier onlyVerifiedAgent(bytes32 nullifier) {
    if (!_accessGranted[nullifier]) revert AccessNotGranted(nullifier);
    _;
}`}</CB>
            <H3>ZKReputationAccumulator</H3>
            <CB>{`// Increment reputation for a nullifier. Uses isAcceptedForPolicy(nullifier, policyId)
// — policy-scoped — to prevent a low-bar nullifier earning reputation in a high-bar pool.
function increment(bytes32 policyId, bytes32 nullifier, uint256 delta) external

function getReputation(bytes32 policyId, bytes32 nullifier) external view returns (uint256)
function getPoolTotal(bytes32 policyId) external view returns (uint256)

// Pool management (authorized creators or owner only)
function createPool(bytes32 policyId, uint256 maxDeltaPerOp) external
function authorizePoolCreator(address creator) external onlyOwner`}</CB>
            <H3>PolicyDescriptor</H3>
            <CB>{`struct PolicyDescriptor {
    address verifier;             // must equal msg.sender at registration time
    bytes32 predicateProgramHash; // keccak256 of canonical predicate JSON
    bytes32 credentialType;       // keccak256("AgentCapabilityCredential")
    bytes32 circuitId;            // keccak256("OpenACGPPresentation.v1")
    uint256 expiryBlock;          // 0 = never expires
    bytes32 issuerCommitment;     // keccak256(issuerPubKey) & ((1<<248)-1)
    bool active;
}

// policyId is deterministic:
policyId = keccak256(abi.encode(msg.sender, predicateProgramHash, credentialType,
                                 circuitId, expiryBlock, issuerCommitment))`}</CB>
            <H3>Gas Costs (Base Sepolia)</H3>
            <T headers={['Operation', 'Gas', 'USD (approx)']} rows={[
              ['anchorCredential()', '~65,000', '~$0.001'],
              ['registerPolicy()', '~80,000', '~$0.001'],
              ['verifyAndRegister() with Groth16 + Poseidon', '~205,000', '~$0.002'],
              ['grantAccess()', '~48,000', '~$0.001'],
              ['setContextHasher()', '~25,000 (one-time)', '~$0.001'],
            ]} />
          </Section>

          {/* ── Verifier SDK ───────────────────────────────────────────── */}
          <Section id="verifier-sdk" label="Verifier SDK" ref_={ref('verifier-sdk')}>
            <H3>PredicateBuilder</H3>
            <P>Builds predicate programs with correct left-associative logical trees. Mixed connectives (AND, OR) are properly handled — each condition's connective is honoured independently in the tree structure, ensuring deterministic and semantically correct predicate hashes.</P>
            <CB>{`const predicate = new PredicateBuilder('AgentCapabilityCredential')
  .require('auditScore').greaterThanOrEqual(80)
  .and()
  .require('capabilities').includes('evm-execution')
  .or()                                              // ← correct: binds only to next condition
  .require('operatorJurisdiction').notIn(['IR', 'KP'])
  .build()

// Produces tree: logical(OR, [logical(AND, [cond(score), cond(cap)]), cond(jurisdiction)])
// predicate.hash      → deterministic bytes32 hash for on-chain policy registration
// predicate.toJSON()  → serialised string for OID4VP request`}</CB>
            <H3>PolicyRegistry</H3>
            <CB>{`const policyId = await registry.registerPolicy(predicate, issuerCommitment)
// → bytes32 "0x…"
// → emits: PolicyRegistered(policyId, verifier, predicateHash, circuitId)`}</CB>
            <H3>PresentationRequestBuilder</H3>
            <CB>{`const { requestUri, sessionId } = builder.createPresentationRequest({
  policyId,
  predicate,
  verifierCallbackUrl: 'https://myprotocol.xyz/verify-callback/' + policyId,
  // nonce is hashed in PresentationHandler: keccak256(nonce) & 0xFFFFFFFFFFFFFFFFn
  // Both holder and verifier must use the same derivation for Step 7 to pass.
  sessionNonce: crypto.getRandomValues(new BigUint64Array(1))[0],
  onchainVerifierAddress: GP_VERIFIER_ADDRESS,
})`}</CB>
            <H3>OffchainVerifier</H3>
            <P>Runs two mandatory checks before on-chain submission:</P>
            <CB>{`const { valid, reason } = await verifier.verifyOffchain({
  presentation, policyId, issuerDid, vpJwt, holderDid
})

// Checks performed:
//  ✓ VP JWT ES256K signature (holder's did:ethr secp256k1 key)    ← cryptographic, not just structural
//  ✓ VP JWT iss claim matches holderDid
//  ✓ VP JWT contains verifiableCredential and zkProof
//  ✓ Groth16 proof bytes (local snark verification)
//  ✓ issuerPubKeyCommitment matches resolved DID
//  ✓ expiryBlock > currentBlock`}</CB>
            <H3>OnchainSubmitter</H3>
            <CB>{`const { nullifier, txHash } = await submitter.submit({
  policyId,
  presentation,
  agentDid,   // must be a valid did:ethr — address extracted via ethers.isAddress()
  nonce,      // must match the nonce used in createPresentationRequest()
})
// submit() will throw if agentDid does not contain a valid Ethereum address`}</CB>
            <H3>Complete Integration Example</H3>
            <CB>{`async function verifyAgent(vpJwt: string, holderDid: string): Promise<string> {
  // 1. Parse VP
  const vpPayload = decodeJwt(vpJwt)
  const presentation: OpenACPresentation = vpPayload.zkProof

  // 2. Off-chain pre-flight — includes ES256K signature check (~50ms)
  const { valid, reason } = await offchainVerifier.verifyOffchain({
    presentation, policyId, issuerDid, vpJwt, holderDid
  })
  if (!valid) throw new Error(\`Verification failed: \${reason}\`)

  // 3. On-chain submission (~500ms)
  const { nullifier, txHash } = await onchainSubmitter.submit({
    policyId, presentation,
    agentDid: holderDid,
    nonce: BigInt(vpPayload.nonce, 16),
  })

  return nullifier  // use in grantAccess(nullifier)
}`}</CB>
          </Section>

          {/* ── Holder SDK ─────────────────────────────────────────────── */}
          <Section id="holder-sdk" label="Holder Integration" ref_={ref('holder-sdk')}>
            <H3>Step 1 — DID Identity Setup</H3>
            <CB>{`const holderIdentity = await createEthrDIDIdentity(process.env.HOLDER_PRIVATE_KEY)`}</CB>
            <H3>Step 2 — Request Credential (OID4VCI)</H3>
            <CB>{`const { credential: jwtVc } = await axios.post(\`\${ISSUER_URL}/credentials\`, {
  format: 'jwt_vc_json',
  types: ['AgentCapabilityCredential'],
  proof: { jwt: popJwt }
}, { headers: { Authorization: \`Bearer \${access_token}\` } })`}</CB>
            <H3>Step 3 — Import and Anchor Credential</H3>
            <CB>{`const adapter = new OpenACAdapter()

// importCredential() now verifies the JWT-VC ES256K signature before accepting
// attribute values. A credential not signed by the resolved issuer DID is rejected.
const handle = await adapter.importCredential(jwtVc, issuerDid, holderIdentity.resolver)
// → { credentialId, commitment: "0x…", merkleRoot: "0x…" }

// Anchor on-chain — anchorCredential() reverts ActiveAnchorExists if an anchor
// already exists for this (agentId, credentialType). Use rotateCredential() to update.
await credentialAnchor.connect(holderIdentity.signer).anchorCredential(
  BigInt(holderIdentity.signer.address),
  CREDENTIAL_TYPE,
  handle.commitment,
  handle.merkleRoot
)`}</CB>
            <H3>Step 4 — Respond to Presentation Request</H3>
            <CB>{`const handler = new PresentationHandler(holderIdentity, credentialStore)

// The nonce is derived as: keccak256(authRequest.nonce) & 0xFFFFFFFFFFFFFFFFn
// This matches the verifier's nonce derivation. Full string → 64-bit uint64 hash,
// preventing the 56-bit truncation bug from earlier versions.
const response = await handler.handlePresentationRequest(authorizationRequest)
// → { vpJwt, zkProof, nullifier }
// The VP JWT is signed with the holder's ES256K key`}</CB>
            <H3>verifyJwtSignature (exported)</H3>
            <CB>{`import { verifyJwtSignature } from '@acta/holder/src/openacAdapter'

// Verify any ES256K-signed JWT against an Ethereum address
const isValid = verifyJwtSignature(jwt, signerEthereumAddress)
// Tries recovery values v=27 and v=28; returns true if either matches`}</CB>
          </Section>

          {/* ── Issuer SDK ─────────────────────────────────────────────── */}
          <Section id="issuer-sdk" label="Issuer Integration" ref_={ref('issuer-sdk')}>
            <H3>Server Setup</H3>
            <CB>{`import { createIssuanceRouter } from '@acta/issuer/src/issuanceRoutes'

app.use('/', createIssuanceRouter(issuerIdentity))

// Endpoints:
// GET  /.well-known/openid-credential-issuer
// GET  /credential-offer
// POST /token                     ← verifies proof-of-possession JWT signature
// POST /credentials               ← issues ES256K-signed JWT-VC`}</CB>
            <H3>Credential Subject (all fields required)</H3>
            <CB>{`const subject: AgentCapabilityCredentialSubject = {
  id:                   holderDid,
  auditScore:           87,              // 0–100
  modelHash:            '0x…',           // keccak256 of model identifier
  operatorJurisdiction: 'US',            // ISO 3166-1 alpha-2
  capabilities:         ['evm-execution'],
  auditedBy:            issuerDid,
  auditDate:            '2026-03-01',    // YYYY-MM-DD
}`}</CB>
            <H3>Key Management</H3>
            <CB>{`// The issuer's secp256k1 key signs JWT-VCs (ES256K), Ethereum transactions, and DID updates.
// In production, use an HSM or secrets manager. Never store in environment variables.

// Key rotation: EthereumDIDRegistry.changeOwner() updates the DID controller.
// Existing credentials remain valid — did:ethr resolution sees the new key.`}</CB>
          </Section>

          {/* ── Deployment Guide ───────────────────────────────────────── */}
          <Section id="deployment" label="Deployment Guide" ref_={ref('deployment')}>
            <H3>Prerequisites</H3>
            <T headers={['Tool', 'Version', 'Purpose']} rows={[
              ['Node.js', '>=20.0.0', 'Runtime for all packages'],
              ['npm', '>=10.0.0', 'Package manager'],
              ['circom', '2.1.x', 'ZK circuit compilation'],
              ['snarkjs', 'latest', 'Trusted setup and proof generation'],
              ['Hardhat', '^2.22', 'Contract compilation and deployment'],
            ]} />
            <H3>Base Sepolia Deployment</H3>
            <CB>{`DEPLOYER_PRIVATE_KEY=0x…
BASESCAN_API_KEY=…

cd packages/contracts
npx hardhat run scripts/deploy.ts --network base-sepolia

# Deployments saved to packages/contracts/deployments/base-sepolia.json`}</CB>
            <H3>Post-Deployment Checklist</H3>
            <CB>{`// 1. Authorize GPVerifier to register nullifiers
await nullifierRegistry.lockAuthorization(gpVerifierAddress)

// 2. Register circuit verifier
await gpVerifier.registerCircuitVerifier(circuitId, snarkVerifierAddress)

// 3. Deploy Poseidon-T4 library (see contracts/lib/PoseidonT4.sol for instructions)
//    and set it as the context hasher — REQUIRED for front-running protection
await gpVerifier.setContextHasher(poseidonT4Address)

// 4. Run consistency test to verify Poseidon output matches snarkjs witness
npx hardhat test test/PoseidonConsistency.test.ts

// 5. Replace placeholder OpenACSnarkVerifier with ceremony-generated verifier
cp contracts/verifiers/OpenACSnarkVerifier_generated.sol \\
   contracts/verifiers/OpenACSnarkVerifier.sol
// (DO NOT use placeholder key in production — all proofs are forgeable with it)

// 6. Verify contracts on Basescan
npx hardhat verify --network base-sepolia <NullifierRegistry> <owner>
// ... one per contract`}</CB>
            <H3>Environment Variables</H3>
            <T headers={['Variable', 'Required', 'Description']} rows={[
              ['ISSUER_PRIVATE_KEY', 'Yes', 'Issuer secp256k1 key — use HSM in production'],
              ['HOLDER_PRIVATE_KEY', 'Yes', 'Holder/agent key'],
              ['VERIFIER_PRIVATE_KEY', 'Yes', 'Verifier key'],
              ['DEPLOYER_PRIVATE_KEY', 'Deploy only', 'Contract deployment key'],
              ['WALLET_KEY', 'Yes', 'Credo.ts wallet encryption key'],
              ['BASE_SEPOLIA_RPC_URL', 'Yes', 'Authenticated RPC endpoint (not public)'],
              ['GP_VERIFIER_ADDRESS', 'Yes', 'Deployed GeneralizedPredicateVerifier'],
              ['CREDENTIAL_ANCHOR_ADDRESS', 'Yes', 'Deployed OpenACCredentialAnchor'],
              ['NULLIFIER_REGISTRY_ADDRESS', 'Yes', 'Deployed NullifierRegistry'],
              ['POSEIDON_T4_ADDRESS', 'Yes', 'Deployed IPoseidonT4 implementation'],
              ['BASESCAN_API_KEY', 'Verify only', 'For contract source verification'],
            ]} />
          </Section>

          {/* ── Security Model ─────────────────────────────────────────── */}
          <Section id="security" label="Security Model" ref_={ref('security')}>
            <H3>Trust Assumptions</H3>
            <T headers={['ID', 'Assumption', 'If Broken']} rows={[
              ['T1', 'Issuer honestly certifies only compliant agents', 'Fraudulent credentials can be issued — mitigated by on-chain issuer commitment and JWT-VC signature verification'],
              ['T2', 'Groth16 on BN254 is computationally sound', 'Fake proofs constructable — requires breaking elliptic curve cryptography'],
              ['T3', 'Poseidon hash (circomlib, BN254) is collision-resistant', 'Commitment or nullifier forgery'],
              ['T4', 'Trusted setup has ≥1 honest participant', 'Fake proofs for any statement — single-party setup MUST NOT be used'],
              ['T5', 'EthereumDIDRegistry (ERC-1056) is uncompromised', 'DID key forgery enabling VP JWT or JWT-VC signature attacks'],
              ['T6', 'IPoseidonT4 implementation matches circomlib constants exactly', 'Step 7 context hash check will always fail or pass incorrectly'],
            ]} />
            <H3>Security Properties</H3>
            <div className="space-y-3 mt-3">
              {[
                { title: 'Replay Prevention', body: 'The nullifier is deterministic for a given (credential, verifier, policy, nonce). Once registered in NullifierRegistry, any second register() call reverts NullifierAlreadyActive. Enforced atomically in Step 9 of verifyAndRegister().' },
                { title: 'Cross-Context Unlinkability', body: 'Two presentations to different verifiers produce computationally unlinkable nullifiers — Poseidon preimage hardness.' },
                { title: 'Front-Running Protection', body: 'Step 7 recomputes Poseidon(msg.sender, policyId, nonce) on-chain via IPoseidonT4 and asserts equality with pubSignals[1]. Requires contextHasher to be set. A front-runner substituting their address changes the hash and fails.' },
                { title: 'Credential Authenticity', body: 'openacAdapter.importCredential() verifies the JWT-VC ES256K signature against the resolved issuer DID before accepting any attribute values. offchainVerifier verifies the VP JWT ES256K signature against the holder DID. Both checks are cryptographic, not structural.' },
                { title: 'Policy-Scoped Access Gating', body: 'AgentAccessGate.grantAccess() calls isAcceptedForPolicy(nullifier, policyId). ZKReputationAccumulator.increment() also uses the policy-scoped check. A nullifier accepted under policy A cannot grant access or earn reputation under policy B.' },
                { title: 'Permanent Revocation', body: 'AgentAccessGate.revokeAccess() sets _permanentlyRevoked[nullifier] = true. Once revoked, grantAccess() always reverts — even if gpVerifier still shows the nullifier as accepted. totalAccessesGranted is decremented.' },
                { title: 'Reentrancy Safety', body: 'verifyAndRegister() carries the nonReentrant modifier (OpenZeppelin ReentrancyGuard). All three external calls (credentialAnchor, circuitVerifier, nullifierRegistry) are to immutable addresses set at construction.' },
                { title: 'Emergency Pause', body: 'Owner can call pause() to halt verifyAndRegister() and registerPolicy() instantly. unpause() resumes operations after remediation.' },
              ].map(p => (
                <div key={p.title} className="p-3 rounded-lg border border-teal-700/30 bg-teal-950/20">
                  <p className="text-xs font-semibold text-teal-300 mb-1">✓ {p.title}</p>
                  <p className="text-xs text-gray-400">{p.body}</p>
                </div>
              ))}
            </div>
            <H3>Known Limitations (v0.1)</H3>
            <T headers={['ID', 'Limitation', 'Future Mitigation']} rows={[
              ['L1', 'Circuit supports only 3 predicate types (audit score, capabilities, jurisdiction)', 'Upgrade circuit; new trusted setup'],
              ['L2', 'IPoseidonT4 must be deployed and set separately — contextHasher address(0) disables Step 7', 'Include Poseidon in deploy script; add deployment validation check'],
              ['L3', 'Groth16 requires trusted setup; compromised ceremony is undetectable', 'Migrate to transparent proof system (STARKs)'],
              ['L4', 'No device binding — credential theft enables proof generation', 'Add ECDSA device binding in circuit'],
              ['L5', 'Revocation requires on-chain re-anchoring (no push mechanism)', 'Add issuer-controlled revocation oracle'],
            ]} />
            <H3>Pre-Production Checklist</H3>
            <CB>{`□ Run Groth16 trusted setup with ≥3 independent parties; publish transcript
□ Replace placeholder OpenACSnarkVerifier with ceremony-generated verifier
□ Deploy IPoseidonT4 matching circomlib constants; call setContextHasher()
□ Run PoseidonConsistency test to verify on-chain Poseidon matches snarkjs
□ Professional Solidity audit of all 5 core contracts
□ ZK circuit audit by ZK specialist (constraint soundness)
□ Replace WALLET_KEY with HSM-backed key management
□ Use authenticated RPC endpoints (not public ones)
□ Set up monitoring on NullifierRegistry for unexpected revocations
□ Configure ERC-1056 key rotation procedures for all actor DIDs
□ Test credential rotation and re-anchoring flows end-to-end
□ Verify issuerCommitment matches your production issuer's key`}</CB>
          </Section>

          {/* ── Error Reference ────────────────────────────────────────── */}
          <Section id="errors" label="Error Reference" ref_={ref('errors')}>
            <H3>GeneralizedPredicateVerifier</H3>
            <T headers={['Error', 'Step', 'Cause', 'Resolution']} rows={[
              ['PolicyNotFound(bytes32)', '1', 'policyId not registered', 'Call registerPolicy() first'],
              ['PolicyInactive(bytes32)', '1', 'Policy deactivated', 'Register a new policy'],
              ['PolicyExpired(bytes32, uint256)', '1', 'expiryBlock passed', 'Register new policy with future expiryBlock'],
              ['InvalidPublicSignalCount(uint256, uint256)', '2', 'pubSignals.length ≠ 6', 'Check signal array construction'],
              ['PredicateHashMismatch(bytes32, bytes32)', '3', 'Wrong predicate in proof', 'Verify predicate JSON canonicalization'],
              ['ExpiryBlockPassed(uint256, uint256)', '4', 'Proof expiry ≤ current block', 'Generate fresh proof'],
              ['MerkleRootNotCurrent(bytes32)', '5', 'Credential not anchored or revoked', 'Call anchorCredential() or rotateCredential()'],
              ['IssuerCommitmentMismatch(bytes32, bytes32)', '6', 'Wrong issuer key in proof', 'Verify issuerPubKeyCommitment matches policy'],
              ['ContextHashMismatch(bytes32, bytes32)', '7', 'Poseidon(msg.sender, policy, nonce) ≠ pubSignals[1]', 'Verify contextHasher is set; check verifier address and nonce match'],
              ['CircuitVerifierNotRegistered(bytes32)', '8', 'No ICircuitVerifier for circuitId', 'Call registerCircuitVerifier()'],
              ['ProofInvalid()', '8', 'Groth16 proof verification failed', 'Check verification key matches ceremony'],
            ]} />
            <H3>NullifierRegistry</H3>
            <T headers={['Error', 'Cause', 'Resolution']} rows={[
              ['NullifierAlreadyActive(bytes32)', 'Replay: same proof submitted twice', 'Each (credential, verifier, policy, nonce) is one-time use'],
              ['InvalidNullifier()', 'nullifier == bytes32(0)', 'Nullifier derivation error in proof generation'],
              ['InvalidExpiryBlock(uint256)', 'expiryBlock ≤ block.number', 'Use a future block for expiry'],
              ['NullifierNotFound(bytes32)', 'revoke() on unregistered nullifier', 'Only revoke registered nullifiers'],
              ['UnauthorizedCaller(address)', 'register() by non-authorized address', 'Call lockAuthorization(gpVerifier) during setup'],
            ]} />
            <H3>OpenACCredentialAnchor</H3>
            <T headers={['Error', 'Cause', 'Resolution']} rows={[
              ['AgentIdMismatch(uint256, address)', 'msg.sender ≠ address(uint160(agentId))', 'Caller must be the DID controller of the agent'],
              ['ActiveAnchorExists(uint256, bytes32)', 'anchorCredential() called when a live anchor already exists', 'Use rotateCredential() to update an existing (non-revoked) anchor'],
              ['CommitmentAlreadyAnchored(bytes32)', 'Commitment reuse attempt', 'Generate new randomness for each credential import'],
              ['NoActiveCredential(uint256, bytes32)', 'rotateCredential() with no existing anchor', 'Call anchorCredential() first'],
              ['CredentialRevoked(uint256, bytes32)', 'Operation on revoked credential', 'Re-anchor with anchorCredential() after revocation'],
            ]} />
            <H3>AgentAccessGate</H3>
            <T headers={['Error', 'Cause', 'Resolution']} rows={[
              ['PresentationNotAccepted(bytes32)', 'isAcceptedForPolicy() returned false for this policyId', 'Run verifyAndRegister() under the correct policyId first'],
              ['AccessAlreadyGranted(bytes32)', 'grantAccess() called twice for same nullifier', 'Check isAccessGranted() first'],
              ['AccessPermanentlyRevoked(bytes32)', 'grantAccess() called after revokeAccess() — nullifier is permanently blocked', 'A permanently revoked nullifier cannot be re-granted. The agent must re-present with a new nonce.'],
              ['AccessNotGranted(bytes32)', 'onlyVerifiedAgent modifier failed', 'Call grantAccess() after successful verifyAndRegister()'],
            ]} />
            <H3>Decoding Errors (ethers.js)</H3>
            <CB>{`try {
  await gpVerifier.verifyAndRegister(policyId, proof, pubSignals, agentId, nonce)
} catch (err) {
  if (err.code === 'CALL_EXCEPTION') {
    const iface = new ethers.Interface(GP_VERIFIER_ABI)
    const decoded = iface.parseError(err.data)
    console.log(decoded?.name, decoded?.args)
    // → "ContextHashMismatch" ["0x…", "0x…"]
    // Likely cause: contextHasher not set, or nonce mismatch between holder and verifier
  }
}`}</CB>
            <div className="mt-10 pt-6 border-t border-gray-700/60 text-center">
              <p className="text-xs text-gray-600">Anonymous Credentials for Trustless Agents (ACTA) · v0.1 · Documentation</p>
            </div>
          </Section>

        </div>
      </div>
    </div>
  )
}

// ── Layout primitives ─────────────────────────────────────────────────────────

function Section({ id, label, ref_, children }: {
  id: string; label: string; ref_: (el: HTMLElement | null) => void; children: React.ReactNode
}) {
  return (
    <section ref={ref_} id={id} className="mb-14 scroll-mt-4">
      <h2 className="text-base font-bold text-white mb-5 pb-2 border-b border-gray-700/50">{label}</h2>
      {children}
    </section>
  )
}
function H3({ children }: { children: React.ReactNode }) {
  return <h3 className="text-sm font-semibold text-gray-200 mt-6 mb-2">{children}</h3>
}
function P({ children }: { children: React.ReactNode }) {
  return <p className="text-gray-400 text-sm leading-relaxed mb-3">{children}</p>
}
function C({ children }: { children: React.ReactNode }) {
  return (
    <code className="px-1.5 py-0.5 rounded bg-gray-800 text-blue-300 text-xs font-mono border border-gray-700/50">
      {children}
    </code>
  )
}
function CB({ children }: { children: string }) {
  return (
    <pre className="bg-gray-900 rounded-lg p-4 text-xs font-mono text-gray-300 overflow-x-auto border border-gray-700/40 mb-4 whitespace-pre">
      {children}
    </pre>
  )
}
function T({ headers, rows }: { headers: string[]; rows: string[][] }) {
  return (
    <div className="overflow-x-auto mb-4">
      <table className="w-full text-xs border-collapse">
        <thead>
          <tr>{headers.map(h => (
            <th key={h} className="text-left px-3 py-2 bg-gray-800/60 text-gray-300 font-semibold border border-gray-700/50">{h}</th>
          ))}</tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/20 transition-colors">
              {row.map((cell, j) => (
                <td key={j} className="px-3 py-2 text-gray-400 border-x border-gray-700/30 align-top">
                  {j === 0 ? <code className="text-blue-300 text-xs font-mono">{cell}</code> : cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
function Note({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex gap-2 p-3 rounded-lg border border-amber-700/30 bg-amber-950/20 mb-4">
      <span className="text-amber-400 text-xs mt-0.5 flex-shrink-0">⚠</span>
      <p className="text-xs text-amber-300/80 leading-relaxed">{children}</p>
    </div>
  )
}
