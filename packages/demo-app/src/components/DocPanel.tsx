import { useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { BookOpen, Wrench, TrendingUp, Code2 } from 'lucide-react'
import { useSimulation } from '../simulation/SimulationEngine'

interface DocContent {
  what: string
  how: string
  product: string
  code: string
}

const STEP_DOCS: Record<number, DocContent> = {
  1: {
    what: 'Three actors are created, each with a unique did:ethr DID. A DID (Decentralised Identifier) is a globally unique, self-sovereign identifier backed by an Ethereum address. No central authority is needed — the identifier is derived directly from a cryptographic key.',
    how: 'Each DID has the form did:ethr:0x14f69:0x<address> where 0x14f69 is Base Sepolia\'s chainId. The DID document is implicit in the EthereumDIDRegistry (ERC-1056) contract — no transaction is needed at creation time. The secp256k1 key is the same key used for Ethereum transactions.',
    product: 'Your integration does not need to manage DIDs directly. The SDK handles DID creation. You only need to know the verifier\'s address to register a policy on-chain.',
    code: `import { createEthrDIDIdentity } from '@acta/issuer'

const identity = await createEthrDIDIdentity()
// → { did: "did:ethr:0x14f69:0x...", signer, resolver }`,
  },
  2: {
    what: 'The Issuer configures what data will go into the AgentCapabilityCredential. Fields include an audit score (0–100), model hash (cryptographic fingerprint of the AI model), jurisdiction, capabilities list, and audit provenance.',
    how: 'The AgentCapabilityCredential follows the W3C Verifiable Credentials Data Model. The credential is not yet signed at this stage — it\'s just the data schema. The JSON-LD context at https://acta.ethereum.org/contexts/AgentCapability/v1 defines the vocabulary.',
    product: 'Work with your issuer partner to define realistic values for your use case. The audit score and capabilities fields are the most important for most DeFi protocols.',
    code: `const vc = buildAgentCapabilityVC({
  issuerDid: identity.did,
  subjectData: {
    id: holderDid,
    auditScore: 87,
    modelHash: "0xabcdef...",
    operatorJurisdiction: "US",
    capabilities: ["evm-execution"],
    auditedBy: issuerDid,
    auditDate: "2026-03-01"
  }
})`,
  },
  3: {
    what: 'The Issuer signs a credential for the Agent using the OpenID for Verifiable Credential Issuance (OID4VCI) protocol. The result is a JWT-VC — a JSON Web Token containing the W3C credential, signed with the Issuer\'s secp256k1 key.',
    how: 'OID4VCI uses a pre-authorized code grant. The Holder gets a credential offer URL, exchanges it for an access token, then requests the credential with a proof-of-possession JWT. The issued JWT-VC has iss = issuer\'s did:ethr, sub = holder\'s did:ethr, alg = ES256K.',
    product: 'Your agents receive credentials from issuer partners. You don\'t handle this directly — your verifier only sees the ZK proof, not the credential. The issuance flow is between the issuer and the agent.',
    code: `// GET /credential-offer → openid-credential-offer://...
// POST /token → access_token
// POST /credentials → { format: "jwt_vc_json", credential: "eyJ..." }`,
  },
  4: {
    what: 'The Agent anchors a cryptographic commitment to their credential on-chain, in the OpenACCredentialAnchor contract. The commitment is a Poseidon hash of the credential attributes plus randomness — it reveals nothing about the actual values.',
    how: 'anchorCredential(agentId, credentialType, commitment, merkleRoot) is called with agentId = uint256(uint160(holderAddress)). The contract enforces msg.sender == address(uint160(agentId)), so only the DID controller can anchor for their DID. The merkleRoot allows ZK proofs to prove attribute membership.',
    product: 'Anchoring happens automatically after issuance. You don\'t need to call this yourself. The agent\'s wallet handles anchoring. You receive the CredentialAnchored event as confirmation.',
    code: `await credentialAnchor.anchorCredential(
  BigInt(holderAddress),          // agentId
  keccak256("AgentCapabilityCredential"), // credentialType
  commitment,                     // Poseidon(attrs, randomness)
  merkleRoot                      // Merkle root of attr tree
)`,
  },
  5: {
    what: 'The Verifier (your protocol) defines what it requires from agents — the "predicate policy". This is a logical formula over credential attributes: "auditScore ≥ 80 AND capabilities includes \'evm-execution\' AND jurisdiction NOT IN [IR, KP]".',
    how: 'The PredicateBuilder SDK compiles conditions into a PredicateProgram struct and computes a deterministic bytes32 hash. The hash is the on-chain representation of the policy — two predicates with identical logic always produce the same hash.',
    product: 'This is your most important integration step. Think carefully about what your protocol actually requires. The predicate is enforced in zero-knowledge — agents prove they satisfy it without revealing their actual values.',
    code: `const predicate = new PredicateBuilder('AgentCapabilityCredential')
  .require('auditScore').greaterThanOrEqual(80)
  .and()
  .require('capabilities').includes('evm-execution')
  .and()
  .require('operatorJurisdiction').notIn(['IR', 'KP'])
  .build()`,
  },
  6: {
    what: 'The predicate policy is registered on-chain in GeneralizedPredicateVerifier. This produces a policyId — a bytes32 identifier that agents reference when generating proofs.',
    how: 'registerPolicy() stores the predicateProgramHash, circuitId, issuerCommitment, and expiryBlock. The policyId is deterministic (keccak256 of canonical policy encoding), so you can pre-compute it. Once registered, the policy cannot be changed — only deactivated.',
    product: 'Register once per compliance requirement. Use one policy for "DeFi trading agents", another for "KYC agents", etc. Share the policyId with your issuer partner so they can include it in credential offers.',
    code: `const policyId = await gpVerifier.registerPolicy({
  verifier: verifierAddress,
  predicateProgramHash: predicate.hash,
  credentialType: keccak256("AgentCapabilityCredential"),
  circuitId: OPENAC_CIRCUIT_ID,
  expiryBlock: 0,  // 0 = never expires
  issuerCommitment: issuerPubKeyCommitment,
  active: true
})`,
  },
  7: {
    what: 'The Verifier sends an OID4VP (OpenID for Verifiable Presentations) authorization request to the Agent. This is a challenge: "Prove you satisfy this policy." The request includes the policyId and the serialised PredicateProgram.',
    how: 'The request has client_id = verifier\'s did:ethr (proves authenticity), a nonce (prevents replay of the request itself), and custom x-openac-predicate and x-openac-policy-id extensions. The Agent verifies the request signature before generating a proof.',
    product: 'You call createPresentationRequest() to get a requestUri. Send this to the agent via any channel — a WebSocket message, a QR code, a deep link. The agent responds asynchronously.',
    code: `const { requestUri } = await verifier.createPresentationRequest({
  policyId,
  predicate,
  verifierCallbackUrl: "https://myprotocol.xyz/verify-callback",
  sessionNonce: crypto.getRandomValues(new BigUint64Array(1))[0],
  onchainVerifierAddress: GP_VERIFIER_ADDRESS
})`,
  },
  8: {
    what: 'The Agent generates a ZK proof that they satisfy the predicate — without revealing their actual credential values. The proof is a Groth16 SNARK that takes ~0.13 seconds to generate on modern hardware.',
    how: 'The ZK circuit (OpenACGPPresentation.circom) takes private inputs (credential attributes, randomness, issuer key) and public inputs (predicate program hash, verifier address, nonce). It outputs 6 public signals: nullifier, contextHash, predicateProgramHash, issuerPubKeyCommitment, credentialMerkleRoot, expiryBlock.',
    product: 'This happens entirely inside the agent. Your protocol never sees the agent\'s credential values. The nullifier in the public signals is the agent\'s anonymous identifier for this specific (policy, verifier) context.',
    code: `// wallet-unit-poc generates the proof
const proof = await openacAdapter.generatePresentationProof({
  credentialHandle,
  predicateProgram: predicate,
  policyId,
  verifierAddress,
  nonce,
  expiryBlock
})
// → { proofBytes, publicSignals: { nullifier, ... } }`,
  },
  9: {
    what: 'The Verifier receives the VP (Verifiable Presentation) containing the ZK proof and verifies it in two phases: first off-chain (fast, cheap), then on-chain (permanent, trustless). The 10-step sequence in GeneralizedPredicateVerifier enforces all security properties.',
    how: 'Off-chain: verifyProof() is called locally using OpenAC SDK, checking the proof and issuer commitment. On-chain: verifyAndRegister() executes the 10-step sequence atomically, registers the nullifier, and emits PresentationAccepted. Both phases use the same verification key.',
    product: 'Call processResponse() in your integration — it handles both phases. On success, you receive a txHash and nullifier. Use isAccepted(nullifier) in your smart contract to gate access.',
    code: `// Off-chain (pre-flight)
const { valid } = await offchainVerifier.verifyOffchain({ presentation, policyId, issuerDid, vpJwt, holderDid })

// On-chain (atomic, irreversible)
const { txHash, nullifier } = await onchainSubmitter.submit({ policyId, presentation, agentDid, nonce })`,
  },
  10: {
    what: 'A smart contract (AgentAccessGate) reads from GeneralizedPredicateVerifier to determine if a nullifier has been verified. Access is granted to any agent with an accepted proof. The same proof cannot be reused — replay attacks are cryptographically impossible.',
    how: 'AgentAccessGate.grantAccess(nullifier) calls gpVerifier.isAccepted(nullifier). If true, the nullifier is granted access. The onlyVerifiedAgent(nullifier) modifier gates protocol functions. A second call with the same nullifier reverts with AccessAlreadyGranted at the gate level, and NullifierAlreadyActive at the registry level.',
    product: 'Add AgentAccessGate to your contract stack, or use the onlyVerifiedAgent modifier pattern. For off-chain gating, call isAccepted() directly. The nullifier is your anonymous agent identifier — log it for your records without linking it to any real identity.',
    code: `// In your smart contract
function executeProtocolAction(bytes32 nullifier, ...) 
  external 
  onlyVerifiedAgent(nullifier) 
{
  // Agent is verified — execute action
}

// Replay attempt → AccessAlreadyGranted revert`,
  },
}

const TABS = [
  { id: 'what',    label: 'What is this?',      icon: BookOpen },
  { id: 'how',     label: 'How it works',        icon: Wrench },
  { id: 'product', label: 'For your product',   icon: TrendingUp },
  { id: 'code',    label: 'In the code',         icon: Code2 },
] as const

export default function DocPanel() {
  const { state } = useSimulation()
  const [activeTab, setActiveTab] = useState<'what' | 'how' | 'product' | 'code'>('what')

  const docs = STEP_DOCS[state.currentStep]

  return (
    <div className="h-full flex flex-col">
      <div className="px-4 py-3 border-b border-gray-700/60">
        <p className="text-xs font-semibold text-gray-200">Documentation</p>
        <p className="text-[10px] text-gray-500">Updates per step</p>
      </div>

      <div className="flex border-b border-gray-700/60">
        {TABS.map(tab => {
          const Icon = tab.icon
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex-1 flex flex-col items-center gap-0.5 py-2 text-[10px] transition-colors ${
                activeTab === tab.id
                  ? 'text-brand-400 border-b-2 border-brand-500'
                  : 'text-gray-500 hover:text-gray-400'
              }`}
            >
              <Icon size={12} />
              <span className="hidden xl:block">{tab.label}</span>
            </button>
          )
        })}
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        <AnimatePresence mode="wait">
          <motion.div
            key={`${state.currentStep}-${activeTab}`}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
          >
            {activeTab !== 'code' && (
              <p className="text-xs text-gray-300 leading-relaxed">
                {docs?.[activeTab]}
              </p>
            )}
            {activeTab === 'code' && (
              <div className="code-block">
                <pre className="text-[11px] text-gray-300 leading-relaxed whitespace-pre-wrap">
                  {docs?.code}
                </pre>
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>

      {/* Step indicator at bottom */}
      <div className="px-4 py-2 border-t border-gray-700/60">
        <p className="text-[10px] text-gray-600">
          Step {state.currentStep} of 10 — {getStepTitle(state.currentStep)}
        </p>
      </div>
    </div>
  )
}

function getStepTitle(step: number): string {
  const titles: Record<number, string> = {
    1: 'Actors Created', 2: 'Schema Configured', 3: 'Credential Issued',
    4: 'On-Chain Anchor', 5: 'Predicate Built', 6: 'Policy Registered',
    7: 'Request Sent', 8: 'ZK Proof Generated', 9: 'Verified', 10: 'Access Granted',
  }
  return titles[step] ?? ''
}
