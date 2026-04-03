import type { ATTRIBUTE_INDEX } from './constants'

// ─── DID Layer ───────────────────────────────────────────────────────────────

export interface EthrDIDIdentity {
  /** Full DID string: "did:ethr:0x14f69:0x<address>" */
  did: string
  /** The Ethereum address embedded in the DID */
  address: string
  /** Hex-encoded secp256k1 private key (0x-prefixed) */
  privateKey: string
  /** Public key in compressed hex form */
  publicKey: string
}

// ─── W3C Credential Layer ────────────────────────────────────────────────────

export interface AgentCapabilityCredentialSubject {
  id: string                      // holder's did:ethr
  auditScore: number              // 0–100
  modelHash: string               // 0x-prefixed hex string (keccak256 of model bytes)
  operatorJurisdiction: string    // ISO 3166-1 alpha-2 (e.g. "US")
  capabilities: string[]          // array of capability identifiers
  auditedBy: string               // auditor's did:ethr
  auditDate: string               // ISO 8601 date string (YYYY-MM-DD)
  // Optional delegation fields for ACTA §4.8
  delegationDepth?: number        // 0 = direct human delegation
  principalDid?: string           // principal's did:ethr (kept private in ZK)
  principalVcHash?: string        // keccak256 of principal's serialised VC
}

export interface AgentCapabilityVC {
  '@context': string[]
  type: ['VerifiableCredential', 'AgentCapabilityCredential']
  issuer: string                   // issuer's did:ethr
  issuanceDate: string
  expirationDate: string
  credentialSubject: AgentCapabilityCredentialSubject
}

export interface SignedJwtVC {
  jwt: string                      // compact JWT-VC string
  decoded: AgentCapabilityVC       // decoded payload
}

// ─── OpenAC / ZK Layer ───────────────────────────────────────────────────────

/** Index tuple matching ATTRIBUTE_INDEX constants */
export type AttributeValues = readonly [
  auditScore: bigint,              // index 0
  modelHash: bigint,               // index 1
  operatorJurisdictionNumeric: bigint, // index 2
  capabilitiesBitmask: bigint,     // index 3
  auditedByHash: bigint,           // index 4
  auditDateUnix: bigint,           // index 5
  ...reserved: bigint[]            // indices 6–15 = 0n
]

export interface CredentialHandle {
  credentialId: string
  commitment: string    // bytes32 hex
  merkleRoot: string    // bytes32 hex
}

export interface OpenACPresentation {
  proofBytes: string            // hex-encoded Groth16 proof
  publicSignals: PublicSignals
  contextHash: string           // bytes32: keccak256(verifierAddress || policyId || nonce)
}

export interface PublicSignals {
  nullifier: string                // bytes32 hex — unique per (credential, verifier, policy)
  contextHash: string              // bytes32 hex
  predicateProgramHash: string     // bytes32 hex
  issuerPubKeyCommitment: string   // bytes32 hex
  credentialMerkleRoot: string     // bytes32 hex
  expiryBlock: number              // block number after which proof is invalid
}

export interface GenerateProofParams {
  credentialHandle: CredentialHandle
  predicateProgram: PredicateProgram
  policyId: string                 // bytes32 from on-chain registration
  verifierAddress: string          // Ethereum address of verifier
  nonce: bigint                    // session nonce from OID4VP request
  expiryBlock: number
}

// ─── Predicate Layer ─────────────────────────────────────────────────────────

export type PredicateOperatorType =
  | 'gte'
  | 'lte'
  | 'eq'
  | 'neq'
  | 'includes'
  | 'not_in'
  | 'between'

export interface PredicateCondition {
  attribute: keyof typeof ATTRIBUTE_INDEX | string
  operator: PredicateOperatorType
  value: string | number | string[] | [number, number]
}

export type LogicalConnective = 'AND' | 'OR' | 'NOT'

export interface PredicateNode {
  type: 'condition' | 'logical'
  condition?: PredicateCondition
  connective?: LogicalConnective
  children?: PredicateNode[]
}

export interface PredicateProgram {
  schemaId: string
  version: number
  root: PredicateNode
  /** Deterministic bytes32 hash of canonical serialisation */
  hash?: string
}

export type AgentPredicateOperator =
  | { op: 'capability_includes'; capabilityId: string }
  | { op: 'audit_score_gte'; threshold: number }
  | { op: 'model_hash_in'; trustedSet: string[] }
  | { op: 'jurisdiction_not_in'; sanctionsList: string[] }
  | { op: 'delegation_depth_lte'; maxDepth: number }
  | { op: 'principal_vc_satisfies'; innerPredicate: PredicateOperator | AgentPredicateOperator }
  | { op: 'delegation_scope_includes'; scopeId: string }

export type PredicateOperator = PredicateCondition

// ─── Policy Registry ─────────────────────────────────────────────────────────

export interface PolicyDescriptor {
  policyId: string           // bytes32
  verifier: string           // Ethereum address
  predicateProgramHash: string // bytes32
  credentialType: string
  circuitId: string
  expiryBlock: number
  active: boolean
}

// ─── OID4VCI / OID4VP ────────────────────────────────────────────────────────

export interface CredentialOffer {
  credential_issuer: string
  credentials: string[]
  grants: {
    'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
      'pre-authorized_code': string
    }
  }
}

export interface PresentationRequestParams {
  policyId: string
  predicate: PredicateProgram
  verifierCallbackUrl: string
  sessionNonce: bigint
  onchainVerifierAddress: string
}

export interface PresentationRequestResult {
  requestUri: string
  authorizationRequest: OID4VPAuthRequest
  sessionId: string
}

export interface OID4VPAuthRequest {
  response_type: 'vp_token'
  client_id: string                 // verifier's did:ethr
  client_id_scheme: 'did'
  nonce: string
  presentation_definition: PresentationDefinition
  'x-openac-predicate': string      // JSON serialised PredicateProgram
  'x-openac-policy-id': string
  'x-onchain-verifier': string
  response_uri: string
}

export interface PresentationDefinition {
  id: string
  input_descriptors: InputDescriptor[]
}

export interface InputDescriptor {
  id: string
  name: string
  purpose: string
  constraints: {
    fields: { path: string[]; filter?: Record<string, unknown> }[]
  }
}

// ─── Event Log ───────────────────────────────────────────────────────────────

export type EventSeverity = 'info' | 'success' | 'warning' | 'error'

export interface EventLogEntry {
  id: string
  timestamp: number
  severity: EventSeverity
  actor: 'issuer' | 'holder' | 'verifier' | 'contract' | 'system'
  message: string
  detail?: string
  txHash?: string
}
