// Base Sepolia chain configuration
export const BASE_SEPOLIA_CHAIN_ID = 84532
export const BASE_SEPOLIA_CHAIN_HEX = '0x14f69'
export const ERC1056_REGISTRY = '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b'
export const BASE_SEPOLIA_RPC = process.env.BASE_SEPOLIA_RPC_URL ?? 'https://sepolia.base.org'

// ACTA credential type identifiers
export const CREDENTIAL_TYPE = 'AgentCapabilityCredential'
export const CREDENTIAL_CONTEXT_V1 = 'https://acta.ethereum.org/contexts/AgentCapability/v1'
export const W3C_CREDENTIAL_CONTEXT = 'https://www.w3.org/2018/credentials/v1'

// DID method prefix for Base Sepolia
export const DID_ETHR_PREFIX = `did:ethr:${BASE_SEPOLIA_CHAIN_HEX}:`

/**
 * Maps credentialSubject field names to their position in the Circom
 * attributeValues[] array. Indices 6–15 are reserved and MUST be 0.
 */
export const ATTRIBUTE_INDEX = {
  AUDIT_SCORE: 0,           // integer 0–100
  MODEL_HASH: 1,            // uint256 (keccak256 of model hash string, truncated to field size)
  OPERATOR_JURISDICTION: 2, // ISO 3166-1 numeric: US=840, GB=826, DE=276, FR=250
  CAPABILITIES_BITMASK: 3,  // each capability maps to a bit position (see CAPABILITY_BIT)
  AUDITED_BY_HASH: 4,       // Poseidon hash of auditorDid string
  AUDIT_DATE_UNIX: 5,       // Unix timestamp of auditDate (YYYY-MM-DD → midnight UTC)
} as const

/** ISO 3166-1 numeric country codes for jurisdictions */
export const JURISDICTION_NUMERIC: Record<string, number> = {
  US: 840, GB: 826, DE: 276, FR: 250, JP: 392,
  SG: 702, AU: 36,  CA: 124, CH: 756, NL: 528,
  // Sanctioned jurisdictions
  IR: 364, KP: 408, RU: 643, BY: 112, SY: 760, CU: 192,
}

/** Capability bitmask positions for CAPABILITIES_BITMASK attribute */
export const CAPABILITY_BIT: Record<string, number> = {
  'evm-execution':    0b00000001,
  'risk-assessment':  0b00000010,
  'medical-analysis': 0b00000100,
  'kyc-verification': 0b00001000,
  'data-oracle':      0b00010000,
  'cross-chain':      0b00100000,
  'nft-valuation':    0b01000000,
  'governance-vote':  0b10000000,
}

// OpenAC circuit constants
export const CIRCUIT_ATTRIBUTE_COUNT = 16  // 0–15, indices 6–15 reserved
export const CIRCUIT_MAX_CONSTRAINTS = 1_000_000
export const NULL_FIELD_VALUE = BigInt(0)

// Contract deployment addresses (populated after deploy)
export const CONTRACT_ADDRESSES = {
  NullifierRegistry: process.env.NULLIFIER_REGISTRY_ADDRESS ?? '',
  OpenACCredentialAnchor: process.env.CREDENTIAL_ANCHOR_ADDRESS ?? '',
  GeneralizedPredicateVerifier: process.env.GP_VERIFIER_ADDRESS ?? '',
  ZKReputationAccumulator: process.env.ZK_REPUTATION_ADDRESS ?? '',
  AgentAccessGate: process.env.AGENT_ACCESS_GATE_ADDRESS ?? '',
} as const

// Credential validity period
export const CREDENTIAL_VALIDITY_DAYS = 90
export const PRESENTATION_EXPIRY_BLOCKS = 100  // ~200 seconds on Base
