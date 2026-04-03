import type { AgentCapabilityCredentialSubject, AgentCapabilityVC } from '@acta/shared'
import { W3C_CREDENTIAL_CONTEXT, CREDENTIAL_CONTEXT_V1, CREDENTIAL_VALIDITY_DAYS } from '@acta/shared'

/**
 * JSON-LD context definition for AgentCapabilityCredential.
 * Published at: https://acta.ethereum.org/contexts/AgentCapability/v1
 *
 * In production, this is served as a static file. In the PoC, it's embedded here
 * and served via the issuer's /contexts/AgentCapability/v1 endpoint.
 */
export const AGENT_CAPABILITY_CONTEXT = {
  '@context': {
    '@version': 1.1,
    'id': '@id',
    'type': '@type',
    'acta': 'https://acta.ethereum.org/vocab#',
    'AgentCapabilityCredential': acta:AgentCapabilityCredential',
    'auditScore': {
      '@id':   acta:auditScore',
      '@type': 'xsd:integer',
    },
    'modelHash': {
      '@id': acta:modelHash',
    },
    'operatorJurisdiction': {
      '@id': acta:operatorJurisdiction',
    },
    'capabilities': {
      '@id':         acta:capabilities',
      '@container':  '@set',
    },
    'auditedBy': {
      '@id': acta:auditedBy',
    },
    'auditDate': {
      '@id':   acta:auditDate',
      '@type': 'xsd:date',
    },
    'delegationDepth': {
      '@id':   acta:delegationDepth',
      '@type': 'xsd:integer',
    },
    'principalDid': {
      '@id': acta:principalDid',
    },
    'principalVcHash': {
      '@id': acta:principalVcHash',
    },
    'xsd': 'http://www.w3.org/2001/XMLSchema#',
  },
}

/**
 * Constructs an unsigned AgentCapabilityVC object from subject data.
 * The returned object is then signed as a JWT-VC by the issuer agent.
 */
export function buildAgentCapabilityVC(params: {
  issuerDid: string
  subjectData: AgentCapabilityCredentialSubject
  validityDays?: number
}): AgentCapabilityVC {
  const now = new Date()
  const expiry = new Date(now.getTime() + (params.validityDays ?? CREDENTIAL_VALIDITY_DAYS) * 86_400_000)

  validateSubjectData(params.subjectData)

  return {
    '@context': [W3C_CREDENTIAL_CONTEXT, CREDENTIAL_CONTEXT_V1],
    type: ['VerifiableCredential', 'AgentCapabilityCredential'],
    issuer: params.issuerDid,
    issuanceDate: now.toISOString(),
    expirationDate: expiry.toISOString(),
    credentialSubject: params.subjectData,
  }
}

/**
 * Validates subject data before signing. Throws descriptive errors.
 */
function validateSubjectData(subject: AgentCapabilityCredentialSubject): void {
  if (!subject.id || !subject.id.startsWith('did:ethr:')) {
    throw new Error(`credentialSubject.id must be a did:ethr DID, got: ${subject.id}`)
  }
  if (typeof subject.auditScore !== 'number' || subject.auditScore < 0 || subject.auditScore > 100) {
    throw new Error(`auditScore must be an integer 0–100, got: ${subject.auditScore}`)
  }
  if (!subject.modelHash || !/^0x[0-9a-fA-F]+$/.test(subject.modelHash)) {
    throw new Error(`modelHash must be a 0x-prefixed hex string`)
  }
  if (!subject.operatorJurisdiction || subject.operatorJurisdiction.length !== 2) {
    throw new Error(`operatorJurisdiction must be a 2-letter ISO 3166-1 alpha-2 code`)
  }
  if (!Array.isArray(subject.capabilities) || subject.capabilities.length === 0) {
    throw new Error(`capabilities must be a non-empty array`)
  }
  if (!subject.auditedBy || !subject.auditedBy.startsWith('did:ethr:')) {
    throw new Error(`auditedBy must be a did:ethr DID`)
  }
  if (!subject.auditDate || !/^\d{4}-\d{2}-\d{2}$/.test(subject.auditDate)) {
    throw new Error(`auditDate must be YYYY-MM-DD format`)
  }
}

/** Default demo credential subject values for development and testing */
export const DEFAULT_CREDENTIAL_SUBJECT: Omit<AgentCapabilityCredentialSubject, 'id' | 'auditedBy'> = {
  auditScore: 87,
  modelHash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
  operatorJurisdiction: 'US',
  capabilities: ['evm-execution', 'risk-assessment'],
  auditDate: '2026-03-01',
}
