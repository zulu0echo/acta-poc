import { createContext, useContext } from 'react'

// ── Simulation Types ───────────────────────────────────────────────────────────

export interface SimulatedActor {
  did: string
  address: string
  role: 'issuer' | 'holder' | 'verifier'
  label: string
  description: string
}

export interface SimulatedCredentialValues {
  auditScore: number
  modelHash: string
  operatorJurisdiction: string
  capabilities: string[]
  auditedBy: string
  auditDate: string
}

export interface SimulatedPublicSignals {
  nullifier: string
  contextHash: string
  predicateProgramHash: string
  issuerPubKeyCommitment: string
  credentialMerkleRoot: string
  expiryBlock: number
}

export interface SimulatedPredicateCondition {
  attribute: string
  operator: string
  value: string | number | string[]
}

export interface VerificationStep {
  label: string
  detail: string
  status: 'pending' | 'running' | 'done' | 'error'
}

export interface EventLogEntry {
  id: string
  timestamp: number
  severity: 'info' | 'success' | 'warning' | 'error'
  actor: 'issuer' | 'holder' | 'verifier' | 'contract' | 'system'
  message: string
  detail?: string
  txHash?: string
}

export interface SimulationState {
  currentStep: number
  actors: { issuer: SimulatedActor; holder: SimulatedActor; verifier: SimulatedActor }
  credentialValues: SimulatedCredentialValues
  jwtVc: string
  jwtHeader: Record<string, string>
  jwtPayload: Record<string, unknown>
  credentialCommitment: string
  anchorTxHash: string
  predicateConditions: SimulatedPredicateCondition[]
  predicateProgramHash: string
  predicateDescription: string
  policyId: string
  policyTxHash: string
  presentationRequest: Record<string, unknown>
  proofGenerating: boolean
  proofProgress: number
  proofTimeMs: number
  zkProof: string
  publicSignals: SimulatedPublicSignals
  nullifier: string
  verificationSteps: VerificationStep[]
  verificationTxHash: string
  accessGranted: boolean
  replayAttempted: boolean
  replayReverted: boolean
  eventLog: EventLogEntry[]
  activeEdges: string[]
}

// ── Deterministic Mock Data Generators ────────────────────────────────────────

function fakeHex(seed: string, bytes = 32): string {
  let h = 0
  for (let i = 0; i < seed.length; i++) {
    h = ((h << 5) - h + seed.charCodeAt(i)) | 0
  }
  let result = ''
  let s = Math.abs(h)
  for (let i = 0; i < bytes * 2; i++) {
    s = (s * 1664525 + 1013904223) & 0xffffffff
    result += Math.abs(s).toString(16).padStart(8, '0')
  }
  return '0x' + result.slice(0, bytes * 2)
}

function fakeAddress(seed: string): string {
  return '0x' + fakeHex(seed, 20).slice(2)
}

function fakeDid(seed: string): string {
  return `did:ethr:0x14f69:${fakeAddress(seed)}`
}

function fakeJwt(header: Record<string, string>, payload: Record<string, unknown>): string {
  const h = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  const p = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  const sig = fakeHex('jwt-sig', 64).slice(2, 90)
  return `${h}.${p}.${sig}`
}

// ── Initial State ─────────────────────────────────────────────────────────────

export function createInitialState(): SimulationState {
  const issuerAddr   = fakeAddress('issuer-2026')
  const holderAddr   = fakeAddress('holder-2026')
  const verifierAddr = fakeAddress('verifier-2026')

  const issuerDid   = `did:ethr:0x14f69:${issuerAddr}`
  const holderDid   = `did:ethr:0x14f69:${holderAddr}`
  const verifierDid = `did:ethr:0x14f69:${verifierAddr}`

  const credentialValues: SimulatedCredentialValues = {
    auditScore:           87,
    modelHash:            fakeHex('model-gpt4-audit', 32),
    operatorJurisdiction: 'US',
    capabilities:         ['evm-execution', 'risk-assessment'],
    auditedBy:            issuerDid,
    auditDate:            '2026-03-01',
  }

  const now = Math.floor(Date.now() / 1000)
  const exp = now + 90 * 86400

  const jwtHeader  = { alg: 'ES256K', typ: 'JWT', kid: `${issuerDid}#controller` }
  const jwtPayload = {
    iss: issuerDid,
    sub: holderDid,
    iat: now,
    nbf: now,
    exp,
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://acta.ethereum.org/contexts/AgentCapability/v1'],
      type:       ['VerifiableCredential', 'AgentCapabilityCredential'],
      issuer:     issuerDid,
      issuanceDate:   new Date(now * 1000).toISOString(),
      expirationDate: new Date(exp * 1000).toISOString(),
      credentialSubject: { id: holderDid, ...credentialValues },
    },
  }

  const jwtVc = fakeJwt(jwtHeader, jwtPayload)

  const predicateConditions: SimulatedPredicateCondition[] = [
    { attribute: 'auditScore',           operator: '≥',       value: 80 },
    { attribute: 'capabilities',         operator: 'includes', value: 'evm-execution' },
    { attribute: 'operatorJurisdiction', operator: 'NOT IN',   value: ['IR', 'KP', 'RU', 'BY'] },
  ]

  const predicateProgramHash = fakeHex('predicate-hash-2026', 32)
  const policyId             = fakeHex('policy-id-2026', 32)

  const nullifier            = fakeHex('nullifier-2026', 32)
  const contextHash          = fakeHex('context-hash-2026', 32)
  const issuerPubKeyCommit   = fakeHex('issuer-pubkey-commit', 32)
  const credMerkleRoot       = fakeHex('cred-merkle-root', 32)

  const verificationSteps: VerificationStep[] = [
    { label: 'Policy loaded',                  detail: `policyId: ${policyId.slice(0, 18)}…`, status: 'pending' },
    { label: 'Signals decoded',                detail: '6 public signals extracted from proof', status: 'pending' },
    { label: 'Predicate hash matches',         detail: `hash: ${predicateProgramHash.slice(0, 18)}…`, status: 'pending' },
    { label: 'Expiry block valid',             detail: 'expiryBlock > block.number ✓', status: 'pending' },
    { label: 'Credential Merkle root current', detail: 'isMerkleRootCurrent() == true', status: 'pending' },
    { label: 'Issuer commitment matches',      detail: 'issuerPubKeyCommitment == policy.issuerCommitment', status: 'pending' },
    { label: 'Context hash matches',           detail: 'keccak256(caller || policyId || nonce) matches', status: 'pending' },
    { label: 'Proof valid',                    detail: 'OpenACSnarkVerifier.verifyProof() == true', status: 'pending' },
    { label: 'Nullifier registered',           detail: `nullifier: ${nullifier.slice(0, 18)}… stored`, status: 'pending' },
    { label: 'PresentationAccepted emitted',   detail: 'Event broadcast on-chain', status: 'pending' },
  ]

  return {
    currentStep:          1,
    actors: {
      issuer:   { did: issuerDid,   address: issuerAddr,   role: 'issuer',   label: 'Issuer',   description: 'A trusted audit firm that certifies AI agents' },
      holder:   { did: holderDid,   address: holderAddr,   role: 'holder',   label: 'Agent',    description: 'The AI trading agent seeking protocol access' },
      verifier: { did: verifierDid, address: verifierAddr, role: 'verifier', label: 'Protocol', description: 'The DeFi protocol checking agent compliance' },
    },
    credentialValues,
    jwtVc,
    jwtHeader,
    jwtPayload,
    credentialCommitment: fakeHex('commitment-2026', 32),
    anchorTxHash:         fakeHex('anchor-tx-2026', 32),
    predicateConditions,
    predicateProgramHash,
    predicateDescription: 'Audit Score ≥ 80 AND Capabilities includes "evm-execution" AND Jurisdiction NOT IN [IR, KP, RU, BY]',
    policyId,
    policyTxHash:         fakeHex('policy-tx-2026', 32),
    presentationRequest: {
      response_type:    'vp_token',
      client_id:        verifierDid,
      client_id_scheme: 'did',
      nonce:            fakeHex('nonce-2026', 8),
      'x-openac-predicate':  '{"schemaId":"AgentCapabilityCredential","version":1,"root":{…}}',
      'x-openac-policy-id':  policyId,
      'x-onchain-verifier':  fakeAddress('gp-verifier'),
    },
    proofGenerating:     false,
    proofProgress:       0,
    proofTimeMs:         0,
    zkProof:             fakeHex('zk-proof-2026', 128),
    publicSignals: {
      nullifier,
      contextHash,
      predicateProgramHash,
      issuerPubKeyCommitment: issuerPubKeyCommit,
      credentialMerkleRoot:   credMerkleRoot,
      expiryBlock:            12_456_789,
    },
    nullifier,
    verificationSteps,
    verificationTxHash: fakeHex('verification-tx-2026', 32),
    accessGranted:      false,
    replayAttempted:    false,
    replayReverted:     false,
    eventLog: [
      {
        id:        'init-1',
        timestamp: Date.now(),
        severity:  'info',
        actor:     'system',
        message:   'ACTA simulation initialised',
        detail:    'All actors generated with deterministic did:ethr identities',
      },
    ],
    activeEdges: [],
  }
}

// ── Simulation Context ────────────────────────────────────────────────────────

export interface SimulationContextValue {
  state: SimulationState
  nextStep: () => void
  prevStep: () => void
  goToStep: (step: number) => void
  reset: () => void
  updateCredentialValues: (values: Partial<SimulatedCredentialValues>) => void
  updatePredicateConditions: (conditions: SimulatedPredicateCondition[]) => void
  runProofGeneration: () => Promise<void>
  runVerificationSteps: () => Promise<void>
  grantAccess: () => void
  attemptReplay: () => void
  addEvent: (entry: Omit<EventLogEntry, 'id' | 'timestamp'>) => void
}

export const SimulationContext = createContext<SimulationContextValue | null>(null)

export function useSimulation(): SimulationContextValue {
  const ctx = useContext(SimulationContext)
  if (!ctx) throw new Error('useSimulation must be used within SimulationProvider')
  return ctx
}
