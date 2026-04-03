import { expect } from 'chai'
import { OpenACAdapter } from '../src/openacAdapter'
import type { PredicateProgram } from '@acta/shared'
import { createEthrDIDIdentity } from '../src/didEthrSetup'

describe('Holder — OpenAC Adapter', () => {
  let adapter: OpenACAdapter
  let identity: Awaited<ReturnType<typeof createEthrDIDIdentity>>

  before(async () => {
    identity = await createEthrDIDIdentity()
    adapter  = new OpenACAdapter()
  })

  const SAMPLE_JWT_VC = buildSampleJwt()

  describe('importCredential', () => {
    it('returns a CredentialHandle with commitment and merkleRoot', async () => {
      const handle = await adapter.importCredential(SAMPLE_JWT_VC, identity.did, identity.resolver)
      expect(handle.commitment).to.match(/^0x[0-9a-f]{64}$/)
      expect(handle.merkleRoot).to.match(/^0x[0-9a-f]{64}$/)
      expect(handle.credentialId).to.be.a('string').with.length.greaterThan(0)
    })
  })

  describe('generatePresentationProof', () => {
    it('produces an OpenACPresentation with valid public signals', async () => {
      const handle = await adapter.importCredential(SAMPLE_JWT_VC, identity.did, identity.resolver)

      const predicate: PredicateProgram = {
        schemaId: 'AgentCapabilityCredential',
        version: 1,
        root: {
          type: 'condition',
          condition: { attribute: 'auditScore', operator: 'gte', value: 80 },
        },
      }

      const presentation = await adapter.generatePresentationProof({
        credentialHandle: handle,
        predicateProgram: predicate,
        policyId:         '0x' + 'ab'.repeat(32),
        verifierAddress:  '0x' + 'cd'.repeat(20),
        nonce:            12345678n,
        expiryBlock:      9999999,
      })

      expect(presentation.proofBytes).to.match(/^0x[0-9a-f]+$/)
      expect(presentation.publicSignals.nullifier).to.match(/^0x[0-9a-f]{64}$/)
      expect(presentation.publicSignals.expiryBlock).to.equal(9999999)
    })
  })

  describe('verifyPresentation', () => {
    it('returns valid=true for a locally generated proof', async () => {
      const handle = await adapter.importCredential(SAMPLE_JWT_VC, identity.did, identity.resolver)
      const predicate: PredicateProgram = {
        schemaId: 'AgentCapabilityCredential',
        version: 1,
        root: {
          type: 'condition',
          condition: { attribute: 'auditScore', operator: 'gte', value: 80 },
        },
      }

      const presentation = await adapter.generatePresentationProof({
        credentialHandle: handle,
        predicateProgram: predicate,
        policyId:         '0x' + 'ab'.repeat(32),
        verifierAddress:  '0x' + 'cd'.repeat(20),
        nonce:            12345678n,
        expiryBlock:      9999999,
      })

      const result = await adapter.verifyPresentation(presentation, '0xpolicy', identity.did, identity.resolver)
      expect(result.valid).to.be.true
    })
  })
})

function buildSampleJwt(): string {
  const header  = Buffer.from(JSON.stringify({ alg: 'ES256K', typ: 'JWT' })).toString('base64url')
  const payload = Buffer.from(JSON.stringify({
    iss: 'did:ethr:0x14f69:0x' + 'aa'.repeat(20),
    sub: 'did:ethr:0x14f69:0x' + 'bb'.repeat(20),
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'AgentCapabilityCredential'],
      issuer: 'did:ethr:0x14f69:0x' + 'aa'.repeat(20),
      issuanceDate: '2026-04-03T00:00:00Z',
      expirationDate: '2026-07-02T00:00:00Z',
      credentialSubject: {
        id: 'did:ethr:0x14f69:0x' + 'bb'.repeat(20),
        auditScore: 87,
        modelHash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        operatorJurisdiction: 'US',
        capabilities: ['evm-execution', 'risk-assessment'],
        auditedBy: 'did:ethr:0x14f69:0x' + 'aa'.repeat(20),
        auditDate: '2026-03-01',
      },
    },
  })).toString('base64url')
  return `${header}.${payload}.fakesignature`
}
