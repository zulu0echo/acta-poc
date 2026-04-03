import { expect } from 'chai'
import { PredicateBuilder } from '../src/predicateBuilder'
import { PresentationRequestBuilder } from '../src/presentationRequest'
import { createEthrDIDIdentity } from '../../issuer/src/didEthrSetup'
import { hashPredicateProgram } from '@acta/shared'

describe('Verifier — PredicateBuilder and PresentationRequest', () => {
  let identity: Awaited<ReturnType<typeof createEthrDIDIdentity>>

  before(async () => {
    identity = await createEthrDIDIdentity()
  })

  describe('PredicateBuilder', () => {
    it('builds a simple single-condition predicate', () => {
      const predicate = new PredicateBuilder('AgentCapabilityCredential')
        .require('auditScore').greaterThanOrEqual(80)
        .build()

      expect(predicate.hash).to.match(/^0x[0-9a-f]{64}$/)
      expect(predicate.toDescription()).to.include('Audit Score ≥ 80')
    })

    it('builds a compound AND predicate', () => {
      const predicate = new PredicateBuilder('AgentCapabilityCredential')
        .require('auditScore').greaterThanOrEqual(80)
        .and()
        .require('capabilities').includes('evm-execution')
        .and()
        .require('operatorJurisdiction').notIn(['IR', 'KP', 'RU', 'BY'])
        .build()

      expect(predicate.hash).to.match(/^0x[0-9a-f]{64}$/)
      const desc = predicate.toDescription()
      expect(desc).to.include('Audit Score')
      expect(desc).to.include('evm-execution')
      expect(desc).to.include('IR')
    })

    it('produces deterministic hashes for same predicate', () => {
      const build = () => new PredicateBuilder('AgentCapabilityCredential')
        .require('auditScore').greaterThanOrEqual(80)
        .and()
        .require('capabilities').includes('evm-execution')
        .build()

      expect(build().hash).to.equal(build().hash)
    })

    it('produces different hashes for different predicates', () => {
      const a = new PredicateBuilder('AgentCapabilityCredential')
        .require('auditScore').greaterThanOrEqual(80)
        .build()
      const b = new PredicateBuilder('AgentCapabilityCredential')
        .require('auditScore').greaterThanOrEqual(90)
        .build()
      expect(a.hash).to.not.equal(b.hash)
    })

    it('serialises to valid JSON', () => {
      const predicate = new PredicateBuilder('AgentCapabilityCredential')
        .require('auditScore').greaterThanOrEqual(75)
        .build()
      const parsed = JSON.parse(predicate.toJSON())
      expect(parsed.schemaId).to.equal('AgentCapabilityCredential')
      expect(parsed.version).to.equal(1)
    })

    it('throws when no conditions are added', () => {
      expect(() => new PredicateBuilder('AgentCapabilityCredential').build())
        .to.throw('at least one condition')
    })
  })

  describe('PresentationRequestBuilder', () => {
    it('creates an OID4VP authorization request', () => {
      const predicate = new PredicateBuilder('AgentCapabilityCredential')
        .require('auditScore').greaterThanOrEqual(80)
        .build()

      const builder = new PresentationRequestBuilder(identity)
      const result = builder.createPresentationRequest({
        policyId:              '0x' + 'ab'.repeat(32),
        predicate:             predicate as never,
        verifierCallbackUrl:   'https://example.com/callback',
        sessionNonce:          12345678n,
        onchainVerifierAddress: '0x' + 'cd'.repeat(20),
      })

      expect(result.requestUri).to.include('openid4vp://')
      expect(result.sessionId).to.be.a('string')
      expect(result.authorizationRequest.client_id).to.equal(identity.did)
      expect(result.authorizationRequest.response_type).to.equal('vp_token')
      expect(result.authorizationRequest['x-openac-predicate']).to.be.a('string')
    })
  })

  describe('PredicateBuilder.fromAgentOperators', () => {
    it('builds from AgentPredicateOperator array', () => {
      const predicate = PredicateBuilder.fromAgentOperators('AgentCapabilityCredential', [
        { op: 'audit_score_gte', threshold: 80 },
        { op: 'capability_includes', capabilityId: 'evm-execution' },
        { op: 'jurisdiction_not_in', sanctionsList: ['IR', 'KP'] },
      ])
      expect(predicate.hash).to.match(/^0x[0-9a-f]{64}$/)
      expect(predicate.toDescription()).to.include('Audit Score')
    })
  })
})
