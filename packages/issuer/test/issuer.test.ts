import { expect } from 'chai'
import { createEthrDIDIdentity } from '../src/didEthrSetup'
import { buildAgentCapabilityVC, DEFAULT_CREDENTIAL_SUBJECT } from '../src/credentialSchema'
import { signCredentialAsJwt } from '../src/agent'

describe('Issuer — did:ethr identity and credential issuance', () => {
  let identity: Awaited<ReturnType<typeof createEthrDIDIdentity>>

  before(async () => {
    // Generate a fresh identity — no RPC needed, wallet is local
    identity = await createEthrDIDIdentity()
  })

  describe('createEthrDIDIdentity', () => {
    it('produces a DID in the correct did:ethr format', () => {
      expect(identity.did).to.match(/^did:ethr:0x14f69:0x[0-9a-fA-F]{40}$/)
    })

    it('DID address component matches wallet address (lowercase)', () => {
      const addressInDid = identity.did.split(':').pop()!.toLowerCase()
      expect(addressInDid).to.equal(identity.signer.address.toLowerCase())
    })

    it('creates a valid Resolver', () => {
      expect(identity.resolver).to.have.property('resolve').that.is.a('function')
    })
  })

  describe('buildAgentCapabilityVC', () => {
    it('constructs a valid VC with issuer and subject DIDs', () => {
      const holderDid = `did:ethr:0x14f69:0x${'a'.repeat(40)}`
      const vc = buildAgentCapabilityVC({
        issuerDid: identity.did,
        subjectData: {
          ...DEFAULT_CREDENTIAL_SUBJECT,
          id: holderDid,
          auditedBy: identity.did,
        },
      })

      expect(vc.issuer).to.equal(identity.did)
      expect(vc.credentialSubject.id).to.equal(holderDid)
      expect(vc.type).to.include('AgentCapabilityCredential')
      expect(vc.credentialSubject.auditScore).to.be.within(0, 100)
    })

    it('throws for invalid auditScore', () => {
      expect(() => buildAgentCapabilityVC({
        issuerDid: identity.did,
        subjectData: {
          ...DEFAULT_CREDENTIAL_SUBJECT,
          id: `did:ethr:0x14f69:0x${'b'.repeat(40)}`,
          auditedBy: identity.did,
          auditScore: 101,
        },
      })).to.throw(/auditScore/)
    })

    it('throws for non-did:ethr subject id', () => {
      expect(() => buildAgentCapabilityVC({
        issuerDid: identity.did,
        subjectData: {
          ...DEFAULT_CREDENTIAL_SUBJECT,
          id: 'did:key:z6Mkk7y...',
          auditedBy: identity.did,
        },
      })).to.throw(/did:ethr/)
    })
  })

  describe('signCredentialAsJwt', () => {
    it('produces a three-part JWT string', async () => {
      const holderDid = `did:ethr:0x14f69:0x${'c'.repeat(40)}`
      const vc = buildAgentCapabilityVC({
        issuerDid: identity.did,
        subjectData: {
          ...DEFAULT_CREDENTIAL_SUBJECT,
          id: holderDid,
          auditedBy: identity.did,
        },
      })
      const jwt = await signCredentialAsJwt(vc, identity)
      const parts = jwt.split('.')
      expect(parts).to.have.length(3)
    })

    it('JWT header contains ES256K alg and correct kid', async () => {
      const holderDid = `did:ethr:0x14f69:0x${'d'.repeat(40)}`
      const vc = buildAgentCapabilityVC({
        issuerDid: identity.did,
        subjectData: {
          ...DEFAULT_CREDENTIAL_SUBJECT,
          id: holderDid,
          auditedBy: identity.did,
        },
      })
      const jwt = await signCredentialAsJwt(vc, identity)
      const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString())
      expect(header.alg).to.equal('ES256K')
      expect(header.kid).to.include(identity.did)
    })

    it('JWT payload contains iss matching issuer DID', async () => {
      const holderDid = `did:ethr:0x14f69:0x${'e'.repeat(40)}`
      const vc = buildAgentCapabilityVC({
        issuerDid: identity.did,
        subjectData: {
          ...DEFAULT_CREDENTIAL_SUBJECT,
          id: holderDid,
          auditedBy: identity.did,
        },
      })
      const jwt = await signCredentialAsJwt(vc, identity)
      const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString())
      expect(payload.iss).to.equal(identity.did)
      expect(payload.sub).to.equal(holderDid)
    })
  })
})
