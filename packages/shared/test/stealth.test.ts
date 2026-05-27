import { expect } from 'chai'
import { deriveStealthIdentity, holderCommitment } from '../src/stealth'

const MASTER = Buffer.from(
  '11111111111111112222222222222222333333333333333344444444444444aa',
  'hex',
)

const BASE_CTX = {
  verifierAddress: '0x' + '11'.repeat(20),
  policyId: '0x' + '22'.repeat(32),
  sessionIndex: 0,
}

describe('Holder — stealth address derivation', () => {
  it('produces a valid EIP-55 address and matching DID', () => {
    const id = deriveStealthIdentity(MASTER, BASE_CTX)
    expect(id.address).to.match(/^0x[0-9a-fA-F]{40}$/)
    expect(id.privateKey).to.match(/^0x[0-9a-f]{64}$/)
    expect(id.publicKeyUncompressed.startsWith('0x04')).to.equal(true)
    expect(id.did.endsWith(id.address)).to.equal(true)
  })

  it('is deterministic for identical inputs', () => {
    const a = deriveStealthIdentity(MASTER, BASE_CTX)
    const b = deriveStealthIdentity(MASTER, BASE_CTX)
    expect(a.address).to.equal(b.address)
    expect(a.privateKey).to.equal(b.privateKey)
  })

  it('changes when verifier changes', () => {
    const a = deriveStealthIdentity(MASTER, BASE_CTX)
    const b = deriveStealthIdentity(MASTER, {
      ...BASE_CTX,
      verifierAddress: '0x' + '99'.repeat(20),
    })
    expect(a.address).to.not.equal(b.address)
  })

  it('changes when policyId changes', () => {
    const a = deriveStealthIdentity(MASTER, BASE_CTX)
    const b = deriveStealthIdentity(MASTER, {
      ...BASE_CTX,
      policyId: '0x' + '33'.repeat(32),
    })
    expect(a.address).to.not.equal(b.address)
  })

  it('changes when sessionIndex changes', () => {
    const a = deriveStealthIdentity(MASTER, BASE_CTX)
    const b = deriveStealthIdentity(MASTER, { ...BASE_CTX, sessionIndex: 1 })
    expect(a.address).to.not.equal(b.address)
  })

  it('changes when master secret changes', () => {
    const a = deriveStealthIdentity(MASTER, BASE_CTX)
    const b = deriveStealthIdentity(
      Buffer.from(
        'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddd11',
        'hex',
      ),
      BASE_CTX,
    )
    expect(a.address).to.not.equal(b.address)
  })

  it('case-normalises verifier address and policy id', () => {
    const a = deriveStealthIdentity(MASTER, BASE_CTX)
    const b = deriveStealthIdentity(MASTER, {
      verifierAddress: BASE_CTX.verifierAddress.toUpperCase().replace('0X', '0x'),
      policyId: BASE_CTX.policyId.toUpperCase().replace('0X', '0x'),
      sessionIndex: 0,
    })
    expect(a.address).to.equal(b.address)
  })

  it('rejects too-short master secret', () => {
    expect(() => deriveStealthIdentity(Buffer.from('deadbeef', 'hex'), BASE_CTX))
      .to.throw(/≥ 32 bytes/)
  })

  it('rejects malformed verifier address', () => {
    expect(() =>
      deriveStealthIdentity(MASTER, { ...BASE_CTX, verifierAddress: '0xdead' }),
    ).to.throw(/verifierAddress/)
  })

  it('rejects malformed policy id', () => {
    expect(() =>
      deriveStealthIdentity(MASTER, { ...BASE_CTX, policyId: '0xnotahash' }),
    ).to.throw(/policyId/)
  })

  it('produces 256 distinct addresses across sessions 0..255', () => {
    const seen = new Set<string>()
    for (let i = 0; i < 256; i++) {
      const id = deriveStealthIdentity(MASTER, { ...BASE_CTX, sessionIndex: i })
      expect(seen.has(id.address)).to.equal(false)
      seen.add(id.address)
    }
    expect(seen.size).to.equal(256)
  })
})

describe('Holder — holderCommitment', () => {
  it('is deterministic', () => {
    const a = holderCommitment(MASTER, 1n)
    const b = holderCommitment(MASTER, 1n)
    expect(a).to.equal(b)
  })

  it('changes with salt', () => {
    expect(holderCommitment(MASTER, 1n)).to.not.equal(holderCommitment(MASTER, 2n))
  })

  it('changes with master', () => {
    const m2 = Buffer.from(
      'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddd11',
      'hex',
    )
    expect(holderCommitment(MASTER, 1n)).to.not.equal(holderCommitment(m2, 1n))
  })

  it('is the expected length', () => {
    expect(holderCommitment(MASTER, 1n)).to.match(/^0x[0-9a-f]{64}$/)
  })
})
