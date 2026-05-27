/**
 * OpenACAdapterV2 end-to-end test using StubWalletUnitV2.
 *
 * Verifies the full presentation flow:
 *   1. Import credential (claim array → commitment + merkleRoot)
 *   2. Build a GPProgram via the GP-native builder
 *   3. Generate a V2 proof
 *   4. Validate public-signal shape + predicateProgramHash binding
 *   5. Off-chain verifyPresentation accepts the sentinel proof
 */

import { expect } from 'chai'
import { ethers } from 'ethers'
import { initPoseidon, gp, ATTRIBUTE_INDEX, computeContextHash, poseidonHash } from '@acta/shared'
import { OpenACAdapterV2, StubWalletUnitV2 } from '../src/openacAdapterV2'

before(async () => {
  await initPoseidon()
})

function makeClaims(opts: { auditScore?: number; jurisdiction?: number } = {}): bigint[] {
  const claims = new Array<bigint>(16).fill(0n)
  claims[ATTRIBUTE_INDEX.AUDIT_SCORE] = BigInt(opts.auditScore ?? 95)
  claims[ATTRIBUTE_INDEX.OPERATOR_JURISDICTION] = BigInt(opts.jurisdiction ?? 840) // US
  return claims
}

function makeProgram(auditMin = 80, allowedJurisdiction = 840): gp.GPProgram {
  return {
    version: 1,
    predicates: [
      { claimIndex: ATTRIBUTE_INDEX.AUDIT_SCORE, op: 'ge', operand: { kind: 'const', value: BigInt(auditMin) } },
      { claimIndex: ATTRIBUTE_INDEX.OPERATOR_JURISDICTION, op: 'eq', operand: { kind: 'const', value: BigInt(allowedJurisdiction) } },
    ],
    expression: [
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'pred', predicateIndex: 1 },
      { kind: 'op', op: 'AND' },
    ],
  }
}

describe('OpenACAdapterV2 — happy path', () => {
  it('imports credential + generates a V2 presentation', async () => {
    const adapter = new OpenACAdapterV2()
    const claims = makeClaims({ auditScore: 90 })
    const handle = await adapter.importExistingCredential({
      attributeValues: claims,
      issuerPubKeyCommitment: BigInt('0x' + 'aa'.repeat(31)),
      randomness: 12345n,
    })
    expect(handle.credentialId).to.match(/^0x[0-9a-f]{64}$/)

    const program = makeProgram(80, 840)
    const verifierAddress = ethers.getAddress('0x' + '11'.repeat(20))
    const policyId        = '0x' + '22'.repeat(32)
    const nonce           = 7n

    const presentation = await adapter.generatePresentationProof({
      credentialHandle: handle,
      predicateProgram: program,
      verifierAddress,
      policyId,
      nonce,
      expiryBlock: 999999,
    })

    const sig = presentation.publicSignals
    // Public-signal shape
    for (const k of ['nullifier','contextHash','predicateProgramHash','issuerPubKeyCommitment','credentialMerkleRoot','credentialCommitment']) {
      expect((sig as Record<string, unknown>)[k]).to.match(/^0x[0-9a-f]{64}$/, `expected bytes32 hex for ${k}`)
    }
    expect(sig.expiryBlock).to.equal(999999)

    // predicateProgramHash matches gp.gpProgramHash(program)
    expect(sig.predicateProgramHash.toLowerCase()).to.equal(gp.gpProgramHash(program).toLowerCase())

    // contextHash matches the off-chain helper
    expect(sig.contextHash.toLowerCase()).to.equal(computeContextHash(verifierAddress, policyId, nonce).toLowerCase())

    // nullifier matches Poseidon(Poseidon(commitment, randomness), contextHash)
    const credSecret = poseidonHash([BigInt(handle.commitment), 12345n])
    const expectedNullifier = '0x' + poseidonHash([credSecret, BigInt(sig.contextHash)]).toString(16).padStart(64, '0')
    expect(sig.nullifier).to.equal(expectedNullifier)
  })
})

describe('OpenACAdapterV2 — rejection paths', () => {
  it('refuses to issue a proof when the GP program is unsatisfied', async () => {
    const adapter = new OpenACAdapterV2()
    const claims = makeClaims({ auditScore: 50 }) // below threshold
    const handle = await adapter.importExistingCredential({
      attributeValues: claims,
      issuerPubKeyCommitment: BigInt('0x' + 'aa'.repeat(31)),
      randomness: 12345n,
    })
    const program = makeProgram(80, 840) // requires ≥ 80

    let err: Error | undefined
    try {
      await adapter.generatePresentationProof({
        credentialHandle: handle,
        predicateProgram: program,
        verifierAddress: ethers.getAddress('0x' + '11'.repeat(20)),
        policyId: '0x' + '22'.repeat(32),
        nonce: 7n,
        expiryBlock: 100,
      })
    } catch (e) {
      err = e as Error
    }
    expect(err).to.exist
    expect(err!.message).to.match(/evaluates to false/)
  })
})

describe('OpenACAdapterV2 — off-chain verify', () => {
  it('accepts a fresh sentinel proof bound to the same predicateProgramHash', async () => {
    const adapter = new OpenACAdapterV2()
    const claims = makeClaims({ auditScore: 90 })
    const handle = await adapter.importExistingCredential({
      attributeValues: claims,
      issuerPubKeyCommitment: BigInt('0x' + 'aa'.repeat(31)),
      randomness: 12345n,
    })
    const program = makeProgram()
    const presentation = await adapter.generatePresentationProof({
      credentialHandle: handle,
      predicateProgram: program,
      verifierAddress: ethers.getAddress('0x' + '11'.repeat(20)),
      policyId: '0x' + '22'.repeat(32),
      nonce: 1n,
      expiryBlock: 1000,
    })
    const expectedHash = gp.gpProgramHash(program)
    const result = await adapter.verifyPresentation(presentation, expectedHash)
    expect(result.valid).to.equal(true)
  })

  it('rejects when expected predicateProgramHash differs', async () => {
    const adapter = new OpenACAdapterV2()
    const claims = makeClaims({ auditScore: 90 })
    const handle = await adapter.importExistingCredential({
      attributeValues: claims,
      issuerPubKeyCommitment: BigInt('0x' + 'aa'.repeat(31)),
      randomness: 12345n,
    })
    const presentation = await adapter.generatePresentationProof({
      credentialHandle: handle,
      predicateProgram: makeProgram(80, 840),
      verifierAddress: ethers.getAddress('0x' + '11'.repeat(20)),
      policyId: '0x' + '22'.repeat(32),
      nonce: 2n,
      expiryBlock: 1000,
    })
    const wrongHash = gp.gpProgramHash(makeProgram(81, 840))
    const result = await adapter.verifyPresentation(presentation, wrongHash)
    expect(result.valid).to.equal(false)
    expect(result.reason).to.match(/predicateProgramHash mismatch/)
  })
})

describe('StubWalletUnitV2 — directly', () => {
  it('verifyProof requires exact sentinel + 7 pubSignals', async () => {
    const w = new StubWalletUnitV2()
    const bad = await w.verifyProof({ proofBytes: Buffer.from('deadbeef', 'hex'), publicSignals: [1n] })
    expect(bad).to.equal(false)
  })
})
