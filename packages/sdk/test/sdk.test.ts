import { expect } from 'chai'
import { initPoseidon } from '@acta/shared'
import { predicate, stealth, ActaClient, NotImplementedError } from '../src'

before(async () => {
  await initPoseidon()
})

describe('@acta/sdk — predicate surface', () => {
  it('builds a GP program with the fluent builder', () => {
    const program = predicate.builder()
      .add({ claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 80n } })
      .add({ claimIndex: 2, op: 'eq', operand: { kind: 'const', value: 840n } })
      .expression_([
        { kind: 'pred', predicateIndex: 0 },
        { kind: 'pred', predicateIndex: 1 },
        { kind: 'op', op: 'AND' },
      ])
      .build()
    expect(program.predicates).to.have.lengthOf(2)
    expect(program.expression).to.have.lengthOf(3)
  })

  it('builds from infix tokens', () => {
    const program = predicate.builder()
      .add({ claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 80n } })
      .add({ claimIndex: 2, op: 'eq', operand: { kind: 'const', value: 840n } })
      .infix([
        { kind: 'pred', predicateIndex: 0 },
        { kind: 'op', op: 'AND' },
        { kind: 'pred', predicateIndex: 1 },
      ])
      .build()
    expect(program.expression.length).to.equal(3)
    expect(program.expression[2]).to.deep.equal({ kind: 'op', op: 'AND' })
  })

  it('computes a deterministic hash', () => {
    const p = predicate.builder()
      .add({ claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 80n } })
      .expression_([{ kind: 'pred', predicateIndex: 0 }])
      .build()
    const h = predicate.hash(p)
    expect(h).to.match(/^0x[0-9a-f]{64}$/)
    expect(h).to.equal(predicate.hash(p))
  })

  it('evaluates a program against claims', () => {
    const p = predicate.builder()
      .add({ claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 80n } })
      .expression_([{ kind: 'pred', predicateIndex: 0 }])
      .build()
    expect(predicate.evaluate(p, [85n])).to.equal(true)
    expect(predicate.evaluate(p, [70n])).to.equal(false)
  })
})

describe('@acta/sdk — stealth surface', () => {
  it('derives a stealth identity', () => {
    const id = stealth.derive(Buffer.alloc(32, 1), {
      verifierAddress: '0x' + '11'.repeat(20),
      policyId: '0x' + '22'.repeat(32),
      sessionIndex: 0,
    })
    expect(id.address).to.match(/^0x[0-9a-fA-F]{40}$/)
    expect(id.did).to.include('did:ethr:')
  })

  it('computes holder commitment', () => {
    const h = stealth.holderCommitment(Buffer.alloc(32, 7), 1n)
    expect(h).to.match(/^0x[0-9a-f]{64}$/)
  })
})

describe('@acta/sdk — client surface', () => {
  it('throws NotImplementedError for ActaClient.create', () => {
    expect(() =>
      ActaClient.create({
        network: 'base-sepolia',
      }),
    ).to.throw(NotImplementedError)
  })
})
