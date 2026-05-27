import { expect } from 'chai'
import { ethers } from 'ethers'
import { initPoseidon, gp, ATTRIBUTE_INDEX } from '@acta/shared'
import { predicate, stealth, holder, verifier, ActaClient, NotImplementedError } from '../src'

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

describe('@acta/sdk — verifier surface (v0.4)', () => {
  it('builds a GP-native policy via verifier.builder()', () => {
    const built = verifier.builder()
      .require('auditScore').greaterThanOrEqual(80)
      .and().not()
      .require('operatorJurisdiction').inJurisdictions(['IR', 'KP'])
      .build()
    expect(built.hash).to.match(/^0x[0-9a-f]{64}$/)
    expect(built.program.predicates).to.have.lengthOf(3)
  })

  it('migrates a V1 program via verifier.fromV1Program()', () => {
    const v1 = {
      schemaId: 'AgentCapabilityCredential',
      version: 1,
      root: {
        type: 'condition' as const,
        condition: { attribute: 'auditScore', operator: 'gte' as const, value: 75 },
      },
    }
    const built = verifier.fromV1Program(v1)
    expect(built.program.predicates).to.have.lengthOf(1)
    expect(built.hash).to.match(/^0x[0-9a-f]{64}$/)
  })
})

describe('@acta/sdk — holder surface (v0.4)', () => {
  it('imports + presents a V2 credential via stub prover', async () => {
    const adapter = holder.createAdapter()
    const claims = new Array<bigint>(16).fill(0n)
    claims[ATTRIBUTE_INDEX.AUDIT_SCORE] = 95n
    claims[ATTRIBUTE_INDEX.OPERATOR_JURISDICTION] = 840n

    const handle = await adapter.importExistingCredential({
      attributeValues: claims,
      issuerPubKeyCommitment: BigInt('0x' + 'aa'.repeat(31)),
      randomness: 1n,
    })

    const program = verifier.builder()
      .require('auditScore').greaterThanOrEqual(80)
      .build()

    const presentation = await adapter.generatePresentationProof({
      credentialHandle: handle,
      predicateProgram: program.program,
      verifierAddress: ethers.getAddress('0x' + '11'.repeat(20)),
      policyId: '0x' + '22'.repeat(32),
      nonce: 1n,
      expiryBlock: 1000,
    })
    expect(presentation.publicSignals.predicateProgramHash.toLowerCase()).to.equal(
      program.hash.toLowerCase(),
    )
  })
})

describe('@acta/sdk — witness surface (v0.4)', () => {
  it('predicate.buildWitness produces a stack trace', () => {
    const p = predicate.builder()
      .add({ claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 80n } })
      .expression_([{ kind: 'pred', predicateIndex: 0 }])
      .build()
    const encoded = predicate.encode(p, [90n])
    const { witness, diagnostics } = predicate.buildWitness(p, encoded, {
      randomness: 1n,
      credentialCommitment: 0n,
      issuerPubKeyCommitment: 0n,
      verifierAddress: 0n,
      policyId: 0n,
      nonce: 0n,
      expiryBlock: 0n,
    })
    expect(diagnostics.programResult).to.equal(true)
    expect(witness.stackTrace[1][0]).to.equal(1n)
  })

  it('predicate.buildSnarkjsInput produces all-string JSON', () => {
    const p = predicate.builder()
      .add({ claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 80n } })
      .expression_([{ kind: 'pred', predicateIndex: 0 }])
      .build()
    const input = predicate.buildSnarkjsInput(p, [90n], {
      randomness: 1n,
      credentialCommitment: 0n,
      issuerPubKeyCommitment: 0n,
      verifierAddress: 0n,
      policyId: 0n,
      nonce: 0n,
      expiryBlock: 0n,
    })
    expect(input.randomness).to.equal('1')
    expect((input.attributeValues as string[])[0]).to.equal('90')
  })

  it('predicate.fromV1 translates a V1 program', () => {
    const v1 = {
      schemaId: 'AgentCapabilityCredential',
      version: 1,
      root: {
        type: 'condition' as const,
        condition: { attribute: 'auditScore', operator: 'gte' as const, value: 60 },
      },
    }
    const gpProg = predicate.fromV1(v1)
    expect(gpProg.predicates).to.have.lengthOf(1)
    expect(predicate.evaluate(gpProg, (() => {
      const a = new Array<bigint>(16).fill(0n)
      a[ATTRIBUTE_INDEX.AUDIT_SCORE] = 70n
      return a
    })())).to.equal(true)
  })
})
