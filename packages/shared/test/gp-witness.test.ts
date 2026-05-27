/**
 * Witness builder tests — proves that `buildCircuitWitness()` produces a
 * stack trace that matches the semantics of `OpenACGPPresentationV2.circom`
 * `PostfixEval` template.
 *
 * These tests are **the** ground truth for the off-chain ↔ on-chain
 * postfix-evaluation contract. If any of them fail after a circuit edit,
 * either the circuit or the builder has drifted.
 */

import { expect } from 'chai'
import { initPoseidon } from '../src/poseidon'
import {
  buildCircuitWitness,
  encodeProgram,
  type GPProgram,
  type CredentialWitnessInputs,
  DEFAULT_GP_BOUNDS,
} from '../src/gp'

before(async () => {
  await initPoseidon()
})

const SAMPLE_CRED: CredentialWitnessInputs = {
  randomness: 1234567890n,
  credentialCommitment: 0n, // placeholder — not validated by builder
  issuerPubKeyCommitment: 0xdeadbeefn,
  verifierAddress: BigInt('0x' + '11'.repeat(20)),
  policyId: BigInt('0x' + '22'.repeat(32)),
  nonce: 7n,
  expiryBlock: 100n,
}

function build(program: GPProgram, claims: bigint[]) {
  const encoded = encodeProgram(program, claims)
  return buildCircuitWitness(program, encoded, SAMPLE_CRED)
}

describe('gp.witness.buildCircuitWitness — initial state', () => {
  const program: GPProgram = {
    version: 1,
    predicates: [{ claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 50n } }],
    expression: [{ kind: 'pred', predicateIndex: 0 }],
  }

  it('initial dpTrace[0] is 0 and stackTrace[0] is all zero', () => {
    const { witness } = build(program, [80n])
    expect(witness.dpTrace[0]).to.equal(0n)
    for (const v of witness.stackTrace[0]) expect(v).to.equal(0n)
  })

  it('stack shape matches T+1 × T+1', () => {
    const { witness, diagnostics } = build(program, [80n])
    const T = DEFAULT_GP_BOUNDS.maxTokens
    expect(witness.dpTrace).to.have.lengthOf(T + 1)
    expect(witness.stackTrace).to.have.lengthOf(T + 1)
    for (const row of witness.stackTrace) expect(row).to.have.lengthOf(T + 1)
    expect(diagnostics.stackShape.steps).to.equal(T + 1)
    expect(diagnostics.stackShape.depth).to.equal(T + 1)
  })
})

describe('gp.witness.buildCircuitWitness — single PRED', () => {
  const program: GPProgram = {
    version: 1,
    predicates: [{ claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 80n } }],
    expression: [{ kind: 'pred', predicateIndex: 0 }],
  }

  it('PRED token pushes the predicate result, then PAD is no-op', () => {
    const { witness, diagnostics } = build(program, [85n])
    // After step 0 (PRED): dp = 1, stack[0] = 1
    expect(witness.dpTrace[1]).to.equal(1n)
    expect(witness.stackTrace[1][0]).to.equal(1n)
    // After step 1 (PAD): unchanged
    expect(witness.dpTrace[2]).to.equal(1n)
    expect(witness.stackTrace[2][0]).to.equal(1n)
    expect(diagnostics.programResult).to.equal(true)
  })

  it('rejects when program evaluates to false', () => {
    expect(() => build(program, [70n])).to.throw(/evaluates to false/)
  })
})

describe('gp.witness.buildCircuitWitness — AND', () => {
  const program: GPProgram = {
    version: 1,
    predicates: [
      { claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 80n } },
      { claimIndex: 2, op: 'eq', operand: { kind: 'const', value: 840n } },
    ],
    expression: [
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'pred', predicateIndex: 1 },
      { kind: 'op', op: 'AND' },
    ],
  }

  it('two PRED pushes then AND collapses to one true', () => {
    const claims = [85n, 0n, 840n]
    const { witness } = build(program, claims)
    // step 0: PRED P0 -> dp=1, stack[0]=1
    expect(witness.dpTrace[1]).to.equal(1n)
    expect(witness.stackTrace[1][0]).to.equal(1n)
    // step 1: PRED P1 -> dp=2, stack[0]=1, stack[1]=1
    expect(witness.dpTrace[2]).to.equal(2n)
    expect(witness.stackTrace[2][0]).to.equal(1n)
    expect(witness.stackTrace[2][1]).to.equal(1n)
    // step 2: AND -> dp=1, stack[0]=1, stack[1]=0
    expect(witness.dpTrace[3]).to.equal(1n)
    expect(witness.stackTrace[3][0]).to.equal(1n)
    expect(witness.stackTrace[3][1]).to.equal(0n)
  })

  it('rejects when AND would yield false', () => {
    const claims = [85n, 0n, 0n] // jurisdiction != US
    expect(() => build(program, claims)).to.throw(/evaluates to false/)
  })
})

describe('gp.witness.buildCircuitWitness — OR', () => {
  const program: GPProgram = {
    version: 1,
    predicates: [
      { claimIndex: 2, op: 'eq', operand: { kind: 'const', value: 840n } },
      { claimIndex: 2, op: 'eq', operand: { kind: 'const', value: 826n } },
    ],
    expression: [
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'pred', predicateIndex: 1 },
      { kind: 'op', op: 'OR' },
    ],
  }

  it('US matches → OR is true', () => {
    const claims = [0n, 0n, 840n]
    const { witness } = build(program, claims)
    // After step 2 (OR): dp=1, stack[0] = 1 + 0 - 0 = 1
    expect(witness.dpTrace[3]).to.equal(1n)
    expect(witness.stackTrace[3][0]).to.equal(1n)
  })

  it('GB matches → OR is true', () => {
    const claims = [0n, 0n, 826n]
    const { witness } = build(program, claims)
    // After step 2 (OR): dp=1, stack[0] = 0 + 1 - 0 = 1
    expect(witness.dpTrace[3]).to.equal(1n)
    expect(witness.stackTrace[3][0]).to.equal(1n)
  })

  it('neither matches → throws', () => {
    expect(() => build(program, [0n, 0n, 100n])).to.throw(/evaluates to false/)
  })
})

describe('gp.witness.buildCircuitWitness — NOT', () => {
  const program: GPProgram = {
    version: 1,
    predicates: [{ claimIndex: 0, op: 'eq', operand: { kind: 'const', value: 0n } }],
    expression: [
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'op', op: 'NOT' },
    ],
  }

  it('NOT(false) is true; depth unchanged', () => {
    const claims = [5n] // P0: 5 == 0 → false
    const { witness } = build(program, claims)
    // step 0: PRED → dp=1, stack[0]=0
    expect(witness.dpTrace[1]).to.equal(1n)
    expect(witness.stackTrace[1][0]).to.equal(0n)
    // step 1: NOT → dp=1, stack[0]=1
    expect(witness.dpTrace[2]).to.equal(1n)
    expect(witness.stackTrace[2][0]).to.equal(1n)
  })

  it('NOT(true) is false → rejected', () => {
    expect(() => build(program, [0n])).to.throw(/evaluates to false/)
  })
})

describe('gp.witness.buildCircuitWitness — zkID spec example', () => {
  // (date_of_birth ≤ "2008-04-04" AND annual_income_eur ≥ 50000) OR country == "Netherlands"
  // Using packed numerics:
  //   claim[0] = date_of_birth as YYYYMMDD bigint
  //   claim[1] = annual_income_eur
  //   claim[2] = country as ISO numeric (NL=528)
  const program: GPProgram = {
    version: 1,
    predicates: [
      { claimIndex: 0, op: 'le', operand: { kind: 'const', value: 20080404n } },
      { claimIndex: 1, op: 'ge', operand: { kind: 'const', value: 50000n } },
      { claimIndex: 2, op: 'eq', operand: { kind: 'const', value: 528n } },
    ],
    expression: [
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'pred', predicateIndex: 1 },
      { kind: 'op', op: 'AND' },
      { kind: 'pred', predicateIndex: 2 },
      { kind: 'op', op: 'OR' },
    ],
  }

  it('Germany resident, eligible by age + income → true', () => {
    // P0=true (1990 ≤ 2008), P1=true (52000 ≥ 50000), P2=false (DE != NL)
    // (P0 AND P1) OR P2 = (T AND T) OR F = T
    const { witness, diagnostics } = build(program, [19900320n, 52000n, 276n])
    // Final: dp=1, stack[0]=1
    const final = witness.dpTrace.length - 1
    expect(witness.dpTrace[final]).to.equal(1n)
    expect(witness.stackTrace[final][0]).to.equal(1n)
    expect(diagnostics.programResult).to.equal(true)
    // diagnostics covers all M_PREDS slots; only the first 3 are active.
    expect(diagnostics.predicateResults.slice(0, program.predicates.length))
      .to.deep.equal([true, true, false])
  })

  it('Dutch resident with low income → true via membership branch', () => {
    // P0=true, P1=false, P2=true
    // (T AND F) OR T = F OR T = T
    const { witness, diagnostics } = build(program, [19900320n, 30000n, 528n])
    expect(witness.stackTrace[witness.dpTrace.length - 1][0]).to.equal(1n)
    expect(diagnostics.predicateResults.slice(0, program.predicates.length))
      .to.deep.equal([true, false, true])
  })

  it('Non-EU, ineligible → throws', () => {
    expect(() => build(program, [20100101n, 30000n, 100n])).to.throw(/evaluates to false/)
  })
})

describe('gp.witness.buildCircuitWitness — claim-to-claim predicates', () => {
  // loan_amount <= account_balance
  const program: GPProgram = {
    version: 1,
    predicates: [{ claimIndex: 1, op: 'le', operand: { kind: 'claim', claimIndex: 0 } }],
    expression: [{ kind: 'pred', predicateIndex: 0 }],
  }

  it('balance > loan → true', () => {
    const claims = [15000n, 12000n] // bal=15000, loan=12000
    expect(() => build(program, claims)).to.not.throw()
  })

  it('balance < loan → throws', () => {
    expect(() => build(program, [10000n, 12000n])).to.throw(/evaluates to false/)
  })
})

describe('gp.witness.buildSnarkjsInput', () => {
  const program: GPProgram = {
    version: 1,
    predicates: [{ claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 80n } }],
    expression: [{ kind: 'pred', predicateIndex: 0 }],
  }

  it('serialises to all-string field elements', async () => {
    const { buildSnarkjsInput } = await import('../src/gp/witness')
    const encoded = encodeProgram(program, [90n])
    const input = buildSnarkjsInput(program, encoded, SAMPLE_CRED)
    // Spot-check several keys
    expect(input.randomness).to.equal(SAMPLE_CRED.randomness.toString())
    expect((input.attributeValues as string[])[0]).to.equal('90')
    expect((input.stackTrace as string[][])[0]).to.have.lengthOf(DEFAULT_GP_BOUNDS.maxTokens + 1)
    // All values must be strings (no bigints — snarkjs requires JSON-serialisable inputs)
    for (const [, v] of Object.entries(input)) {
      if (Array.isArray(v)) {
        for (const row of v) {
          if (Array.isArray(row)) for (const x of row) expect(typeof x).to.equal('string')
          else expect(typeof row).to.equal('string')
        }
      } else {
        expect(typeof v).to.equal('string')
      }
    }
  })
})

describe('gp.encoder.buildHashLeaves — circuit parity', () => {
  const program: GPProgram = {
    version: 1,
    predicates: [
      { claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 80n } },
      { claimIndex: 2, op: 'eq', operand: { kind: 'const', value: 840n } },
    ],
    expression: [
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'pred', predicateIndex: 1 },
      { kind: 'op', op: 'AND' },
    ],
  }

  it('produces exactly 128 leaves for default bounds (75 active + 53 zero-padding)', async () => {
    const { buildHashLeaves, encodeProgram } = await import('../src/gp/encoder')
    const encoded = encodeProgram(program, [85n, 0n, 840n])
    const leaves = buildHashLeaves(encoded.inputs)
    expect(leaves).to.have.lengthOf(128)
    // Header
    expect(leaves[0]).to.equal(1n)
    expect(leaves[1]).to.equal(8n)   // M_PREDS
    expect(leaves[2]).to.equal(16n)  // T_TOKENS
    // First active predicate: claimIdx=0, op=ge(=1), operand=80, isClaimRef=0, isActive=1
    expect(leaves[3]).to.equal(0n)
    expect(leaves[4]).to.equal(1n)
    expect(leaves[5]).to.equal(80n)
    expect(leaves[6]).to.equal(0n)
    expect(leaves[7]).to.equal(1n)
    // Padding tail must be zero
    for (let i = 75; i < 128; i++) expect(leaves[i]).to.equal(0n)
  })

  it('rejects non-power-of-2 fold inputs', async () => {
    const { foldPoseidonHash } = await import('../src/gp/encoder')
    expect(() => foldPoseidonHash([1n, 2n, 3n])).to.throw(/power of 2/)
  })
})

describe('gp.witness — trace size budget', () => {
  it('max stack depth never exceeds T_TOKENS', () => {
    // Construct a pathological "stack-heavy" program: many pushes then collapses
    const program: GPProgram = {
      version: 1,
      predicates: [
        { claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 0n } },
        { claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 0n } },
        { claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 0n } },
        { claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 0n } },
        { claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 0n } },
        { claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 0n } },
        { claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 0n } },
        { claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 0n } },
      ],
      // 8 pushes then 7 ANDs
      expression: [
        { kind: 'pred', predicateIndex: 0 },
        { kind: 'pred', predicateIndex: 1 },
        { kind: 'pred', predicateIndex: 2 },
        { kind: 'pred', predicateIndex: 3 },
        { kind: 'pred', predicateIndex: 4 },
        { kind: 'pred', predicateIndex: 5 },
        { kind: 'pred', predicateIndex: 6 },
        { kind: 'pred', predicateIndex: 7 },
        { kind: 'op', op: 'AND' },
        { kind: 'op', op: 'AND' },
        { kind: 'op', op: 'AND' },
        { kind: 'op', op: 'AND' },
        { kind: 'op', op: 'AND' },
        { kind: 'op', op: 'AND' },
        { kind: 'op', op: 'AND' },
      ],
    }
    const { diagnostics } = build(program, [100n])
    expect(diagnostics.maxStackDepth).to.equal(8)
    expect(diagnostics.maxStackDepth).to.be.lessThanOrEqual(DEFAULT_GP_BOUNDS.maxTokens)
  })
})
