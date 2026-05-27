/**
 * zkID Generalized Predicates — TS implementation tests.
 *
 * Vectors derived from the zkID spec
 *   https://github.com/privacy-ethereum/zkID/tree/main/generalized-predicates/README.md
 *
 * The "Evaluation Flow" example uses:
 *   P0 P1 AND P2 OR    →  true OR (false OR P2) etc.
 * with claims (date_of_birth=2003-06-15, annual_income_eur=52000, country="Germany").
 *
 * Below we model that claim set with three numeric claims:
 *   claim[0] = date_of_birth as Unix days
 *   claim[1] = annual_income_eur
 *   claim[2] = country as ISO-numeric
 */

import { expect } from 'chai'
import { initPoseidon } from '../src/poseidon'
import {
  evaluateProgram,
  evaluatePostfix,
  evaluatePredicate,
  validateProgram,
  infixToPostfix,
} from '../src/gp/compiler'
import {
  DEFAULT_GP_BOUNDS,
  GP_COMPARE_OP_CODE,
  GP_TOKEN_TYPE_CODE,
  type GPProgram,
} from '../src/gp/types'
import { encodeProgram, gpProgramHash } from '../src/gp/encoder'

before(async () => {
  await initPoseidon()
})

describe('gp.compiler.infixToPostfix', () => {
  it('handles a single predicate', () => {
    const out = infixToPostfix([{ kind: 'pred', predicateIndex: 0 }])
    expect(out).to.deep.equal([{ kind: 'pred', predicateIndex: 0 }])
  })

  it('handles AND', () => {
    const out = infixToPostfix([
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'op', op: 'AND' },
      { kind: 'pred', predicateIndex: 1 },
    ])
    expect(out).to.deep.equal([
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'pred', predicateIndex: 1 },
      { kind: 'op', op: 'AND' },
    ])
  })

  it('handles (A AND B) OR C', () => {
    const out = infixToPostfix([
      { kind: 'lparen' },
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'op', op: 'AND' },
      { kind: 'pred', predicateIndex: 1 },
      { kind: 'rparen' },
      { kind: 'op', op: 'OR' },
      { kind: 'pred', predicateIndex: 2 },
    ])
    expect(out).to.deep.equal([
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'pred', predicateIndex: 1 },
      { kind: 'op', op: 'AND' },
      { kind: 'pred', predicateIndex: 2 },
      { kind: 'op', op: 'OR' },
    ])
  })

  it('honours AND > OR precedence', () => {
    // A OR B AND C  ≡  A OR (B AND C)  ≡  A B C AND OR
    const out = infixToPostfix([
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'op', op: 'OR' },
      { kind: 'pred', predicateIndex: 1 },
      { kind: 'op', op: 'AND' },
      { kind: 'pred', predicateIndex: 2 },
    ])
    expect(out).to.deep.equal([
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'pred', predicateIndex: 1 },
      { kind: 'pred', predicateIndex: 2 },
      { kind: 'op', op: 'AND' },
      { kind: 'op', op: 'OR' },
    ])
  })

  it('throws on unmatched parens', () => {
    expect(() =>
      infixToPostfix([{ kind: 'lparen' }, { kind: 'pred', predicateIndex: 0 }]),
    ).to.throw(/unmatched left parenthesis/)
    expect(() =>
      infixToPostfix([{ kind: 'pred', predicateIndex: 0 }, { kind: 'rparen' }]),
    ).to.throw(/unmatched right parenthesis/)
  })
})

describe('gp.compiler.evaluatePredicate', () => {
  const claims = [
    1980_03_20n, // P0 LHS: date_of_birth as packed YYYYMMDD
    52000n,      // P1 LHS: annual_income_eur
    276n,        // P2 LHS: country (Germany=276)
  ]
  it('le constant', () => {
    expect(
      evaluatePredicate(
        { claimIndex: 0, op: 'le', operand: { kind: 'const', value: 2008_04_04n } },
        claims,
      ),
    ).to.equal(true)
  })
  it('ge constant', () => {
    expect(
      evaluatePredicate(
        { claimIndex: 1, op: 'ge', operand: { kind: 'const', value: 50000n } },
        claims,
      ),
    ).to.equal(true)
  })
  it('eq constant (false)', () => {
    expect(
      evaluatePredicate(
        { claimIndex: 2, op: 'eq', operand: { kind: 'const', value: 528n } }, // NL
        claims,
      ),
    ).to.equal(false)
  })
  it('claim-to-claim ge', () => {
    expect(
      evaluatePredicate(
        { claimIndex: 1, op: 'ge', operand: { kind: 'claim', claimIndex: 0 } }, // income >= dob (silly but tests the path)
        claims,
      ),
    ).to.equal(false) // 52000 >= 19800320 → false
  })
})

describe('gp.compiler.evaluatePostfix (zkID spec example)', () => {
  it('(P0 AND P1) OR P2 → true', () => {
    // P0=true, P1=true, P2=false → true AND true OR false → true
    const out = evaluatePostfix(
      [
        { kind: 'pred', predicateIndex: 0 },
        { kind: 'pred', predicateIndex: 1 },
        { kind: 'op', op: 'AND' },
        { kind: 'pred', predicateIndex: 2 },
        { kind: 'op', op: 'OR' },
      ],
      [true, true, false],
    )
    expect(out).to.equal(true)
  })
  it('NOT P0', () => {
    const out = evaluatePostfix(
      [
        { kind: 'pred', predicateIndex: 0 },
        { kind: 'op', op: 'NOT' },
      ],
      [true],
    )
    expect(out).to.equal(false)
  })
})

describe('gp.compiler.validateProgram', () => {
  const ok: GPProgram = {
    version: 1,
    predicates: [
      { claimIndex: 0, op: 'le', operand: { kind: 'const', value: 100n } },
    ],
    expression: [{ kind: 'pred', predicateIndex: 0 }],
  }
  it('accepts a minimal program', () => {
    expect(() => validateProgram(ok)).to.not.throw()
  })
  it('rejects bad version', () => {
    expect(() => validateProgram({ ...ok, version: 2 as 1 })).to.throw(/version/)
  })
  it('rejects out-of-range claim index', () => {
    expect(() =>
      validateProgram({
        ...ok,
        predicates: [{ claimIndex: 999, op: 'eq', operand: { kind: 'const', value: 0n } }],
      }),
    ).to.throw(/claimIndex/)
  })
  it('rejects stack-underflow expressions', () => {
    expect(() =>
      validateProgram({
        ...ok,
        expression: [{ kind: 'op', op: 'AND' }],
      }),
    ).to.throw(/AND.*needs 2 operands/)
  })
  it('rejects expressions that leave depth != 1', () => {
    expect(() =>
      validateProgram({
        ...ok,
        predicates: [
          { claimIndex: 0, op: 'le', operand: { kind: 'const', value: 100n } },
          { claimIndex: 0, op: 'ge', operand: { kind: 'const', value: 0n } },
        ],
        expression: [
          { kind: 'pred', predicateIndex: 0 },
          { kind: 'pred', predicateIndex: 1 },
        ],
      }),
    ).to.throw(/depth/)
  })
})

describe('gp.encoder.encodeProgram', () => {
  const program: GPProgram = {
    version: 1,
    predicates: [
      { claimIndex: 0, op: 'le', operand: { kind: 'const', value: 20080404n } },
      { claimIndex: 1, op: 'ge', operand: { kind: 'const', value: 50000n } },
      { claimIndex: 2, op: 'eq', operand: { kind: 'const', value: 528n } }, // NL
    ],
    expression: [
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'pred', predicateIndex: 1 },
      { kind: 'op', op: 'AND' },
      { kind: 'pred', predicateIndex: 2 },
      { kind: 'op', op: 'OR' },
    ],
  }
  const claims = [19800320n, 52000n, 276n]

  it('pads to circuit bounds and packs codes correctly', () => {
    const enc = encodeProgram(program, claims)
    expect(enc.inputs.claims).to.have.lengthOf(DEFAULT_GP_BOUNDS.maxClaims)
    expect(enc.inputs.predClaimIdx).to.have.lengthOf(DEFAULT_GP_BOUNDS.maxPredicates)
    expect(enc.inputs.exprTokenType).to.have.lengthOf(DEFAULT_GP_BOUNDS.maxTokens)

    expect(enc.inputs.predOpCode[0]).to.equal(BigInt(GP_COMPARE_OP_CODE.le))
    expect(enc.inputs.predOpCode[1]).to.equal(BigInt(GP_COMPARE_OP_CODE.ge))
    expect(enc.inputs.predOpCode[2]).to.equal(BigInt(GP_COMPARE_OP_CODE.eq))
    expect(enc.inputs.predIsActive[0]).to.equal(1n)
    expect(enc.inputs.predIsActive[3]).to.equal(0n)

    expect(enc.inputs.exprTokenType[0]).to.equal(BigInt(GP_TOKEN_TYPE_CODE.pred))
    expect(enc.inputs.exprTokenType[2]).to.equal(BigInt(GP_TOKEN_TYPE_CODE.AND))
    expect(enc.inputs.exprTokenType[4]).to.equal(BigInt(GP_TOKEN_TYPE_CODE.OR))
    expect(enc.inputs.exprTokenType[5]).to.equal(BigInt(GP_TOKEN_TYPE_CODE.pad))
  })

  it('produces a deterministic predicateProgramHash', () => {
    const a = encodeProgram(program, claims).predicateProgramHash
    const b = encodeProgram(program, claims).predicateProgramHash
    expect(a).to.equal(b)
    expect(a).to.match(/^0x[0-9a-f]{64}$/)
  })

  it('hash is independent of claim values', () => {
    const a = encodeProgram(program, claims).predicateProgramHash
    const b = encodeProgram(program, [0n, 0n, 0n]).predicateProgramHash
    expect(a).to.equal(b)
  })

  it('changes hash when a predicate operand changes', () => {
    const a = encodeProgram(program, claims).predicateProgramHash
    const mutated: GPProgram = {
      ...program,
      predicates: [
        ...program.predicates.slice(0, 2),
        { claimIndex: 2, op: 'eq', operand: { kind: 'const', value: 529n } }, // bumped
      ],
    }
    const b = encodeProgram(mutated, claims).predicateProgramHash
    expect(a).to.not.equal(b)
  })

  it('changes hash when expression changes', () => {
    const a = encodeProgram(program, claims).predicateProgramHash
    const mutated: GPProgram = {
      ...program,
      expression: [
        { kind: 'pred', predicateIndex: 0 },
        { kind: 'pred', predicateIndex: 1 },
        { kind: 'pred', predicateIndex: 2 },
        { kind: 'op', op: 'OR' }, // P1 OR P2
        { kind: 'op', op: 'AND' }, // P0 AND (P1 OR P2)
      ],
    }
    const b = encodeProgram(mutated, claims).predicateProgramHash
    expect(a).to.not.equal(b)
  })

  it('matches the spec example evaluation', () => {
    // (P0 AND P1) OR P2 with the spec's truth values [true, true, false] → true
    expect(evaluateProgram(program, claims)).to.equal(true)
  })

  it('gpProgramHash() helper matches encodeProgram()', () => {
    const a = encodeProgram(program, claims).predicateProgramHash
    const b = gpProgramHash(program)
    expect(a).to.equal(b)
  })
})
