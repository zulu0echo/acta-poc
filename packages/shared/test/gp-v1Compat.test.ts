import { expect } from 'chai'
import { initPoseidon } from '../src/poseidon'
import { v1ToGP } from '../src/gp/v1Compat'
import { evaluateProgram } from '../src/gp/compiler'
import { ATTRIBUTE_INDEX } from '../src/constants'
import type { PredicateProgram } from '../src/types'

before(async () => {
  await initPoseidon()
})

function attrsFor(opts: { auditScore?: number; jurisdiction?: number }): bigint[] {
  const claims = new Array<bigint>(16).fill(0n)
  if (opts.auditScore !== undefined) {
    claims[ATTRIBUTE_INDEX.AUDIT_SCORE] = BigInt(opts.auditScore)
  }
  if (opts.jurisdiction !== undefined) {
    claims[ATTRIBUTE_INDEX.OPERATOR_JURISDICTION] = BigInt(opts.jurisdiction)
  }
  return claims
}

describe('gp.v1Compat — single condition translations', () => {
  it('translates auditScore gte 80', () => {
    const v1: PredicateProgram = {
      schemaId: 'AgentCapabilityCredential',
      version: 1,
      root: { type: 'condition', condition: { attribute: 'auditScore', operator: 'gte', value: 80 } },
    }
    const gp = v1ToGP(v1)
    expect(gp.predicates).to.have.lengthOf(1)
    expect(gp.predicates[0]).to.deep.equal({
      claimIndex: ATTRIBUTE_INDEX.AUDIT_SCORE,
      op: 'ge',
      operand: { kind: 'const', value: 80n },
    })
    expect(gp.expression).to.deep.equal([{ kind: 'pred', predicateIndex: 0 }])

    expect(evaluateProgram(gp, attrsFor({ auditScore: 85 }))).to.equal(true)
    expect(evaluateProgram(gp, attrsFor({ auditScore: 70 }))).to.equal(false)
  })

  it('translates operatorJurisdiction not_in [US] (single)', () => {
    const v1: PredicateProgram = {
      schemaId: 'AgentCapabilityCredential',
      version: 1,
      root: {
        type: 'condition',
        condition: { attribute: 'operatorJurisdiction', operator: 'not_in', value: ['US'] },
      },
    }
    const gp = v1ToGP(v1)
    // Expression: P0 NOT  (where P0 = jur == 840)
    expect(gp.expression).to.deep.equal([
      { kind: 'pred', predicateIndex: 0 },
      { kind: 'op', op: 'NOT' },
    ])
    expect(evaluateProgram(gp, attrsFor({ jurisdiction: 840 }))).to.equal(false) // US
    expect(evaluateProgram(gp, attrsFor({ jurisdiction: 826 }))).to.equal(true)  // GB
  })

  it('translates operatorJurisdiction not_in [IR, KP, RU] (multi)', () => {
    const v1: PredicateProgram = {
      schemaId: 'AgentCapabilityCredential',
      version: 1,
      root: {
        type: 'condition',
        condition: { attribute: 'operatorJurisdiction', operator: 'not_in', value: ['IR', 'KP', 'RU'] },
      },
    }
    const gp = v1ToGP(v1)
    // Predicates: P0:jur==IR, P1:jur==KP, P2:jur==RU
    // Expression: P0 NOT  P1 NOT AND  P2 NOT AND
    expect(gp.predicates).to.have.lengthOf(3)
    // Sanity-check by evaluation
    expect(evaluateProgram(gp, attrsFor({ jurisdiction: 364 }))).to.equal(false) // IR
    expect(evaluateProgram(gp, attrsFor({ jurisdiction: 408 }))).to.equal(false) // KP
    expect(evaluateProgram(gp, attrsFor({ jurisdiction: 643 }))).to.equal(false) // RU
    expect(evaluateProgram(gp, attrsFor({ jurisdiction: 840 }))).to.equal(true)  // US (allowed)
  })
})

describe('gp.v1Compat — AND of multiple V1 conditions', () => {
  it('audit ≥ 80 AND jurisdiction not_in [IR, KP]', () => {
    const v1: PredicateProgram = {
      schemaId: 'AgentCapabilityCredential',
      version: 1,
      root: {
        type: 'logical',
        connective: 'AND',
        children: [
          { type: 'condition', condition: { attribute: 'auditScore', operator: 'gte', value: 80 } },
          {
            type: 'condition',
            condition: {
              attribute: 'operatorJurisdiction',
              operator: 'not_in',
              value: ['IR', 'KP'],
            },
          },
        ],
      },
    }
    const gp = v1ToGP(v1)
    // P0: audit ≥ 80
    // P1: jur == IR
    // P2: jur == KP
    expect(gp.predicates).to.have.lengthOf(3)
    expect(evaluateProgram(gp, attrsFor({ auditScore: 85, jurisdiction: 840 }))).to.equal(true)
    expect(evaluateProgram(gp, attrsFor({ auditScore: 85, jurisdiction: 364 }))).to.equal(false) // IR banned
    expect(evaluateProgram(gp, attrsFor({ auditScore: 70, jurisdiction: 840 }))).to.equal(false) // audit too low
    expect(evaluateProgram(gp, attrsFor({ auditScore: 70, jurisdiction: 408 }))).to.equal(false) // both fail
  })
})

describe('gp.v1Compat — refusals', () => {
  it('refuses capabilities includes', () => {
    const v1: PredicateProgram = {
      schemaId: 'AgentCapabilityCredential',
      version: 1,
      root: {
        type: 'condition',
        condition: { attribute: 'capabilities', operator: 'includes', value: 'evm-execution' },
      },
    }
    expect(() => v1ToGP(v1)).to.throw(/capabilities `includes`/)
  })

  it('refuses unknown jurisdiction codes', () => {
    const v1: PredicateProgram = {
      schemaId: 'AgentCapabilityCredential',
      version: 1,
      root: {
        type: 'condition',
        condition: { attribute: 'operatorJurisdiction', operator: 'not_in', value: ['XX'] },
      },
    }
    expect(() => v1ToGP(v1)).to.throw(/unknown jurisdiction/)
  })

  it('refuses OR/NOT logical nodes at the V1 root', () => {
    const v1: PredicateProgram = {
      schemaId: 'AgentCapabilityCredential',
      version: 1,
      root: {
        type: 'logical',
        connective: 'OR',
        children: [
          { type: 'condition', condition: { attribute: 'auditScore', operator: 'gte', value: 80 } },
          { type: 'condition', condition: { attribute: 'auditScore', operator: 'lte', value: 30 } },
        ],
      },
    }
    expect(() => v1ToGP(v1)).to.throw(/flat AND/)
  })

  it('refuses unsupported V1 operators', () => {
    const v1: PredicateProgram = {
      schemaId: 'AgentCapabilityCredential',
      version: 1,
      root: {
        type: 'condition',
        condition: { attribute: 'auditScore', operator: 'between', value: [60, 90] },
      },
    }
    expect(() => v1ToGP(v1)).to.throw(/unsupported condition/)
  })
})
