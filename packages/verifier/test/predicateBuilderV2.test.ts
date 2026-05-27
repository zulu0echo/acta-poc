/**
 * PredicateBuilderV2 tests — verifies the fluent GP-native API produces
 * the same canonical GP IR + hash as direct programmatic construction,
 * and that V1 → V2 migration preserves semantics.
 */

import { expect } from 'chai'
import { initPoseidon, gp, ATTRIBUTE_INDEX } from '@acta/shared'
import { PredicateBuilderV2 } from '../src/predicateBuilderV2'

before(async () => {
  await initPoseidon()
})

function attrs(opts: { auditScore?: number; jurisdiction?: number; capabilities?: number }): bigint[] {
  const claims = new Array<bigint>(16).fill(0n)
  if (opts.auditScore !== undefined)   claims[ATTRIBUTE_INDEX.AUDIT_SCORE] = BigInt(opts.auditScore)
  if (opts.jurisdiction !== undefined) claims[ATTRIBUTE_INDEX.OPERATOR_JURISDICTION] = BigInt(opts.jurisdiction)
  if (opts.capabilities !== undefined) claims[ATTRIBUTE_INDEX.CAPABILITIES_BITMASK] = BigInt(opts.capabilities)
  return claims
}

describe('PredicateBuilderV2 — fluent API', () => {
  it('audit ≥ 80 (single condition)', () => {
    const built = new PredicateBuilderV2('AgentCapabilityCredential')
      .require('auditScore').greaterThanOrEqual(80)
      .build()

    expect(built.program.predicates).to.have.lengthOf(1)
    expect(built.program.predicates[0]).to.deep.equal({
      claimIndex: ATTRIBUTE_INDEX.AUDIT_SCORE,
      op: 'ge',
      operand: { kind: 'const', value: 80n },
    })
    expect(built.program.expression).to.deep.equal([{ kind: 'pred', predicateIndex: 0 }])
    expect(built.hash).to.match(/^0x[0-9a-f]{64}$/)
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 85 }))).to.equal(true)
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 50 }))).to.equal(false)
  })

  it('audit ≥ 80 AND NOT jurisdiction in [IR, KP, RU]', () => {
    const built = new PredicateBuilderV2('AgentCapabilityCredential')
      .require('auditScore').greaterThanOrEqual(80)
      .and().not()
      .require('operatorJurisdiction').inJurisdictions(['IR', 'KP', 'RU'])
      .build()

    expect(built.program.predicates).to.have.lengthOf(4) // 1 audit + 3 jurisdictions
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 85, jurisdiction: 840 }))).to.equal(true)  // US ok
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 85, jurisdiction: 364 }))).to.equal(false) // IR banned
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 70, jurisdiction: 840 }))).to.equal(false) // audit low
  })

  it('audit ≥ 80 OR audit ≤ 30 (low-trust whitelist)', () => {
    const built = new PredicateBuilderV2('AgentCapabilityCredential')
      .require('auditScore').greaterThanOrEqual(80)
      .or()
      .require('auditScore').lessThanOrEqual(30)
      .build()
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 100 }))).to.equal(true)
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 50 }))).to.equal(false)
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 10 }))).to.equal(true)
  })

  it('AND > OR precedence: a AND b OR c parses as (a AND b) OR c', () => {
    // P0: audit ≥ 80, P1: jur == US, P2: jur == GB
    const built = new PredicateBuilderV2('AgentCapabilityCredential')
      .require('auditScore').greaterThanOrEqual(80)
      .and().require('operatorJurisdiction').equals('US')
      .or().require('operatorJurisdiction').equals('GB')
      .build()
    // Only GB (any audit) OR (US AND audit≥80) → true
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 50, jurisdiction: 826 }))).to.equal(true)  // GB
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 50, jurisdiction: 840 }))).to.equal(false) // US, audit low
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 90, jurisdiction: 840 }))).to.equal(true)  // US, audit high
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 90, jurisdiction: 276 }))).to.equal(false) // DE
  })

  it('claim-to-claim comparison', () => {
    // require AUDIT_SCORE ≥ CAPABILITIES_BITMASK (toy example)
    const built = new PredicateBuilderV2('Toy')
      .require(ATTRIBUTE_INDEX.AUDIT_SCORE).greaterThanOrEqualClaim(ATTRIBUTE_INDEX.CAPABILITIES_BITMASK)
      .build()
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 90, capabilities: 50 }))).to.equal(true)
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 10, capabilities: 50 }))).to.equal(false)
  })

  it('refuses capabilities.includes() with a helpful message', () => {
    expect(() =>
      new PredicateBuilderV2('AgentCapabilityCredential')
        .require('capabilities')
        .includes('evm-execution'),
    ).to.throw(/not yet supported in v0.4/)
  })

  it('describes the program in human-readable form', () => {
    const built = new PredicateBuilderV2('AgentCapabilityCredential')
      .require('auditScore').greaterThanOrEqual(80)
      .and().not()
      .require('operatorJurisdiction').equals('IR')
      .build()
    const desc = built.toDescription()
    expect(desc).to.contain('auditScore ≥ 80')
    expect(desc).to.contain('NOT')
    expect(desc).to.contain('AND')
  })
})

describe('PredicateBuilderV2 — V1 migration', () => {
  it('fromV1Program(audit ≥ 80 AND jur ∉ [IR, KP])', () => {
    const v1 = {
      schemaId: 'AgentCapabilityCredential',
      version: 1,
      root: {
        type: 'logical' as const,
        connective: 'AND' as const,
        children: [
          { type: 'condition' as const, condition: { attribute: 'auditScore', operator: 'gte' as const, value: 80 } },
          {
            type: 'condition' as const,
            condition: {
              attribute: 'operatorJurisdiction',
              operator: 'not_in' as const,
              value: ['IR', 'KP'],
            },
          },
        ],
      },
    }
    const built = PredicateBuilderV2.fromV1Program(v1)
    expect(built.program.predicates).to.have.lengthOf(3)
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 85, jurisdiction: 840 }))).to.equal(true)
    expect(gp.evaluateProgram(built.program, attrs({ auditScore: 85, jurisdiction: 364 }))).to.equal(false)
  })
})

describe('PredicateBuilderV2 — determinism', () => {
  it('hash is stable across rebuilds', () => {
    const make = () =>
      new PredicateBuilderV2('X')
        .require('auditScore').greaterThanOrEqual(80)
        .and().require('operatorJurisdiction').equals('US')
        .build()
    expect(make().hash).to.equal(make().hash)
  })

  it('hash changes when operator changes', () => {
    const a = new PredicateBuilderV2('X').require('auditScore').greaterThanOrEqual(80).build()
    const b = new PredicateBuilderV2('X').require('auditScore').greaterThanOrEqual(81).build()
    expect(a.hash).to.not.equal(b.hash)
  })
})
