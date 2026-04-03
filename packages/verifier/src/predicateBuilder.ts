import { hashPredicateProgram, describePredicateProgram, validatePredicateProgram } from '@acta/shared'
import type {
  PredicateProgram,
  PredicateNode,
  PredicateCondition,
  PredicateOperatorType,
  AgentCapabilityCredentialSubject,
  AgentPredicateOperator,
} from '@acta/shared'

/**
 * Fluent API for constructing PredicatePrograms.
 *
 * Example — DeFi protocol requiring a compliant execution agent:
 *
 *   const predicate = new PredicateBuilder('AgentCapabilityCredential')
 *     .require('auditScore').greaterThanOrEqual(80)
 *     .and()
 *     .require('capabilities').includes('evm-execution')
 *     .and()
 *     .require('operatorJurisdiction').notIn(['IR', 'KP', 'RU', 'BY'])
 *     .build()
 *
 *   // Hash for on-chain registration
 *   const policyHash = predicate.hash
 *   // Human-readable description for UI
 *   const desc = new PredicateBuilder('AgentCapabilityCredential').build().toDescription()
 */
export class PredicateBuilder {
  private schemaId: string
  private conditions: Array<{ condition: PredicateCondition; connective?: 'AND' | 'OR' | 'NOT' }> = []
  private nextConnective: 'AND' | 'OR' | 'NOT' | undefined

  constructor(schemaId: string) {
    this.schemaId = schemaId
  }

  /**
   * Start a condition for the given attribute.
   * Returns an AttributeConstraint to chain the operator.
   */
  require(attribute: keyof AgentCapabilityCredentialSubject | string): AttributeConstraint {
    return new AttributeConstraint(attribute as string, this)
  }

  /** @internal — called by AttributeConstraint.finish() */
  _addCondition(condition: PredicateCondition): this {
    this.conditions.push({ condition, connective: this.nextConnective })
    this.nextConnective = undefined
    return this
  }

  and(): this {
    this.nextConnective = 'AND'
    return this
  }

  or(): this {
    this.nextConnective = 'OR'
    return this
  }

  not(): this {
    this.nextConnective = 'NOT'
    return this
  }

  /**
   * Build the PredicateProgram from accumulated conditions.
   * Returns a frozen, validated PredicateProgram with its hash computed.
   */
  build(): BuiltPredicate {
    if (this.conditions.length === 0) {
      throw new Error('PredicateBuilder: at least one condition is required')
    }

    let root: PredicateNode

    if (this.conditions.length === 1) {
      root = { type: 'condition', condition: this.conditions[0].condition }
    } else {
      root = buildLogicalTree(this.conditions)
    }

    const program: PredicateProgram = {
      schemaId: this.schemaId,
      version:  1,
      root,
    }

    validatePredicateProgram(program)
    const hash = hashPredicateProgram(program)
    program.hash = hash

    return new BuiltPredicate(program)
  }

  /**
   * Convenience: build a PredicateProgram from an AgentPredicateOperator array.
   * All conditions are AND-ed together.
   */
  static fromAgentOperators(
    schemaId: string,
    operators: AgentPredicateOperator[]
  ): BuiltPredicate {
    const builder = new PredicateBuilder(schemaId)
    for (let i = 0; i < operators.length; i++) {
      if (i > 0) builder.and()
      applyAgentOperator(builder, operators[i])
    }
    return builder.build()
  }
}

export class AttributeConstraint {
  constructor(
    private attribute: string,
    private builder: PredicateBuilder
  ) {}

  private finish(op: PredicateOperatorType, value: PredicateCondition['value']): PredicateBuilder {
    this.builder._addCondition({ attribute: this.attribute, operator: op, value })
    return this.builder
  }

  greaterThanOrEqual(value: number): PredicateBuilder { return this.finish('gte', value) }
  lessThanOrEqual(value: number): PredicateBuilder    { return this.finish('lte', value) }
  equals(value: string | number): PredicateBuilder   { return this.finish('eq', value) }
  notEquals(value: string | number): PredicateBuilder { return this.finish('neq', value) }
  includes(value: string): PredicateBuilder           { return this.finish('includes', value) }
  notIn(values: string[]): PredicateBuilder           { return this.finish('not_in', values) }
  between(min: number, max: number): PredicateBuilder { return this.finish('between', [min, max]) }
}

export class BuiltPredicate {
  constructor(private program: PredicateProgram) {}

  /** Deterministic bytes32 hash — used as on-chain predicateProgramHash */
  get hash(): string { return this.program.hash! }

  /** Raw PredicateProgram for serialisation */
  get raw(): PredicateProgram { return this.program }

  /** JSON for embedding in OID4VP x-openac-predicate extension */
  toJSON(): string { return JSON.stringify(this.program) }

  /** Human-readable description for UI display */
  toDescription(): string { return describePredicateProgram(this.program) }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/**
 * Build a left-associative binary logical tree that correctly honours every
 * per-condition connective.
 *
 * Example: A AND B OR C  produces:
 *   logical(OR, [logical(AND, [cond(A), cond(B)]), cond(C)])
 *
 * The previous flat-array implementation used only the connective at index 1 for
 * ALL conditions, producing identical hashes for semantically different predicates
 * (e.g. "A AND B OR C" and "A OR B OR C" would both hash the same way).
 */
function buildLogicalTree(
  conditions: Array<{ condition: PredicateCondition; connective?: 'AND' | 'OR' | 'NOT' }>
): PredicateNode {
  let acc: PredicateNode = { type: 'condition', condition: conditions[0].condition }

  for (let i = 1; i < conditions.length; i++) {
    const connective = (conditions[i].connective ?? 'AND') as 'AND' | 'OR'
    const right: PredicateNode = { type: 'condition', condition: conditions[i].condition }
    acc = { type: 'logical', connective, children: [acc, right] }
  }

  return acc
}

function applyAgentOperator(builder: PredicateBuilder, op: AgentPredicateOperator): void {
  switch (op.op) {
    case 'audit_score_gte':
      builder.require('auditScore').greaterThanOrEqual(op.threshold)
      break
    case 'capability_includes':
      builder.require('capabilities').includes(op.capabilityId)
      break
    case 'jurisdiction_not_in':
      builder.require('operatorJurisdiction').notIn(op.sanctionsList)
      break
    case 'model_hash_in':
      builder.require('modelHash').includes(op.trustedSet[0] ?? '')
      break
    case 'delegation_depth_lte':
      builder.require('delegationDepth').lessThanOrEqual(op.maxDepth)
      break
    case 'delegation_scope_includes':
      builder.require('capabilities').includes(op.scopeId)
      break
    case 'principal_vc_satisfies':
      builder.require('principalVcHash').notEquals('')
      break
  }
}
