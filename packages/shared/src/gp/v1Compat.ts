/**
 * Compatibility shim: translate a v0.2 `PredicateProgram` into a zkID
 * `GPProgram` so V1-authored policies can be re-used by the V2 stack
 * without re-authoring.
 *
 * V1 condition → GP IR translation:
 *
 *   auditScore gte N              ↦ GE(claim[AUDIT_SCORE], const(N))
 *                                   → tokens: [P_i]
 *
 *   operatorJurisdiction not_in   ↦ for each banned ISO code Xj:
 *     [X0, X1, …]                       EQ(claim[OPERATOR_JURISDICTION], const(Xj))
 *                                   → tokens: P_j NOT, AND-chained across j
 *
 *   capabilities includes X       ✗ refused — zkID GP cannot express
 *                                   bitmask containment without a schema
 *                                   change (one claim per bit). See
 *                                   docs/ROADMAP.md Phase 1 open item
 *                                   "Capability bitmask containment".
 *
 * Conditions are combined left-associatively with AND, matching the
 * `validatePredicateProgramSupported()` shape from `predicateCircuit.ts`.
 */

import { JURISDICTION_NUMERIC, ATTRIBUTE_INDEX } from '../constants'
import type {
  PredicateCondition,
  PredicateNode,
  PredicateProgram,
} from '../types'
import { validateProgram } from './compiler'
import type { GPPredicate, GPProgram, GPToken } from './types'

/**
 * Translate a V1 `PredicateProgram` into a V2 `GPProgram`.
 *
 * Throws on unsupported predicate shapes or operators so silent semantic
 * loss is impossible. Tests in `gp-v1Compat.test.ts` enumerate the
 * supported translations.
 */
export function v1ToGP(program: PredicateProgram): GPProgram {
  const conditions = flattenAndConditions(program.root)
  if (conditions.length === 0) {
    throw new Error('v1ToGP: program contains zero conditions')
  }

  const predicates: GPPredicate[] = []
  // Sub-expressions per V1 condition, each a postfix sequence yielding
  // one boolean. They are AND-chained at the end.
  const subExpressions: GPToken[][] = []

  for (const c of conditions) {
    subExpressions.push(translateCondition(c, predicates))
  }

  // Combine sub-expressions left-to-right with AND.
  const expression: GPToken[] = [...subExpressions[0]]
  for (let i = 1; i < subExpressions.length; i++) {
    expression.push(...subExpressions[i])
    expression.push({ kind: 'op', op: 'AND' })
  }

  const out: GPProgram = {
    version: 1,
    claimLabels: ['auditScore', 'modelHash', 'operatorJurisdiction', 'capabilitiesBitmask', 'auditedByHash', 'auditDateUnix'],
    predicates,
    expression,
  }
  validateProgram(out)
  return out
}

/**
 * Translate one V1 condition into:
 *  - zero or more new entries appended to `predicates`
 *  - a postfix sub-expression of GPToken[]
 *
 * The sub-expression must consume zero stack and produce one boolean.
 */
function translateCondition(
  c: PredicateCondition,
  predicates: GPPredicate[],
): GPToken[] {
  if (c.attribute === 'auditScore' && c.operator === 'gte') {
    const idx = predicates.length
    predicates.push({
      claimIndex: ATTRIBUTE_INDEX.AUDIT_SCORE,
      op: 'ge',
      operand: { kind: 'const', value: BigInt(Number(c.value)) },
    })
    return [{ kind: 'pred', predicateIndex: idx }]
  }

  if (
    (c.attribute === 'operatorJurisdiction' || c.attribute === 'OPERATOR_JURISDICTION') &&
    c.operator === 'not_in'
  ) {
    const list = Array.isArray(c.value) ? c.value : [c.value]
    if (list.length === 0) {
      throw new Error('v1ToGP: operatorJurisdiction not_in with empty list')
    }

    // For each banned code Xj: add `jur == Xj` and emit `P_j NOT`.
    // AND-chain the negations.
    const tokens: GPToken[] = []
    for (let j = 0; j < list.length; j++) {
      const code = list[j] as string
      const num = JURISDICTION_NUMERIC[code]
      if (num === undefined) {
        throw new Error(`v1ToGP: unknown jurisdiction code "${code}"`)
      }
      const idx = predicates.length
      predicates.push({
        claimIndex: ATTRIBUTE_INDEX.OPERATOR_JURISDICTION,
        op: 'eq',
        operand: { kind: 'const', value: BigInt(num) },
      })
      tokens.push({ kind: 'pred', predicateIndex: idx })
      tokens.push({ kind: 'op', op: 'NOT' })
      if (j > 0) tokens.push({ kind: 'op', op: 'AND' })
    }
    return tokens
  }

  if (c.attribute === 'capabilities' && c.operator === 'includes') {
    throw new Error(
      'v1ToGP: capabilities `includes` cannot be expressed in zkID GP without a ' +
        'credential-schema change (one claim per capability bit). See docs/ROADMAP.md ' +
        'Phase 1 open work item "Capability bitmask containment in GP".',
    )
  }

  throw new Error(
    `v1ToGP: unsupported condition (${c.attribute} ${c.operator}). ` +
      'Use the GP-native builder to express this policy.',
  )
}

function flattenAndConditions(root: PredicateNode): PredicateCondition[] {
  if (root.type === 'condition' && root.condition) {
    return [root.condition]
  }
  if (root.type === 'logical' && root.connective === 'AND' && root.children) {
    return root.children.flatMap(flattenAndConditions)
  }
  throw new Error(
    'v1ToGP: only flat AND of conditions is supported; non-AND logic must be re-authored in GP IR',
  )
}
