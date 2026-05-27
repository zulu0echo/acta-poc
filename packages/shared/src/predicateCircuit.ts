import type { PredicateProgram, PredicateNode, PredicateCondition } from './types'
import { CAPABILITY_BIT, JURISDICTION_NUMERIC } from './constants'
import { poseidonHashHex } from './poseidon'

/** Witness inputs for OpenACGPPresentation predicate constraints (must match Circom). */
export interface CircuitPredicateInputs {
  predicateAuditScoreMin: bigint
  predicateCapabilityMask: bigint
  predicateJurisdictionSanctions: bigint[]
}

const SANCTION_SLOTS = 8

/**
 * Supported predicate shape: flat AND of:
 *   - auditScore gte N
 *   - capabilities includes <id>  (bitmask)
 *   - operatorJurisdiction not_in [ISO codes]
 */
export function validatePredicateProgramSupported(program: PredicateProgram): void {
  if (program.version !== 1) {
    throw new Error('Only PredicateProgram version 1 is supported by OpenACGPPresentation')
  }
  const conditions = flattenAndConditions(program.root)
  if (conditions.length === 0) {
    throw new Error('Predicate must contain at least one condition')
  }
  for (const c of conditions) {
    validateSupportedCondition(c)
  }
}

export function predicateToCircuitInputs(program: PredicateProgram): CircuitPredicateInputs {
  validatePredicateProgramSupported(program)
  const conditions = flattenAndConditions(program.root)

  let predicateAuditScoreMin = 0n
  let predicateCapabilityMask = 0n
  const sanctions = new Set<number>()

  for (const c of conditions) {
    if (c.attribute === 'auditScore' && c.operator === 'gte') {
      predicateAuditScoreMin = BigInt(Number(c.value))
    } else if (
      (c.attribute === 'capabilities' || c.attribute === 'CAPABILITIES_BITMASK') &&
      c.operator === 'includes'
    ) {
      const bit = CAPABILITY_BIT[String(c.value)] ?? 0
      if (bit === 0) throw new Error(`Unknown capability: ${c.value}`)
      predicateCapabilityMask |= BigInt(bit)
    } else if (
      (c.attribute === 'operatorJurisdiction' || c.attribute === 'OPERATOR_JURISDICTION') &&
      c.operator === 'not_in'
    ) {
      const list = Array.isArray(c.value) ? c.value : [c.value]
      for (const code of list) {
        const num = JURISDICTION_NUMERIC[String(code)]
        if (num === undefined) throw new Error(`Unknown jurisdiction code: ${code}`)
        sanctions.add(num)
      }
    }
  }

  const predicateJurisdictionSanctions: bigint[] = []
  const sorted = [...sanctions].slice(0, SANCTION_SLOTS)
  for (let i = 0; i < SANCTION_SLOTS; i++) {
    predicateJurisdictionSanctions.push(BigInt(sorted[i] ?? 0))
  }

  return {
    predicateAuditScoreMin,
    predicateCapabilityMask,
    predicateJurisdictionSanctions,
  }
}

/**
 * Poseidon(min, mask, sanction[0..7]) — must match OpenACGPPresentation.circom predHasher.
 */
export function hashPredicateCircuitInputs(inputs: CircuitPredicateInputs): string {
  const fields: bigint[] = [
    inputs.predicateAuditScoreMin,
    inputs.predicateCapabilityMask,
    ...inputs.predicateJurisdictionSanctions,
  ]
  if (fields.length !== 10) {
    throw new Error(`Expected 10 Poseidon inputs, got ${fields.length}`)
  }
  return poseidonHashHex(fields)
}

export function hashPredicateProgramCircuit(program: PredicateProgram): string {
  return hashPredicateCircuitInputs(predicateToCircuitInputs(program))
}

function flattenAndConditions(root: PredicateNode): PredicateCondition[] {
  if (root.type === 'condition' && root.condition) {
    return [root.condition]
  }
  if (root.type === 'logical' && root.connective === 'AND' && root.children) {
    return root.children.flatMap(child => flattenAndConditions(child))
  }
  throw new Error(
    'Unsupported predicate shape: only flat AND of auditScore/capabilities/jurisdiction conditions is ZK-enforced'
  )
}

function validateSupportedCondition(c: PredicateCondition): void {
  const ok =
    (c.attribute === 'auditScore' && c.operator === 'gte') ||
    ((c.attribute === 'capabilities' || c.attribute === 'CAPABILITIES_BITMASK') &&
      c.operator === 'includes') ||
    ((c.attribute === 'operatorJurisdiction' || c.attribute === 'OPERATOR_JURISDICTION') &&
      c.operator === 'not_in')

  if (!ok) {
    throw new Error(
      `Condition not supported by circuit: ${c.attribute} ${c.operator} (use auditScore gte, capabilities includes, operatorJurisdiction not_in)`
    )
  }
}
