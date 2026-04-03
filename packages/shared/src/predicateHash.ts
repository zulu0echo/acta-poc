import { ethers } from 'ethers'
import type { PredicateProgram, PredicateNode, PredicateCondition } from './types'

/**
 * Computes a deterministic bytes32 hash of a PredicateProgram.
 *
 * The canonical serialisation walks the predicate tree in depth-first order,
 * encoding each node into a fixed tuple and hashing the concatenated result
 * with keccak256. This matches the on-chain hash computed in
 * GeneralizedPredicateVerifier._hashPredicateProgram().
 *
 * Security property: two PredicatePrograms produce the same hash if and only
 * if they express identical logical constraints over identical attribute indices.
 * Operator ordering (AND vs OR) is included in the hash.
 */
export function hashPredicateProgram(program: PredicateProgram): string {
  const canonical = canonicaliseProgram(program)
  return ethers.keccak256(ethers.toUtf8Bytes(canonical))
}

/**
 * Returns a deterministic JSON string representation of the predicate program.
 * Keys are sorted, arrays are normalised, and all number values are bigint-safe strings.
 */
export function canonicaliseProgram(program: PredicateProgram): string {
  const normalised = {
    schemaId: program.schemaId,
    version: program.version,
    root: canonicaliseNode(program.root),
  }
  return JSON.stringify(normalised)
}

function canonicaliseNode(node: PredicateNode): unknown {
  if (node.type === 'condition' && node.condition) {
    return {
      type: 'condition',
      condition: canonicaliseCondition(node.condition),
    }
  }
  if (node.type === 'logical' && node.connective) {
    return {
      type: 'logical',
      connective: node.connective,
      children: (node.children ?? []).map(canonicaliseNode),
    }
  }
  throw new Error(`Malformed predicate node: ${JSON.stringify(node)}`)
}

function canonicaliseCondition(cond: PredicateCondition): unknown {
  const value = Array.isArray(cond.value)
    ? [...cond.value].sort().map(String)
    : String(cond.value)
  return {
    attribute: cond.attribute,
    operator: cond.operator,
    value,
  }
}

/**
 * Converts a PredicateProgram to a human-readable English description.
 * Used in the PredicateEditor UI and in the Doc Panel.
 */
export function describePredicateProgram(program: PredicateProgram): string {
  return describeNode(program.root)
}

function describeNode(node: PredicateNode): string {
  if (node.type === 'condition' && node.condition) {
    return describeCondition(node.condition)
  }
  if (node.type === 'logical' && node.connective && node.children) {
    if (node.connective === 'NOT' && node.children.length === 1) {
      return `NOT (${describeNode(node.children[0])})`
    }
    const parts = node.children.map(describeNode)
    return parts.join(` ${node.connective} `)
  }
  return '[unknown]'
}

function describeCondition(cond: PredicateCondition): string {
  const attr = friendlyAttributeName(cond.attribute)
  switch (cond.operator) {
    case 'gte':
      return `${attr} ≥ ${cond.value}`
    case 'lte':
      return `${attr} ≤ ${cond.value}`
    case 'eq':
      return `${attr} = "${cond.value}"`
    case 'neq':
      return `${attr} ≠ "${cond.value}"`
    case 'includes':
      return `${attr} includes "${cond.value}"`
    case 'not_in': {
      const list = Array.isArray(cond.value) ? cond.value.join(', ') : cond.value
      return `${attr} NOT IN [${list}]`
    }
    case 'between': {
      const [min, max] = cond.value as [number, number]
      return `${attr} between ${min} and ${max}`
    }
    default:
      return `${attr} ${cond.operator} ${cond.value}`
  }
}

const ATTRIBUTE_FRIENDLY: Record<string, string> = {
  AUDIT_SCORE: 'Audit Score',
  MODEL_HASH: 'Model Hash',
  OPERATOR_JURISDICTION: 'Jurisdiction',
  CAPABILITIES_BITMASK: 'Capabilities',
  AUDITED_BY_HASH: 'Audited By',
  AUDIT_DATE_UNIX: 'Audit Date',
  auditScore: 'Audit Score',
  modelHash: 'Model Hash',
  operatorJurisdiction: 'Jurisdiction',
  capabilities: 'Capabilities',
  auditedBy: 'Audited By',
  auditDate: 'Audit Date',
}

function friendlyAttributeName(attr: string): string {
  return ATTRIBUTE_FRIENDLY[attr] ?? attr
}

/**
 * Validates that a PredicateProgram is well-formed and safe to hash/submit.
 * Throws a descriptive error if validation fails.
 */
export function validatePredicateProgram(program: PredicateProgram): void {
  if (!program.schemaId || typeof program.schemaId !== 'string') {
    throw new Error('PredicateProgram.schemaId must be a non-empty string')
  }
  if (program.version !== 1) {
    throw new Error('PredicateProgram.version must be 1 in ACTA v0.1')
  }
  validateNode(program.root, 0)
}

const MAX_PREDICATE_DEPTH = 8

function validateNode(node: PredicateNode, depth: number): void {
  if (depth > MAX_PREDICATE_DEPTH) {
    throw new Error(`Predicate tree exceeds maximum depth of ${MAX_PREDICATE_DEPTH}`)
  }
  if (node.type === 'condition') {
    if (!node.condition) throw new Error('Condition node missing condition field')
    validateCondition(node.condition)
  } else if (node.type === 'logical') {
    if (!node.connective) throw new Error('Logical node missing connective field')
    if (!node.children || node.children.length === 0) {
      throw new Error('Logical node must have at least one child')
    }
    if (node.connective === 'NOT' && node.children.length !== 1) {
      throw new Error('NOT node must have exactly one child')
    }
    node.children.forEach(child => validateNode(child, depth + 1))
  } else {
    throw new Error(`Unknown node type: ${(node as PredicateNode).type}`)
  }
}

function validateCondition(cond: PredicateCondition): void {
  if (!cond.attribute) throw new Error('Condition missing attribute')
  if (!cond.operator) throw new Error('Condition missing operator')
  if (cond.value === undefined || cond.value === null) {
    throw new Error(`Condition missing value for attribute ${cond.attribute}`)
  }
}
