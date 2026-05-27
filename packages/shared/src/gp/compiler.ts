/**
 * Compiler / well-formedness checker for the zkID generalized-predicate IR.
 *
 * Provides:
 *   - `infixToPostfix(tokens)` — shunting-yard for the logical layer (AND/OR/NOT).
 *   - `validateProgram(program, bounds)` — structural and semantic checks.
 *   - `evaluatePostfix(expression, predicateResults)` — reference evaluator
 *     used by tests and the off-chain verifier.
 *
 * The compiler operates over the IR types in ./types.ts. A parser from
 * a string DSL into the IR lives in `@acta/sdk` (so the shared package
 * stays string-format-agnostic).
 */

import type {
  GPBounds,
  GPLogicalOp,
  GPProgram,
  GPToken,
} from './types'
import { DEFAULT_GP_BOUNDS } from './types'

// ── Infix → postfix (shunting yard) ────────────────────────────────────────

export type InfixToken =
  | { kind: 'pred'; predicateIndex: number }
  | { kind: 'op'; op: GPLogicalOp }
  | { kind: 'lparen' }
  | { kind: 'rparen' }

const PRECEDENCE: Record<GPLogicalOp, number> = {
  NOT: 3, // highest
  AND: 2,
  OR: 1, // lowest
}

const RIGHT_ASSOCIATIVE: Record<GPLogicalOp, boolean> = {
  NOT: true, // unary
  AND: false,
  OR: false,
}

/**
 * Convert an infix expression to postfix.
 *
 * Throws on unmatched parentheses or invalid token sequences.
 */
export function infixToPostfix(tokens: ReadonlyArray<InfixToken>): GPToken[] {
  const output: GPToken[] = []
  const opStack: Array<{ kind: 'op'; op: GPLogicalOp } | { kind: 'lparen' }> = []

  for (const tok of tokens) {
    if (tok.kind === 'pred') {
      output.push({ kind: 'pred', predicateIndex: tok.predicateIndex })
    } else if (tok.kind === 'op') {
      while (opStack.length > 0) {
        const top = opStack[opStack.length - 1]
        if (top.kind === 'lparen') break
        const topPrec = PRECEDENCE[top.op]
        const curPrec = PRECEDENCE[tok.op]
        const shouldPop =
          topPrec > curPrec ||
          (topPrec === curPrec && !RIGHT_ASSOCIATIVE[tok.op])
        if (!shouldPop) break
        opStack.pop()
        output.push({ kind: 'op', op: top.op })
      }
      opStack.push({ kind: 'op', op: tok.op })
    } else if (tok.kind === 'lparen') {
      opStack.push({ kind: 'lparen' })
    } else if (tok.kind === 'rparen') {
      let matched = false
      while (opStack.length > 0) {
        const top = opStack.pop()!
        if (top.kind === 'lparen') {
          matched = true
          break
        }
        output.push({ kind: 'op', op: top.op })
      }
      if (!matched) throw new Error('GPCompiler: unmatched right parenthesis')
    }
  }
  while (opStack.length > 0) {
    const top = opStack.pop()!
    if (top.kind === 'lparen') {
      throw new Error('GPCompiler: unmatched left parenthesis')
    }
    output.push({ kind: 'op', op: top.op })
  }
  return output
}

// ── Validation ─────────────────────────────────────────────────────────────

export function validateProgram(
  program: GPProgram,
  bounds: GPBounds = DEFAULT_GP_BOUNDS,
): void {
  if (program.version !== 1) {
    throw new Error(`GPCompiler: unsupported program version ${program.version}`)
  }
  if (program.predicates.length === 0) {
    throw new Error('GPCompiler: program has zero predicates')
  }
  if (program.predicates.length > bounds.maxPredicates) {
    throw new Error(
      `GPCompiler: too many predicates (${program.predicates.length} > ${bounds.maxPredicates})`,
    )
  }
  if (program.expression.length === 0) {
    throw new Error('GPCompiler: expression has zero tokens')
  }
  if (program.expression.length > bounds.maxTokens) {
    throw new Error(
      `GPCompiler: too many expression tokens (${program.expression.length} > ${bounds.maxTokens})`,
    )
  }

  // Predicate well-formedness
  program.predicates.forEach((p, i) => {
    if (!Number.isInteger(p.claimIndex) || p.claimIndex < 0 || p.claimIndex >= bounds.maxClaims) {
      throw new Error(
        `GPCompiler: predicate ${i} claimIndex=${p.claimIndex} out of range [0,${bounds.maxClaims})`,
      )
    }
    if (p.op !== 'le' && p.op !== 'ge' && p.op !== 'eq') {
      throw new Error(`GPCompiler: predicate ${i} has unsupported op '${p.op}'`)
    }
    if (p.operand.kind === 'claim') {
      const ci = p.operand.claimIndex
      if (!Number.isInteger(ci) || ci < 0 || ci >= bounds.maxClaims) {
        throw new Error(
          `GPCompiler: predicate ${i} claim-ref operand=${ci} out of range [0,${bounds.maxClaims})`,
        )
      }
    } else if (p.operand.kind === 'const') {
      if (typeof p.operand.value !== 'bigint') {
        throw new Error(`GPCompiler: predicate ${i} constant operand must be bigint`)
      }
      if (p.operand.value < 0n) {
        throw new Error(
          `GPCompiler: predicate ${i} negative constant ${p.operand.value} is not supported`,
        )
      }
    } else {
      throw new Error(`GPCompiler: predicate ${i} has unknown operand kind`)
    }
  })

  // Expression well-formedness (stack-machine simulation)
  let depth = 0
  let maxDepth = 0
  program.expression.forEach((tok, k) => {
    if (tok.kind === 'pred') {
      if (
        !Number.isInteger(tok.predicateIndex) ||
        tok.predicateIndex < 0 ||
        tok.predicateIndex >= program.predicates.length
      ) {
        throw new Error(
          `GPCompiler: token ${k} predicateIndex=${tok.predicateIndex} out of range`,
        )
      }
      depth += 1
    } else if (tok.op === 'NOT') {
      if (depth < 1) throw new Error(`GPCompiler: NOT at token ${k} with empty stack`)
      // depth unchanged
    } else {
      // AND, OR are binary
      if (depth < 2) throw new Error(`GPCompiler: ${tok.op} at token ${k} needs 2 operands, depth=${depth}`)
      depth -= 1
    }
    if (depth > maxDepth) maxDepth = depth
    if (maxDepth > bounds.maxTokens) {
      throw new Error(
        `GPCompiler: stack depth ${maxDepth} exceeds circuit capacity ${bounds.maxTokens}`,
      )
    }
  })
  if (depth !== 1) {
    throw new Error(
      `GPCompiler: expression must end with exactly one value on the stack (got depth=${depth})`,
    )
  }
}

// ── Reference evaluation ───────────────────────────────────────────────────

/**
 * Reference evaluator used by tests and the off-chain verifier as a
 * sanity-check against the circuit output.
 */
export function evaluatePostfix(
  expression: ReadonlyArray<GPToken>,
  predicateResults: ReadonlyArray<boolean>,
): boolean {
  const stack: boolean[] = []
  for (const tok of expression) {
    if (tok.kind === 'pred') {
      const r = predicateResults[tok.predicateIndex]
      if (typeof r !== 'boolean') {
        throw new Error(`evaluatePostfix: missing result for predicate ${tok.predicateIndex}`)
      }
      stack.push(r)
    } else if (tok.op === 'NOT') {
      const a = stack.pop()
      if (a === undefined) throw new Error('evaluatePostfix: NOT on empty stack')
      stack.push(!a)
    } else if (tok.op === 'AND') {
      const b = stack.pop()
      const a = stack.pop()
      if (a === undefined || b === undefined) throw new Error('evaluatePostfix: AND needs 2 operands')
      stack.push(a && b)
    } else {
      // OR
      const b = stack.pop()
      const a = stack.pop()
      if (a === undefined || b === undefined) throw new Error('evaluatePostfix: OR needs 2 operands')
      stack.push(a || b)
    }
  }
  if (stack.length !== 1) {
    throw new Error(`evaluatePostfix: final stack depth ${stack.length} != 1`)
  }
  return stack[0]
}

/** Evaluate a single predicate against a claim vector (reference impl). */
export function evaluatePredicate(
  predicate: GPProgram['predicates'][number],
  claims: ReadonlyArray<bigint>,
): boolean {
  const lhs = claims[predicate.claimIndex]
  if (lhs === undefined) {
    throw new Error(`evaluatePredicate: missing claim at index ${predicate.claimIndex}`)
  }
  let rhs: bigint
  if (predicate.operand.kind === 'const') {
    rhs = predicate.operand.value
  } else {
    rhs = claims[predicate.operand.claimIndex]
    if (rhs === undefined) {
      throw new Error(`evaluatePredicate: missing claim at ref index ${predicate.operand.claimIndex}`)
    }
  }
  switch (predicate.op) {
    case 'le':
      return lhs <= rhs
    case 'ge':
      return lhs >= rhs
    case 'eq':
      return lhs === rhs
  }
}

/** Evaluate an entire program against a claim vector. */
export function evaluateProgram(
  program: GPProgram,
  claims: ReadonlyArray<bigint>,
): boolean {
  const results = program.predicates.map(p => evaluatePredicate(p, claims))
  return evaluatePostfix(program.expression, results)
}
