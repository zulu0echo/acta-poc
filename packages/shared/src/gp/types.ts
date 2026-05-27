/**
 * zkID Generalized Predicates — TypeScript IR.
 *
 * Mirrors the model in
 *   https://github.com/privacy-ethereum/zkID/tree/main/generalized-predicates
 *
 * Notation:
 *
 *   Claims       C = (c_0, c_1, …, c_{N-1})   private
 *   Predicates   P_i = (j_i, op_i, v_i)        public
 *   Expression   L   = postfix tokens          public
 *
 * Where j_i is a claim index, op_i ∈ {≤, ≥, ==}, and v_i is either a
 * constant or a reference to another claim index (encoded by isClaimRef).
 *
 * Logical operators are AND, OR, NOT (zkID supports OR explicitly for
 * constraint efficiency even though {AND, NOT} is functionally complete).
 *
 * The circuit asserts:
 *   - For each i:   r_i = op_i(c_{j_i}, rhs_i)         where rhs_i is constant or c_{j_i'}
 *   - Postfix(L)(R) = 1                                 (policy is satisfied)
 *
 * Public on-chain hash:
 *   predicateProgramHash = Poseidon(canonical_encoding(predicates, expression))
 *   (see encoder.ts for the exact encoding).
 */

/** Comparison operators supported in-circuit. */
export type GPCompareOp = 'le' | 'ge' | 'eq'

/** Logical operators supported in-circuit. */
export type GPLogicalOp = 'AND' | 'OR' | 'NOT'

/**
 * Operand reference.
 *   - kind: 'const' — a numeric constant (must fit the circuit's compare-bit width)
 *   - kind: 'claim' — a reference to another claim index
 */
export type GPOperand =
  | { kind: 'const'; value: bigint }
  | { kind: 'claim'; claimIndex: number }

/** One predicate of the form (claim[claimIndex] op operand). */
export interface GPPredicate {
  claimIndex: number
  op: GPCompareOp
  operand: GPOperand
}

/**
 * Postfix expression token. A token is either:
 *   - A reference to a predicate result by index, or
 *   - A logical operator applied to the top of stack.
 */
export type GPToken =
  | { kind: 'pred'; predicateIndex: number }
  | { kind: 'op'; op: GPLogicalOp }

/** A complete generalised-predicate program. */
export interface GPProgram {
  /** Version of the canonical encoding. Bumped if encoder.ts changes. */
  version: 1

  /**
   * Optional human-readable labels for claim indices. These are NOT part of
   * the canonical hash — they exist for tooling/debug only.
   */
  claimLabels?: ReadonlyArray<string>

  /** Public list of predicates. */
  predicates: ReadonlyArray<GPPredicate>

  /** Public postfix expression evaluated over predicate results. */
  expression: ReadonlyArray<GPToken>
}

/** Encoder bounds — must match the Circom circuit constants. */
export interface GPBounds {
  /** Maximum number of claim slots in the circuit. */
  maxClaims: number
  /** Maximum number of predicates in a program. */
  maxPredicates: number
  /** Maximum number of postfix tokens in an expression. */
  maxTokens: number
}

/** Default bounds aligned with OpenACGPPresentationV2.circom. */
export const DEFAULT_GP_BOUNDS: GPBounds = {
  maxClaims: 16,
  maxPredicates: 8,
  maxTokens: 16,
}

/** Circuit-level numeric codes for compare operators (must match Circom). */
export const GP_COMPARE_OP_CODE: Record<GPCompareOp, number> = {
  le: 0,
  ge: 1,
  eq: 2,
}

/** Circuit-level numeric codes for postfix token types (must match Circom). */
export const GP_TOKEN_TYPE_CODE = {
  pad: 0,
  pred: 1,
  AND: 2,
  OR: 3,
  NOT: 4,
} as const

export type GPTokenTypeCode = typeof GP_TOKEN_TYPE_CODE[keyof typeof GP_TOKEN_TYPE_CODE]
