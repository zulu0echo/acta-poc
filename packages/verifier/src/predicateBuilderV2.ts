/**
 * PredicateBuilderV2 — zkID generalized-predicates builder for ACTA v0.4+.
 *
 * Replaces the V1 hard-coded `PredicateBuilder` with a GP-native fluent
 * API. The V1 builder remains in `predicateBuilder.ts` for backwards
 * compatibility; it will be removed in v0.5.
 *
 * Design contract:
 *   - Each `require(claim)` call refers to a claim by name OR by numeric
 *     index. Numeric indices flow straight through to the circuit;
 *     name-based lookups use ACTA's `ATTRIBUTE_INDEX` mapping.
 *   - `.greaterThanOrEqual(v) / .lessThanOrEqual(v) / .equals(v)` map to
 *     zkID's `ge`, `le`, `eq` operators.
 *   - Logical composition uses `.and() / .or() / .not()` AND/OR are
 *     binary, NOT is unary; precedence is `NOT > AND > OR` (standard).
 *   - `.build()` produces a `BuiltGPPredicate` carrying:
 *       * the canonical `GPProgram` IR
 *       * the on-chain `predicateProgramHash` (Poseidon Merkle fold)
 *       * a human-readable description
 *
 * Migration helpers:
 *   - `PredicateBuilderV2.fromV1Program(program)` translates an audit-era
 *     V1 `PredicateProgram` into a GP IR via `@acta/shared/gp/v1Compat`.
 */

import {
  ATTRIBUTE_INDEX,
  JURISDICTION_NUMERIC,
  CAPABILITY_BIT,
  gp,
} from '@acta/shared'
import type { PredicateProgram } from '@acta/shared'

type GPProgram = gp.GPProgram
type GPPredicate = gp.GPPredicate
type GPToken = gp.GPToken

// ── Builder ───────────────────────────────────────────────────────────────

/** Postfix sub-expression returned by an `AttributeConstraintV2` finish. */
interface SubExpression {
  /** Predicates appended to the program. */
  predicates: GPPredicate[]
  /** Postfix tokens for this sub-expression (consumes 0, produces 1). */
  tokens: GPToken[]
}

type PendingOp = 'AND' | 'OR' | 'NOT' | undefined

/**
 * Fluent builder for zkID generalised-predicate programs.
 *
 * Example:
 *
 *   const built = new PredicateBuilderV2('AgentCapabilityCredential')
 *     .require('auditScore').greaterThanOrEqual(80)
 *     .and()
 *     .not().require('operatorJurisdiction').inJurisdictions(['IR', 'KP', 'RU'])
 *     .build()
 *
 *   const policyHash = built.hash       // predicateProgramHash (bytes32)
 *   const gpProgram  = built.program    // GPProgram IR
 */
export class PredicateBuilderV2 {
  private schemaId: string
  /** Accumulated predicates, indexed by position in the GP program. */
  private predicates: GPPredicate[] = []
  /**
   * Accumulated sub-expressions per top-level term. Each entry yields one
   * boolean. They are combined by `.build()` using the recorded
   * connectives.
   */
  private terms: Array<{ tokens: GPToken[]; negate: boolean }> = []
  /** Connective for the *next* term being added. */
  private pendingConnective: 'AND' | 'OR' = 'AND'
  /** Whether the next term should be wrapped in NOT. */
  private pendingNegate = false
  /**
   * Track per-term connectives so we can build a left-associative tree
   * respecting AND > OR precedence. Stored as the connective used to
   * combine this term with the one before it.
   */
  private connectives: Array<'AND' | 'OR'> = []

  constructor(schemaId: string) {
    this.schemaId = schemaId
  }

  /** Start a constraint on a claim. */
  require(claim: keyof typeof ATTRIBUTE_INDEX | string | number): AttributeConstraintV2 {
    return new AttributeConstraintV2(this, resolveClaim(claim))
  }

  /** Apply NOT to the next term. */
  not(): this {
    this.pendingNegate = !this.pendingNegate
    return this
  }

  /** AND the next term with what's been built. */
  and(): this {
    this.pendingConnective = 'AND'
    return this
  }

  /** OR the next term with what's been built. */
  or(): this {
    this.pendingConnective = 'OR'
    return this
  }

  /** @internal — invoked by AttributeConstraintV2 when a term is finished. */
  _appendTerm(sub: SubExpression): this {
    for (const p of sub.predicates) this.predicates.push(p)
    const negate = this.pendingNegate
    this.pendingNegate = false
    if (this.terms.length === 0) {
      this.terms.push({ tokens: sub.tokens, negate })
    } else {
      this.connectives.push(this.pendingConnective)
      this.pendingConnective = 'AND' // reset to default for the term after this
      this.terms.push({ tokens: sub.tokens, negate })
    }
    return this
  }

  /** Build the final GPProgram + hash. */
  build(): BuiltGPPredicate {
    if (this.terms.length === 0) {
      throw new Error('PredicateBuilderV2: at least one term is required')
    }

    // Combine terms into a postfix expression honouring AND > OR precedence.
    const expression = combineWithPrecedence(this.terms, this.connectives)

    const program: GPProgram = {
      version: 1,
      claimLabels: CLAIM_LABELS_CAMEL,
      predicates: this.predicates,
      expression,
    }
    gp.validateProgram(program)
    const hash = gp.gpProgramHash(program)

    return new BuiltGPPredicate(this.schemaId, program, hash)
  }

  /**
   * Translate a V1 `PredicateProgram` into a `BuiltGPPredicate` via the
   * `@acta/shared/gp/v1Compat.v1ToGP` shim. Throws on unsupported V1
   * shapes (see v1Compat.ts for the list).
   */
  static fromV1Program(program: PredicateProgram, schemaId?: string): BuiltGPPredicate {
    const gpProgram = gp.v1ToGP(program)
    return new BuiltGPPredicate(
      schemaId ?? program.schemaId,
      gpProgram,
      gp.gpProgramHash(gpProgram),
    )
  }
}

/**
 * Combine N terms with `connectives[i] ∈ {AND, OR}` and per-term NOT flags
 * into a single postfix expression respecting AND > OR precedence.
 *
 * Strategy: split the term list into OR-separated runs. Inside each run,
 * AND the terms left-to-right. Then OR the runs.
 */
function combineWithPrecedence(
  terms: Array<{ tokens: GPToken[]; negate: boolean }>,
  connectives: Array<'AND' | 'OR'>,
): GPToken[] {
  // Group into OR runs.
  type Run = Array<{ tokens: GPToken[]; negate: boolean }>
  const runs: Run[] = [[terms[0]]]
  for (let i = 1; i < terms.length; i++) {
    const conn = connectives[i - 1]
    if (conn === 'OR') {
      runs.push([terms[i]])
    } else {
      runs[runs.length - 1].push(terms[i])
    }
  }

  // Postfix-combine one run: AND-chain its terms (with per-term NOTs).
  const combineRun = (run: Run): GPToken[] => {
    const out: GPToken[] = []
    let first = true
    for (const t of run) {
      out.push(...t.tokens)
      if (t.negate) out.push({ kind: 'op', op: 'NOT' })
      if (!first) out.push({ kind: 'op', op: 'AND' })
      first = false
    }
    return out
  }

  if (runs.length === 1) return combineRun(runs[0])

  // OR-chain the runs.
  const out: GPToken[] = combineRun(runs[0])
  for (let r = 1; r < runs.length; r++) {
    out.push(...combineRun(runs[r]))
    out.push({ kind: 'op', op: 'OR' })
  }
  return out
}

// ── Constraint helper ─────────────────────────────────────────────────────

export class AttributeConstraintV2 {
  constructor(
    private parent: PredicateBuilderV2,
    private claimIndex: number,
  ) {}

  private finish(op: 'le' | 'ge' | 'eq', operand: gp.GPOperand): PredicateBuilderV2 {
    // Allocate one predicate for this term. Token = PRED only.
    const pred: GPPredicate = { claimIndex: this.claimIndex, op, operand }
    const sub: SubExpression = {
      predicates: [pred],
      tokens: [{ kind: 'pred', predicateIndex: -1 }], // patched in _appendTerm
    }
    // Patch the index to the new predicate's position.
    const i = predicateCountOf(this.parent) // call-site index BEFORE append
    sub.tokens = [{ kind: 'pred', predicateIndex: i }]
    return this.parent._appendTerm(sub)
  }

  greaterThanOrEqual(v: number | bigint): PredicateBuilderV2 {
    return this.finish('ge', { kind: 'const', value: BigInt(v) })
  }
  lessThanOrEqual(v: number | bigint): PredicateBuilderV2 {
    return this.finish('le', { kind: 'const', value: BigInt(v) })
  }
  equals(v: number | bigint | string): PredicateBuilderV2 {
    return this.finish('eq', { kind: 'const', value: toConstValue(v) })
  }

  /**
   * Compare against another claim (claim-to-claim).
   * Example: `require('account_balance').greaterThanOrEqualClaim('loan_amount')`.
   */
  greaterThanOrEqualClaim(other: keyof typeof ATTRIBUTE_INDEX | string | number): PredicateBuilderV2 {
    return this.finish('ge', { kind: 'claim', claimIndex: resolveClaim(other) })
  }
  lessThanOrEqualClaim(other: keyof typeof ATTRIBUTE_INDEX | string | number): PredicateBuilderV2 {
    return this.finish('le', { kind: 'claim', claimIndex: resolveClaim(other) })
  }
  equalsClaim(other: keyof typeof ATTRIBUTE_INDEX | string | number): PredicateBuilderV2 {
    return this.finish('eq', { kind: 'claim', claimIndex: resolveClaim(other) })
  }

  /**
   * Convenience: `operatorJurisdiction in [ISO codes]` as an OR chain of
   * equality predicates. Produces ONE boolean sub-expression.
   *
   * Returned indirectly via the parent — typical usage:
   *   builder.not().require('operatorJurisdiction').inJurisdictions(['IR', 'KP'])
   *      → "jurisdiction ∉ {IR, KP}"
   */
  inJurisdictions(codes: ReadonlyArray<string>): PredicateBuilderV2 {
    if (codes.length === 0) {
      throw new Error('inJurisdictions: empty list')
    }
    const predicates: GPPredicate[] = []
    const tokens: GPToken[] = []
    const startIdx = predicateCountOf(this.parent)
    for (let j = 0; j < codes.length; j++) {
      const code = codes[j]
      const num = JURISDICTION_NUMERIC[code]
      if (num === undefined) {
        throw new Error(`inJurisdictions: unknown jurisdiction code "${code}"`)
      }
      predicates.push({
        claimIndex: this.claimIndex,
        op: 'eq',
        operand: { kind: 'const', value: BigInt(num) },
      })
      tokens.push({ kind: 'pred', predicateIndex: startIdx + j })
      if (j > 0) tokens.push({ kind: 'op', op: 'OR' })
    }
    return this.parent._appendTerm({ predicates, tokens })
  }

  /**
   * Convenience: `capabilities includes X` — REFUSED in v0.4. zkID GP
   * cannot express bitmask containment without a credential schema
   * change. See docs/ROADMAP.md Phase 1.
   */
  includes(capability: string): never {
    throw new Error(
      `includes('${capability}'): bitmask containment is not yet supported in v0.4. ` +
        'See docs/ROADMAP.md Phase 1 ("Capability bitmask containment in GP"). ' +
        'Express the policy with individual capability claims and `.equals(1)` instead.',
    )
  }
}

// ── Built predicate ────────────────────────────────────────────────────────

export class BuiltGPPredicate {
  constructor(
    public readonly schemaId: string,
    public readonly program: GPProgram,
    public readonly hash: string,
  ) {}

  /** JSON for embedding in OID4VP x-openac-predicate extension. */
  toJSON(): string {
    return JSON.stringify({
      schemaId: this.schemaId,
      version: this.program.version,
      predicates: this.program.predicates.map(p => ({
        claimIndex: p.claimIndex,
        op: p.op,
        operand:
          p.operand.kind === 'const'
            ? { kind: 'const', value: p.operand.value.toString() }
            : p.operand,
      })),
      expression: this.program.expression,
    })
  }

  /** Compact human-readable summary. */
  toDescription(): string {
    return describeGPProgram(this.program)
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/**
 * Friendly camelCase aliases for `ATTRIBUTE_INDEX` so the builder accepts
 * both `'auditScore'` (V1-style) and `'AUDIT_SCORE'` (constants-style).
 */
const CLAIM_ALIASES: Record<string, keyof typeof ATTRIBUTE_INDEX> = {
  auditScore:           'AUDIT_SCORE',
  modelHash:            'MODEL_HASH',
  operatorJurisdiction: 'OPERATOR_JURISDICTION',
  capabilities:         'CAPABILITIES_BITMASK',
  capabilitiesBitmask:  'CAPABILITIES_BITMASK',
  auditedByHash:        'AUDITED_BY_HASH',
  auditDateUnix:        'AUDIT_DATE_UNIX',
}

/**
 * Canonical camelCase claim labels by claim index, used for the
 * GPProgram's `claimLabels` field and human-readable descriptions.
 * Index N has label CLAIM_LABELS_CAMEL[N].
 */
const CLAIM_LABELS_CAMEL: string[] = (() => {
  const out: string[] = []
  const inverse: Record<keyof typeof ATTRIBUTE_INDEX, string> = {
    AUDIT_SCORE:           'auditScore',
    MODEL_HASH:            'modelHash',
    OPERATOR_JURISDICTION: 'operatorJurisdiction',
    CAPABILITIES_BITMASK:  'capabilitiesBitmask',
    AUDITED_BY_HASH:       'auditedByHash',
    AUDIT_DATE_UNIX:       'auditDateUnix',
  }
  for (const [k, v] of Object.entries(ATTRIBUTE_INDEX)) {
    out[v as number] = inverse[k as keyof typeof ATTRIBUTE_INDEX] ?? k
  }
  return out
})()

function resolveClaim(c: keyof typeof ATTRIBUTE_INDEX | string | number): number {
  if (typeof c === 'number') {
    if (!Number.isInteger(c) || c < 0) {
      throw new Error(`resolveClaim: invalid numeric claim index ${c}`)
    }
    return c
  }
  const direct = (ATTRIBUTE_INDEX as Record<string, number>)[c]
  if (direct !== undefined) return direct
  const aliased = CLAIM_ALIASES[c]
  if (aliased !== undefined) return ATTRIBUTE_INDEX[aliased]
  throw new Error(
    `resolveClaim: unknown claim "${c}" — known: ${Object.keys(ATTRIBUTE_INDEX).join(', ')}; ` +
      `aliases: ${Object.keys(CLAIM_ALIASES).join(', ')}`,
  )
}

function toConstValue(v: number | bigint | string): bigint {
  if (typeof v === 'bigint') return v
  if (typeof v === 'number') return BigInt(v)
  // String — try jurisdiction code first, then capability bit, else throw.
  const jur = JURISDICTION_NUMERIC[v]
  if (jur !== undefined) return BigInt(jur)
  const cap = CAPABILITY_BIT[v]
  if (cap !== undefined) return BigInt(cap)
  // Fallback: parse as decimal integer if looks numeric.
  if (/^-?\d+$/.test(v)) return BigInt(v)
  throw new Error(
    `toConstValue: cannot convert "${v}" to a circuit-field bigint. Use a numeric literal or a known jurisdiction/capability code.`,
  )
}

/** Look up the current predicate count of the parent. */
function predicateCountOf(_b: PredicateBuilderV2): number {
  // PredicateBuilderV2 keeps `predicates` private. We expose count via a
  // pseudo-friend pattern: a getter on the class instance. Cast through
  // unknown to avoid widening the public surface.
  return (
    (_b as unknown as { predicates: GPPredicate[] }).predicates.length
  )
}

function describeGPProgram(p: GPProgram): string {
  const opSym = (op: gp.GPCompareOp) => (op === 'le' ? '≤' : op === 'ge' ? '≥' : '=')
  const claimName = (i: number) =>
    p.claimLabels?.[i] ??
    Object.entries(ATTRIBUTE_INDEX).find(([, v]) => v === i)?.[0] ??
    `claim[${i}]`
  const pred = (i: number) => {
    const x = p.predicates[i]
    const rhs =
      x.operand.kind === 'const' ? x.operand.value.toString() : claimName(x.operand.claimIndex)
    return `${claimName(x.claimIndex)} ${opSym(x.op)} ${rhs}`
  }
  // Render the postfix expression by simulating a stack of string operands.
  const stack: string[] = []
  for (const t of p.expression) {
    if (t.kind === 'pred') stack.push(pred(t.predicateIndex))
    else if (t.op === 'NOT') {
      const a = stack.pop()!
      stack.push(`NOT(${a})`)
    } else if (t.op === 'AND') {
      const b = stack.pop()!
      const a = stack.pop()!
      stack.push(`(${a} AND ${b})`)
    } else if (t.op === 'OR') {
      const b = stack.pop()!
      const a = stack.pop()!
      stack.push(`(${a} OR ${b})`)
    }
  }
  return stack[0] ?? '(empty)'
}
