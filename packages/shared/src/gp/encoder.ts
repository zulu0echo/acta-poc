/**
 * Canonical encoder: zkID generalized-predicate IR -> fixed-shape circuit witness.
 *
 * Lock-step contract:
 *
 *   The shape of `EncodedCircuitInputs` below MUST match the public-signal
 *   layout and witness inputs of `circuits/presentation/OpenACGPPresentationV2.circom`.
 *
 *   The `canonicalEncoding()` function defines the byte layout that feeds
 *   the on-chain `predicateProgramHash`. Changing it requires:
 *     - bumping the encoder version
 *     - re-deriving every policy's hash
 *     - re-running the ceremony if the circuit's witness signal count changes
 *
 * The Poseidon hash is computed via `@acta/shared/poseidon`. In production
 * this requires `circomlibjs`; in local dev a Keccak-based fallback is used
 * (this fallback IS NOT compatible with on-chain Poseidon and must not be
 * used to deploy real policies — `initPoseidon()` will hard-fail in
 * `NODE_ENV=production`).
 */

import { poseidonHash, poseidonHashHex } from '../poseidon'
import { validateProgram } from './compiler'
import type { GPBounds, GPProgram } from './types'
import {
  DEFAULT_GP_BOUNDS,
  GP_COMPARE_OP_CODE,
  GP_TOKEN_TYPE_CODE,
} from './types'

/**
 * The witness inputs the Circom V2 circuit expects. Each field is an array
 * of fixed length aligned to the circuit's constants. Slot 0 of any padding
 * value is always zero.
 */
export interface EncodedCircuitInputs {
  /** Claim values (private). Padded with 0n to bounds.maxClaims. */
  claims: bigint[]

  /** Predicate LHS claim indices (public-via-hash). Padded with 0. */
  predClaimIdx: bigint[]
  /** Predicate op codes (public-via-hash). Padded with 0. */
  predOpCode: bigint[]
  /** Predicate operand values (public-via-hash). Padded with 0. */
  predOperand: bigint[]
  /** 1 if operand is a claim reference, 0 if constant (public-via-hash). */
  predIsClaimRef: bigint[]
  /** 1 if the slot is an active predicate, 0 if padding (public-via-hash). */
  predIsActive: bigint[]

  /** Postfix token type codes per slot (public-via-hash). 0 = PAD. */
  exprTokenType: bigint[]
  /** Postfix token value (predicate index for PRED, else 0). */
  exprTokenValue: bigint[]
}

/** Encoded inputs + the canonical Poseidon hash for `predicateProgramHash`. */
export interface EncodedProgram {
  bounds: GPBounds
  inputs: EncodedCircuitInputs
  /** Poseidon hash over the public part of `inputs`. Hex bytes32 string. */
  predicateProgramHash: string
}

/**
 * Encode a GPProgram into circuit witness shape + compute the canonical
 * Poseidon hash. Pads short programs with zero slots up to bounds.
 *
 * Throws via `validateProgram()` if the program is malformed.
 */
export function encodeProgram(
  program: GPProgram,
  claims: ReadonlyArray<bigint>,
  bounds: GPBounds = DEFAULT_GP_BOUNDS,
): EncodedProgram {
  validateProgram(program, bounds)
  if (claims.length > bounds.maxClaims) {
    throw new Error(
      `encodeProgram: too many claims (${claims.length} > ${bounds.maxClaims})`,
    )
  }

  // Pad claims
  const paddedClaims: bigint[] = []
  for (let i = 0; i < bounds.maxClaims; i++) {
    paddedClaims.push(i < claims.length ? claims[i] : 0n)
  }

  // Pack predicates
  const predClaimIdx: bigint[] = []
  const predOpCode: bigint[] = []
  const predOperand: bigint[] = []
  const predIsClaimRef: bigint[] = []
  const predIsActive: bigint[] = []
  for (let i = 0; i < bounds.maxPredicates; i++) {
    const p = program.predicates[i]
    if (p === undefined) {
      predClaimIdx.push(0n)
      predOpCode.push(0n)
      predOperand.push(0n)
      predIsClaimRef.push(0n)
      predIsActive.push(0n)
    } else {
      predClaimIdx.push(BigInt(p.claimIndex))
      predOpCode.push(BigInt(GP_COMPARE_OP_CODE[p.op]))
      if (p.operand.kind === 'const') {
        predOperand.push(p.operand.value)
        predIsClaimRef.push(0n)
      } else {
        predOperand.push(BigInt(p.operand.claimIndex))
        predIsClaimRef.push(1n)
      }
      predIsActive.push(1n)
    }
  }

  // Pack expression
  const exprTokenType: bigint[] = []
  const exprTokenValue: bigint[] = []
  for (let k = 0; k < bounds.maxTokens; k++) {
    const t = program.expression[k]
    if (t === undefined) {
      exprTokenType.push(BigInt(GP_TOKEN_TYPE_CODE.pad))
      exprTokenValue.push(0n)
    } else if (t.kind === 'pred') {
      exprTokenType.push(BigInt(GP_TOKEN_TYPE_CODE.pred))
      exprTokenValue.push(BigInt(t.predicateIndex))
    } else {
      const code =
        t.op === 'AND' ? GP_TOKEN_TYPE_CODE.AND :
        t.op === 'OR'  ? GP_TOKEN_TYPE_CODE.OR  :
                          GP_TOKEN_TYPE_CODE.NOT
      exprTokenType.push(BigInt(code))
      exprTokenValue.push(0n)
    }
  }

  const inputs: EncodedCircuitInputs = {
    claims: paddedClaims,
    predClaimIdx,
    predOpCode,
    predOperand,
    predIsClaimRef,
    predIsActive,
    exprTokenType,
    exprTokenValue,
  }

  const predicateProgramHash = canonicalProgramHash(inputs, bounds)

  return { bounds, inputs, predicateProgramHash }
}

/**
 * Canonical hash over (predicates ‖ expression) — exactly the layout the
 * Circom circuit reproduces in its `predHasher` Poseidon component.
 *
 * Algorithm:
 *   1. Build fields[] from:
 *        version prefix          : 1 field
 *        bounds (M, T)           : 2 fields
 *        per-predicate (5 fields) : 5 * maxPredicates fields
 *        per-token (2 fields)     : 2 * maxTokens fields
 *   2. Poseidon-fold into one field via a Merkle-style binary tree of
 *      Poseidon(2) hashes, then collapse with a final Poseidon over the
 *      tree root and the version prefix.
 *
 * The fold is required because BN254 Poseidon's `Poseidon(n)` only supports
 * small `n` (typically n ≤ 16). For our default bounds (M=8, T=16) the flat
 * vector is 1 + 2 + 5*8 + 2*16 = 75 fields, so we fold.
 */
export function canonicalProgramHash(
  inputs: EncodedCircuitInputs,
  bounds: GPBounds = DEFAULT_GP_BOUNDS,
): string {
  const fields: bigint[] = []
  // Version + bounds
  fields.push(1n) // encoder version
  fields.push(BigInt(bounds.maxPredicates))
  fields.push(BigInt(bounds.maxTokens))
  // Predicates
  for (let i = 0; i < bounds.maxPredicates; i++) {
    fields.push(inputs.predClaimIdx[i])
    fields.push(inputs.predOpCode[i])
    fields.push(inputs.predOperand[i])
    fields.push(inputs.predIsClaimRef[i])
    fields.push(inputs.predIsActive[i])
  }
  // Expression
  for (let k = 0; k < bounds.maxTokens; k++) {
    fields.push(inputs.exprTokenType[k])
    fields.push(inputs.exprTokenValue[k])
  }
  return foldPoseidonHashHex(fields)
}

/**
 * Binary-tree fold of arbitrarily many field elements using Poseidon(2).
 *
 * For odd lengths we duplicate the last leaf (standard Merkle convention).
 * The output is the root as a 0x-prefixed bytes32 hex string.
 */
export function foldPoseidonHash(fields: bigint[]): bigint {
  if (fields.length === 0) return 0n
  if (fields.length === 1) return fields[0]
  let level = fields.slice()
  while (level.length > 1) {
    const next: bigint[] = []
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i]
      const b = i + 1 < level.length ? level[i + 1] : level[i]
      next.push(poseidonHash([a, b]))
    }
    level = next
  }
  return level[0]
}

function foldPoseidonHashHex(fields: bigint[]): string {
  const h = foldPoseidonHash(fields)
  return '0x' + h.toString(16).padStart(64, '0')
}

/** Re-export for callers that want a one-shot hex hash from a GPProgram. */
export function gpProgramHash(
  program: GPProgram,
  bounds: GPBounds = DEFAULT_GP_BOUNDS,
): string {
  // Compute by encoding with zero claims — the hash is independent of claim values.
  const stub: bigint[] = new Array<bigint>(bounds.maxClaims).fill(0n)
  return encodeProgram(program, stub, bounds).predicateProgramHash
}

/**
 * Hash helper exposed for tests that want to inspect intermediate folds.
 * (Equivalent to `poseidonHashHex` for length ≤ 16.)
 */
export { poseidonHashHex }
