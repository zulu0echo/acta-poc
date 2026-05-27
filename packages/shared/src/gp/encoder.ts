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
 * Layout (must match `OpenACGPPresentationV2.circom`'s `hashLeaves[]`):
 *   leaf 0           : version (currently 1)
 *   leaf 1           : bounds.maxPredicates (M)
 *   leaf 2           : bounds.maxTokens (T)
 *   leaves 3..3+5M-1 : per-predicate fields
 *                       (claimIdx, opCode, operand, isClaimRef, isActive)
 *   next 2T leaves   : per-token fields (type, value)
 *   remaining        : zero-padded to the next power of 2 (currently 128).
 *
 * For default bounds (M=8, T=16) the active leaf count is
 *   1 + 2 + 5*8 + 2*16 = 75
 * and the padded leaf count is 128 (= 2^7).
 *
 * The fold uses Poseidon(2) at each level. Padding to a power of 2 with
 * zeros matches the circuit's straight-pair fold (no odd-length leaf
 * duplication). Changing the leaf layout or padding scheme requires
 * bumping the encoder version + re-deriving every policy hash.
 */
export function canonicalProgramHash(
  inputs: EncodedCircuitInputs,
  bounds: GPBounds = DEFAULT_GP_BOUNDS,
): string {
  const fields = buildHashLeaves(inputs, bounds)
  return foldPoseidonHashHex(fields)
}

/**
 * Build the leaf vector exactly as the V2 circuit does. Exposed so the
 * holder and integration tests can assert byte-for-byte parity.
 */
export function buildHashLeaves(
  inputs: EncodedCircuitInputs,
  bounds: GPBounds = DEFAULT_GP_BOUNDS,
): bigint[] {
  const leaves: bigint[] = []
  leaves.push(1n) // version
  leaves.push(BigInt(bounds.maxPredicates))
  leaves.push(BigInt(bounds.maxTokens))
  for (let i = 0; i < bounds.maxPredicates; i++) {
    leaves.push(inputs.predClaimIdx[i])
    leaves.push(inputs.predOpCode[i])
    leaves.push(inputs.predOperand[i])
    leaves.push(inputs.predIsClaimRef[i])
    leaves.push(inputs.predIsActive[i])
  }
  for (let k = 0; k < bounds.maxTokens; k++) {
    leaves.push(inputs.exprTokenType[k])
    leaves.push(inputs.exprTokenValue[k])
  }
  // Zero-pad to next power of 2.
  const target = nextPowerOfTwo(leaves.length)
  while (leaves.length < target) leaves.push(0n)
  return leaves
}

/**
 * Binary-tree fold of `fields[]` using Poseidon(2). REQUIRES `fields.length`
 * to be a positive power of 2 (zero-padded by the caller). Matches the
 * circuit's straight-pair fold.
 */
export function foldPoseidonHash(fields: bigint[]): bigint {
  if (fields.length === 0) return 0n
  if (fields.length === 1) return fields[0]
  if ((fields.length & (fields.length - 1)) !== 0) {
    throw new Error(
      `foldPoseidonHash: input length ${fields.length} is not a power of 2; ` +
        'zero-pad before folding to match the circuit',
    )
  }
  let level = fields.slice()
  while (level.length > 1) {
    const next: bigint[] = []
    for (let i = 0; i < level.length; i += 2) {
      next.push(poseidonHash([level[i], level[i + 1]]))
    }
    level = next
  }
  return level[0]
}

function foldPoseidonHashHex(fields: bigint[]): string {
  const h = foldPoseidonHash(fields)
  return '0x' + h.toString(16).padStart(64, '0')
}

function nextPowerOfTwo(n: number): number {
  if (n <= 1) return 1
  let p = 1
  while (p < n) p <<= 1
  return p
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
