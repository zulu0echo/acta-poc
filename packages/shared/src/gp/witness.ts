/**
 * Witness builder for OpenACGPPresentationV2.circom.
 *
 * Given an `EncodedProgram` (from encoder.ts) and a list of claim values,
 * produces the **complete** circuit input map that snarkjs needs:
 *
 *   - All public inputs (program parameters)
 *   - The private claims
 *   - The prover-supplied stack-trace + depth-trace for the postfix
 *     evaluator (`PostfixEval.circom`).
 *
 * The witness builder is **the** authoritative off-chain reference for
 * what the circuit will verify. It is exercised by:
 *
 *   - `packages/shared/test/gp/witness.test.ts` — parity vectors.
 *   - `packages/holder/src/openacAdapterV2.ts` — production prover input.
 *
 * Reference for the stack-machine semantics:
 *   - circuits/lib/PostfixEval.circom
 *   - docs/adr/0001-zkid-generalized-predicates.md
 */

import { evaluatePredicate, evaluatePostfix } from './compiler'
import {
  DEFAULT_GP_BOUNDS,
  GP_TOKEN_TYPE_CODE,
  type GPBounds,
  type GPProgram,
} from './types'
import type { EncodedCircuitInputs, EncodedProgram } from './encoder'

/** Token type code → semantic name (for diagnostic messages). */
const TOKEN_TYPE_NAME: Record<number, string> = {
  [GP_TOKEN_TYPE_CODE.pad]: 'PAD',
  [GP_TOKEN_TYPE_CODE.pred]: 'PRED',
  [GP_TOKEN_TYPE_CODE.AND]: 'AND',
  [GP_TOKEN_TYPE_CODE.OR]: 'OR',
  [GP_TOKEN_TYPE_CODE.NOT]: 'NOT',
}

/**
 * The complete witness needed for OpenACGPPresentationV2.circom.
 *
 * Naming MUST match the `signal input` declarations in the circuit. snarkjs
 * resolves witness inputs by key.
 */
export interface CircuitWitnessV2 {
  // Private credential inputs
  attributeValues: bigint[]                   // length N_CLAIMS
  randomness: bigint
  credentialCommitment: bigint
  issuerPubKeyCommitmentPrivate: bigint
  verifierAddress: bigint
  policyId: bigint
  nonce: bigint
  expiryBlockPrivate: bigint

  // GP program (witness-private but bound to predicateProgramHash output)
  predClaimIdx: bigint[]                      // length M_PREDS
  predOpCode: bigint[]
  predOperand: bigint[]
  predIsClaimRef: bigint[]
  predIsActive: bigint[]
  exprTokenType: bigint[]                     // length T_TOKENS
  exprTokenValue: bigint[]

  // Postfix evaluator witness (prover-supplied trace)
  stackTrace: bigint[][]                      // shape [T+1][T+1]
  dpTrace: bigint[]                           // length T+1
}

/** Diagnostic info attached to a witness (useful for tests + error messages). */
export interface WitnessDiagnostics {
  /** Final boolean result of the GP program over the supplied claims. */
  programResult: boolean
  /** Per-predicate boolean results (length = active predicates, padded with false). */
  predicateResults: boolean[]
  /** Maximum stack depth observed during evaluation. */
  maxStackDepth: number
  /** Stack-trace size (T+1 × T+1). */
  stackShape: { steps: number; depth: number }
}

export interface WitnessBuildResult {
  witness: CircuitWitnessV2
  diagnostics: WitnessDiagnostics
}

/** Inputs needed in addition to the encoded GP program to build a witness. */
export interface CredentialWitnessInputs {
  randomness: bigint
  credentialCommitment: bigint
  issuerPubKeyCommitment: bigint
  verifierAddress: bigint               // raw uint160 (left-zero padded to bytes32 on chain)
  policyId: bigint                      // bytes32 as bigint
  nonce: bigint
  expiryBlock: bigint
}

/**
 * Build the full circuit witness for a presentation.
 *
 * Throws if:
 *   - The GP program does not evaluate to `true` for the supplied claims.
 *     (The circuit asserts `finalValue === 1`; failing fast here gives a
 *     better error than a witness-generation failure.)
 *   - The expression overflows the bounds (validated upstream by encoder,
 *     but checked again as a defence in depth).
 */
export function buildCircuitWitness(
  program: GPProgram,
  encoded: EncodedProgram,
  credential: CredentialWitnessInputs,
  bounds: GPBounds = DEFAULT_GP_BOUNDS,
): WitnessBuildResult {
  const inputs = encoded.inputs

  // ── 1. Evaluate every predicate over the supplied claims ──
  const predResults: boolean[] = []
  for (let p = 0; p < bounds.maxPredicates; p++) {
    const isActive = inputs.predIsActive[p] === 1n
    if (!isActive) {
      predResults.push(false)
      continue
    }
    const pred = program.predicates[p]
    if (!pred) {
      throw new Error(
        `witness: predicate slot ${p} marked active but missing from GPProgram`,
      )
    }
    predResults.push(evaluatePredicate(pred, inputs.claims))
  }

  // ── 2. Build the stack trace by replaying the expression ──
  const T = bounds.maxTokens
  const STACK_W = T + 1
  const stackTrace: bigint[][] = []
  const dpTrace: bigint[] = []

  let dp = 0
  let stack: bigint[] = new Array<bigint>(STACK_W).fill(0n)

  const snapshot = (): bigint[] => stack.slice()
  stackTrace.push(snapshot())
  dpTrace.push(BigInt(dp))

  let maxDepth = 0

  for (let k = 0; k < T; k++) {
    const tokenType = Number(inputs.exprTokenType[k])
    const tokenValue = Number(inputs.exprTokenValue[k])

    switch (tokenType) {
      case GP_TOKEN_TYPE_CODE.pad: {
        // No-op.
        break
      }
      case GP_TOKEN_TYPE_CODE.pred: {
        if (dp >= STACK_W) {
          throw new Error(`witness: stack overflow at step ${k} (PRED)`)
        }
        const r = predResults[tokenValue]
        if (r === undefined) {
          throw new Error(
            `witness: PRED token at step ${k} references missing predicate ${tokenValue}`,
          )
        }
        stack[dp] = r ? 1n : 0n
        dp += 1
        break
      }
      case GP_TOKEN_TYPE_CODE.NOT: {
        if (dp < 1) {
          throw new Error(`witness: NOT underflow at step ${k} (dp=${dp})`)
        }
        const top1 = stack[dp - 1]
        stack[dp - 1] = 1n - top1
        break
      }
      case GP_TOKEN_TYPE_CODE.AND: {
        if (dp < 2) {
          throw new Error(`witness: AND underflow at step ${k} (dp=${dp})`)
        }
        const top1 = stack[dp - 1]
        const top2 = stack[dp - 2]
        stack[dp - 2] = top1 * top2
        stack[dp - 1] = 0n
        dp -= 1
        break
      }
      case GP_TOKEN_TYPE_CODE.OR: {
        if (dp < 2) {
          throw new Error(`witness: OR underflow at step ${k} (dp=${dp})`)
        }
        const top1 = stack[dp - 1]
        const top2 = stack[dp - 2]
        // top1 + top2 - top1*top2
        stack[dp - 2] = top1 + top2 - top1 * top2
        stack[dp - 1] = 0n
        dp -= 1
        break
      }
      default:
        throw new Error(
          `witness: unknown token type ${tokenType} (${TOKEN_TYPE_NAME[tokenType] ?? '?'}) at step ${k}`,
        )
    }

    if (dp > maxDepth) maxDepth = dp
    stackTrace.push(snapshot())
    dpTrace.push(BigInt(dp))
  }

  // ── 3. Sanity-check the final state ──
  if (dp !== 1) {
    throw new Error(
      `witness: expression must end with depth 1, got ${dp} (program likely malformed; should have been caught by validateProgram)`,
    )
  }
  if (stack[0] !== 1n) {
    throw new Error(
      'witness: GP program evaluates to false for the supplied claims — refusing to build a witness because circuit asserts finalValue === 1',
    )
  }

  // ── 4. Reference sanity check: our trace agrees with evaluatePostfix() ──
  const reference = evaluatePostfix(program.expression, predResults.slice(0, program.predicates.length))
  if (reference !== true) {
    throw new Error('witness: reference evaluator disagrees with trace builder — bug')
  }

  // ── 5. Pack the full circuit witness ──
  const witness: CircuitWitnessV2 = {
    attributeValues: inputs.claims,
    randomness: credential.randomness,
    credentialCommitment: credential.credentialCommitment,
    issuerPubKeyCommitmentPrivate: credential.issuerPubKeyCommitment,
    verifierAddress: credential.verifierAddress,
    policyId: credential.policyId,
    nonce: credential.nonce,
    expiryBlockPrivate: credential.expiryBlock,
    predClaimIdx: inputs.predClaimIdx,
    predOpCode: inputs.predOpCode,
    predOperand: inputs.predOperand,
    predIsClaimRef: inputs.predIsClaimRef,
    predIsActive: inputs.predIsActive,
    exprTokenType: inputs.exprTokenType,
    exprTokenValue: inputs.exprTokenValue,
    stackTrace,
    dpTrace,
  }

  return {
    witness,
    diagnostics: {
      programResult: true,
      predicateResults: predResults,
      maxStackDepth: maxDepth,
      stackShape: { steps: T + 1, depth: STACK_W },
    },
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────

/** Convert a 0x-prefixed hex string to a bigint, tolerating empty strings. */
export function hexToBigInt(hex: string): bigint {
  if (!hex) return 0n
  const clean = hex.startsWith('0x') || hex.startsWith('0X') ? hex : '0x' + hex
  return BigInt(clean)
}

/** Convert a bigint to a 0x-prefixed 32-byte hex string. */
export function bigintToBytes32(x: bigint): string {
  return '0x' + x.toString(16).padStart(64, '0')
}

/**
 * Flatten the circuit witness into the JSON form `snarkjs` expects (string
 * field elements rather than bigints). The keys are kept identical so it
 * can be passed directly as `input.json` to `snarkjs wtns calculate`.
 */
export function witnessToSnarkjsInput(w: CircuitWitnessV2): Record<string, string | string[] | string[][]> {
  const s = (b: bigint) => b.toString()
  const arr = (a: bigint[]) => a.map(s)
  return {
    attributeValues: arr(w.attributeValues),
    randomness: s(w.randomness),
    credentialCommitment: s(w.credentialCommitment),
    issuerPubKeyCommitmentPrivate: s(w.issuerPubKeyCommitmentPrivate),
    verifierAddress: s(w.verifierAddress),
    policyId: s(w.policyId),
    nonce: s(w.nonce),
    expiryBlockPrivate: s(w.expiryBlockPrivate),
    predClaimIdx: arr(w.predClaimIdx),
    predOpCode: arr(w.predOpCode),
    predOperand: arr(w.predOperand),
    predIsClaimRef: arr(w.predIsClaimRef),
    predIsActive: arr(w.predIsActive),
    exprTokenType: arr(w.exprTokenType),
    exprTokenValue: arr(w.exprTokenValue),
    stackTrace: w.stackTrace.map(arr),
    dpTrace: arr(w.dpTrace),
  }
}

/**
 * Convenience: produce the `inputs` map snarkjs needs from a high-level
 * `(program, encoded, credential)` triple in one call.
 */
export function buildSnarkjsInput(
  program: GPProgram,
  encoded: EncodedProgram,
  credential: CredentialWitnessInputs,
  bounds: GPBounds = DEFAULT_GP_BOUNDS,
): Record<string, string | string[] | string[][]> {
  const { witness } = buildCircuitWitness(program, encoded, credential, bounds)
  return witnessToSnarkjsInput(witness)
}

/** Exported only for the snarkjs input layout test in witness.test.ts. */
export const __unused_diag_types__: WitnessDiagnostics | undefined = undefined

// Also keep these exported types referenced from EncodedCircuitInputs/EncodedProgram
export type { EncodedCircuitInputs, EncodedProgram }
