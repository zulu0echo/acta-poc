/**
 * Predicate surface — zkID GP IR builder, encoder, and canonical hash.
 *
 * Thin wrapper over @acta/shared/gp so SDK users have one stable import.
 */

import { gp } from '@acta/shared'

export type GPProgram = gp.GPProgram
export type GPPredicate = gp.GPPredicate
export type GPToken = gp.GPToken
export type GPCompareOp = gp.GPCompareOp
export type GPLogicalOp = gp.GPLogicalOp

export const DEFAULT_BOUNDS = gp.DEFAULT_GP_BOUNDS

/**
 * Fluent builder for GP programs. Designed for the common case where the
 * developer adds predicates left-to-right and then provides an explicit
 * postfix expression (or uses `infix()` to compile one from infix tokens).
 */
export class GPProgramBuilder {
  private predicates: gp.GPPredicate[] = []
  private expression: gp.GPToken[] = []

  add(predicate: gp.GPPredicate): this {
    this.predicates.push(predicate)
    return this
  }

  /** Replace the expression with a literal postfix sequence. */
  expression_(tokens: gp.GPToken[]): this {
    this.expression = tokens
    return this
  }

  /** Compile an infix token sequence to postfix and use it. */
  infix(tokens: gp.InfixToken[]): this {
    this.expression = gp.infixToPostfix(tokens)
    return this
  }

  build(): gp.GPProgram {
    const program: gp.GPProgram = {
      version: 1,
      predicates: [...this.predicates],
      expression: [...this.expression],
    }
    gp.validateProgram(program)
    return program
  }
}

/** Factory for a new builder. */
export function builder(): GPProgramBuilder {
  return new GPProgramBuilder()
}

/** Compute the canonical Poseidon `predicateProgramHash` for a program. */
export function hash(program: gp.GPProgram): string {
  return gp.gpProgramHash(program)
}

/** Encode a program to circuit witness shape. */
export function encode(
  program: gp.GPProgram,
  claims: ReadonlyArray<bigint>,
  bounds: gp.GPBounds = gp.DEFAULT_GP_BOUNDS,
): gp.EncodedProgram {
  return gp.encodeProgram(program, claims, bounds)
}

/** Reference-evaluate a program off-circuit (used for testing). */
export function evaluate(
  program: gp.GPProgram,
  claims: ReadonlyArray<bigint>,
): boolean {
  return gp.evaluateProgram(program, claims)
}

/**
 * Build the full circuit witness for a (program, claims, credential)
 * triple. The returned witness is consumable by the V2 Groth16 circuit
 * (after snarkjs `wtns calculate`).
 */
export function buildWitness(
  program: gp.GPProgram,
  encoded: gp.EncodedProgram,
  credential: gp.CredentialWitnessInputs,
  bounds: gp.GPBounds = gp.DEFAULT_GP_BOUNDS,
): gp.WitnessBuildResult {
  return gp.buildCircuitWitness(program, encoded, credential, bounds)
}

/** Build a JSON-serialisable snarkjs `input.json` map in one step. */
export function buildSnarkjsInput(
  program: gp.GPProgram,
  claims: ReadonlyArray<bigint>,
  credential: gp.CredentialWitnessInputs,
  bounds: gp.GPBounds = gp.DEFAULT_GP_BOUNDS,
): Record<string, string | string[] | string[][]> {
  const encoded = gp.encodeProgram(program, claims, bounds)
  return gp.buildSnarkjsInput(program, encoded, credential, bounds)
}

/** Translate a V1 `PredicateProgram` into a GP `GPProgram`. */
export function fromV1(v1Program: Parameters<typeof gp.v1ToGP>[0]): gp.GPProgram {
  return gp.v1ToGP(v1Program)
}

export { gp as raw }
