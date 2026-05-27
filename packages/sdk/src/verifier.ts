/**
 * Verifier surface — V0.4 PredicateBuilderV2 + OffchainVerifier V2.
 *
 * Verifier-side integration boils down to:
 *   1. Build a GP program via `verifier.builder()`.
 *   2. Register `built.hash` on-chain as the `predicateProgramHash`.
 *   3. Call `acta.verifier.verifyOffchainV2()` on incoming presentations.
 *   4. Submit on-chain via `OnchainSubmitter` (see @acta/verifier docs).
 */

import {
  PredicateBuilderV2,
  BuiltGPPredicate,
} from '@acta/verifier/src/predicateBuilderV2'

export type { BuiltGPPredicate }

/** Factory for the GP-native fluent builder. */
export function builder(schemaId = 'AgentCapabilityCredential'): PredicateBuilderV2 {
  return new PredicateBuilderV2(schemaId)
}

/** Migration: translate a V1 `PredicateProgram` into a built GP predicate. */
export const fromV1Program = PredicateBuilderV2.fromV1Program
