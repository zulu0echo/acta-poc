/**
 * Stealth surface — wrapper around @acta/shared/stealth so SDK users have
 * one stable import.
 *
 * See ADR-0002 (`docs/adr/0002-stealth-addresses-for-unlinkability.md`).
 */

import { stealth as sharedStealth } from '@acta/shared'

export type StealthContext = sharedStealth.StealthContext
export type StealthIdentity = sharedStealth.StealthIdentity

/**
 * Derive a stealth identity from a holder master secret and a context.
 *
 * The derivation is HKDF-SHA256-then-SHA256 of `(master, verifierAddress,
 * policyId, sessionIndex)`. The output is a secp256k1 keypair and the
 * matching Ethereum address.
 */
export function derive(
  masterSecret: Uint8Array | Buffer | string,
  ctx: StealthContext,
): StealthIdentity {
  return sharedStealth.deriveStealthIdentity(masterSecret, ctx)
}

/** Holder-binding commitment used by ADR-0003 anchoring (placeholder). */
export function holderCommitment(
  masterSecret: Uint8Array | Buffer | string,
  salt: bigint,
): string {
  return sharedStealth.holderCommitment(masterSecret, salt)
}
