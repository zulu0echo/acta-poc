/**
 * BN254 Poseidon (circomlib-compatible) for off-chain hashes that must match Circom.
 *
 * Notes:
 * - In local dev / PoC mode we can fall back to a deterministic Keccak-based
 *   placeholder when circomlibjs is unavailable.
 * - In production we hard-fail if Poseidon cannot be initialized, because
 *   policy hashes and commitments must match the circuit exactly.
 */

import { ethers } from 'ethers'

// SNARK_SCALAR_FIELD for BN254 (must fit into the same range checks on-chain).
const SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let poseidon: any = null
let poseidonAvailable = false

function assertPoseidonOrFail(): void {
  if (process.env.NODE_ENV === 'production' && !poseidonAvailable) {
    throw new Error(
      '[acta/shared] Poseidon is required in production but circomlibjs is unavailable. ' +
        'Install Poseidon dependencies or ensure wallet-unit-poc computes matching values.'
    )
  }
}

function poseidonFallback(inputs: bigint[]): bigint {
  // Deterministic placeholder. It is NOT compatible with circomlib Poseidon,
  // so it must only be used in non-production environments.
  const enc = inputs.map(x => x.toString()).join(',')
  const digest = ethers.keccak256(ethers.toUtf8Bytes(`poseidon:${enc}`))
  return BigInt(digest) % SNARK_SCALAR_FIELD
}

export async function initPoseidon(): Promise<void> {
  if (poseidonAvailable) return
  try {
    const { buildPoseidon } = await import('circomlibjs')
    poseidon = await buildPoseidon()
    poseidonAvailable = true
  } catch (err) {
    poseidon = null
    poseidonAvailable = false
    assertPoseidonOrFail()
  }
}

export function poseidonHash(inputs: bigint[]): bigint {
  assertPoseidonOrFail()
  if (!poseidonAvailable || !poseidon) return poseidonFallback(inputs)

  const F = poseidon.F
  const elements = inputs.map(x => F.e(x))
  const out = poseidon(elements)
  return BigInt(F.toString(out))
}

export function poseidonHashHex(inputs: bigint[]): string {
  const h = poseidonHash(inputs)
  return '0x' + h.toString(16).padStart(64, '0')
}
