import { CIRCUIT_ATTRIBUTE_COUNT } from './constants'
import { poseidonHash, poseidonHashHex } from './poseidon'

/**
 * Poseidon(attributeValues[16], randomness) — matches OpenACGPPresentation commitment.
 */
export function computeCredentialCommitment(
  attributeValues: bigint[],
  randomness: bigint
): string {
  if (attributeValues.length !== CIRCUIT_ATTRIBUTE_COUNT) {
    throw new Error(`attributeValues must have length ${CIRCUIT_ATTRIBUTE_COUNT}`)
  }
  return poseidonHashHex([...attributeValues, randomness])
}

/**
 * Merkle root over 16 attribute leaves (pairwise Poseidon) — matches presentation circuit.
 */
export function computeCredentialMerkleRoot(attributeValues: bigint[]): string {
  if (attributeValues.length !== CIRCUIT_ATTRIBUTE_COUNT) {
    throw new Error(`attributeValues must have length ${CIRCUIT_ATTRIBUTE_COUNT}`)
  }
  const l0: bigint[] = []
  for (let i = 0; i < 8; i++) {
    l0.push(poseidonHash([attributeValues[i * 2], attributeValues[i * 2 + 1]]))
  }
  const l1: bigint[] = []
  for (let i = 0; i < 4; i++) {
    l1.push(poseidonHash([l0[i * 2], l0[i * 2 + 1]]))
  }
  const l2: bigint[] = []
  for (let i = 0; i < 2; i++) {
    l2.push(poseidonHash([l1[i * 2], l1[i * 2 + 1]]))
  }
  return poseidonHashHex([l2[0], l2[1]])
}

export function computeContextHash(
  verifierAddress: string,
  policyId: string,
  nonce: bigint
): string {
  const verifierField = BigInt(verifierAddress)
  const policyField = BigInt(policyId)
  return poseidonHashHex([verifierField, policyField, nonce])
}
