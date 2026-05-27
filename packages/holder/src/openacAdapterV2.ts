/**
 * OpenACAdapterV2 — V0.4 holder adapter for the generalised-predicate
 * (zkID-style) presentation flow.
 *
 * Responsibilities:
 *   1. Import a W3C JWT-VC (delegating to the V1 adapter's import path).
 *   2. Encode a verifier-supplied `GPProgram` against the credential's
 *      claim array → `EncodedProgram` (`@acta/shared/gp/encoder`).
 *   3. Build the full circuit witness (`@acta/shared/gp/witness`).
 *   4. Pass that witness to a `WalletUnitV2` prover and assemble the
 *      `OpenACPresentation`.
 *
 * Until the v0.4 ceremony is run, this adapter uses a `StubWalletUnitV2`
 * that produces well-formed but Groth16-unverifiable proofs accepted only
 * by `TestOpenACSnarkVerifier`. The interface is the **same shape** as
 * the eventual real `WalletUnitV2`, so swapping in a snarkjs-backed
 * prover later is a one-line change.
 *
 * Coexistence with V1:
 *   - The V1 `OpenACAdapter` is unchanged and still services current
 *     callers.
 *   - V0.4 callers (e.g. `@acta/sdk` ActaClient) opt in by importing
 *     `OpenACAdapterV2` directly.
 *   - The on-chain `GeneralizedPredicateVerifier` reads the same 7 public
 *     signals from either V1 or V2 proofs; the differentiator is the
 *     `predicateProgramHash` semantics (V1 = V1 Poseidon, V2 = GP-canonical).
 */

import { ethers } from 'ethers'
import {
  ATTRIBUTE_INDEX,
  JURISDICTION_NUMERIC,
  CAPABILITY_BIT,
  CIRCUIT_ATTRIBUTE_COUNT,
  NULL_FIELD_VALUE,
  computeCredentialCommitment,
  computeCredentialMerkleRoot,
  computeContextHash,
  poseidonHash,
  gp,
} from '@acta/shared'
import type {
  AgentCapabilityCredentialSubject,
  CredentialHandle,
  OpenACPresentation,
  PublicSignals,
  GenerateProofParamsV2,
} from '@acta/shared'

// ── Prover interface ──────────────────────────────────────────────────────

/** Result of `WalletUnitV2.generateProof()`. */
export interface WalletUnitV2ProofResult {
  /** Hex-encoded Groth16 proof bytes (or sentinel for the stub). */
  proofBytes: Buffer
  publicSignals: {
    nullifier: bigint
    contextHash: bigint
    predicateProgramHash: bigint
    issuerPubKeyCommitment: bigint
    credentialMerkleRoot: bigint
    credentialCommitment: bigint
    expiryBlock: number
  }
}

export interface IWalletUnitV2 {
  importCredential(params: {
    attributeValues: bigint[]
    issuerPubKeyCommitment: bigint
    randomness: bigint
  }): Promise<{ commitment: bigint; merkleRoot: bigint; credentialId: string }>

  /**
   * Generate a V2 Groth16 proof.
   *
   * `gpProgram` and `claims` together drive witness construction. The
   * prover must hash the program canonically (matching the in-circuit
   * Merkle-fold) and bind the resulting `predicateProgramHash` into the
   * public signals.
   */
  generateProof(params: {
    credentialId: string
    gpProgram: gp.GPProgram
    verifierAddress: string
    policyId: string
    nonce: bigint
    expiryBlock: number
  }): Promise<WalletUnitV2ProofResult>

  verifyProof(params: {
    proofBytes: Buffer
    publicSignals: bigint[]
  }): Promise<boolean>
}

// ── Stub V2 prover ────────────────────────────────────────────────────────

const SENTINEL_V2 = ethers.keccak256(ethers.toUtf8Bytes('OPENAC_TEST_PROOF_V2'))

/**
 * Stub WalletUnitV2 — local Hardhat / dev ONLY.
 *
 * Produces well-formed (V2 public-signal-compatible) sentinel proofs that
 * `TestOpenACSnarkVerifier` accepts. Performs full GP-canonical hashing
 * and the same nullifier derivation the V2 circuit will use, so on-chain
 * Step 5/6/7 invariants are correctly enforced even without a real
 * Groth16 ceremony.
 *
 * Off-chain agreement is enforced because both the stub and the real
 * circuit consume the same `buildCircuitWitness()` output.
 */
export class StubWalletUnitV2 implements IWalletUnitV2 {
  private store: Map<
    string,
    {
      attributeValues: bigint[]
      issuerPubKeyCommitment: bigint
      randomness: bigint
      commitment: bigint
      merkleRoot: bigint
    }
  > = new Map()

  async importCredential(params: {
    attributeValues: bigint[]
    issuerPubKeyCommitment: bigint
    randomness: bigint
  }) {
    const id = ethers.keccak256(
      ethers.toUtf8Bytes(params.attributeValues.join(',') + params.randomness.toString()),
    )
    const commitmentHex = computeCredentialCommitment(params.attributeValues, params.randomness)
    const merkleRootHex = computeCredentialMerkleRoot(params.attributeValues)
    const commitment = BigInt(commitmentHex)
    const merkleRoot = BigInt(merkleRootHex)
    this.store.set(id, { ...params, commitment, merkleRoot })
    return { commitment, merkleRoot, credentialId: id }
  }

  async generateProof(params: {
    credentialId: string
    gpProgram: gp.GPProgram
    verifierAddress: string
    policyId: string
    nonce: bigint
    expiryBlock: number
  }) {
    const cred = this.store.get(params.credentialId)
    if (!cred) {
      throw new Error(`StubWalletUnitV2: unknown credentialId ${params.credentialId}`)
    }

    // Hash the GP program canonically (matches in-circuit Poseidon fold).
    const predicateProgramHash = BigInt(gp.gpProgramHash(params.gpProgram))

    const contextHash = BigInt(
      computeContextHash(params.verifierAddress, params.policyId, params.nonce),
    )

    const credSecret = poseidonHash([cred.commitment, cred.randomness])
    const nullifier = poseidonHash([credSecret, contextHash])

    // Encode + build the witness as a real prover would. This validates
    // the GP program against the credential claims and ensures the stub
    // refuses to produce a "proof" for an unsatisfied policy.
    const encoded = gp.encodeProgram(params.gpProgram, cred.attributeValues)
    gp.buildCircuitWitness(params.gpProgram, encoded, {
      randomness: cred.randomness,
      credentialCommitment: cred.commitment,
      issuerPubKeyCommitment: cred.issuerPubKeyCommitment,
      verifierAddress: BigInt(params.verifierAddress),
      policyId: BigInt(params.policyId),
      nonce: params.nonce,
      expiryBlock: BigInt(params.expiryBlock),
    })

    const proofBytes = Buffer.from(SENTINEL_V2.slice(2).padEnd(512, '0'), 'hex')

    return {
      proofBytes,
      publicSignals: {
        nullifier,
        contextHash,
        predicateProgramHash,
        issuerPubKeyCommitment: cred.issuerPubKeyCommitment,
        credentialMerkleRoot: cred.merkleRoot,
        credentialCommitment: cred.commitment,
        expiryBlock: params.expiryBlock,
      },
    }
  }

  async verifyProof(p: { proofBytes: Buffer; publicSignals: bigint[] }): Promise<boolean> {
    const sentinelBytes = Buffer.from(SENTINEL_V2.slice(2).padEnd(512, '0'), 'hex')
    return p.proofBytes.equals(sentinelBytes) && p.publicSignals.length === 7
  }
}

// ── Adapter ───────────────────────────────────────────────────────────────

export class OpenACAdapterV2 {
  private walletUnit: IWalletUnitV2

  /**
   * If `walletUnit` is omitted, defaults to `StubWalletUnitV2`. Real
   * deployments inject a snarkjs-backed prover here.
   */
  constructor(walletUnit?: IWalletUnitV2) {
    this.walletUnit = walletUnit ?? new StubWalletUnitV2()
  }

  /**
   * Re-uses the existing V1 adapter's logic for JWT-VC validation +
   * commitment derivation. Callers wanting the V2 flow with a typed
   * `CredentialHandle` should pass it through unchanged.
   *
   * If you already have a CredentialHandle from V1, you can call
   * `importExistingCredential()` to register it with the V2 prover
   * without re-validating the JWT.
   */
  async importExistingCredential(params: {
    attributeValues: bigint[]
    issuerPubKeyCommitment: bigint
    randomness: bigint
  }): Promise<CredentialHandle & { credentialId: string; randomnessHex: string }> {
    const result = await this.walletUnit.importCredential(params)
    const randomnessHex = params.randomness.toString(16).padStart(62, '0')
    return {
      credentialId:  result.credentialId,
      commitment:    '0x' + result.commitment.toString(16).padStart(64, '0'),
      merkleRoot:    '0x' + result.merkleRoot.toString(16).padStart(64, '0'),
      randomnessHex,
    }
  }

  /**
   * Generate a V2 presentation proof.
   */
  async generatePresentationProof(
    params: GenerateProofParamsV2,
  ): Promise<OpenACPresentation> {
    const program = params.predicateProgram as gp.GPProgram

    const result = await this.walletUnit.generateProof({
      credentialId: params.credentialHandle.credentialId,
      gpProgram: program,
      verifierAddress: params.verifierAddress,
      policyId: params.policyId,
      nonce: params.nonce,
      expiryBlock: params.expiryBlock,
    })

    const sig = result.publicSignals
    const publicSignals: PublicSignals = {
      nullifier:              toBytes32(sig.nullifier),
      contextHash:            toBytes32(sig.contextHash),
      predicateProgramHash:   toBytes32(sig.predicateProgramHash),
      issuerPubKeyCommitment: toBytes32(sig.issuerPubKeyCommitment),
      credentialMerkleRoot:   toBytes32(sig.credentialMerkleRoot),
      credentialCommitment:   toBytes32(sig.credentialCommitment),
      expiryBlock:            sig.expiryBlock,
    }

    return {
      proofBytes:  '0x' + result.proofBytes.toString('hex'),
      publicSignals,
      contextHash: publicSignals.contextHash,
    }
  }

  /**
   * Off-chain verification — matches `OpenACAdapter.verifyPresentation()`
   * surface but expects V2 public signals (same shape, GP-canonical hash).
   */
  async verifyPresentation(
    presentation: OpenACPresentation,
    expectedPredicateProgramHash: string,
  ): Promise<{ valid: boolean; reason?: string }> {
    const sig = presentation.publicSignals
    if (sig.predicateProgramHash.toLowerCase() !== expectedPredicateProgramHash.toLowerCase()) {
      return {
        valid: false,
        reason: 'predicateProgramHash mismatch — proof was generated for a different policy',
      }
    }
    const proofBytes = Buffer.from(presentation.proofBytes.slice(2), 'hex')
    const pubSignals = [
      BigInt(sig.nullifier),
      BigInt(sig.contextHash),
      BigInt(sig.predicateProgramHash),
      BigInt(sig.issuerPubKeyCommitment),
      BigInt(sig.credentialMerkleRoot),
      BigInt(sig.credentialCommitment),
      BigInt(sig.expiryBlock),
    ]
    const valid = await this.walletUnit.verifyProof({ proofBytes, publicSignals: pubSignals })
    if (!valid) return { valid: false, reason: 'Proof verification failed' }
    return { valid: true }
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────

function toBytes32(x: bigint): string {
  return '0x' + x.toString(16).padStart(64, '0')
}

/**
 * Helper for tests + integration: map a typed `AgentCapabilityCredentialSubject`
 * to the 16-element `attributeValues[]` array consumed by the V2 circuit.
 * Identical layout to V1.
 */
export function credentialSubjectToAttributesV2(
  subject: AgentCapabilityCredentialSubject,
): bigint[] {
  const values: bigint[] = new Array(CIRCUIT_ATTRIBUTE_COUNT).fill(NULL_FIELD_VALUE)
  values[ATTRIBUTE_INDEX.AUDIT_SCORE] = BigInt(Math.round(subject.auditScore))
  const modelHashHex = subject.modelHash.startsWith('0x')
    ? subject.modelHash.slice(2)
    : subject.modelHash
  values[ATTRIBUTE_INDEX.MODEL_HASH] = BigInt('0x' + modelHashHex.slice(0, 62))
  values[ATTRIBUTE_INDEX.OPERATOR_JURISDICTION] = BigInt(
    JURISDICTION_NUMERIC[subject.operatorJurisdiction] ?? 0,
  )
  let bitmask = 0
  for (const cap of subject.capabilities) bitmask |= CAPABILITY_BIT[cap] ?? 0
  values[ATTRIBUTE_INDEX.CAPABILITIES_BITMASK] = BigInt(bitmask)
  const auditedByHash = ethers.keccak256(ethers.toUtf8Bytes(subject.auditedBy))
  values[ATTRIBUTE_INDEX.AUDITED_BY_HASH] = BigInt(auditedByHash) & ((1n << 248n) - 1n)
  const auditTimestamp = Date.parse(subject.auditDate + 'T00:00:00Z') / 1000
  values[ATTRIBUTE_INDEX.AUDIT_DATE_UNIX] = BigInt(auditTimestamp)
  return values
}
