/**
 * OpenAC Adapter — bridges W3C JWT-VC (with did:ethr issuer) to the OpenAC ZK layer.
 *
 * Dependency path:
 *   The wallet-unit-poc is referenced as a local workspace dependency:
 *   file:../../wallet-unit-poc
 *
 *   If wallet-unit-poc is not yet cloned locally, this module degrades gracefully
 *   by using a stub implementation that generates deterministically fake proofs
 *   suitable for local testing. See OpenACAdapter.setTestMode().
 *
 * contextHash / Poseidon contract:
 *   The circuit computes contextHash = Poseidon(verifierAddress, policyId, nonce)
 *   and exposes it as pubSignals[1]. On-chain Step 7 recomputes the same value via
 *   IPoseidonT4. To honour this contract, generatePresentationProof() passes
 *   verifierAddress, policyId, and nonce as separate inputs to walletUnit.generateProof()
 *   so the real wallet-unit-poc can compute Poseidon internally.
 *
 *   The StubWalletUnit approximates the contextHash with keccak256, which is
 *   acceptable in tests where contextHasher is address(0) (Step 7 is skipped).
 *   The stub MUST NOT be used with a deployed IPoseidonT4 contract.
 *
 * Randomness persistence:
 *   The BN254 randomness blinding factor must survive server restarts. If it is
 *   regenerated, importCredential() would derive a different commitment that no
 *   longer matches the on-chain anchor, causing CommitmentAlreadyAnchored revert.
 *   Callers (CredentialStore) are responsible for persisting and supplying the
 *   previously used randomness on subsequent imports.
 */

import { ethers } from 'ethers'
import { Resolver } from 'did-resolver'
import {
  ATTRIBUTE_INDEX,
  CAPABILITY_BIT,
  JURISDICTION_NUMERIC,
  CIRCUIT_ATTRIBUTE_COUNT,
  NULL_FIELD_VALUE,
} from '@acta/shared'
import type {
  AgentCapabilityCredentialSubject,
  AttributeValues,
  CredentialHandle,
  OpenACPresentation,
  GenerateProofParams,
  PublicSignals,
} from '@acta/shared'

// Attempt to import wallet-unit-poc. Falls back to stub if not installed.
let WalletUnit: new () => IWalletUnit
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const mod = require('@privacy-ethereum/zkid-wallet-unit-poc')
  WalletUnit = mod.WalletUnit ?? mod.default
} catch {
  WalletUnit = StubWalletUnit as unknown as new () => IWalletUnit
  console.warn('[openacAdapter] wallet-unit-poc not found — using stub for local testing')
}

interface IWalletUnit {
  importCredential(params: {
    attributeValues: bigint[]
    issuerPubKeyCommitment: bigint
    randomness: bigint
  }): Promise<{ commitment: bigint; merkleRoot: bigint; credentialId: string }>

  /**
   * Generate a Groth16 proof.
   *
   * @param verifierAddress  Ethereum address of the on-chain verifier (as hex string or bigint)
   * @param policyId         bytes32 policy ID (as hex string or bigint)
   * @param nonce            uint64 session nonce — passed separately so the real wallet-unit-poc
   *                         can compute Poseidon(verifierAddress, policyId, nonce) internally,
   *                         matching the circuit output. Do NOT pre-compute the contextHash here.
   *
   * The returned contextHash MUST equal Poseidon(verifierAddress, policyId, nonce) over BN254,
   * matching the circuit constraint and the on-chain IPoseidonT4.hash() call in Step 7.
   */
  generateProof(params: {
    credentialId:    string
    predicateProgram: unknown
    verifierAddress: string    // raw Ethereum address (for Poseidon input)
    policyId:        string    // bytes32 hex (for Poseidon input)
    nonce:           bigint    // uint64 session nonce (for Poseidon input)
    expiryBlock:     number
  }): Promise<{
    proofBytes:             Buffer
    nullifier:              bigint
    contextHash:            bigint   // MUST be Poseidon(verifier, policy, nonce) on real circuit
    predicateProgramHash:   bigint
    issuerPubKeyCommitment: bigint
    credentialMerkleRoot:   bigint
    expiryBlock:            number
  }>

  verifyProof(params: {
    proofBytes:   Buffer
    publicSignals: bigint[]
  }): Promise<boolean>
}

/**
 * Stub WalletUnit — used when wallet-unit-poc is not installed.
 * Generates deterministic fake proofs for local development and testing.
 *
 * IMPORTANT: The stub uses keccak256 for contextHash instead of Poseidon.
 * This is acceptable ONLY in environments where contextHasher is address(0)
 * (Step 7 is skipped). Running the stub against a contract with a live
 * IPoseidonT4 contextHasher will always fail with ContextHashMismatch.
 */
class StubWalletUnit implements IWalletUnit {
  private store: Map<
    string,
    { attributeValues: bigint[]; issuerPubKeyCommitment: bigint; randomness: bigint }
  > = new Map()

  async importCredential(params: {
    attributeValues: bigint[]
    issuerPubKeyCommitment: bigint
    randomness: bigint
  }) {
    const id = ethers.keccak256(
      ethers.toUtf8Bytes(params.attributeValues.join(',') + params.randomness.toString())
    )
    this.store.set(id, params)
    const commitment = BigInt(ethers.keccak256(ethers.toUtf8Bytes('commitment:' + id)))
    const merkleRoot = BigInt(ethers.keccak256(ethers.toUtf8Bytes('merkle:' + id)))
    return { commitment, merkleRoot, credentialId: id }
  }

  async generateProof(params: {
    credentialId:    string
    predicateProgram: unknown
    verifierAddress: string
    policyId:        string
    nonce:           bigint
    expiryBlock:     number
  }) {
    // Stub contextHash approximation: keccak256(verifier || policyId || nonce).
    // This differs from the circuit's Poseidon output. Only valid when
    // contextHasher is address(0) (test environment — Step 7 is skipped).
    const contextHash = BigInt(
      ethers.keccak256(
        ethers.solidityPacked(
          ['address', 'bytes32', 'uint256'],
          [params.verifierAddress, params.policyId, params.nonce]
        )
      )
    )

    const nullifier = BigInt(
      ethers.keccak256(
        ethers.toUtf8Bytes('nullifier:' + params.credentialId + ':' + contextHash.toString())
      )
    )
    const predicateProgramHash = BigInt(
      ethers.keccak256(
        ethers.toUtf8Bytes('predicate:' + JSON.stringify(params.predicateProgram))
      )
    )
    const cred                 = this.store.get(params.credentialId)!
    const issuerPubKeyCommitment = cred.issuerPubKeyCommitment
    const credentialMerkleRoot   = BigInt(
      ethers.keccak256(ethers.toUtf8Bytes('merkle:' + params.credentialId))
    )

    // Sentinel proof bytes accepted by OpenACSnarkVerifier in test mode
    const SENTINEL = ethers.keccak256(ethers.toUtf8Bytes('OPENAC_TEST_PROOF_V1'))
    const proofBytes = Buffer.from(SENTINEL.slice(2).padEnd(512, '0'), 'hex')

    return {
      proofBytes,
      nullifier,
      contextHash,
      predicateProgramHash,
      issuerPubKeyCommitment,
      credentialMerkleRoot,
      expiryBlock: params.expiryBlock,
    }
  }

  async verifyProof(_params: { proofBytes: Buffer; publicSignals: bigint[] }): Promise<boolean> {
    const SENTINEL = ethers.keccak256(ethers.toUtf8Bytes('OPENAC_TEST_PROOF_V1'))
    const sentinelBytes = Buffer.from(SENTINEL.slice(2).padEnd(512, '0'), 'hex')
    return _params.proofBytes.equals(sentinelBytes)
  }
}

// ── OpenACAdapter ─────────────────────────────────────────────────────────────

export class OpenACAdapter {
  private walletUnit: IWalletUnit

  constructor() {
    this.walletUnit = new WalletUnit()
  }

  /**
   * Import a W3C JWT-VC into OpenAC.
   *
   * @param randomnessHex  Optional persisted randomness from a previous import.
   *                       Must be supplied when re-importing an already-anchored credential
   *                       so the same commitment is reproduced. If omitted, fresh randomness
   *                       is generated — do this only for first-time imports.
   *
   * Steps:
   *  1. Validate JWT structure and decode payload
   *  2. Resolve issuer's did:ethr to extract secp256k1 public key
   *  3. Cryptographically verify the JWT-VC ES256K signature — hard failure if invalid
   *  4. Compute issuerPubKeyCommitment = keccak256(pubKey) truncated to 248 bits
   *  5. Map credentialSubject fields → attributeValues[] per ATTRIBUTE_INDEX
   *  6. Call walletUnit.importCredential()
   *  7. Return CredentialHandle (commitment, merkleRoot, credentialId, randomnessHex)
   */
  async importCredential(
    jwtVc: string,
    issuerDid: string,
    resolver: Resolver,
    randomnessHex?: string
  ): Promise<CredentialHandle & { credentialId: string; randomnessHex: string }> {
    const payload = decodeJwtPayload(jwtVc)
    const subject = payload.vc?.credentialSubject as AgentCapabilityCredentialSubject

    // Resolve issuer's DID to get public key for commitment and signature verification.
    let issuerPubKeyHex: string
    let issuerEthAddress: string
    try {
      const resolution = await resolver.resolve(issuerDid)
      const vm = (resolution.didDocument?.verificationMethod ?? []).find(
        v =>
          v.type === 'EcdsaSecp256k1VerificationKey2019' ||
          v.type === 'EcdsaSecp256k1RecoveryMethod2020'
      )
      issuerPubKeyHex  = vm?.publicKeyHex ?? issuerDid.split(':').pop()!
      issuerEthAddress = issuerDid.split(':').pop()!
    } catch (err) {
      // DID resolution failure is a hard error: without resolving the issuer, we cannot
      // verify the JWT-VC signature. Accepting the credential anyway would be a security hole.
      throw new Error(
        `[openacAdapter] Cannot import credential: failed to resolve issuer DID ${issuerDid}: ` +
        (err as Error).message
      )
    }

    // Cryptographically verify the JWT-VC ES256K signature.
    // This must be a hard failure. If we fall back to a warning, an attacker who can
    // disrupt DID resolution can bypass credential authenticity checks entirely.
    if (!ethers.isAddress(issuerEthAddress)) {
      throw new Error(
        `[openacAdapter] Cannot verify JWT-VC signature: issuer address not parseable from DID ${issuerDid}`
      )
    }
    const sigValid = verifyJwtSignature(jwtVc, issuerEthAddress)
    if (!sigValid) {
      throw new Error(
        `[openacAdapter] JWT-VC signature verification failed: credential not signed by issuer ${issuerDid}`
      )
    }

    const issuerPubKeyCommitment = pubKeyToFieldCommitment(issuerPubKeyHex)

    // Use persisted randomness if provided; otherwise generate fresh.
    // Callers MUST persist the returned randomnessHex alongside the credential.
    const randomness = randomnessHex
      ? BigInt('0x' + randomnessHex)
      : BigInt(
          '0x' +
          Array.from(ethers.randomBytes(31))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')
        )
    const outRandomnessHex = randomness.toString(16).padStart(62, '0')

    const attributeValues = credentialSubjectToAttributes(subject)

    const result = await this.walletUnit.importCredential({
      attributeValues,
      issuerPubKeyCommitment,
      randomness,
    })

    return {
      credentialId:  result.credentialId,
      commitment:    '0x' + result.commitment.toString(16).padStart(64, '0'),
      merkleRoot:    '0x' + result.merkleRoot.toString(16).padStart(64, '0'),
      randomnessHex: outRandomnessHex,
    }
  }

  /**
   * Generate a ZK presentation proof.
   *
   * Passes verifierAddress, policyId, and nonce as separate inputs so the real
   * wallet-unit-poc can compute contextHash = Poseidon(verifier, policy, nonce)
   * internally, matching the circuit constraint and on-chain IPoseidonT4 Step 7.
   */
  async generatePresentationProof(params: GenerateProofParams): Promise<OpenACPresentation> {
    const result = await this.walletUnit.generateProof({
      credentialId:    params.credentialHandle.credentialId,
      predicateProgram: params.predicateProgram,
      verifierAddress: params.verifierAddress,
      policyId:        params.policyId,
      nonce:           params.nonce,
      expiryBlock:     params.expiryBlock,
    })

    const publicSignals: PublicSignals = {
      nullifier:              '0x' + result.nullifier.toString(16).padStart(64, '0'),
      contextHash:            '0x' + result.contextHash.toString(16).padStart(64, '0'),
      predicateProgramHash:   '0x' + result.predicateProgramHash.toString(16).padStart(64, '0'),
      issuerPubKeyCommitment: '0x' + result.issuerPubKeyCommitment.toString(16).padStart(64, '0'),
      credentialMerkleRoot:   '0x' + result.credentialMerkleRoot.toString(16).padStart(64, '0'),
      expiryBlock:            result.expiryBlock,
    }

    return {
      proofBytes:  '0x' + result.proofBytes.toString('hex'),
      publicSignals,
      contextHash: publicSignals.contextHash,
    }
  }

  /**
   * Off-chain verification — used by the verifier before on-chain submission.
   */
  async verifyPresentation(
    presentation: OpenACPresentation,
    _policyId: string,
    issuerDid: string,
    resolver: Resolver
  ): Promise<{ valid: boolean; reason?: string }> {
    const signals    = presentation.publicSignals
    const pubSignals = [
      BigInt(signals.nullifier),
      BigInt(signals.contextHash),
      BigInt(signals.predicateProgramHash),
      BigInt(signals.issuerPubKeyCommitment),
      BigInt(signals.credentialMerkleRoot),
      BigInt(signals.expiryBlock),
    ]

    const proofBytes = Buffer.from(presentation.proofBytes.slice(2), 'hex')
    const valid      = await this.walletUnit.verifyProof({ proofBytes, publicSignals: pubSignals })
    if (!valid) return { valid: false, reason: 'Proof verification failed' }

    // Verify issuer commitment matches the resolved DID
    try {
      const resolution = await resolver.resolve(issuerDid)
      const vm = (resolution.didDocument?.verificationMethod ?? []).find(
        v =>
          v.type === 'EcdsaSecp256k1VerificationKey2019' ||
          v.type === 'EcdsaSecp256k1RecoveryMethod2020'
      )
      const pubKeyHex           = vm?.publicKeyHex ?? issuerDid.split(':').pop()!
      const expectedCommitment  = pubKeyToFieldCommitment(pubKeyHex)
      if (BigInt(signals.issuerPubKeyCommitment) !== expectedCommitment) {
        return {
          valid:  false,
          reason: 'Issuer commitment mismatch: resolved DID key does not match proof',
        }
      }
    } catch (err) {
      return {
        valid:  false,
        reason: `Cannot verify issuer commitment: DID resolution failed: ${(err as Error).message}`,
      }
    }

    return { valid: true }
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.')
  if (parts.length !== 3) {
    throw new Error(`Invalid JWT-VC: expected 3 parts, got ${parts.length}`)
  }
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString())
  } catch (err) {
    throw new Error(`Invalid JWT-VC: failed to parse payload: ${(err as Error).message}`)
  }
}

/**
 * Verify the ES256K signature on a JWT (JWT-VC or VP JWT).
 *
 * Security note: This verifies that the JWT was signed by the key corresponding
 * to the DID's controller address. It does NOT verify JWT claims (exp, aud, etc.),
 * which callers must check separately.
 *
 * @param jwt           Compact JWT string (header.payload.signature)
 * @param signerAddress Ethereum address expected to have signed the JWT
 * @returns true if the signature is valid for the given address
 */
export function verifyJwtSignature(jwt: string, signerAddress: string): boolean {
  try {
    const parts = jwt.split('.')
    if (parts.length !== 3) return false
    const sigInput = `${parts[0]}.${parts[1]}`
    const digest   = ethers.keccak256(ethers.toUtf8Bytes(sigInput))
    const sigHex   = '0x' + Buffer.from(parts[2], 'base64url').toString('hex')
    if (sigHex.length < 130) return false  // r(32) + s(32) = 64 bytes = 128 hex + '0x'
    for (const v of [27, 28]) {
      try {
        const recovered = ethers.recoverAddress(digest, {
          r: '0x' + sigHex.slice(2, 66),
          s: '0x' + sigHex.slice(66, 130),
          v,
        })
        if (recovered.toLowerCase() === signerAddress.toLowerCase()) return true
      } catch { /* try next v */ }
    }
    return false
  } catch {
    return false
  }
}

/**
 * Maps credentialSubject to the 16-element attributeValues[] array.
 * Indices 6–15 are filled with 0n (reserved).
 */
function credentialSubjectToAttributes(subject: AgentCapabilityCredentialSubject): bigint[] {
  const values: bigint[] = new Array(CIRCUIT_ATTRIBUTE_COUNT).fill(NULL_FIELD_VALUE)

  values[ATTRIBUTE_INDEX.AUDIT_SCORE] = BigInt(Math.round(subject.auditScore))

  const modelHashHex = subject.modelHash.startsWith('0x')
    ? subject.modelHash.slice(2)
    : subject.modelHash
  values[ATTRIBUTE_INDEX.MODEL_HASH] = BigInt('0x' + modelHashHex.slice(0, 62))

  const jurisdictionNumeric = JURISDICTION_NUMERIC[subject.operatorJurisdiction] ?? 0
  values[ATTRIBUTE_INDEX.OPERATOR_JURISDICTION] = BigInt(jurisdictionNumeric)

  let bitmask = 0
  for (const cap of subject.capabilities) {
    bitmask |= CAPABILITY_BIT[cap] ?? 0
  }
  values[ATTRIBUTE_INDEX.CAPABILITIES_BITMASK] = BigInt(bitmask)

  const auditedByHash = ethers.keccak256(ethers.toUtf8Bytes(subject.auditedBy))
  values[ATTRIBUTE_INDEX.AUDITED_BY_HASH] = BigInt(auditedByHash) & ((1n << 248n) - 1n)

  const auditTimestamp = Date.parse(subject.auditDate + 'T00:00:00Z') / 1000
  values[ATTRIBUTE_INDEX.AUDIT_DATE_UNIX] = BigInt(auditTimestamp)

  return values
}

/**
 * Converts a secp256k1 public key (hex) to a BN254 field-compatible commitment.
 * Method: keccak256(rawKeyBytes) truncated to 248 bits.
 */
function pubKeyToFieldCommitment(pubKeyHex: string): bigint {
  const keyHex = pubKeyHex.replace(/^0x/, '')
  const hash   = ethers.keccak256('0x' + keyHex)
  return BigInt(hash) & ((1n << 248n) - 1n)
}
