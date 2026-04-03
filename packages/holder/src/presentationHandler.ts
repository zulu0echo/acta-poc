import { ethers } from 'ethers'
import type { EthrDIDIdentity } from './didEthrSetup'
import type { CredentialStore } from './credentialStore'
import { OpenACAdapter } from './openacAdapter'
import type {
  OID4VPAuthRequest,
  OpenACPresentation,
  PredicateProgram,
  GenerateProofParams,
} from '@acta/shared'

export interface PresentationResponse {
  vpJwt: string
  zkProof: OpenACPresentation
  nullifier: string
}

/**
 * Handles incoming OID4VP presentation requests.
 *
 * Flow:
 *  1. Parse and validate the OID4VP authorization request
 *  2. Find a matching credential in the store
 *  3. Import the credential into OpenAC (if not already imported)
 *  4. Generate ZK proof using the predicate from the request
 *  5. Construct a VP JWT (iss = holder did:ethr) with the zkProof claim
 *  6. POST the VP to the verifier's response_uri
 */
export class PresentationHandler {
  private openacAdapter: OpenACAdapter
  private importedHandles: Map<string, Awaited<ReturnType<OpenACAdapter['importCredential']>>> = new Map()

  constructor(
    private identity: EthrDIDIdentity,
    private credentialStore: CredentialStore
  ) {
    this.openacAdapter = new OpenACAdapter()
  }

  async handlePresentationRequest(
    authRequest: OID4VPAuthRequest
  ): Promise<PresentationResponse> {
    // Validate request
    if (!authRequest['x-openac-predicate']) {
      throw new Error('Missing x-openac-predicate in OID4VP request')
    }
    const predicate = JSON.parse(authRequest['x-openac-predicate']) as PredicateProgram
    const policyId  = authRequest['x-openac-policy-id']
    const verifierOnchainAddress = authRequest['x-onchain-verifier']
    // Derive a deterministic uint64 nonce from the OID4VP nonce string.
    // The previous implementation truncated the UTF-8 hex to 8 bytes, silently
    // discarding 56 bits and causing nonce mismatches against the verifier's
    // uint256 nonce in verifyAndRegister(). We now hash to a full 32-byte value
    // and take the low 64 bits — consistent with verifier/src/presentationRequest.ts.
    const nonceHashHex = ethers.keccak256(ethers.toUtf8Bytes(authRequest.nonce))
    const nonce = BigInt(nonceHashHex) & 0xFFFFFFFFFFFFFFFFn

    // Get credential from store
    const cred = this.credentialStore.getLatest()
    if (!cred) throw new Error('No credential in store. Request issuance first.')

    // Determine current block number for expiry
    let currentBlock = 1000
    try {
      currentBlock = await this.identity.provider.getBlockNumber()
    } catch {
      // Offline/dev mode
    }
    const expiryBlock = currentBlock + 100

    // Import credential into OpenAC (in-memory cache, survives within one process lifetime).
    // On re-import after server restart, pass the persisted randomnessHex so the wallet unit
    // reproduces the same Poseidon commitment that was anchored on-chain. A different randomness
    // would produce a different commitment and fail with CommitmentAlreadyAnchored.
    let handle = this.importedHandles.get(cred.id)
    if (!handle) {
      handle = await this.openacAdapter.importCredential(
        cred.jwtVc,
        cred.issuerDid,
        this.identity.resolver,
        cred.randomnessHex  // undefined on first import; persisted value on subsequent imports
      )
      this.importedHandles.set(cred.id, handle)

      // Persist the randomness returned by importCredential if this is a first-time import
      // (randomnessHex wasn't stored yet). This ensures future re-imports reproduce the same
      // commitment without generating fresh randomness.
      if (!cred.randomnessHex && handle.randomnessHex) {
        this.credentialStore.setAnchorData(
          cred.id,
          handle.commitment,
          handle.merkleRoot,
          handle.randomnessHex
        )
      }
    }

    // Generate ZK proof
    const proofParams: GenerateProofParams = {
      credentialHandle:  handle,
      predicateProgram:  predicate,
      policyId,
      verifierAddress:   verifierOnchainAddress,
      nonce,
      expiryBlock,
    }
    const zkProof = await this.openacAdapter.generatePresentationProof(proofParams)

    // Build VP JWT with zkProof claim
    const vpJwt = await this.buildVPJwt(
      authRequest.nonce,
      authRequest.client_id,
      cred.jwtVc,
      zkProof
    )

    return {
      vpJwt,
      zkProof,
      nullifier: zkProof.publicSignals.nullifier,
    }
  }

  private async buildVPJwt(
    nonce: string,
    verifierDid: string,
    vcJwt: string,
    zkProof: OpenACPresentation
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000)
    const header = {
      alg: 'ES256K',
      typ: 'JWT',
      kid: `${this.identity.did}#controller`,
    }
    const payload = {
      iss:     this.identity.did,
      aud:     verifierDid,
      iat:     now,
      exp:     now + 300,
      nonce,
      vp: {
        '@context':          ['https://www.w3.org/2018/credentials/v1'],
        type:                ['VerifiablePresentation'],
        verifiableCredential: [vcJwt],
      },
      zkProof,
    }

    const headerB64  = Buffer.from(JSON.stringify(header)).toString('base64url')
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const sigInput   = `${headerB64}.${payloadB64}`

    const sigBytes = this.identity.signer.signingKey.sign(
      ethers.keccak256(ethers.toUtf8Bytes(sigInput))
    )
    const sig = Buffer.from(sigBytes.r.slice(2) + sigBytes.s.slice(2), 'hex').toString('base64url')

    return `${sigInput}.${sig}`
  }
}
