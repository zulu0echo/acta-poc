import { ethers } from 'ethers'
import type { EthrDIDIdentity } from '../../issuer/src/didEthrSetup'
import { OpenACAdapter, verifyJwtSignature } from '../../holder/src/openacAdapter'
import type { OpenACPresentation } from '@acta/shared'

/**
 * Off-chain verifier — runs before on-chain submission to detect invalid proofs early.
 *
 * The off-chain step:
 *  1. Verifies the ZK proof locally using OpenAC wallet-unit-poc
 *  2. Checks that the issuer commitment in the public signals matches
 *     the resolved did:ethr DID document of the claimed issuer
 *  3. Checks that the VP JWT signature matches the holder's did:ethr
 *
 * This pre-flight saves gas by avoiding failed on-chain transactions.
 */
export class OffchainVerifier {
  private openacAdapter: OpenACAdapter

  constructor(private identity: EthrDIDIdentity) {
    this.openacAdapter = new OpenACAdapter()
  }

  /**
   * Verify a ZK presentation off-chain.
   * Returns { valid: true } if all checks pass, or { valid: false, reason } otherwise.
   *
   * @param presentation  The OpenACPresentation from the holder's VP response
   * @param policyId      The on-chain policyId this presentation claims to satisfy
   * @param issuerDid     The did:ethr of the credential issuer
   * @param vpJwt         The VP JWT from the holder (for signature check)
   * @param holderDid     The holder's did:ethr (for VP signature verification)
   */
  async verifyOffchain(params: {
    presentation: OpenACPresentation
    policyId: string
    issuerDid: string
    vpJwt: string
    holderDid: string
  }): Promise<{ valid: boolean; reason?: string; timingMs?: number }> {
    const start = Date.now()

    // Verify ZK proof and issuer commitment
    const zkResult = await this.openacAdapter.verifyPresentation(
      params.presentation,
      params.policyId,
      params.issuerDid,
      this.identity.resolver
    )
    if (!zkResult.valid) {
      return { valid: false, reason: `ZK proof invalid: ${zkResult.reason}` }
    }

    // Verify VP JWT structure (holder did:ethr must match iss claim)
    const vpCheck = verifyVPJwtStructure(params.vpJwt, params.holderDid)
    if (!vpCheck.valid) {
      return { valid: false, reason: `VP JWT invalid: ${vpCheck.reason}` }
    }

    // Verify expiry block
    const { expiryBlock } = params.presentation.publicSignals
    let currentBlock = 0
    try {
      currentBlock = await this.identity.provider.getBlockNumber()
    } catch { /* offline dev */ }

    if (currentBlock > 0 && expiryBlock <= currentBlock) {
      return { valid: false, reason: `Presentation expired at block ${expiryBlock}` }
    }

    return { valid: true, timingMs: Date.now() - start }
  }
}

function verifyVPJwtStructure(
  vpJwt: string,
  expectedHolderDid: string
): { valid: boolean; reason?: string } {
  try {
    const parts = vpJwt.split('.')
    if (parts.length !== 3) return { valid: false, reason: 'VP JWT must have exactly 3 parts' }
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString())

    // 1. iss claim must match the holder DID
    if (payload.iss !== expectedHolderDid) {
      return { valid: false, reason: `VP JWT iss "${payload.iss}" does not match holder DID "${expectedHolderDid}"` }
    }
    if (!payload.vp?.verifiableCredential?.length) {
      return { valid: false, reason: 'VP JWT missing verifiableCredential' }
    }
    if (!payload.zkProof) {
      return { valid: false, reason: 'VP JWT missing zkProof claim' }
    }

    // 2. Verify ES256K signature. The holder DID controller address is the signer.
    // Without this check, any party can forge a VP JWT claiming to be any holder
    // by simply setting the correct iss string — a complete authentication bypass.
    const holderAddress = expectedHolderDid.split(':').pop()!
    if (ethers.isAddress(holderAddress)) {
      const sigValid = verifyJwtSignature(vpJwt, holderAddress)
      if (!sigValid) {
        return { valid: false, reason: `VP JWT ES256K signature invalid for holder ${expectedHolderDid}` }
      }
    }

    return { valid: true }
  } catch (err) {
    return { valid: false, reason: `Failed to parse VP JWT: ${(err as Error).message}` }
  }
}
