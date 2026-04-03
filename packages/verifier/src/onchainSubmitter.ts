import { ethers } from 'ethers'
import type { EthrDIDIdentity } from '../../issuer/src/didEthrSetup'
import type { OpenACPresentation } from '@acta/shared'

const GP_VERIFIER_ABI = [
  'function verifyAndRegister(bytes32 policyId, bytes calldata proof, uint256[] calldata pubSignals, uint256 agentId, uint256 nonce) external',
  'function isAccepted(bytes32 nullifier) external view returns (bool)',
  'function isAcceptedForPolicy(bytes32 nullifier, bytes32 policyId) external view returns (bool)',
  'event PresentationAccepted(bytes32 indexed policyId, bytes32 indexed nullifier, bytes32 contextHash, address indexed verifier, uint256 blockNumber)',
]

export interface OnchainSubmitResult {
  txHash: string
  blockNumber: number
  gasUsed: string
  nullifier: string
  presentationAcceptedEvent: {
    policyId: string
    nullifier: string
    contextHash: string
    blockNumber: number
  }
}

/**
 * Submits a verified ZK presentation to the GeneralizedPredicateVerifier contract.
 * This triggers the 10-step on-chain verification and emits PresentationAccepted.
 */
export class OnchainSubmitter {
  constructor(
    private identity: EthrDIDIdentity,
    private gpVerifierAddress: string
  ) {}

  /**
   * Submit a ZK presentation on-chain.
   *
   * @param policyId      bytes32 policyId from PolicyRegistry
   * @param presentation  OpenACPresentation from the holder
   * @param agentDid      Holder's did:ethr (for extracting agentId)
   * @param nonce         Session nonce that was in the OID4VP request
   */
  async submit(params: {
    policyId: string
    presentation: OpenACPresentation
    agentDid: string
    nonce: bigint
  }): Promise<OnchainSubmitResult> {
    const contract = new ethers.Contract(
      this.gpVerifierAddress,
      GP_VERIFIER_ABI,
      this.identity.signer
    )

    const { publicSignals, proofBytes } = params.presentation

    // Extract the Ethereum address from a did:ethr DID.
    // Format: did:ethr:0x<chainId>:0x<address>  or  did:ethr:0x<address>
    // We resolve to a checksummed address via ethers to handle both formats safely.
    const rawAddress = params.agentDid.split(':').pop()!
    if (!ethers.isAddress(rawAddress)) {
      throw new Error(`Cannot extract Ethereum address from agentDid: ${params.agentDid}`)
    }
    const agentId = BigInt(rawAddress)

    const pubSignalsArray = [
      BigInt(publicSignals.nullifier),
      BigInt(publicSignals.contextHash),
      BigInt(publicSignals.predicateProgramHash),
      BigInt(publicSignals.issuerPubKeyCommitment),
      BigInt(publicSignals.credentialMerkleRoot),
      BigInt(publicSignals.expiryBlock),
    ]

    const tx = await contract.verifyAndRegister(
      params.policyId,
      proofBytes,
      pubSignalsArray,
      agentId,
      params.nonce
    )
    const receipt = await tx.wait()

    // Parse PresentationAccepted event
    const iface = new ethers.Interface(GP_VERIFIER_ABI)
    let event = {
      policyId:    params.policyId,
      nullifier:   publicSignals.nullifier,
      contextHash: publicSignals.contextHash,
      blockNumber: receipt?.blockNumber ?? 0,
    }
    for (const log of (receipt?.logs ?? [])) {
      try {
        const parsed = iface.parseLog(log)
        if (parsed?.name === 'PresentationAccepted') {
          event = {
            policyId:    parsed.args.policyId,
            nullifier:   parsed.args.nullifier,
            contextHash: parsed.args.contextHash,
            blockNumber: Number(parsed.args.blockNumber),
          }
          break
        }
      } catch { /* skip */ }
    }

    return {
      txHash:      receipt?.hash ?? '',
      blockNumber: receipt?.blockNumber ?? 0,
      gasUsed:     receipt?.gasUsed?.toString() ?? '0',
      nullifier:   publicSignals.nullifier,
      presentationAcceptedEvent: event,
    }
  }
}
