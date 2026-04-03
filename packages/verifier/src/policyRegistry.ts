import { ethers } from 'ethers'
import type { EthrDIDIdentity } from '../../issuer/src/didEthrSetup'
import type { BuiltPredicate } from './predicateBuilder'
import type { PolicyDescriptor } from '@acta/shared'
import { CREDENTIAL_TYPE } from '@acta/shared'

const CIRCUIT_ID = ethers.keccak256(ethers.toUtf8Bytes('OpenACGPPresentation.v1'))

/**
 * Manages policy registration in the GeneralizedPredicateVerifier contract.
 * Maintains an in-memory registry of registered policies for fast lookup.
 */
export class PolicyRegistry {
  private policies: Map<string, PolicyDescriptor> = new Map()

  constructor(
    private identity: EthrDIDIdentity,
    private gpVerifierAddress: string
  ) {}

  /**
   * Register a predicate policy on-chain.
   * Returns the on-chain policyId (bytes32).
   *
   * @param predicate    BuiltPredicate from PredicateBuilder
   * @param issuerCommitment  Poseidon commitment of the trusted issuer's public key
   * @param expiryBlock  Block number after which the policy expires (0 = never)
   */
  async registerPolicy(
    predicate: BuiltPredicate,
    issuerCommitment: string,
    expiryBlock = 0
  ): Promise<string> {
    const abi = [
      'function registerPolicy((address verifier, bytes32 predicateProgramHash, bytes32 credentialType, bytes32 circuitId, uint256 expiryBlock, bytes32 issuerCommitment, bool active) desc) returns (bytes32)',
    ]
    const contract = new ethers.Contract(this.gpVerifierAddress, abi, this.identity.signer)

    const desc = {
      verifier:             this.identity.signer.address,
      predicateProgramHash: predicate.hash,
      credentialType:       ethers.keccak256(ethers.toUtf8Bytes(CREDENTIAL_TYPE)),
      circuitId:            CIRCUIT_ID,
      expiryBlock:          expiryBlock,
      issuerCommitment:     issuerCommitment,
      active:               true,
    }

    const tx = await contract.registerPolicy(desc)
    const receipt = await tx.wait()

    // Extract policyId from PolicyRegistered event
    const iface = new ethers.Interface(abi)
    let policyId = ''
    for (const log of (receipt?.logs ?? [])) {
      try {
        const parsed = iface.parseLog(log)
        if (parsed?.name === 'PolicyRegistered') {
          policyId = parsed.args.policyId
          break
        }
      } catch { /* skip */ }
    }

    if (!policyId) {
      // Compute deterministic policyId locally as fallback
      policyId = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['address', 'bytes32', 'bytes32', 'bytes32', 'uint256', 'bytes32'],
          [desc.verifier, desc.predicateProgramHash, desc.credentialType, desc.circuitId, desc.expiryBlock, desc.issuerCommitment]
        )
      )
    }

    const descriptor: PolicyDescriptor = {
      policyId,
      verifier:             this.identity.signer.address,
      predicateProgramHash: predicate.hash,
      credentialType:       CREDENTIAL_TYPE,
      circuitId:            CIRCUIT_ID,
      expiryBlock,
      active:               true,
    }
    this.policies.set(policyId, descriptor)

    return policyId
  }

  getPolicy(policyId: string): PolicyDescriptor | undefined {
    return this.policies.get(policyId)
  }

  getAllPolicies(): PolicyDescriptor[] {
    return Array.from(this.policies.values())
  }
}
