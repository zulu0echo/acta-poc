import { expect } from 'chai'
import { ethers } from 'hardhat'
import type { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/signers'
import type {
  NullifierRegistry,
  OpenACCredentialAnchor,
  OpenACSnarkVerifier,
  GeneralizedPredicateVerifier,
  AgentAccessGate,
} from '../../typechain-types'

/**
 * Full integration test for the ACTA on-chain flow.
 * Simulates: did:ethr identities → credential anchor → policy registration →
 *             ZK proof verification → nullifier registration → access gate.
 *
 * Uses a sentinel proof value accepted by OpenACSnarkVerifier in test mode.
 */
describe('ACTA Full Integration Flow', () => {
  let issuer:   HardhatEthersSigner
  let holder:   HardhatEthersSigner
  let verifier: HardhatEthersSigner

  let nullifierRegistry:  NullifierRegistry
  let credentialAnchor:   OpenACCredentialAnchor
  let snarkVerifier:      OpenACSnarkVerifier
  let gpVerifier:         GeneralizedPredicateVerifier
  let accessGate:         AgentAccessGate

  const CREDENTIAL_TYPE = ethers.keccak256(ethers.toUtf8Bytes('AgentCapabilityCredential'))
  const CIRCUIT_ID      = ethers.keccak256(ethers.toUtf8Bytes('OpenACGPPresentation.v1'))

  // Sentinel proof accepted by OpenACSnarkVerifier in test mode
  const TEST_PROOF = ethers.keccak256(ethers.toUtf8Bytes('OPENAC_TEST_PROOF_V1'))
  const SENTINEL_PROOF = ethers.zeroPadBytes(TEST_PROOF, 256)

  let policyId: string
  let commitment: string
  let merkleRoot: string
  let nullifier: string

  before(async () => {
    ;[issuer, holder, verifier] = await ethers.getSigners()

    // Deploy all contracts
    nullifierRegistry = await (await ethers.getContractFactory('NullifierRegistry'))
      .deploy(issuer.address) as NullifierRegistry
    await nullifierRegistry.waitForDeployment()

    credentialAnchor = await (await ethers.getContractFactory('OpenACCredentialAnchor'))
      .deploy(issuer.address) as OpenACCredentialAnchor
    await credentialAnchor.waitForDeployment()

    snarkVerifier = await (await ethers.getContractFactory('OpenACSnarkVerifier'))
      .deploy() as OpenACSnarkVerifier
    await snarkVerifier.waitForDeployment()

    gpVerifier = await (await ethers.getContractFactory('GeneralizedPredicateVerifier'))
      .deploy(
        issuer.address,
        await nullifierRegistry.getAddress(),
        await credentialAnchor.getAddress()
      ) as GeneralizedPredicateVerifier
    await gpVerifier.waitForDeployment()

    // Wire up
    await nullifierRegistry.connect(issuer).lockAuthorization(await gpVerifier.getAddress())
    await gpVerifier.connect(issuer).registerCircuitVerifier(CIRCUIT_ID, await snarkVerifier.getAddress())

    // Create actor identities (Ethereum addresses represent did:ethr addresses)
    commitment  = ethers.keccak256(ethers.toUtf8Bytes('holder-commitment'))
    merkleRoot  = ethers.keccak256(ethers.toUtf8Bytes('holder-merkle-root'))
    nullifier   = ethers.keccak256(ethers.toUtf8Bytes('holder-nullifier'))
  })

  describe('Phase 1: did:ethr identity checks', () => {
    it('each signer address maps to a valid did:ethr', () => {
      // did:ethr:0x14f69:0x<address> — validate address format
      const chainHex = '0x14f69'
      for (const actor of [issuer, holder, verifier]) {
        const did = `did:ethr:${chainHex}:${actor.address.toLowerCase()}`
        expect(did).to.match(/^did:ethr:0x14f69:0x[0-9a-f]{40}$/)
      }
    })

    it('agentId is uint256(uint160(holderAddress))', () => {
      const agentId = BigInt(holder.address)
      expect(agentId).to.equal(BigInt(holder.address))
      // Reconstruct address: address(uint160(agentId)) == holder.address
      expect(ethers.getAddress(`0x${agentId.toString(16).padStart(40, '0')}`))
        .to.equal(holder.address)
    })
  })

  describe('Phase 2: Credential anchoring', () => {
    it('holder anchors credential with their did:ethr address as agentId', async () => {
      const agentId = BigInt(holder.address)
      await expect(
        credentialAnchor.connect(holder).anchorCredential(
          agentId, CREDENTIAL_TYPE, commitment, merkleRoot
        )
      ).to.emit(credentialAnchor, 'CredentialAnchored')
        .withArgs(agentId, CREDENTIAL_TYPE, commitment, merkleRoot, await ethers.provider.getBlockNumber() + 1)
    })

    it('non-holder cannot anchor for holder agentId', async () => {
      const agentId = BigInt(holder.address)
      await expect(
        credentialAnchor.connect(verifier).anchorCredential(
          agentId, CREDENTIAL_TYPE, ethers.keccak256(ethers.toUtf8Bytes('other')), merkleRoot
        )
      ).to.be.revertedWithCustomError(credentialAnchor, 'AgentIdMismatch')
    })

    it('Merkle root is current after anchoring', async () => {
      const agentId = BigInt(holder.address)
      expect(
        await credentialAnchor.isMerkleRootCurrent(agentId, CREDENTIAL_TYPE, merkleRoot)
      ).to.be.true
    })
  })

  describe('Phase 3: Policy registration', () => {
    it('verifier registers a policy and gets a policyId', async () => {
      const predicateHash   = ethers.keccak256(ethers.toUtf8Bytes('audit_score_gte_80'))
      const issuerCommitment = ethers.keccak256(ethers.toUtf8Bytes('issuer-pubkey'))
      const expiryBlock     = (await ethers.provider.getBlockNumber()) + 10000

      const desc = {
        verifier:              verifier.address,
        predicateProgramHash:  predicateHash,
        credentialType:        CREDENTIAL_TYPE,
        circuitId:             CIRCUIT_ID,
        expiryBlock:           expiryBlock,
        issuerCommitment:      issuerCommitment,
        active:                true,
      }

      const tx = await gpVerifier.connect(verifier).registerPolicy(desc)
      const receipt = await tx.wait()

      const event = receipt?.logs
        .map(log => {
          try { return gpVerifier.interface.parseLog(log) } catch { return null }
        })
        .find(e => e?.name === 'PolicyRegistered')

      expect(event).to.not.be.undefined
      policyId = event!.args.policyId
      expect(policyId).to.match(/^0x[0-9a-f]{64}$/)
    })
  })

  describe('Phase 4: ZK proof verification (10-step sequence)', () => {
    let nonce: bigint
    let pubSignals: bigint[]

    before(async () => {
      nonce = BigInt('0x' + ethers.randomBytes(8).reduce((a, b) => a + b.toString(16).padStart(2, '0'), ''))

      const policy = await gpVerifier.getPolicy(policyId)
      const expiryBlock = (await ethers.provider.getBlockNumber()) + 100

      const contextHash = ethers.keccak256(
        ethers.solidityPacked(
          ['address', 'bytes32', 'uint256'],
          [verifier.address, policyId, nonce]
        )
      )

      pubSignals = [
        BigInt(nullifier),
        BigInt(contextHash),
        BigInt(policy.predicateProgramHash),
        BigInt(policy.issuerCommitment),
        BigInt(merkleRoot),
        BigInt(expiryBlock),
      ]
    })

    it('verifyAndRegister completes all 10 steps and emits PresentationAccepted', async () => {
      const agentId = BigInt(holder.address)

      await expect(
        gpVerifier.connect(verifier).verifyAndRegister(
          policyId,
          SENTINEL_PROOF,
          pubSignals,
          agentId,
          nonce
        )
      ).to.emit(gpVerifier, 'PresentationAccepted')
        .withArgs(policyId, nullifier, pubSignals[1], verifier.address, await ethers.provider.getBlockNumber() + 1)
    })

    it('replay reverts with NullifierAlreadyActive (Step 9 enforcement)', async () => {
      const agentId = BigInt(holder.address)
      await expect(
        gpVerifier.connect(verifier).verifyAndRegister(
          policyId,
          SENTINEL_PROOF,
          pubSignals,
          agentId,
          nonce
        )
      ).to.be.revertedWithCustomError(nullifierRegistry, 'NullifierAlreadyActive')
    })
  })

  describe('Phase 5: AgentAccessGate', () => {
    before(async () => {
      accessGate = await (await ethers.getContractFactory('AgentAccessGate'))
        .deploy(issuer.address, await gpVerifier.getAddress(), policyId) as AgentAccessGate
      await accessGate.waitForDeployment()
    })

    it('grants access after accepted presentation', async () => {
      await expect(
        accessGate.connect(holder).grantAccess(nullifier)
      ).to.emit(accessGate, 'AccessGranted')
      expect(await accessGate.isAccessGranted(nullifier)).to.be.true
    })

    it('allows gated protocol action with valid nullifier', async () => {
      await expect(
        accessGate.connect(holder).executeProtocolAction(nullifier, ethers.toUtf8Bytes('do-something'))
      ).to.not.be.reverted
    })

    it('cross-policy: nullifier accepted under a different policyId cannot grant access', async () => {
      // Register a SECOND policy with different predicateHash
      const weakPredicateHash = ethers.keccak256(ethers.toUtf8Bytes('audit_score_gte_10'))
      const issuerCommitment  = ethers.keccak256(ethers.toUtf8Bytes('issuer-pubkey'))
      const weakDesc = {
        verifier:             verifier.address,
        predicateProgramHash: weakPredicateHash,
        credentialType:       CREDENTIAL_TYPE,
        circuitId:            CIRCUIT_ID,
        expiryBlock:          (await ethers.provider.getBlockNumber()) + 10000,
        issuerCommitment,
        active:               true,
      }
      const weakTx       = await gpVerifier.connect(verifier).registerPolicy(weakDesc)
      const weakReceipt  = await weakTx.wait()
      const weakEvent    = weakReceipt?.logs
        .map(log => { try { return gpVerifier.interface.parseLog(log) } catch { return null } })
        .find(e => e?.name === 'PolicyRegistered')
      const weakPolicyId = weakEvent!.args.policyId

      // A gate keyed to the STRONG policy should reject a nullifier accepted for the WEAK policy
      const strongGate = await (await ethers.getContractFactory('AgentAccessGate'))
        .deploy(issuer.address, await gpVerifier.getAddress(), policyId) as AgentAccessGate
      await strongGate.waitForDeployment()

      // nullifier was accepted under policyId (strong), not weakPolicyId
      // So it should FAIL on a gate keyed to weakPolicyId
      const weakGate = await (await ethers.getContractFactory('AgentAccessGate'))
        .deploy(issuer.address, await gpVerifier.getAddress(), weakPolicyId) as AgentAccessGate
      await weakGate.waitForDeployment()

      await expect(
        weakGate.connect(holder).grantAccess(nullifier)
      ).to.be.revertedWithCustomError(weakGate, 'PresentationNotAccepted')
    })

    it('isAcceptedForPolicy returns false for wrong policyId', async () => {
      const randomPolicyId = ethers.keccak256(ethers.toUtf8Bytes('random'))
      expect(await gpVerifier.isAcceptedForPolicy(nullifier, randomPolicyId)).to.be.false
      expect(await gpVerifier.isAcceptedForPolicy(nullifier, policyId)).to.be.true
    })
  })

  describe('Phase 6: registerPolicy input validation', () => {
    it('reverts when desc.verifier != msg.sender', async () => {
      const desc = {
        verifier:             issuer.address, // deliberate mismatch — caller is verifier
        predicateProgramHash: ethers.keccak256(ethers.toUtf8Bytes('p')),
        credentialType:       CREDENTIAL_TYPE,
        circuitId:            CIRCUIT_ID,
        expiryBlock:          0,
        issuerCommitment:     ethers.keccak256(ethers.toUtf8Bytes('k')),
        active:               true,
      }
      await expect(
        gpVerifier.connect(verifier).registerPolicy(desc)
      ).to.be.revertedWithCustomError(gpVerifier, 'UnauthorizedPolicyOwner')
    })

    it('accepts desc.verifier == address(0) (zero is treated as unset, uses msg.sender)', async () => {
      const desc = {
        verifier:             ethers.ZeroAddress,
        predicateProgramHash: ethers.keccak256(ethers.toUtf8Bytes('p2')),
        credentialType:       CREDENTIAL_TYPE,
        circuitId:            CIRCUIT_ID,
        expiryBlock:          0,
        issuerCommitment:     ethers.keccak256(ethers.toUtf8Bytes('k2')),
        active:               true,
      }
      await expect(
        gpVerifier.connect(verifier).registerPolicy(desc)
      ).to.emit(gpVerifier, 'PolicyRegistered')
    })
  })
})
