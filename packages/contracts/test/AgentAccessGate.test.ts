import { expect } from 'chai'
import { ethers } from 'hardhat'
import type { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/signers'

describe('AgentAccessGate', () => {
  let owner: HardhatEthersSigner
  let verifier: HardhatEthersSigner
  let agent: HardhatEthersSigner

  const TEST_NULLIFIER = ethers.keccak256(ethers.toUtf8Bytes('agent-nullifier'))
  const TEST_POLICY_ID = ethers.keccak256(ethers.toUtf8Bytes('test-policy'))

  /**
   * Minimal mock of GeneralizedPredicateVerifier that accepts a hardcoded nullifier.
   * Deployed inline as a mock to test AgentAccessGate in isolation.
   */
  async function deployMockGPVerifier(acceptedNullifier: string) {
    const MockGP = await ethers.getContractFactory('MockGPVerifier')
    const mock = await MockGP.deploy(acceptedNullifier)
    await mock.waitForDeployment()
    return mock
  }

  beforeEach(async () => {
    ;[owner, verifier, agent] = await ethers.getSigners()
  })

  it('grants access for an accepted nullifier', async () => {
    // Deploy a mock that reports TEST_NULLIFIER as accepted
    const mockGP = await deployMockGPVerifier(TEST_NULLIFIER)
    const mockGPAddr = await mockGP.getAddress()

    const Gate = await ethers.getContractFactory('AgentAccessGate')
    const gate = await Gate.deploy(owner.address, mockGPAddr, TEST_POLICY_ID)
    await gate.waitForDeployment()

    await expect(gate.connect(agent).grantAccess(TEST_NULLIFIER))
      .to.emit(gate, 'AccessGranted')
      .withArgs(TEST_NULLIFIER, await ethers.provider.getBlockNumber() + 1)

    expect(await gate.isAccessGranted(TEST_NULLIFIER)).to.be.true
  })

  it('reverts on double-grant (replay protection)', async () => {
    const mockGP = await deployMockGPVerifier(TEST_NULLIFIER)
    const Gate = await ethers.getContractFactory('AgentAccessGate')
    const gate = await Gate.deploy(owner.address, await mockGP.getAddress(), TEST_POLICY_ID)
    await gate.waitForDeployment()

    await gate.connect(agent).grantAccess(TEST_NULLIFIER)
    await expect(
      gate.connect(agent).grantAccess(TEST_NULLIFIER)
    ).to.be.revertedWithCustomError(gate, 'AccessAlreadyGranted')
  })

  it('reverts for a nullifier not accepted in GPVerifier', async () => {
    const differentNullifier = ethers.keccak256(ethers.toUtf8Bytes('other'))
    const mockGP = await deployMockGPVerifier(TEST_NULLIFIER)
    const Gate = await ethers.getContractFactory('AgentAccessGate')
    const gate = await Gate.deploy(owner.address, await mockGP.getAddress(), TEST_POLICY_ID)
    await gate.waitForDeployment()

    await expect(
      gate.connect(agent).grantAccess(differentNullifier)
    ).to.be.revertedWithCustomError(gate, 'PresentationNotAccepted')
  })

  it('allows owner to revoke access', async () => {
    const mockGP = await deployMockGPVerifier(TEST_NULLIFIER)
    const Gate = await ethers.getContractFactory('AgentAccessGate')
    const gate = await Gate.deploy(owner.address, await mockGP.getAddress(), TEST_POLICY_ID)
    await gate.waitForDeployment()

    await gate.connect(agent).grantAccess(TEST_NULLIFIER)
    await gate.connect(owner).revokeAccess(TEST_NULLIFIER)
    expect(await gate.isAccessGranted(TEST_NULLIFIER)).to.be.false
  })

  it('blocks onlyVerifiedAgent calls without granted access', async () => {
    const mockGP = await deployMockGPVerifier(TEST_NULLIFIER)
    const Gate = await ethers.getContractFactory('AgentAccessGate')
    const gate = await Gate.deploy(owner.address, await mockGP.getAddress(), TEST_POLICY_ID)
    await gate.waitForDeployment()

    const unverifiedNullifier = ethers.keccak256(ethers.toUtf8Bytes('unverified'))
    await expect(
      gate.connect(agent).executeProtocolAction(unverifiedNullifier, '0x')
    ).to.be.revertedWithCustomError(gate, 'AccessNotGranted')
  })
})
