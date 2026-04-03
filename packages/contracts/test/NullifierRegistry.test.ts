import { expect } from 'chai'
import { ethers } from 'hardhat'
import { NullifierRegistry } from '../typechain-types'
import { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/signers'

describe('NullifierRegistry', () => {
  let registry: NullifierRegistry
  let owner: HardhatEthersSigner
  let authorized: HardhatEthersSigner
  let stranger: HardhatEthersSigner

  const NULLIFIER = ethers.keccak256(ethers.toUtf8Bytes('test-nullifier-1'))
  const CONTEXT   = ethers.keccak256(ethers.toUtf8Bytes('test-context-1'))

  beforeEach(async () => {
    ;[owner, authorized, stranger] = await ethers.getSigners()
    const Factory = await ethers.getContractFactory('NullifierRegistry')
    registry = await Factory.deploy(owner.address) as NullifierRegistry
    await registry.waitForDeployment()
    await registry.connect(owner).lockAuthorization(authorized.address)
  })

  describe('lockAuthorization', () => {
    it('allows owner to authorize callers', async () => {
      expect(await registry.isAuthorized(authorized.address)).to.be.true
    })

    it('reverts if non-owner tries to authorize', async () => {
      await expect(
        registry.connect(stranger).lockAuthorization(stranger.address)
      ).to.be.revertedWithCustomError(registry, 'OwnableUnauthorizedAccount')
    })
  })

  describe('register', () => {
    it('registers a nullifier successfully', async () => {
      const futureBlock = (await ethers.provider.getBlockNumber()) + 100
      await expect(
        registry.connect(authorized).register(NULLIFIER, CONTEXT, futureBlock)
      ).to.emit(registry, 'NullifierRegistered')
        .withArgs(NULLIFIER, CONTEXT, futureBlock)
    })

    it('reverts if nullifier is zero', async () => {
      const futureBlock = (await ethers.provider.getBlockNumber()) + 100
      await expect(
        registry.connect(authorized).register(ethers.ZeroHash, CONTEXT, futureBlock)
      ).to.be.revertedWithCustomError(registry, 'InvalidNullifier')
    })

    it('reverts if expiryBlock is in the past', async () => {
      const pastBlock = (await ethers.provider.getBlockNumber()) - 1
      await expect(
        registry.connect(authorized).register(NULLIFIER, CONTEXT, pastBlock)
      ).to.be.revertedWithCustomError(registry, 'InvalidExpiryBlock')
    })

    it('reverts for unauthorized callers', async () => {
      const futureBlock = (await ethers.provider.getBlockNumber()) + 100
      await expect(
        registry.connect(stranger).register(NULLIFIER, CONTEXT, futureBlock)
      ).to.be.revertedWithCustomError(registry, 'UnauthorizedCaller')
    })

    it('reverts on replay (NullifierAlreadyActive)', async () => {
      const futureBlock = (await ethers.provider.getBlockNumber()) + 100
      await registry.connect(authorized).register(NULLIFIER, CONTEXT, futureBlock)
      await expect(
        registry.connect(authorized).register(NULLIFIER, CONTEXT, futureBlock)
      ).to.be.revertedWithCustomError(registry, 'NullifierAlreadyActive')
    })

    it('allows re-registration of an expired nullifier (intended: nonce-bound expiry)', async () => {
      // An expired nullifier can be re-registered. This is intentional: the nullifier is
      // deterministic for a given (credential, verifier, policy, nonce) tuple. If a verifier
      // reuses a nonce after expiry, the same nullifier is re-registered. Verifiers MUST
      // use fresh, non-reused nonces to prevent this session replay.
      const expiryBlock = (await ethers.provider.getBlockNumber()) + 2
      await registry.connect(authorized).register(NULLIFIER, CONTEXT, expiryBlock)
      await ethers.provider.send('hardhat_mine', ['0x5'])

      // Re-registration should succeed since the record is expired
      const newExpiry = (await ethers.provider.getBlockNumber()) + 100
      await expect(
        registry.connect(authorized).register(NULLIFIER, CONTEXT, newExpiry)
      ).to.emit(registry, 'NullifierRegistered')
    })

    it('allows re-registration of a revoked nullifier (new credential after revocation)', async () => {
      // A revoked nullifier can be re-registered. This covers the case where an agent
      // gets a NEW credential (new commitment + randomness) that produces the same nullifier —
      // which is negligible-probability under Poseidon collision resistance. In practice,
      // it covers the case where revocation is used administratively and then the agent
      // re-authenticates with a fresh proof. Note: with the SAME credential and SAME context,
      // the nullifier is deterministic, so the agent cannot re-register after revocation
      // unless the verifier issues a new nonce (which changes the contextHash and nullifier).
      const futureBlock = (await ethers.provider.getBlockNumber()) + 1000
      await registry.connect(authorized).register(NULLIFIER, CONTEXT, futureBlock)
      await registry.connect(authorized).revoke(NULLIFIER)
      expect(await registry.isActive(NULLIFIER)).to.be.false

      const newExpiry = (await ethers.provider.getBlockNumber()) + 100
      await expect(
        registry.connect(authorized).register(NULLIFIER, CONTEXT, newExpiry)
      ).to.emit(registry, 'NullifierRegistered')
      expect(await registry.isActive(NULLIFIER)).to.be.true
    })

    it('reverts with current-block expiryBlock (must be strictly in the future)', async () => {
      const currentBlock = await ethers.provider.getBlockNumber()
      await expect(
        registry.connect(authorized).register(NULLIFIER, CONTEXT, currentBlock)
      ).to.be.revertedWithCustomError(registry, 'InvalidExpiryBlock')
    })
  })

  describe('isActive', () => {
    it('returns true for a registered non-expired nullifier', async () => {
      const futureBlock = (await ethers.provider.getBlockNumber()) + 1000
      await registry.connect(authorized).register(NULLIFIER, CONTEXT, futureBlock)
      expect(await registry.isActive(NULLIFIER)).to.be.true
    })

    it('returns false for an unknown nullifier', async () => {
      expect(await registry.isActive(NULLIFIER)).to.be.false
    })

    it('returns false after expiryBlock has passed', async () => {
      const expiryBlock = (await ethers.provider.getBlockNumber()) + 2
      await registry.connect(authorized).register(NULLIFIER, CONTEXT, expiryBlock)
      expect(await registry.isActive(NULLIFIER)).to.be.true

      // Mine enough blocks to pass the expiry
      await ethers.provider.send('hardhat_mine', ['0x5']) // mine 5 blocks
      expect(await registry.isActive(NULLIFIER)).to.be.false
    })
  })

  describe('revoke', () => {
    beforeEach(async () => {
      const futureBlock = (await ethers.provider.getBlockNumber()) + 1000
      await registry.connect(authorized).register(NULLIFIER, CONTEXT, futureBlock)
    })

    it('allows authorized registrar to revoke', async () => {
      await expect(
        registry.connect(authorized).revoke(NULLIFIER)
      ).to.emit(registry, 'NullifierRevoked')
        .withArgs(NULLIFIER, authorized.address)
      expect(await registry.isActive(NULLIFIER)).to.be.false
    })

    it('allows owner to revoke', async () => {
      await registry.connect(owner).revoke(NULLIFIER)
      expect(await registry.isActive(NULLIFIER)).to.be.false
    })

    it('reverts if stranger tries to revoke', async () => {
      await expect(
        registry.connect(stranger).revoke(NULLIFIER)
      ).to.be.revertedWithCustomError(registry, 'UnauthorizedCaller')
    })

    it('reverts for unknown nullifier', async () => {
      const unknown = ethers.keccak256(ethers.toUtf8Bytes('unknown'))
      await expect(
        registry.connect(owner).revoke(unknown)
      ).to.be.revertedWithCustomError(registry, 'NullifierNotFound')
    })
  })

  describe('getRecord', () => {
    it('returns the full record for a registered nullifier', async () => {
      const futureBlock = (await ethers.provider.getBlockNumber()) + 100
      await registry.connect(authorized).register(NULLIFIER, CONTEXT, futureBlock)
      const [contextHash, expiryBlock, registeredBy, , revoked] =
        await registry.getRecord(NULLIFIER)
      expect(contextHash).to.equal(CONTEXT)
      expect(expiryBlock).to.equal(futureBlock)
      expect(registeredBy).to.equal(authorized.address)
      expect(revoked).to.be.false
    })
  })
})
